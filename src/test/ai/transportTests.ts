import assert from "node:assert/strict";
import { NativeTransport, withDeadline } from "../../ai/transport.js";
import { AnalysisBudget } from "../../ai/budget.js";
import { limitsSchema } from "../../ai/config.js";
import type { CallContext } from "../../ai/contracts.js";

function context(ms = 1000, signal?: AbortSignal): CallContext {
    const budget = new AnalysisBudget("prompt", limitsSchema.parse({}), { deadlineMs: Date.now() + ms });
    return { budget, deadlineMs: budget.deadlineMs, signal, role: "semantic", runId: "fixture", configHash: "fixture" };
}
const request = { url: "https://provider.invalid/inference", headers: { authorization: "secret-fixture-key" }, body: "{}", timeoutMs: 1000 };
// Timers can wake before the absolute Date.now boundary. Control both clocks so
// this regression does not depend on a particular Node version or machine load.
async function earlyDeadlineTimer(operation: "wrapper" | "transport", outcome: "timeout" | "cancelled" | "complete"): Promise<void> {
    const originalNow = Date.now;
    const originalSetTimeout = globalThis.setTimeout;
    const originalClearTimeout = globalThis.clearTimeout;
    let now = 1000;
    let nextId = 0;
    const timers = new Map<number, () => void>();
    Date.now = () => now;
    globalThis.setTimeout = ((callback: () => void) => {
        const id = ++nextId;
        timers.set(id, callback);
        return id;
    }) as unknown as typeof setTimeout;
    globalThis.clearTimeout = ((id: number) => { timers.delete(id); }) as unknown as typeof clearTimeout;
    const fireTimer = () => {
        const [id, callback] = timers.entries().next().value!;
        timers.delete(id);
        callback();
    };
    const external = new AbortController();
    let signal: AbortSignal | undefined;
    let finish!: () => void;
    let pending: Promise<unknown> | undefined;
    try {
        pending = operation === "wrapper"
            ? withDeadline(async active => { signal = active; return new Promise<string>(resolve => { finish = () => resolve("finished"); }); }, 1100, external.signal)
            : new NativeTransport({ fetch: async (_url, init) => { signal = init?.signal ?? undefined; return new Promise<Response>(resolve => { finish = () => resolve(new Response("{}")); }); } }).postJson(request, context(100, external.signal));
        // Observe rejection immediately, including when this regression fails.
        const settled = pending.then(value => ({ value }), error => ({ error }));
        await Promise.resolve();
        assert.ok(signal, "the operation must start before exercising its deadline");
        now = 1099;
        fireTimer();
        assert.equal(signal.aborted, false, `${operation} must not abort before its absolute deadline`);
        assert.equal(timers.size, 1, "an early timer must rearm for the remaining interval");
        if (outcome === "timeout") { now = 1100; fireTimer(); }
        else if (outcome === "cancelled") external.abort();
        else finish();
        const result = await settled;
        if (operation === "wrapper") {
            if (outcome === "complete") assert.deepEqual(result, { value: "finished" });
            else assert.equal("error" in result && result.error.code, outcome);
        } else {
            assert.ok("value" in result);
            const value = result.value as Awaited<ReturnType<NativeTransport["postJson"]>>;
            assert.equal(value.attempts, 1, "timer boundaries cannot add physical attempts");
            assert.equal(value.status, outcome === "complete" ? "ok" : "unavailable");
            if (value.status === "unavailable") assert.equal(value.code, outcome);
        }
        assert.equal(timers.size, 0, "completion, timeout and cancellation must clear all deadline timers");
        assert.equal(signal.aborted, outcome !== "complete");
        external.abort();
        assert.equal(signal.aborted, outcome !== "complete", "completed work must remove the external abort listener");
    } finally {
        external.abort();
        await pending?.catch(() => {});
        Date.now = originalNow;
        globalThis.setTimeout = originalSetTimeout;
        globalThis.clearTimeout = originalClearTimeout;
    }
}
for (const operation of ["wrapper", "transport"] as const) {
    for (const outcome of ["timeout", "cancelled", "complete"] as const) await earlyDeadlineTimer(operation, outcome);
}
let expiredCallbackCalls = 0;
await assert.rejects(withDeadline(async () => { expiredCallbackCalls++; throw new Error("must not run"); }, Date.now() - 1));
assert.equal(expiredCallbackCalls, 0, "expired work must not start");
const alreadyAborted = new AbortController();
alreadyAborted.abort();
await assert.rejects(withDeadline(async () => { expiredCallbackCalls++; throw new Error("must not run"); }, Date.now() + 1000, alreadyAborted.signal));
assert.equal(expiredCallbackCalls, 0, "pre-aborted work must not start");
const blockedClock = new NativeTransport({ fetch: async () => {
    const end = Date.now() + 30;
    while (Date.now() < end) { /* simulate synchronous provider/stream work */ }
    return new Response("{}");
} });
assert.equal((await blockedClock.postJson(request, context(10))).status, "unavailable", "expired results must not beat the overdue timer callback");
await assert.rejects(withDeadline(async () => {
    const end = Date.now() + 30;
    while (Date.now() < end) { /* simulated event-loop stall */ }
    return "late";
}, Date.now() + 10));
let calls = 0;
const retryTransport = new NativeTransport({ fetch: async () => { calls++; return calls === 1 ? new Response("do not disclose secret-fixture-key", { status: 503, headers: { "retry-after": "0" } }) : new Response('{"answer":1}'); } });
const retried = await retryTransport.postJson(request, context());
assert.equal(retried.status, "ok");
assert.equal(retried.attempts, 2);
assert.equal(calls, 2);
for (const [status, expectedCalls, code] of [[529, 2, "transport"], [400, 1, "unsupported"], [422, 1, "unsupported"], [401, 1, "authentication"]] as const) {
    let dispatched = 0;
    const failing = new NativeTransport({ fetch: async () => { dispatched++; return new Response("private error body", { status, headers: { "retry-after": "0" } }); } });
    const failure = await failing.postJson(request, context());
    assert.equal(dispatched, expectedCalls);
    assert.equal(failure.status === "unavailable" && failure.code, code);
}
const redirect = await new NativeTransport({ fetch: async () => new Response("secret-fixture-key", { status: 302, headers: { location: "https://evil.invalid" } }) }).postJson(request, context());
assert.equal(redirect.status, "unavailable");
assert.ok(!JSON.stringify(redirect).includes("secret"));
let cancelledBody = false;
const overflow = await new NativeTransport({ fetch: async () => new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode("12345678")); }, cancel() { cancelledBody = true; } })) }).postJson({ ...request, maxResponseBytes: 4 }, context());
assert.equal(overflow.status, "unavailable");
assert.ok(cancelledBody);
const slow = new NativeTransport({ fetch: async () => new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode("{")); } })) });
const start = Date.now();
const timed = await slow.postJson(request, context(25));
assert.equal(timed.status === "unavailable" && timed.code, "timeout");
assert.ok(Date.now() - start < 500, "deadline includes slow response body");
const noHeaders = new NativeTransport({ fetch: async () => new Promise<Response>(() => {}) });
assert.equal((await noHeaders.postJson(request, context(20))).status, "unavailable", "fetch ignoring abort still cannot hang caller");
let release!: (response: Response) => void;
let queuedCalls = 0;
const queued = new NativeTransport({ maxConcurrent: 1, maxQueue: 1, fetch: async () => { queuedCalls++; return new Promise<Response>((resolve) => { release = resolve; }); } });
const first = queued.postJson(request, context());
await new Promise((resolve) => setTimeout(resolve, 1));
const abort = new AbortController();
const second = queued.postJson(request, context(1000, abort.signal));
const full = await queued.postJson(request, context());
assert.equal(full.status === "unavailable" && full.code, "budget_exceeded");
abort.abort();
assert.equal((await second).status, "unavailable");
release(new Response("{}"));
assert.equal((await first).status, "ok");
assert.equal(queuedCalls, 1, "cancelled queued work never dispatches");
let deadlineCalls = 0;
const deadline = new NativeTransport({ fetch: async () => { deadlineCalls++; return new Response("", { status: 429, headers: { "retry-after": "10" } }); } });
const limited = await deadline.postJson(request, context(20));
assert.equal(limited.status, "unavailable");
assert.equal(deadlineCalls, 1, "retry-after cannot reset or exceed original deadline");
console.log("PASS transport cancellation, bounds, retries and privacy");
