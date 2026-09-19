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
