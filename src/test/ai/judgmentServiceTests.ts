import assert from "node:assert/strict";
import { JudgmentService, effectiveJudgmentMode } from "../../services/JudgmentService.js";
import { loadAIConfig, parseAIConfig } from "../../ai/config.js";
import { AnalysisBudget } from "../../ai/budget.js";
import type { CallContext, JudgmentRequest } from "../../ai/contracts.js";
const legacy = loadAIConfig({});
const snapshot = parseAIConfig({ ...legacy.config, typesafe: { ...legacy.config.typesafe, descriptor: "shadow", prompt: "shadow", capability: "shadow" } });
const req: JudgmentRequest = { model: "jev-1.13.0", state: '{"source":"fixture"}', rubricVersion: "1", schemaVersion: "1", questions: { risk: { type: "noul", instructions: "Risk?", criteria: { true: "Malicious", false: "Benign" } } } };
const ctx = (deadlineMs?: number): CallContext => {
    const budget = new AnalysisBudget("descriptor", snapshot.config.limits, { deadlineMs });
    budget.authorizeShadow({ requiredWorkComplete: true });
    return { budget, deadlineMs: budget.deadlineMs, runId: "fixture", role: "judgment", configHash: snapshot.hash };
};
function deferred<T>() {
    let resolve!: (value: T) => void;
    const promise = new Promise<T>(accept => { resolve = accept; });
    return { promise, resolve };
}
// Provider startup is deliberately untimed by the host scheduler. Each fixture
// advances the absolute clock only after fetch confirms a physical dispatch.
async function withControlledTime(work: (advance: (milliseconds: number) => void) => Promise<void>): Promise<void> {
    const originalNow = Date.now;
    const originalSetTimeout = globalThis.setTimeout;
    const originalClearTimeout = globalThis.clearTimeout;
    let now = originalNow();
    let nextId = 0;
    const timers = new Map<number, { callback: () => void; due: number }>();
    Date.now = () => now;
    globalThis.setTimeout = ((callback: () => void, delay = 0) => {
        const id = ++nextId;
        timers.set(id, { callback, due: now + delay });
        return id;
    }) as unknown as typeof setTimeout;
    globalThis.clearTimeout = ((id: number) => { timers.delete(id); }) as unknown as typeof clearTimeout;
    try {
        await work(milliseconds => {
            now += milliseconds;
            for (;;) {
                const next = [...timers].filter(([, timer]) => timer.due <= now).sort((a, b) => a[1].due - b[1].due)[0];
                if (!next) break;
                timers.delete(next[0]);
                next[1].callback();
            }
        });
        await new Promise<void>(resolve => setImmediate(resolve));
        assert.equal(timers.size, 0, "settled judgments must release their deadline timers");
    } finally {
        Date.now = originalNow;
        globalThis.setTimeout = originalSetTimeout;
        globalThis.clearTimeout = originalClearTimeout;
    }
}
async function awaitDispatch(dispatched: Promise<void>, pending: Promise<unknown>): Promise<void> {
    await Promise.race([dispatched, pending.then(() => { throw new Error("Judgment completed before expected physical dispatch"); })]);
}
let calls = 0;
const response = () => new Response(JSON.stringify({ model: req.model, answers: { risk: { type: "noul", noul: .1 } }, usage: { input_tokens: 50, output_tokens: 10 } }));
const service = new JudgmentService(snapshot, { apiKey: "fixture", fetch: async () => { calls++; return response(); }, prices: { version: "fixture", inputPerMillion: .042, outputPerMillion: 0 } });
const complete = { completeSource: true, trustedContext: { origin: "unspecified" }, coverage: { allFields: true } };
assert.equal((await service.evaluate("descriptor", req, ctx(), complete)).cache, "miss");
const hit = await service.evaluate("descriptor", req, ctx(), complete);
assert.equal(hit.cache, "hit"); assert.equal(hit.coverage, "complete"); assert.equal(calls, 1);
assert.equal((await service.evaluate("descriptor", req, ctx(), { ...complete, trustedContext: { origin: "other" } })).cache, "miss");
assert.equal((await service.evaluate("descriptor", req, ctx(), { completeSource: false })).coverage, "partial");
assert.equal((await service.evaluate("descriptor", req, ctx(), { completeSource: false })).cache, "disabled");
const beforePrompts = calls;
await service.evaluate("prompt", req, ctx(), complete); await service.evaluate("prompt", req, ctx(), complete);
assert.equal(calls - beforePrompts, 2, "general prompt caching is disabled");
const beforeOff = calls;
assert.equal((await service.evaluate("skill", req, ctx(), complete)).coverage, "not_requested");
assert.equal((await service.evaluate("capability", req, ctx(), { ...complete, parentTask: "skill" })).mode, "off");
assert.equal(calls, beforeOff);
const missing = await new JudgmentService(snapshot, { apiKey: "" }).evaluate("descriptor", req, ctx(), complete);
assert.equal(missing.result?.status === "unavailable" && missing.result.code, "not_configured");
assert.equal(missing.coverage, "unavailable");
const off = await new JudgmentService(legacy, { apiKey: "" }).evaluate("descriptor", req, ctx());
assert.equal(off.result, null);
const spoof = await service.evaluate("descriptor", { ...req, model: "jev-preview" }, ctx(), complete);
assert.equal(spoof.result?.status === "unavailable" && spoof.result.code, "unsupported");
await withControlledTime(async advance => {
    let sharedCalls = 0;
    const dispatched = deferred<void>();
    const reply = deferred<Response>();
    const shared = new JudgmentService(snapshot, { apiKey: "fixture", fetch: async () => {
        sharedCalls++; dispatched.resolve(); return reply.promise;
    } });
    const shortContext = ctx(Date.now() + 15);
    const longContext = ctx(Date.now() + 1000);
    const short = shared.evaluate("descriptor", req, shortContext, complete);
    const long = shared.evaluate("descriptor", req, longContext, complete);
    await awaitDispatch(dispatched.promise, short);
    advance(15);
    const shortResult = await short;
    assert.equal(shortResult.result?.status === "unavailable" && shortResult.result.code, "timeout");
    assert.equal(shortResult.completion, "waiter_timed_out");
    reply.resolve(response());
    const longResult = await long;
    assert.equal(longResult.result?.status, "ok"); assert.equal(longResult.cache, "shared");
    assert.equal(longResult.completion, "completed");
    assert.equal(shortResult.result?.meta.callId, longResult.result?.meta.callId, "the owning waiter's timeout retains operation identity");
    assert.equal(sharedCalls, 1); assert.equal(shortContext.budget.attempts, 1); assert.equal(longContext.budget.attempts, 0);
    assert.equal(shortContext.budget.usage.summary().calls, 1); assert.equal(longContext.budget.usage.summary().calls, 0);
});
for (const exit of ["timeout", "cancel"] as const) {
    await withControlledTime(async advance => {
        const dispatched = deferred<void>();
        const reply = deferred<Response>();
        const coalesced = new JudgmentService(snapshot, { apiKey: "fixture", fetch: async () => { dispatched.resolve(); return reply.promise; } });
        const owner = coalesced.evaluate("descriptor", req, ctx(Date.now() + 1000), complete);
        const controller = new AbortController();
        const waiterContext = { ...ctx(Date.now() + (exit === "timeout" ? 15 : 1000)), signal: controller.signal };
        const waiter = coalesced.evaluate("descriptor", req, waiterContext, complete);
        await awaitDispatch(dispatched.promise, owner);
        advance(15);
        if (exit === "cancel") controller.abort();
        const left = await waiter;
        reply.resolve(response());
        const finished = await owner;
        assert.equal(left.result?.meta.callId, finished.result?.meta.callId, "joining waiters share physical operation identity");
        assert.equal(left.result?.meta.attempts, 1);
        assert.equal(left.result!.meta.elapsedMs, 15);
        assert.equal(left.completion, exit === "cancel" ? "waiter_cancelled" : "waiter_timed_out");
    });
}
const immutable = new JudgmentService(snapshot, { provider: { evaluate: async (request) => {
    assert.ok(Object.isFrozen(request)); assert.ok(Object.isFrozen(request.questions)); assert.ok(Object.isFrozen(request.questions.risk.criteria));
    throw new Error("sensitive fixture source must not escape");
} } });
const sanitized = await immutable.evaluate("descriptor", req, ctx(), complete);
assert.equal(sanitized.coverage, "unavailable"); assert.ok(!JSON.stringify(sanitized).includes("sensitive fixture"));
const mutableOptions = { completeSource: false };
const mutating = new JudgmentService(snapshot, { apiKey: "fixture", fetch: async () => { mutableOptions.completeSource = true; return response(); } });
assert.equal((await mutating.evaluate("prompt", req, ctx(), mutableOptions)).coverage, "partial", "in-flight caller mutation cannot upgrade coverage");
const timeoutConfig = parseAIConfig({ ...snapshot.config, limits: { ...snapshot.config.limits, judgmentTimeoutMs: 20 } });
await withControlledTime(async advance => {
    const dispatched = deferred<void>();
    let physicalCalls = 0;
    const sharedTimeout = new JudgmentService(timeoutConfig, { apiKey: "fixture", fetch: async (_url, init) => {
        physicalCalls++; dispatched.resolve();
        return new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true }));
    } });
    const pending = Promise.all([sharedTimeout.evaluate("descriptor", req, ctx(), complete), sharedTimeout.evaluate("descriptor", req, ctx(), complete)]);
    await awaitDispatch(dispatched.promise, pending);
    advance(20);
    const results = await pending;
    assert.equal(physicalCalls, 1);
    assert.equal(results[0].result?.meta.callId, results[1].result?.meta.callId);
    for (const result of results) { assert.equal(result.result?.meta.attempts, 1); assert.equal(result.result?.status === "unavailable" && result.result.code, "timeout"); }
});
for (const task of ["prompt", "descriptor"] as const) {
    await withControlledTime(async advance => {
        const budget = new AnalysisBudget("descriptor", timeoutConfig.config.limits);
        budget.authorizeShadow({ requiredWorkComplete: true });
        const dispatched = deferred<void>();
        let physicalCalls = 0;
        const timeoutService = new JudgmentService(timeoutConfig, { apiKey: "fixture", fetch: async (_url, init) => {
            physicalCalls++; dispatched.resolve();
            return new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true }));
        } });
        const expired = await timeoutService.evaluate(task, req, ctx(Date.now() - 1), complete);
        assert.equal(expired.result?.status === "unavailable" && expired.result.code, "timeout");
        assert.equal(expired.result?.meta.attempts, 0, "expiry before dispatch cannot invent a physical attempt");
        assert.equal(physicalCalls, 0);
        const pending = timeoutService.evaluate(task, req, { budget, deadlineMs: budget.deadlineMs, runId: "timed", role: "judgment", configHash: timeoutConfig.hash }, complete);
        await awaitDispatch(dispatched.promise, pending);
        advance(20);
        const timed = await pending;
        assert.equal(timed.result?.status === "unavailable" && timed.result.code, "timeout");
        assert.equal(timed.result?.meta.attempts, 1, "timeout retains actual dispatched attempts");
        assert.equal(timed.result!.meta.elapsedMs, 20);
        assert.equal(physicalCalls, 1);
        await new Promise<void>(resolve => setImmediate(resolve));
        assert.equal(budget.usage.summary().calls, 1);
    });
}
for (const parent of ["off", "shadow", "enforce", "cascade"] as const) for (const child of ["off", "shadow", "enforce"] as const) {
    // This table tests composition only. Startup still rejects unqualified modes.
    const candidate = { ...snapshot, config: { ...snapshot.config, typesafe: { ...snapshot.config.typesafe, skill: parent, capability: child } } };
    const expected = parent === "off" || child === "off" ? "off" : parent === "shadow" ? "shadow" : child;
    assert.equal(effectiveJudgmentMode(candidate, "capability", "skill"), expected);
}
console.log("PASS judgment service off/shadow modes, complete-source cache, coalesced budgets and source isolation");
