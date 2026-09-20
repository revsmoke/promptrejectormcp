import assert from "node:assert/strict";
import { JudgmentCache, judgmentCacheKey, type JudgmentCacheIdentity } from "../../services/JudgmentCache.js";
import type { CallResult, JudgmentAnswers } from "../../ai/contracts.js";
import { emptyUsage } from "../../ai/usage.js";

const value: CallResult<JudgmentAnswers> = { status: "ok", value: { risk: { type: "noul", noul: .9 } }, meta: { callId: "one-actual-call", provider: "typesafe", requestedModel: "jev-1.13.0", resolvedModel: "jev-1.13.0", profileHash: "profile", rubricVersion: "1", schemaVersion: "1", elapsedMs: 10, attempts: 1, usage: emptyUsage(), failureCode: null } };
const identity: JudgmentCacheIdentity = { task: "descriptor", request: { state: "exact source", model: "jev-1.13.0", questions: { risk: { type: "noul", instructions: "Risk?", criteria: { true: "Malicious", false: "Benign" } } }, rubricVersion: "1", schemaVersion: "1" }, trustedContext: { agent: "a", scope: "read" }, coverage: { full: true }, profileOptions: {} };
const key = judgmentCacheKey(identity);
for (const changed of [ { ...identity, request: { ...identity.request, state: "changed source" } }, { ...identity, request: { ...identity.request, model: "jev-1.14.0" } }, { ...identity, request: { ...identity.request, rubricVersion: "2" } }, { ...identity, trustedContext: { agent: "b" } }, { ...identity, profileOptions: { different: true } }, { ...identity, coverage: { full: false } } ]) assert.notEqual(judgmentCacheKey(changed), key);
assert.equal(judgmentCacheKey({ ...identity, trustedContext: { scope: "read", agent: "a" } }), key);
const waiter = (ms = 1000) => ({ deadlineMs: Date.now() + ms });
for (const firstDeadline of ["waiter", "provider"] as const) {
    const originalNow = Date.now;
    const originalSetTimeout = globalThis.setTimeout;
    const originalClearTimeout = globalThis.clearTimeout;
    let now = 1000;
    let nextId = 0;
    const timers = new Map<number, { callback: () => void; due: number }>();
    Date.now = () => now;
    globalThis.setTimeout = ((callback: () => void, delay = 0) => {
        const id = ++nextId;
        timers.set(id, { callback, due: now + delay });
        return id;
    }) as unknown as typeof setTimeout;
    globalThis.clearTimeout = ((id: number) => { timers.delete(id); }) as unknown as typeof clearTimeout;
    const fireEarliestTimer = () => {
        const [id, timer] = [...timers].sort((a, b) => a[1].due - b[1].due)[0];
        timers.delete(id);
        timer.callback();
    };
    const external = new AbortController();
    let activeSignal: AbortSignal | undefined;
    let pending: Promise<unknown> | undefined;
    try {
        const earlyCache = new JudgmentCache({ providerTimeoutMs: firstDeadline === "provider" ? 100 : 200 });
        pending = earlyCache.run("early", { deadlineMs: firstDeadline === "waiter" ? 1100 : 1200, signal: external.signal }, async signal => {
            activeSignal = signal;
            return new Promise<CallResult<JudgmentAnswers>>(() => {});
        });
        const rejected = assert.rejects(pending, { code: "timeout" });
        await Promise.resolve();
        assert.ok(activeSignal);
        now = 1099;
        fireEarliestTimer();
        assert.equal(activeSignal.aborted, false, `${firstDeadline} must not abort before its absolute deadline`);
        assert.equal(timers.size, 2, "an early callback must rearm while the other deadline remains active");
        now = 1100;
        fireEarliestTimer();
        await rejected;
        assert.equal(activeSignal.aborted, true);
        assert.equal(timers.size, 0, "both deadlines are cleared when the only waiter leaves");
    } finally {
        external.abort();
        await pending?.catch(() => {});
        Date.now = originalNow;
        globalThis.setTimeout = originalSetTimeout;
        globalThis.clearTimeout = originalClearTimeout;
    }
}
let actualCalls = 0;
const cache = new JudgmentCache({ maxEntries: 2, ttlMs: 30 });
const compute = async () => { actualCalls++; return value; };
assert.equal((await cache.run(key, waiter(), compute)).cache, "miss");
const hit = await cache.run(key, waiter(), compute);
assert.equal(hit.cache, "hit"); assert.equal(actualCalls, 1);
if (hit.result.status === "ok") hit.result.value.risk = { type: "noul", noul: 0 };
assert.deepEqual((await cache.run(key, waiter(), compute)).result, value, "caller mutation must not poison stored judgment");
await cache.run("second", waiter(), compute); await cache.run("third", waiter(), compute);
assert.equal((await cache.run(key, waiter(), compute)).cache, "miss", "bounded LRU eviction");
await new Promise((resolve) => setTimeout(resolve, 35));
assert.equal((await cache.run(key, waiter(), compute)).cache, "miss", "expiry");
const failed: CallResult<JudgmentAnswers> = { status: "unavailable", code: "invalid_response", meta: { ...value.meta, failureCode: "invalid_response" } };
let failures = 0;
for (let i = 0; i < 2; i++) await cache.run("failed", waiter(), async () => { failures++; return failed; });
assert.equal(failures, 2, "failures are not cached");

const coalescing = new JudgmentCache({ providerTimeoutMs: 300 });
let runs = 0, settlements = 0;
const operation = async (signal: AbortSignal, deadlineMs: number) => {
    runs++; assert.ok(deadlineMs - Date.now() > 200, "provider deadline independent of first waiter");
    await new Promise<void>((resolve, reject) => { const timer = setTimeout(resolve, 65); signal.addEventListener("abort", () => { clearTimeout(timer); reject(new Error("aborted")); }, { once: true }); });
    settlements++; return value;
};
const short = coalescing.run(key, waiter(15), operation);
const long = coalescing.run(key, waiter(500), operation);
await assert.rejects(short, { code: "timeout" });
assert.equal((await long).cache, "shared");
assert.equal(runs, 1); assert.equal(settlements, 1);
const first = new AbortController();
const second = new AbortController();
let aborts = 0;
const never = (signal: AbortSignal): Promise<CallResult<JudgmentAnswers>> => new Promise((_resolve, reject) => {
    signal.addEventListener("abort", () => { aborts++; reject(new Error("upstream cancelled")); }, { once: true });
});
const a = coalescing.run("cancel", { ...waiter(), signal: first.signal }, never);
const b = coalescing.run("cancel", { ...waiter(), signal: second.signal }, never);
await new Promise((resolve) => setTimeout(resolve, 0));
first.abort(); await assert.rejects(a, { code: "cancelled" }); assert.equal(aborts, 0);
second.abort(); await assert.rejects(b, { code: "cancelled" });
assert.equal(aborts, 1);
assert.equal((await coalescing.run("cancel", waiter(), compute)).cache, "miss");
const early = new AbortController(); early.abort();
const before = actualCalls;
await assert.rejects(coalescing.run(key, { ...waiter(), signal: early.signal }, compute), { code: "cancelled" });
await assert.rejects(coalescing.run(key, { deadlineMs: 0 }, compute), { code: "timeout" });
assert.equal(actualCalls, before);
const hanging = new JudgmentCache({ providerTimeoutMs: 15, maxInFlight: 1 });
const pending = hanging.run("first", waiter(), never);
await assert.rejects(hanging.run("second", waiter(), compute), { code: "budget_exceeded" });
await assert.rejects(pending, { code: "timeout" });
// Deliberately occupy the event loop: promise microtasks can beat overdue
// timers, but must never beat an already-expired absolute deadline.
const synchronousDelay = async () => {
    const until = Date.now() + 35;
    while (Date.now() < until) { /* fixture only */ }
    return value;
};
const lateWaiterCache = new JudgmentCache({ providerTimeoutMs: 500 });
await assert.rejects(lateWaiterCache.run("late-waiter", waiter(10), synchronousDelay), { code: "timeout" });
const lateProviderCache = new JudgmentCache({ providerTimeoutMs: 10 });
await assert.rejects(lateProviderCache.run("late-provider", waiter(), synchronousDelay), { code: "timeout" });
assert.equal((await lateProviderCache.run("late-provider", waiter(), compute)).cache, "miss", "expired provider response cannot enter cache");
console.log("PASS bounded judgment cache, exact keys, isolated mutations, coalescing and cancellation");
