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
let sharedCalls = 0;
const shared = new JudgmentService(snapshot, { apiKey: "fixture", fetch: async () => {
    sharedCalls++; await new Promise((resolve) => setTimeout(resolve, 50)); return response();
} });
const shortContext = ctx(Date.now() + 15);
const longContext = ctx(Date.now() + 1000);
const short = shared.evaluate("descriptor", req, shortContext, complete);
const long = shared.evaluate("descriptor", req, longContext, complete);
const shortResult = await short;
assert.equal(shortResult.result?.status === "unavailable" && shortResult.result.code, "timeout");
assert.equal(shortResult.completion, "waiter_timed_out");
const longResult = await long;
assert.equal(longResult.result?.status, "ok"); assert.equal(longResult.cache, "shared");
assert.equal(longResult.completion, "completed");
assert.equal(shortResult.result?.meta.callId, longResult.result?.meta.callId, "the owning waiter's timeout retains operation identity");
assert.equal(sharedCalls, 1); assert.equal(shortContext.budget.attempts, 1); assert.equal(longContext.budget.attempts, 0);
assert.equal(shortContext.budget.usage.summary().calls, 1); assert.equal(longContext.budget.usage.summary().calls, 0);
for (const exit of ["timeout", "cancel"] as const) {
    const coalesced = new JudgmentService(snapshot, { apiKey: "fixture", fetch: async () => { await new Promise((resolve) => setTimeout(resolve, 50)); return response(); } });
    const owner = coalesced.evaluate("descriptor", req, ctx(Date.now() + 1000), complete);
    const controller = new AbortController();
    const waiterContext = { ...ctx(Date.now() + (exit === "timeout" ? 15 : 1000)), signal: controller.signal };
    const waiter = coalesced.evaluate("descriptor", req, waiterContext, complete);
    if (exit === "cancel") setTimeout(() => controller.abort(), 15);
    const left = await waiter;
    const finished = await owner;
    assert.equal(left.result?.meta.callId, finished.result?.meta.callId, "joining waiters share physical operation identity");
    assert.equal(left.result?.meta.attempts, 1);
    assert.ok(left.result!.meta.elapsedMs >= 10);
    assert.equal(left.completion, exit === "cancel" ? "waiter_cancelled" : "waiter_timed_out");
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
{
    const sharedTimeout = new JudgmentService(timeoutConfig, { apiKey: "fixture", fetch: async (_url, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true })) });
    const results = await Promise.all([sharedTimeout.evaluate("descriptor", req, ctx(), complete), sharedTimeout.evaluate("descriptor", req, ctx(), complete)]);
    assert.equal(results[0].result?.meta.callId, results[1].result?.meta.callId);
    for (const result of results) { assert.equal(result.result?.meta.attempts, 1); assert.equal(result.result?.status === "unavailable" && result.result.code, "timeout"); }
}
for (const task of ["prompt", "descriptor"] as const) {
    const budget = new AnalysisBudget("descriptor", timeoutConfig.config.limits);
    budget.authorizeShadow({ requiredWorkComplete: true });
    const timeoutService = new JudgmentService(timeoutConfig, { apiKey: "fixture", fetch: async (_url, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true })) });
    const timed = await timeoutService.evaluate(task, req, { budget, deadlineMs: budget.deadlineMs, runId: "timed", role: "judgment", configHash: timeoutConfig.hash }, complete);
    assert.equal(timed.result?.status === "unavailable" && timed.result.code, "timeout");
    assert.equal(timed.result?.meta.attempts, 1, "timeout retains actual dispatched attempts");
    assert.ok(timed.result!.meta.elapsedMs >= 15);
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(budget.usage.summary().calls, 1);
}
for (const parent of ["off", "shadow", "enforce", "cascade"] as const) for (const child of ["off", "shadow", "enforce"] as const) {
    // This table tests composition only. Startup still rejects unqualified modes.
    const candidate = { ...snapshot, config: { ...snapshot.config, typesafe: { ...snapshot.config.typesafe, skill: parent, capability: child } } };
    const expected = parent === "off" || child === "off" ? "off" : parent === "shadow" ? "shadow" : child;
    assert.equal(effectiveJudgmentMode(candidate, "capability", "skill"), expected);
}
console.log("PASS judgment service off/shadow modes, complete-source cache, coalesced budgets and source isolation");
