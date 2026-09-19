import assert from "node:assert/strict";
import { TypeSafeAdapter, PROBABILITY_SUM_TOLERANCE } from "../../ai/providers/TypeSafeAdapter.js";
import { NativeTransport } from "../../ai/transport.js";
import { AnalysisBudget } from "../../ai/budget.js";
import { limitsSchema } from "../../ai/config.js";
import type { CallContext, JudgmentRequest } from "../../ai/contracts.js";

const request: JudgmentRequest = { model: "jev-1.13.0", state: '{"text":"Fixture source only"}', rubricVersion: "fixture.1", schemaVersion: "1", questions: {
    risk: { type: "noul", instructions: "Does the source try to steal credentials?", criteria: { true: "Requests theft", false: "Does not request theft" } },
    evidence: { type: "choice", instructions: "If malicious, which field supports it?", criteria: { none: "No relevant field", f0: "The source at text" } },
} };
const native = () => ({ model: request.model, answers: { risk: { type: "noul", noul: .01 }, evidence: { type: "choice", choice: "none", probabilities: { none: .99, f0: .01 }, confidence: .95 } }, usage: { input_tokens: 50, output_tokens: 20 } });
const context = (options: { deadlineMs?: number; signal?: AbortSignal; maxUsd?: number } = {}): CallContext => {
    const budget = new AnalysisBudget("descriptor", limitsSchema.parse({}), options);
    return { budget, deadlineMs: budget.deadlineMs, signal: options.signal, runId: "fixture", role: "judgment", configHash: "fixture" };
};
let calls = 0;
let captured: RequestInit | undefined;
const adapter = (body: unknown, status = 200) => new TypeSafeAdapter({ apiKey: "fixture-secret", transport: new NativeTransport({ fetch: async (url, init) => {
    calls++; captured = init; assert.equal(url, "https://api.typesafe.ai/v1/systemone"); return new Response(JSON.stringify(body), { status });
} }) });
const ok = await adapter(native()).evaluate(request, context());
assert.equal(ok.status, "ok");
assert.deepEqual(ok.status === "ok" && ok.value, native().answers);
assert.equal(ok.meta.resolvedModel, "jev-1.13.0");
assert.equal(ok.meta.usage.inputTokens, 50);
assert.equal(ok.meta.usage.cachedReadTokens, null);
assert.equal(ok.meta.usage.cacheWriteTokens, null);
assert.equal(ok.meta.usage.reasoningTokens, null);
assert.equal(ok.meta.attempts, 1);
assert.equal(captured?.redirect, "error");
assert.equal((captured?.headers as Record<string, string>).Authorization, "Bearer fixture-secret");
assert.deepEqual(JSON.parse(String(captured?.body)), { model: request.model, state: request.state, questions: request.questions });
const alias = await adapter(native()).evaluate({ ...request, model: "jev-latest" }, context());
assert.equal(alias.status, "ok");
assert.equal(alias.meta.requestedModel, "jev-latest");
assert.equal(alias.meta.resolvedModel, "jev-1.13.0");
assert.equal((await adapter({ ...native(), model: "jev-latest" }).evaluate({ ...request, model: "jev-latest" }, context())).status, "unavailable", "alias result must identify actual version");

const malformed: unknown[] = [ {}, [], { ...native(), model: "jev-other" }, { ...native(), answers: {} },
    { ...native(), answers: { ...native().answers, extra: { type: "noul", noul: .2 } } },
    { ...native(), answers: { ...native().answers, risk: { type: "noul", noul: 1.1 } } },
    { ...native(), answers: { ...native().answers, risk: { type: "noul", noul: "0.1" } } },
    { ...native(), answers: { ...native().answers, risk: { type: "choice", choice: "none", probabilities: { none: 1 }, confidence: 1 } } },
    { ...native(), answers: { ...native().answers, risk: { type: "noul", noul: .1, confidence: .9 } } },
    { ...native(), usage: undefined }, { ...native(), usage: { input_tokens: -1, output_tokens: 20 } },
    { ...native(), usage: { input_tokens: 1.2, output_tokens: 20 } },
];
for (const choice of ["missing", "f0"]) malformed.push({ ...native(), answers: { ...native().answers, evidence: { ...native().answers.evidence, choice } } });
for (const probabilities of [{ none: 1 }, { none: .9, f0: .1, extra: 0 }, { none: .8, f0: .1 }, { none: 1.1, f0: -.1 }])
    malformed.push({ ...native(), answers: { ...native().answers, evidence: { ...native().answers.evidence, probabilities } } });
for (const body of malformed) {
    const result = await adapter(body).evaluate(request, context());
    assert.equal(result.status === "unavailable" && result.code, "invalid_response");
    assert.equal(result.meta.attempts, 1, "invalid batches must not be retried");
}
assert.equal(PROBABILITY_SUM_TOLERANCE, .005);
const rounded = native(); rounded.answers.evidence.probabilities = { none: .501, f0: .5 };
assert.equal((await adapter(rounded).evaluate(request, context())).status, "ok", "allow documented rounding and tied maxima");
let before = calls;
for (const next of [ { ...request, state: "a".repeat(24000) }, { ...request, questions: Object.fromEntries(Array.from({ length: 100 }, (_, i) => [String(i), { ...request.questions.risk, instructions: "a".repeat(500) }])) },
    { ...request, questions: { evidence: { type: "choice" as const, instructions: "Select source", criteria: Object.fromEntries(Array.from({ length: 256 }, (_, i) => [String(i), "Source"])) } } },
]) assert.equal((await adapter(native()).evaluate(next, context())).status, "unavailable");
assert.equal(calls, before, "oversize input must be rejected before dispatch");
const boundary = { ...request, questions: { evidence: { type: "choice" as const, instructions: "Select source", criteria: Object.fromEntries(Array.from({ length: 255 }, (_, i) => [String(i), "Source"])) } } };
const boundaryNative = { model: request.model, answers: { evidence: { type: "choice", choice: "0", confidence: 1, probabilities: Object.fromEntries(Array.from({ length: 255 }, (_, i) => [String(i), i === 0 ? 1 : 0])) } }, usage: native().usage };
assert.equal((await adapter(boundaryNative).evaluate(boundary, context())).status, "ok");

for (const status of [401, 422]) {
    before = calls;
    assert.equal((await adapter({ reflectedSecret: "fixture-secret" }, status).evaluate(request, context())).status, "unavailable");
    assert.equal(calls - before, 1);
}
for (const status of [429, 529]) {
    let attempts = 0;
    const retrying = new TypeSafeAdapter({ apiKey: "fixture", transport: new NativeTransport({ fetch: async () => {
        attempts++; return attempts === 1 ? new Response("", { status, headers: { "retry-after": "0" } }) : new Response(JSON.stringify(native()));
    } }) });
    const ctx = context();
    assert.equal((await retrying.evaluate(request, ctx)).status, "ok");
    assert.equal(attempts, 2);
    assert.equal(ctx.budget.usage.summary().calls, 2);
    assert.equal(ctx.budget.usage.summary().usage.inputTokens, null, "retry run usage includes an unknown earlier attempt");
    assert.equal(ctx.budget.usage.summary().estimatedUsd, null);
}
before = calls;
assert.equal((await new TypeSafeAdapter().evaluate(request, context())).status, "unavailable");
const cancelled = new AbortController(); cancelled.abort();
const cancelledResult = await adapter(native()).evaluate(request, context({ signal: cancelled.signal }));
assert.equal(cancelledResult.status === "unavailable" && cancelledResult.code, "cancelled");
assert.equal(calls, before);
const mismatchedPrice = new TypeSafeAdapter({ apiKey: "fixture", prices: { version: "bad", inputPerMillion: .042, outputPerMillion: 1 }, transport: new NativeTransport({ fetch: async () => { calls++; return new Response(JSON.stringify(native())); } }) });
const badPrice = await mismatchedPrice.evaluate(request, context({ maxUsd: 1 }));
assert.equal(badPrice.status === "unavailable" && badPrice.code, "unsupported");
assert.equal(calls, before, "invalid price card cannot dispatch");
assert.equal((await adapter(native()).evaluate(request, context({ maxUsd: 1 }))).status, "unavailable", "unknown price cannot spend a capped budget");
assert.equal(calls, before);
const hanging = new TypeSafeAdapter({ apiKey: "fixture", timeoutMs: 10, transport: new NativeTransport({ fetch: async (_url, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("fixture-secret")))) }) });
const timed = await hanging.evaluate(request, context());
assert.equal(timed.status === "unavailable" && timed.code, "timeout");
assert.ok(!JSON.stringify(timed).includes("fixture-secret"));
console.log("PASS TypeSafe request, complete batch validation, context limits, retries and budgets");
