import assert from "node:assert/strict";
import { GeminiAdapter } from "../../ai/providers/GeminiAdapter.js";
import { NativeTransport } from "../../ai/transport.js";
import { AnalysisBudget } from "../../ai/budget.js";
import { limitsSchema, loadAIConfig, parseAIConfig } from "../../ai/config.js";
import { ProviderRegistry } from "../../ai/registry.js";
import { SemanticAnalysisService } from "../../services/SemanticAnalysisService.js";
import { semanticFindingSchema, nativeJsonSchema } from "../../ai/taskSchemas.js";
import type { StructuredRequest, CallContext } from "../../ai/contracts.js";

export const benign = { verdict: "benign" as const, severity: "low" as const, categories: [], explanation: "A harmless summary request.", evidenceIds: [], isInjection: false, selfReportedConfidence: 0.9 };
const req: StructuredRequest<typeof benign> = { profile: { provider: "gemini", model: "gemini-3-flash-preview", maxOutputTokens: 2048 }, systemInstruction: "trusted rubric", state: '{"input":"untrusted input"}', schemaId: "semantic", schemaVersion: "1", rubricVersion: "1", jsonSchema: nativeJsonSchema(semanticFindingSchema), parse: (value) => semanticFindingSchema.parse(value) as typeof benign, maxOutputTokens: 2048 };
const ctx = (): CallContext => { const budget = new AnalysisBudget("prompt", limitsSchema.parse({})); return { budget, deadlineMs: budget.deadlineMs, runId: "test", role: "semantic", configHash: "test" }; };
let captured: { url?: string; init?: RequestInit } = {};
function adapter(body: unknown, key = "fixture-key") {
    return new GeminiAdapter({ apiKey: key, transport: new NativeTransport({ fetch: async (url, init) => { captured = { url: String(url), init }; return new Response(JSON.stringify(body)); } }) });
}
function native(value: unknown, finishReason = "STOP") { return { candidates: [{ finishReason, content: { parts: [{ text: JSON.stringify(value) }] } }], modelVersion: "gemini-3-flash-preview-actual", usageMetadata: { promptTokenCount: 50, candidatesTokenCount: 20, thoughtsTokenCount: 4, cachedContentTokenCount: 10 } }; }
const result = await adapter(native(benign)).generate(req, ctx());
assert.equal(result.status, "ok");
assert.equal(result.meta.resolvedModel, "gemini-3-flash-preview-actual");
assert.equal(result.meta.usage.reasoningIsOutputSubset, false);
assert.equal(result.meta.usage.inputTokens, 50);
assert.ok(!captured.url?.includes("fixture-key"));
const sent = JSON.parse(String(captured.init?.body));
assert.equal(sent.systemInstruction.parts[0].text, "trusted rubric");
assert.equal(sent.contents[0].parts[0].text, req.state);
assert.equal(sent.generationConfig.responseMimeType, "application/json");
assert.deepEqual(sent.generationConfig.responseJsonSchema.required, Object.keys(benign));
assert.equal(sent.generationConfig.temperature, undefined);
assert.equal((captured.init?.headers as Record<string, string>)["x-goog-api-key"], "fixture-key");
for (const value of [{}, [], { ...benign, extra: true }, { ...benign, categories: ["made_up"] }, { ...benign, evidenceIds: ["not-input"] }, { ...benign, selfReportedConfidence: 2 }, { ...benign, isInjection: "false" }]) {
    const rejected = await adapter(native(value)).generate(req, ctx());
    assert.equal(rejected.status === "unavailable" && rejected.code, "invalid_response");
}
for (const [body, code] of [
    [{ candidates: [] }, "invalid_response"],
    [{ candidates: [native(benign).candidates[0], native(benign).candidates[0]] }, "invalid_response"],
    [{ promptFeedback: { blockReason: "SAFETY" } }, "refusal"],
    [native(benign, "SAFETY"), "refusal"],
    [native(benign, "MAX_TOKENS"), "incomplete"],
] as const) assert.equal((await adapter(body).generate(req, ctx())).status, "unavailable", code);
const missing = await adapter(native(benign), "").generate(req, ctx());
assert.equal(missing.status === "unavailable" && missing.code, "not_configured");
assert.equal(missing.meta.attempts, 0);
const absentUsage = await adapter({ candidates: native(benign).candidates }).generate(req, ctx());
assert.equal(absentUsage.meta.resolvedModel, null);
assert.equal(absentUsage.meta.usage.inputTokens, null);
let retryCalls = 0;
const retriedContext = ctx();
const retryAdapter = new GeminiAdapter({ apiKey: "fixture-key", transport: new NativeTransport({ fetch: async () => {
    retryCalls++;
    return retryCalls === 1 ? new Response("", { status: 503, headers: { "retry-after": "0" } }) : new Response(JSON.stringify(native(benign)));
} }) });
const retried = await retryAdapter.generate(req, retriedContext);
assert.equal(retried.status, "ok");
assert.equal(retriedContext.budget.usage.summary().calls, 2);
assert.equal(retriedContext.budget.usage.summary().usage.inputTokens, null, "unknown retry usage cannot masquerade as a complete final-response total");
// Fallback gets its own bounded call within the original shared task deadline.
// A primary 25ms timeout must not consume the whole 150ms task budget.
const base = loadAIConfig({}).config;
const fallbackConfig = parseAIConfig({ ...base,
    profiles: { ...base.profiles, fallback: { ...base.profiles["legacy-gemini"], maxOutputTokens: 1024 } },
    roles: { ...base.roles, semantic: { primary: "legacy-gemini", fallback: "fallback" } },
    limits: { ...base.limits, analysisDeadlineMs: 150, reasoningTimeoutMs: 25 },
});
let fallbackCalls = 0;
const fallbackRegistry = new ProviderRegistry(fallbackConfig, { env: { GEMINI_API_KEY: "fixture-key" }, fetch: async () => {
    fallbackCalls++;
    return fallbackCalls % 2 === 1 ? new Promise<Response>(() => {}) : new Response(JSON.stringify(native(benign)));
} });
const fallbackService = new SemanticAnalysisService(fallbackConfig, fallbackRegistry);
const fallbackContext = fallbackService.createContext("prompt");
const fallbackStart = Date.now();
const recovered = await fallbackService.analyze("A harmless request", "prompt", fallbackContext);
assert.equal(recovered.status, "ok", "primary timeout should leave remaining task time for configured fallback");
assert.equal(fallbackCalls, 2);
assert.equal(fallbackContext.routing?.length, 2);
assert.ok(Date.now() - fallbackStart < 150);
let expiredFallbackCalls = 0;
const expiredRegistry = new ProviderRegistry(fallbackConfig, { env: { GEMINI_API_KEY: "fixture-key" }, fetch: async () => { expiredFallbackCalls++; return new Promise<Response>(() => {}); } });
const expiredService = new SemanticAnalysisService(fallbackConfig, expiredRegistry);
const expiredContext = { ...expiredService.createContext("prompt"), deadlineMs: Date.now() + 10 };
const expiredResult = await expiredService.analyze("A harmless request", "prompt", expiredContext);
assert.equal(expiredResult.status === "unavailable" && expiredResult.code, "timeout");
assert.equal(expiredFallbackCalls, 1, "no fallback may dispatch after the actual request deadline");
console.log("PASS Gemini native schema, strict parsing, termination and attribution");
import { skillReasoningSchema } from "../../ai/taskSchemas.js";
const skillSchema = skillReasoningSchema(["skillContent"], []);
const skillValue = { security: benign, capabilities: { completeDeclaredScope: true, restrictionEvidenceIds: ["skillContent"], privateDataRead: { state: "absent", evidenceIds: ["skillContent"] }, untrustedContentFetch: { state: "absent", evidenceIds: ["skillContent"] }, externalEgress: { state: "absent", evidenceIds: ["skillContent"] }, explanation: "Explicit complete arithmetic-only scope." }, references: [] };
const hasMaxItems = (value: unknown): boolean => value !== null && typeof value === "object" && (Object.prototype.hasOwnProperty.call(value, "maxItems") || Object.values(value).some(hasMaxItems));
let wireResponse: unknown = skillValue;
let skillCalls = 0;
const skillAdapter = new GeminiAdapter({ apiKey: "fixture-key", transport: new NativeTransport({ fetch: async (_url, init) => {
    skillCalls++;
    const request = JSON.parse(String(init?.body));
    // Mirrors the observed API rejection: the combined bounded-array task
    // grammar failed; removing maxItems alone made this same request work.
    if (hasMaxItems(request.generationConfig.responseJsonSchema)) return new Response(JSON.stringify({ error: { code: 400, status: "INVALID_ARGUMENT" } }), { status: 400 });
    return new Response(JSON.stringify(native(wireResponse)));
} }) });
const skillRequest = { ...req, schemaId: "skill_context", jsonSchema: nativeJsonSchema(skillSchema), parse: (value: unknown) => skillSchema.parse(value) };
const nativeSkill = await skillAdapter.generate(skillRequest, ctx());
assert.equal(nativeSkill.status, "ok", "whole-skill Gemini grammar must not encode the rejected maxItems constraints");
assert.equal(skillCalls, 1);
for (const oversized of [
    { ...skillValue, security: { ...benign, categories: Array(9).fill("prompt_injection") } },
    { ...skillValue, capabilities: { ...skillValue.capabilities, restrictionEvidenceIds: Array(65).fill("skillContent") } },
    { ...skillValue, references: [{ id: "invented", classification: "model" }] },
]) {
    wireResponse = oversized;
    const invalid = await skillAdapter.generate(skillRequest, ctx());
    assert.equal(invalid.status === "unavailable" && invalid.code, "invalid_response", "local strict array bounds remain authoritative");
}
console.log("PASS Gemini whole-skill wire grammar and local strict array bounds");
