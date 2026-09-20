import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, cpSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadAIConfig, parseAIConfig } from "../../ai/config.js";
import { ProviderRegistry } from "../../ai/registry.js";
import { SemanticAnalysisService } from "../../services/SemanticAnalysisService.js";
import { PatternService } from "../../services/PatternService.js";
import { VulnFeedService } from "../../services/VulnFeedService.js";
import { TasteTesterService } from "../../services/TasteTesterService.js";
const base = loadAIConfig({}).config;
const clean = { intents: [], monitorVerdict: "clean", monitorRationale: "No action observed.", severity: "safe" };
for (const [provider, model] of [["gemini", "gemini-3-flash-preview"], ["anthropic", "claude-sonnet-5"], ["openai", "gpt-6-astra"]] as const) {
    const snapshot = parseAIConfig({ ...base, profiles: { ...base.profiles, selected: { provider, model, maxOutputTokens: 2048 } }, roles: { ...base.roles, semantic: { primary: "selected" }, patternDraft: { primary: "selected" }, monitor: { primary: "selected" } } });
    const calls: any[] = [];
    let fixture: unknown = { patterns: [{ pattern: "attack", flags: "gi", description: "Synthetic", category: "xss", severity: "high" }] };
    const native = (value: unknown) => provider === "gemini" ? { candidates: [{ finishReason: "STOP", content: { parts: [{ text: JSON.stringify(value) }] } }] } : provider === "anthropic" ? { stop_reason: "end_turn", content: [{ type: "text", text: JSON.stringify(value) }] } : { status: "completed", output: [{ type: "message", role: "assistant", status: "completed", content: [{ type: "output_text", text: JSON.stringify(value) }] }] };
    const service = new SemanticAnalysisService(snapshot, new ProviderRegistry(snapshot, { env: { GEMINI_API_KEY: "fake", ANTHROPIC_API_KEY: "fake", OPENAI_API_KEY: "fake" }, fetch: async (_url, init) => { calls.push(JSON.parse(String(init?.body))); return new Response(JSON.stringify(native(fixture))); } }));
    const cappedSnapshot = parseAIConfig({ ...snapshot.config,
        profiles: { ...snapshot.config.profiles, smaller: { provider, model, maxOutputTokens: 8 } },
        roles: { ...snapshot.config.roles, monitor: { primary: "selected", fallback: "smaller" } },
    });
    const monitorCaps: number[] = [];
    const cappedMonitor = new SemanticAnalysisService(cappedSnapshot, new ProviderRegistry(cappedSnapshot, {
        env: { GEMINI_API_KEY: "fake", ANTHROPIC_API_KEY: "fake", OPENAI_API_KEY: "fake" }, fetch: async (_url, init) => {
            const body = JSON.parse(String(init?.body));
            monitorCaps.push(body.max_tokens ?? body.max_output_tokens ?? body.generationConfig.maxOutputTokens);
            return monitorCaps.length === 1 ? new Response("", { status: 401 }) : new Response(JSON.stringify(native(clean)));
        },
    }));
    const previousTokenCap = process.env.TASTE_TESTER_MAX_TOKENS;
    try {
        process.env.TASTE_TESTER_MAX_TOKENS = "32";
        for (const explicit of [true, false]) {
            monitorCaps.length = 0;
            const expectedCap = explicit ? 16 : 32;
            const capped = new TasteTesterService({ enabled: true, apiKey: "fake", ...(explicit ? { maxTokens: 16 } : {}), monitor: cappedMonitor,
                anthropicFactory: () => ({ messages: { create: async (request) => {
                    assert.equal(request.max_tokens, expectedCap, "legacy Taster caller/environment limit remains effective");
                    return { content: [{ type: "text", text: "Done." }], stop_reason: "end_turn" };
                } } }),
            });
            const cappedResult = await capped.run({ prompt: "synthetic capped Monitor" });
            assert.equal(cappedResult.monitorStatus, "ok");
            assert.deepEqual(monitorCaps, [expectedCap, 8], `${provider}: every Monitor primary/fallback must obey both profile and caller/environment limits`);
        }
    } finally {
        if (previousTokenCap === undefined) delete process.env.TASTE_TESTER_MAX_TOKENS;
        else process.env.TASTE_TESTER_MAX_TOKENS = previousTokenCap;
    }
    const dir = mkdtempSync(join(tmpdir(), "draft-route-"));
    try {
        cpSync("patterns", dir, { recursive: true });
        const feed = new VulnFeedService(new PatternService(dir), service, dir);
        const candidates = await (feed as any).generatePatternsFromCVE({ cveId: "CVE-2026-0001", cweIds: ["CWE-79"], description: "ADVISORY_UNTRUSTED", source: "nvd" });
        assert.equal(candidates.length, 1, `${provider} patternDraft must use its configured role`);
        assert.ok(JSON.stringify(calls[0]).includes("ADVISORY_UNTRUSTED"));
        const system = calls[0].system ?? calls[0].instructions ?? calls[0].systemInstruction;
        assert.ok(!JSON.stringify(system).includes("ADVISORY_UNTRUSTED"));
        fixture = {};
        await assert.rejects((feed as any).generatePatternsFromCVE({ cveId: "CVE-2026-0002", cweIds: [], description: "invalid fixture", source: "nvd" }), /Pattern drafting unavailable/);
        fixture = clean;
        let tasterCalls = 0;
        const taster = new TasteTesterService({ enabled: true, apiKey: "fake", monitor: service, anthropicFactory: () => ({ messages: { create: async () => { tasterCalls++; return { content: [{ type: "text", text: "Nothing to do." }], stop_reason: "end_turn", usage: { input_tokens: 5, output_tokens: 2 } }; } } }) });
        const report = await taster.run({ prompt: "synthetic" });
        assert.equal(tasterCalls, 1, "Monitor must use its own role rather than the Taster client");
        assert.equal(report.behaviorReport.monitorVerdict, "clean", `${provider} Monitor role`);
        fixture = {};
        const partial = await taster.run({ prompt: "synthetic" });
        assert.equal(partial.behaviorReport.monitorVerdict, "suspicious");
        assert.equal(partial.monitorStatus, "unavailable");
    } finally { rmSync(dir, { recursive: true, force: true }); }
}
const slowSnapshot = parseAIConfig({ ...base, limits: { ...base.limits, reasoningTimeoutMs: 50 } });
const slowMonitor = new SemanticAnalysisService(slowSnapshot, new ProviderRegistry(slowSnapshot, { env: { GEMINI_API_KEY: "fake" }, fetch: async () => new Promise<Response>(() => {}) }));
const timed = await new TasteTesterService({ enabled: true, apiKey: "fake", monitor: slowMonitor, timeoutMs: 5, anthropicFactory: () => ({ messages: { create: async () => ({ content: [{ type: "text", text: "Done." }], stop_reason: "end_turn", usage: { input_tokens: 5, output_tokens: 2 } }) } }) }).run({ prompt: "synthetic" });
assert.equal(timed.monitorStatus, "unavailable");
assert.equal(timed.usage, undefined, "a timed-out Monitor cannot make Taster-only usage look complete");
// Verdicts and refusals must not shop another configured provider.
const snapshot = parseAIConfig({ ...base, profiles: { ...base.profiles, primary: { provider: "openai", model: "gpt-6-astra", maxOutputTokens: 1024 } }, roles: { ...base.roles, semantic: { primary: "primary", fallback: "legacy-gemini" } } });
let calls = 0;
const refusal = JSON.parse(readFileSync("src/test/fixtures/ai/providers/openai.json", "utf8")).refusal;
const service = new SemanticAnalysisService(snapshot, new ProviderRegistry(snapshot, { env: { OPENAI_API_KEY: "fake", GEMINI_API_KEY: "fake" }, fetch: async () => { calls++; return new Response(JSON.stringify(refusal)); } }));
const refused = await service.analyze("synthetic");
assert.equal(refused.status === "unavailable" && refused.code, "refusal");
assert.equal(calls, 1);
let fallbackCalls = 0;
const nativeGemini = { candidates: [{ finishReason: "STOP", content: { parts: [{ text: JSON.stringify({ verdict: "benign", severity: "low", categories: [], explanation: "Synthetic.", evidenceIds: [], isInjection: false, selfReportedConfidence: .8 }) }] } }] };
const fallback = new SemanticAnalysisService(snapshot, new ProviderRegistry(snapshot, { env: { OPENAI_API_KEY: "fake", GEMINI_API_KEY: "fake" }, fetch: async () => {
    fallbackCalls++; return fallbackCalls === 1 ? new Response("", { status: 401 }) : new Response(JSON.stringify(nativeGemini));
} }));
const recovered = await fallback.analyze("synthetic");
assert.equal(recovered.status, "ok");
assert.equal(recovered.meta.provider, "gemini");
assert.equal(fallbackCalls, 2);
assert.equal(fallback.supportsV1, false, "a non-Gemini configured route still requires v2 even if fallback succeeds on Gemini");
console.log("PASS independent structured role routing and refusal boundary");
