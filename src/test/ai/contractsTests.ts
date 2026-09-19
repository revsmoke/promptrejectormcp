import assert from "node:assert/strict";
import { GeminiService } from "../../services/GeminiService.js";
import { SecurityService } from "../../services/SecurityService.js";
import { SkillScanService } from "../../services/SkillScanService.js";
import { HuggingFaceService } from "../../services/HuggingFaceService.js";
import { semanticFindingSchema } from "../../ai/taskSchemas.js";
import { benignFinding, fixtureSemantic } from "./fixtures.js";

// Regression: a syntactically valid but empty provider object is unavailable,
// never an invented benign classification. This uses the real HTTP boundary.
process.env.GEMINI_API_KEY = "offline-test-key";
const originalFetch = globalThis.fetch;
globalThis.fetch = async () => new Response(JSON.stringify({
    candidates: [{ content: { parts: [{ text: "{}" }] }, finishReason: "STOP" }],
}), { headers: { "content-type": "application/json" } });
try {
    const result = await new GeminiService().checkPrompt("Summarize a weather report.");
    assert.equal(result.error, true, "empty provider objects must be unavailable");
    const report = await new SecurityService().runSecurityScan("Summarize a weather report.");
    assert.equal(report.safe, false, "missing required semantic analysis must not allow");
} finally {
    globalThis.fetch = originalFetch;
}
for (const malformed of [{}, [], null, { ...benignFinding, extra: 1 }, { ...benignFinding, verdict: "safe" }, { ...benignFinding, isInjection: 0 }, { ...benignFinding, selfReportedConfidence: NaN }, { ...benignFinding, selfReportedConfidence: Infinity }, { ...benignFinding, selfReportedConfidence: -0.1 }, { ...benignFinding, evidenceIds: ["missing"] }]) assert.equal(semanticFindingSchema.safeParse(malformed).success, false);
const unusual = fixtureSemantic({ finding: { ...benignFinding, verdict: "malicious", isInjection: false, severity: "medium", selfReportedConfidence: 0.8 } });
const security = new SecurityService(undefined, unusual);
const legacy = await security.runSecurityScan("A plain request.");
assert.equal(legacy.safe, true, "valid v1 success preserves historical formula");
assert.equal(legacy.gemini.isInjection, false, "v1 isInjection must not be derived from verdict");
assert.equal(legacy.overallConfidence, 0.8);
assert.equal((await security.runSecurityScanV2("A plain request.")).decision, "block");
const nullable = new SecurityService(undefined, fixtureSemantic({ finding: { ...benignFinding, selfReportedConfidence: null } }));
assert.equal((await nullable.runSecurityScan("Plain request.")).geminiAvailable, false);
assert.equal((await nullable.runSecurityScan("Plain request.")).safe, false);
assert.equal((await nullable.runSecurityScanV2("Plain request.")).safe, true, "v2 does not fabricate or require confidence");
const noKey = new GeminiService(new (await import("../../services/SemanticAnalysisService.js")).SemanticAnalysisService(
    (await import("../../ai/config.js")).loadAIConfig({}),
    new (await import("../../ai/registry.js")).ProviderRegistry((await import("../../ai/config.js")).loadAIConfig({}), { env: {} }),
));
assert.equal((await noKey.checkPrompt("hello")).failureCode, "not_configured");
class FailedHF extends HuggingFaceService {
    override extractModelIds() { return ["owner/model"]; }
    override async checkModel(): Promise<never> { throw new Error("sensitive provider detail"); }
}
const missingHf = await new SkillScanService(undefined, new FailedHF(), fixtureSemantic()).scanSkillV2("Analyze a spreadsheet.");
assert.equal(missingHf.decision, "unavailable");
assert.equal(missingHf.coverage.find((check) => check.check === "hugging_face")?.status, "partial");
class OverflowHF extends HuggingFaceService {
    calls = 0;
    override extractModelIds() { return Array.from({ length: 17 }, (_, index) => `owner/model${index}`); }
    override async checkModel(modelId: string) { this.calls++; return { modelId, fetchedAt: new Date().toISOString(), flags: [], severity: "safe" as const }; }
}
const overflowHf = new OverflowHF();
const overflow = await new SkillScanService(undefined, overflowHf, fixtureSemantic()).scanSkillV2("Analyze a spreadsheet.");
assert.equal(overflow.safe, false);
assert.equal(overflow.coverage.find((check) => check.check === "hugging_face")?.reason, "reference_limit");
assert.equal(overflowHf.calls, 16);
const skillOutage = await new SkillScanService(undefined, new HuggingFaceService(), fixtureSemantic({ unavailable: "timeout" })).scanSkill("Analyze a spreadsheet.");
assert.equal(skillOutage.safe, false);
assert.equal(skillOutage.analysisAvailable, false);
console.log("PASS strict semantic regression");
