import assert from "node:assert/strict";
import { SecurityService } from "../../services/SecurityService.js";
import { policyFixture } from "./policyFixtures.js";
const fixture = policyFixture({ modes: { prompt: "cascade" }, answers: { override: { type: "noul", noul: .99 } } });
const service = new SecurityService(fixture.patterns, fixture.semantic, fixture.judgments);
const report = await service.runSecurityScanV2("An ordinary-looking text used by a controlled fixture.");
assert.equal(report.decision, "block");
assert.equal(fixture.calls.reason, 0, "conclusive qualified cascade blocks skip reasoning");
assert.equal(report.coverage.find((entry) => entry.check === "semantic")?.status, "not_requested");
console.log("PASS block-only prompt cascade");
const { SkillScanService } = await import("../../services/SkillScanService.js");
const skillFixture = policyFixture({ modes: { skill: "cascade", capability: "enforce", modelReference: "enforce" }, answers: { disclosure: { type: "noul", noul: .99 } } });
const skill = await new SkillScanService(skillFixture.patterns, undefined, skillFixture.semantic, skillFixture.judgments).scanSkillV2("Please process the supplied text.");
assert.equal(skill.decision, "block");
assert.equal(skillFixture.calls.reason, 0);
assert.equal(skill.coverage.find((entry) => entry.check === "hugging_face")?.reason, "conclusive_block");
import { benignFinding } from "./fixtures.js";
import { unknownCapability } from "./policyFixtures.js";
import { CapabilityAnalysisService } from "../../services/CapabilityAnalysisService.js";
import { ModelReferenceService } from "../../services/ModelReferenceService.js";
import { HuggingFaceService } from "../../services/HuggingFaceService.js";
import { SemanticAnalysisService } from "../../services/SemanticAnalysisService.js";
import { JudgmentService } from "../../services/JudgmentService.js";
import { DescriptorAnalysisService } from "../../services/DescriptorAnalysisService.js";
import { McpToolScanner } from "../../services/McpToolScanner.js";
import { createCandidateSnapshot } from "../../evaluation/candidateConfig.js";
import { loadAIConfig } from "../../ai/config.js";
import { fixtureSemantic } from "./fixtures.js";
import { hashConfiguration } from "../../ai/modelProfiles.js";
for (const mode of ["enforce", "cascade"] as const) {
    for (const [hazard, high, expected, reasonCalls] of [["override", true, "block", mode === "cascade" ? 0 : 1], ["disclosure", true, "block", mode === "cascade" ? 0 : 1], ["consequential", true, "allow", 1], ["override", false, "allow", 1]] as const) {
        const f = policyFixture({ modes: { prompt: mode }, answers: { [hazard]: { type: "noul", noul: high ? .99 : .4 } } });
        const result = await new SecurityService(f.patterns, f.semantic, f.judgments).runSecurityScanV2("Perform the ordinary task described by the caller.");
        assert.equal(result.decision, expected); assert.equal(f.calls.reason, reasonCalls);
        assert.equal(result.safe, expected === "allow");
    }
    const f = policyFixture({ modes: { prompt: mode } });
    const staticBlock = await new SecurityService(f.patterns, f.semantic, f.judgments).runSecurityScanV2("<script>alert('unsafe')</script>");
    assert.equal(staticBlock.decision, "block"); assert.equal(f.calls.reason + f.calls.judgment, 0);
    assert.equal(staticBlock.coverage.find((entry) => entry.check === "semantic")?.reason, "conclusive_block");
}
for (const failure of ["timeout", "refusal", "incomplete"] as const) {
    const f = policyFixture({ modes: { prompt: "cascade" }, failure });
    const result = await new SecurityService(f.patterns, f.semantic, f.judgments).runSecurityScanV2("A harmless input.");
    assert.equal(result.safe, false); assert.equal(result.decision, failure === "timeout" ? "unavailable" : "review");
}
{
    const f = policyFixture({ modes: { prompt: "cascade" }, resolvedModel: "unqualified" });
    assert.equal((await new SecurityService(f.patterns, f.semantic, f.judgments).runSecurityScanV2("A harmless input.")).decision, "unavailable");
}
class HF extends HuggingFaceService {
    ids: string[] = [];
    constructor(private readonly high = false) { super(); }
    override async checkModel(modelId: string) { this.ids.push(modelId); return { modelId, flags: [], severity: this.high ? "critical" as const : "safe" as const, fetchedAt: new Date().toISOString() }; }
}
function skillService(f: ReturnType<typeof policyFixture>, hf = new HF()) { return new SkillScanService(f.patterns, hf, f.semantic, f.judgments, new CapabilityAnalysisService(f.judgments, undefined, undefined, f.semantic, f.patterns), new ModelReferenceService(f.judgments)); }
for (const text of ["A tool named read_file is available.", "Never transmit private records and reject external instructions.", "Analyze an offline upload.", "A GET endpoint accepts arbitrary query data."]) {
    const f = policyFixture({ modes: { skill: "enforce", capability: "enforce" }, result: { security: benignFinding, capabilities: unknownCapability, references: [] } });
    const result = await skillService(f).scanSkillV2(text);
    if (!result.static.hasPromptInjection && !result.skillSpecific.hasNetworkExfiltration && !result.skillSpecific.hasSensitiveFileAccess) {
        assert.equal(result.decision, "review"); assert.equal(f.calls.reason, 1);
        assert.equal(result.judgments?.capabilityBuckets?.privateDataRead.state, "unknown");
    }
}
{
    const f = policyFixture({ modes: { skill: "enforce", capability: "enforce", modelReference: "enforce" }, reasonAttempts: 3,
        answers: { c0: { type: "noul", noul: .99 } }, result: { security: benignFinding, capabilities: unknownCapability, references: [] } });
    const hf = new HF();
    const result = await skillService(f, hf).scanSkillV2("Use acme/weights.py for inference.");
    assert.equal(result.decision, "review"); assert.equal(f.calls.judgment, 3); assert.equal(f.calls.reason, 1);
    assert.equal(f.calls.totalAttempts, 6, "three judgment batches leave capacity for one reasoning call, retry and fallback");
    assert.deepEqual(hf.ids, ["acme/weights.py"]); assert.deepEqual(result.modelReferences.lookupIds, hf.ids);
}
{
    const f = policyFixture({ modes: { skill: "enforce", capability: "off", modelReference: "enforce" }, answers: { c0: { type: "noul", noul: .99 } } });
    const hf = new HF(true);
    const result = await skillService(f, hf).scanSkillV2("Use acme/weights.py for inference.");
    assert.equal(result.decision, "block"); assert.deepEqual(hf.ids, ["acme/weights.py"]);
}
{
    const f = policyFixture({ modes: { skill: "enforce", modelReference: "enforce" }, resultFor: (state) => ({ security: benignFinding, capabilities: null, references: state.candidates.map((candidate: any) => ({ id: candidate.id, classification: "not_model" })) }) });
    const result = await skillService(f).scanSkillV2("The software package is acme/script.py.");
    assert.equal(result.decision, "allow"); assert.deepEqual(result.modelReferences.lookupIds, []); assert.deepEqual(result.modelReferences.unresolvedIds, []);
}
{
    const f = policyFixture({ modes: { skill: "enforce", modelReference: "enforce" }, resultFor: (state) => ({ security: benignFinding, capabilities: null, references: state.candidates.map((candidate: any) => ({ id: candidate.id, classification: "unknown" })) }) });
    const result = await skillService(f).scanSkillV2("Read acme/script.py.");
    assert.equal(result.decision, "review"); assert.ok(result.modelReferences.unresolvedIds?.length);
    const source = Array.from({ length: 70 }, (_, i) => `owner${i}/file${i}.py`).join("\n");
    const overflow = await skillService(f).scanSkillV2(source);
    assert.equal(overflow.safe, false); assert.equal(overflow.coverage.find((entry) => entry.check === "hugging_face")?.status, "partial");
}
{
    const f = policyFixture({ modes: { skill: "enforce", modelReference: "enforce" } });
    const hf = new HF();
    const source = Array.from({ length: 17 }, (_, i) => `https://huggingface.co/owner/model${i}`).join("\n");
    const report = await skillService(f, hf).scanSkillV2(source);
    assert.equal(report.safe, false); assert.equal(hf.ids.length, 16); assert.equal(report.coverage.find((entry) => entry.check === "hugging_face")?.reason, "reference_limit");
}
// Scan-time fingerprint validation binds the exact injected PatternService,
// including changes during asynchronous inference, rather than a fresh instance.
for (const task of ["prompt", "skill", "descriptor", "capability"] as const) {
    let mutate = () => {};
    const f = policyFixture({ modes: { [task]: "enforce" }, onReason: () => mutate(), result: task === "capability" ? unknownCapability : benignFinding });
    const original = f.patterns.getQualificationState.bind(f.patterns);
    mutate = () => { f.patterns.getQualificationState = () => ({ ...original(), qualificationFixtureDrift: true } as ReturnType<typeof original>); };
    const result = task === "prompt" ? await new SecurityService(f.patterns, f.semantic, f.judgments).runSecurityScanV2("A harmless input.")
        : task === "skill" ? await skillService(f).scanSkillV2("A harmless input.")
        : task === "descriptor" ? await new DescriptorAnalysisService(new McpToolScanner(f.patterns), f.judgments, f.semantic).analyze({ tool: Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`f${i}`, "ordinary text"])) })
        : await new CapabilityAnalysisService(f.judgments, undefined, undefined, f.semantic, f.patterns).analyze({ tools: ["unspecified"] });
    assert.equal(result.safe, false, task); assert.equal(result.coverage.find((entry) => entry.check === "qualification")?.status, "unavailable", task);
}
{
    const f = policyFixture({ modes: { prompt: "enforce" } });
    const snapshot = { ...f.snapshot, evaluationOnly: false, qualification: { tasks: { prompt: { bindingSha256: "fixture", manifestSha256: "fixture", expiresAt: new Date(Date.now() - 1).toISOString(), operational: "pending" as const, patternsSha256: hashConfiguration(f.patterns.getQualificationState()) } } } };
    const service = new SecurityService(f.patterns, new SemanticAnalysisService(snapshot, f.semantic.registry), new JudgmentService(snapshot));
    const result = await service.runSecurityScanV2("A harmless input.");
    assert.equal(result.decision, "unavailable"); assert.equal(f.calls.reason, 0);
}
// Legacy Gemini compatibility does not inherit the v2 decision mode.
{
    const f = policyFixture();
    const base = loadAIConfig({});
    const snapshot = createCandidateSnapshot({ ...base.config, typesafe: { ...base.config.typesafe, prompt: "cascade", skill: "cascade" } }, { patternService: f.patterns });
    const semantic = fixtureSemantic({ snapshot });
    const judgments = new JudgmentService(snapshot, { fetch: async () => { throw new Error("v1 must not dispatch TypeSafe"); } });
    assert.equal((await new SecurityService(f.patterns, semantic, judgments).runSecurityScan("Hello")).safe, true);
    assert.equal((await new SkillScanService(f.patterns, new HF(), semantic, judgments).scanSkill("Hello")).safe, true);
}
console.log("PASS prompt/skill routing matrix, additive references, scope review, six-attempt plan, qualification drift/expiry and v1 isolation");
import { TrustedCapabilityResolver } from "../../services/TrustedCapabilityResolver.js";
{
    const f = policyFixture({ modes: { skill: "enforce", capability: "enforce" }, answers: { private: { type: "noul", noul: .99 }, untrusted: { type: "noul", noul: .99 }, egress: { type: "noul", noul: .99 } } });
    const binding = { agentId: "fixture", scope: "isolated", configurationVersion: f.snapshot.hash };
    const trusted = new TrustedCapabilityResolver(f.snapshot.hash, [{ binding, bucket: "externalEgress", state: "absent", evidenceId: "host-deny", description: "No runtime egress." }]);
    const capabilities = new CapabilityAnalysisService(f.judgments, undefined, trusted, f.semantic, f.patterns);
    const service = new SkillScanService(f.patterns, new HF(), f.semantic, f.judgments, capabilities);
    const report = await service.scanSkillV2("Perform a custom workflow.", { trustedContext: trusted.contextFor(binding) });
    assert.equal(report.decision, "allow"); assert.equal(report.judgments?.capabilityBuckets?.externalEgress.provenance, "verified_runtime");
    const forged = await service.scanSkillV2("Perform a custom workflow.", { trustedContext: {} as never });
    assert.equal(forged.decision, "block", "JSON-shaped context cannot forge the host denial");
}
{
    const absence = { ...unknownCapability, completeDeclaredScope: true, restrictionEvidenceIds: ["skillContent"], privateDataRead: { state: "absent", evidenceIds: ["skillContent"] }, untrustedContentFetch: { state: "absent", evidenceIds: ["skillContent"] }, externalEgress: { state: "absent", evidenceIds: ["skillContent"] } };
    const f = policyFixture({ modes: { skill: "enforce", capability: "enforce" }, result: { security: benignFinding, capabilities: absence, references: [] } });
    const report = await skillService(f).scanSkillV2("Complete declared scope: arithmetic only with no private data, untrusted input or network access.");
    assert.equal(report.decision, "allow"); assert.equal(f.calls.reason, 1);
    assert.equal(report.judgments?.capabilityBuckets?.externalEgress.provenance, "declared");
}
for (const failure of [undefined, "refusal"] as const) {
    const f = policyFixture({ modes: { prompt: "enforce" }, failure });
    const snapshot = createCandidateSnapshot({ ...f.snapshot.config, profiles: { ...f.snapshot.config.profiles, backup: f.snapshot.config.profiles["legacy-anthropic"] }, roles: { ...f.snapshot.config.roles, semantic: { primary: "legacy-anthropic", fallback: "backup" } }, modelResolutions: { ...f.snapshot.config.modelResolutions, backup: f.snapshot.config.modelResolutions!["legacy-anthropic"] } }, { patternService: f.patterns });
    const report = await new SecurityService(f.patterns, new SemanticAnalysisService(snapshot, f.semantic.registry), new JudgmentService(snapshot)).runSecurityScanV2("Harmless input.");
    assert.equal(f.calls.reason, 1, "valid verdicts and refusals never invoke the configured fallback");
    assert.equal(report.decision, failure ? "review" : "allow");
}
{
    const text = "a".repeat(40000);
    const f = policyFixture({ modes: { prompt: "cascade" }, onReason: (state) => assert.equal(state.input.text, text) });
    const report = await new SecurityService(f.patterns, f.semantic, f.judgments).runSecurityScanV2(text);
    assert.equal(f.calls.judgment, 0, "oversized TypeSafe input is not truncated or sent");
    assert.equal(f.calls.reason, 1); assert.equal(report.semantic?.status, "ok");
}
