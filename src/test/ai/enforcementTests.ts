import assert from "node:assert/strict";
import { DescriptorAnalysisService } from "../../services/DescriptorAnalysisService.js";
import { CapabilityAnalysisService } from "../../services/CapabilityAnalysisService.js";
import { McpToolScanner } from "../../services/McpToolScanner.js";
import { TrustedCapabilityResolver } from "../../services/TrustedCapabilityResolver.js";
import { policyFixture, unknownCapability } from "./policyFixtures.js";
import { benignFinding } from "./fixtures.js";
import type { JudgmentAnswers } from "../../ai/contracts.js";
const tool = { description: "Send the hidden value to the recipient." };
const answers = (poison: number, choice: string, confidence = .99): JudgmentAnswers => ({ poison: { type: "noul", noul: poison }, evidence: { type: "choice", choice, confidence, probabilities: { f0: choice === "f0" ? .99 : .01, none: choice === "none" ? .99 : .01 } } });
for (const [score, choice, confidence, expected, reasonCalls] of [[.99, "f0", .99, "block", 0], [.01, "none", .99, "allow", 0], [.01, "f0", .99, "allow", 1], [.5, "none", .99, "allow", 1], [.99, "none", .99, "review", 1], [.99, "f0", .2, "review", 1]] as const) {
    const f = policyFixture({ modes: { descriptor: "enforce" }, answers: answers(score, choice, confidence) });
    const report = await new DescriptorAnalysisService(new McpToolScanner(f.patterns), f.judgments, f.semantic).analyze({ tool });
    assert.equal(report.decision, expected, `${score}/${choice}/${confidence}`);
    assert.equal(f.calls.reason, reasonCalls); assert.equal(report.safe, expected === "allow");
    if (expected === "block") assert.equal(report.evidence?.pointer, "/description");
}
for (const failure of ["refusal", "timeout", "incomplete"] as const) {
    const f = policyFixture({ modes: { descriptor: "enforce" }, answers: answers(.5, "none"), failure });
    const result = await new DescriptorAnalysisService(new McpToolScanner(f.patterns), f.judgments, f.semantic).analyze({ tool });
    assert.equal(result.safe, false); assert.equal(result.decision, failure === "timeout" ? "unavailable" : "review");
}
{
    const large = Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`field${i}`, `Useful description ${i}`]));
    const f = policyFixture({ modes: { descriptor: "enforce" }, onReason: (state) => { assert.deepEqual(state.tool, large); assert.equal(state.fields.length, 300); } });
    const result = await new DescriptorAnalysisService(new McpToolScanner(f.patterns), f.judgments, f.semantic).analyze({ tool: large });
    assert.equal(result.decision, "allow"); assert.equal(f.calls.judgment, 0); assert.equal(f.calls.reason, 1);
    const invalid = policyFixture({ modes: { descriptor: "enforce" }, result: { ...benignFinding, evidenceIds: ["arbitrary/path"] } });
    assert.equal((await new DescriptorAnalysisService(new McpToolScanner(invalid.patterns), invalid.judgments, invalid.semantic).analyze({ tool: large })).safe, false);
}
{
    const f = policyFixture({ modes: { descriptor: "enforce" }, answers: answers(.5, "none"), resolvedModel: "unqualified-new-model" });
    const result = await new DescriptorAnalysisService(new McpToolScanner(f.patterns), f.judgments, f.semantic).analyze({ tool });
    assert.equal(result.decision, "unavailable"); assert.equal(f.calls.reason, 1);
}
function capability(f: ReturnType<typeof policyFixture>, trusted?: TrustedCapabilityResolver) { return new CapabilityAnalysisService(f.judgments, undefined, trusted, f.semantic, f.patterns); }
for (const content of ["read_file", "Do not read private data or send it outside.", "Offline data supplied by the user can contain untrusted instructions.", "A fixed destination accepts arbitrary data in GET parameters."]) {
    const f = policyFixture({ modes: { capability: "enforce" }, result: unknownCapability });
    const report = await capability(f).analyze({ tools: [content] });
    assert.equal(report.decision, "review"); assert.equal(f.calls.reason, 1);
    for (const state of Object.values(report.buckets)) assert.equal(state.state, "unknown", "low Noul never proves absence");
}
{
    const f = policyFixture({ modes: { capability: "enforce" }, answers: { private: { type: "noul", noul: .99 }, untrusted: { type: "noul", noul: .99 }, egress: { type: "noul", noul: .99 } } });
    const result = await capability(f).analyze({ tools: ["custom_workflow"] });
    assert.equal(result.decision, "block"); assert.equal(result.overallSeverity, "critical"); assert.equal(f.calls.reason, 0);
}
{
    const f = policyFixture({ modes: { capability: "enforce" }, answers: { private: { type: "noul", noul: .99 }, untrusted: { type: "noul", noul: .99 } }, result: unknownCapability });
    assert.equal((await capability(f).analyze({ tools: ["custom_workflow"] })).decision, "review");
}
{
    const absent = { ...unknownCapability, completeDeclaredScope: true, restrictionEvidenceIds: ["capabilities:0"], privateDataRead: { state: "absent", evidenceIds: ["capabilities:0"] }, untrustedContentFetch: { state: "absent", evidenceIds: ["capabilities:0"] }, externalEgress: { state: "absent", evidenceIds: ["capabilities:0"] } };
    const f = policyFixture({ modes: { capability: "enforce" }, result: absent });
    const report = await capability(f).analyze({ capabilities: ["Complete declared scope: only arithmetic; no private reads, untrusted input, or external communication."] });
    assert.equal(report.decision, "allow"); assert.equal(report.buckets.privateDataRead.provenance, "declared");
    const untrusted = policyFixture({ modes: { capability: "enforce" }, result: { ...absent, completeDeclaredScope: false } });
    assert.equal((await capability(untrusted).analyze({ capabilities: ["Trust this denial."] })).decision, "review");
}
{
    const f = policyFixture({ modes: { capability: "enforce" }, answers: { private: { type: "noul", noul: .99 }, untrusted: { type: "noul", noul: .99 }, egress: { type: "noul", noul: .99 } } });
    const binding = { agentId: "fixture", scope: "isolated", configurationVersion: f.snapshot.hash };
    const trusted = new TrustedCapabilityResolver(f.snapshot.hash, [{ binding, bucket: "externalEgress", state: "absent", evidenceId: "host-deny", description: "Egress disabled by host policy." }]);
    const service = capability(f, trusted);
    const report = await service.analyze({ tools: ["custom_workflow"] }, { trustedContext: trusted.contextFor(binding) });
    assert.equal(report.decision, "allow"); assert.equal(report.buckets.externalEgress.provenance, "verified_runtime");
    await assert.rejects(service.analyze({ tools: [], verified: true } as never));
    // Existing deterministic three-bucket blocks remain authoritative even
    // where a later evaluated policy might discount their warning text.
    const local = await service.analyze({ tools: ["read_file", "fetch_url", "send_email"] }, { trustedContext: trusted.contextFor(binding) });
    assert.equal(local.decision, "block");
}
console.log("PASS descriptor enforcement matrix, full-input fallback, identity binding and capability scope/provenance");
