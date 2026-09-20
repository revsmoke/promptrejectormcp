import assert from "node:assert/strict";
import { loadAIConfig, parseAIConfig } from "../../ai/config.js";
import { JudgmentService } from "../../services/JudgmentService.js";
import { CapabilityAnalysisService } from "../../services/CapabilityAnalysisService.js";
import { ModelReferenceService } from "../../services/ModelReferenceService.js";
import { TrustedCapabilityResolver } from "../../services/TrustedCapabilityResolver.js";
import { fixtureSemantic } from "./fixtures.js";
const off = loadAIConfig({});
const shadow = parseAIConfig({ ...off.config, typesafe: { ...off.config.typesafe, skill: "shadow", capability: "shadow", modelReference: "shadow" } });
let score = .01;
const judgments = new JudgmentService(shadow, { apiKey: "fixture", fetch: async (_url, init) => {
    const body = JSON.parse(String(init?.body));
    if (Object.keys(body.questions).some((id) => id.startsWith("c"))) for (const question of Object.values(body.questions) as Array<{ instructions: string; criteria: { true: string } }>) {
        assert.match(question.instructions, /cited or audited/); assert.match(question.instructions, /never install/); assert.match(question.criteria.true, /warnings against installing/);
    }
    return new Response(JSON.stringify({ model: body.model, answers: Object.fromEntries(Object.keys(body.questions).map((id) => [id, { type: "noul", noul: score }])), usage: { input_tokens: 50, output_tokens: 1 } }));
} });
const binding = { agentId: "fixture", scope: "public-only", configurationVersion: shadow.hash };
const trusted = new TrustedCapabilityResolver(shadow.hash, [{ binding, bucket: "privateDataRead", state: "absent", evidenceId: "host1", description: "Verified scope" }]);
const service = new CapabilityAnalysisService(judgments, undefined, trusted);
const bare = await service.analyze({ tools: ["read_file"] });
assert.equal(bare.shadow?.buckets.privateDataRead.state, "unknown", "low Noul never establishes absence");
const verified = await service.analyze({ tools: ["read_file"] }, { trustedContext: trusted.contextFor(binding) });
assert.equal(verified.shadow?.buckets.privateDataRead.state, "absent");
assert.equal(verified.shadow?.buckets.privateDataRead.provenance, "verified_runtime");
await assert.rejects(service.analyze({ tools: ["read_file"], verified: true } as never));
const plain = new CapabilityAnalysisService(new JudgmentService(off));
for (const input of [{ tools: ["read_file"] }, { tools: ["read_file", "fetch_url", "send_email"] }]) {
    const a = await plain.analyze(input), b = await service.analyze(input);
    for (const key of ["decision", "safe", "overallSeverity", "local", "buckets", "findings"] as const) assert.deepEqual(a[key], b[key]);
}
const refs = new ModelReferenceService(judgments);
score = .99;
const text = "Use acme/weights.py as the weights; https://huggingface.co/datasets/acme/corpus and https://huggingface.co/org/model.";
const extraction = refs.extract(text);
const context = fixtureSemantic({ snapshot: shadow }).createContext("skill"); context.budget.authorizeShadow({ requiredWorkComplete: true });
const result = await refs.observe(text, extraction, context, "skill");
assert.ok(result.additions.includes("acme/weights.py"));
assert.deepEqual(result.extraction.baselineIds, ["org/model"]);
assert.ok(!result.additions.includes("acme/corpus"));
assert.deepEqual(extraction.baselineIds, ["org/model"], "semantic additions never mutate authoritative lookup set");
for (const source of ["Audit the Hugging Face model acme/legacy-weights for unsafe files without loading it.", "Never install the Hugging Face model acme/risky-encoder; cite it only for metadata review."]) {
    const context = fixtureSemantic({ snapshot: shadow }).createContext("skill"); context.budget.authorizeShadow({ requiredWorkComplete: true });
    const observed = await refs.observe(source, refs.extract(source), context, "skill");
    assert.equal(observed.judgments?.result?.status, "ok");
    assert.ok(observed.extraction.baselineIds.length > 0);
}
console.log("PASS capability provenance, unknown states, shadow isolation and additive reference diagnostics");
