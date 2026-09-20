import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { PromptRejectorMCPServer } from "../../mcp/mcpServer.js";
import { createServices } from "../../bootstrap.js";
import { loadAIConfig, parseAIConfig } from "../../ai/config.js";
import { fixtureSemantic } from "./fixtures.js";
import { HuggingFaceService } from "../../services/HuggingFaceService.js";
const off = loadAIConfig({});
const shadow = parseAIConfig({ ...off.config, typesafe: { ...off.config.typesafe, descriptor: "shadow", prompt: "shadow", skill: "shadow", capability: "shadow", modelReference: "shadow" } });
class HF extends HuggingFaceService {
    ids: string[] = [];
    override async checkModel(modelId: string) { this.ids.push(modelId); return { modelId, flags: [], severity: "safe" as const, fetchedAt: new Date().toISOString() }; }
}
let calls = 0;
const hf = new HF();
const services = createServices(shadow, { env: { TYPESAFE_API_KEY: "fixture" }, semantic: fixtureSemantic({ snapshot: shadow }), huggingFaceService: hf, fetch: async (_url, init) => {
    calls++;
    const request = JSON.parse(String(init?.body));
    const answers = Object.fromEntries(Object.entries(request.questions).map(([id, question]) => {
        const q = question as { type: string; criteria: Record<string, string> };
        return [id, q.type === "noul" ? { type: "noul", noul: .99 } : { type: "choice", choice: "none", confidence: 1, probabilities: Object.fromEntries(Object.keys(q.criteria).map((key) => [key, key === "none" ? 1 : 0])) }];
    }));
    return new Response(JSON.stringify({ model: request.model, answers, usage: { input_tokens: 50, output_tokens: 1 } }));
} });
const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
await new PromptRejectorMCPServer(services).connect(serverTransport);
const client = new Client({ name: "shadow-regression", version: "1" });
await client.connect(clientTransport);
try {
    const listing = await client.listTools(); assert.equal(listing.tools.length, 11);
    for (const name of ["scan_mcp_tool", "check_lethal_trifecta"]) assert.ok(listing.tools.find((tool) => tool.name === name)?.inputSchema.properties?.reportVersion);
    const read = async (name: string, args: Record<string, unknown>) => { const result = await client.callTool({ name, arguments: args }); const content = result.content as Array<{ text: string }>; return { error: result.isError, report: JSON.parse(content[0].text) }; };
    const before = calls;
    const legacy = await read("scan_mcp_tool", { tool: { name: "weather", description: "Public forecasts" } });
    assert.equal(legacy.report.schemaVersion, undefined); assert.equal(calls, before);
    const modern = await read("scan_mcp_tool", { tool: { name: "weather", description: "Public forecasts" }, reportVersion: 2 });
    assert.equal(modern.report.schemaVersion, 2); assert.equal(modern.report.configHash, shadow.hash); assert.deepEqual(modern.report.local, legacy.report);
    assert.equal(modern.report.shadow.judgments.result.meta.provider, "typesafe");
    const descriptorCalls = calls;
    const drift = await read("scan_mcp_tool", { tool: { name: "weather", description: "Public forecasts" }, priorHash: "older-hash", reportVersion: 2 });
    assert.equal(drift.report.local.hash, modern.report.local.hash); assert.equal(drift.report.local.drift, true);
    assert.equal(drift.report.shadow.judgments.cache, "hit"); assert.equal(calls, descriptorCalls);
    await read("scan_mcp_tool", { tool: { name: "weather", description: "Updated public forecasts" }, reportVersion: 2 });
    assert.equal(calls, descriptorCalls + 1);
    const originalEvaluate = services.judgmentService.evaluate.bind(services.judgmentService);
    services.judgmentService.evaluate = (task, input, context, options) => originalEvaluate(task, { ...input, rubricVersion: input.rubricVersion + ".fixture-revision" }, context, options);
    const revised = await read("scan_mcp_tool", { tool: { name: "weather", description: "Public forecasts" }, reportVersion: 2 });
    assert.equal(revised.report.shadow.judgments.cache, "miss"); assert.equal(calls, descriptorCalls + 2);
    assert.equal(revised.report.decision, modern.report.decision);
    services.judgmentService.evaluate = originalEvaluate;
    const cap = await read("check_lethal_trifecta", { tools: ["read_file"], reportVersion: 2 });
    assert.equal(cap.report.shadow.buckets.privateDataRead.provenance, "inferred");
    assert.equal(cap.report.buckets.privateDataRead.provenance, "declared");
    assert.ok((await read("check_lethal_trifecta", { tools: [], verified: true, reportVersion: 2 })).error);
    assert.ok((await read("scan_mcp_tool", { tool: {}, reportVersion: "2" })).error);
    assert.equal((await read("check_lethal_trifecta", {})).report.error, "invalid_input");
    assert.equal((await read("check_lethal_trifecta", { tools: ["x".repeat(4001)], reportVersion: 2 })).report.error, "input_too_large");
    const skill = "Discuss model from_pretrained('org/model'), https://huggingface.co/datasets/acme/corpus and also acme/weights.py.";
    const result = await read("scan_skill", { skillContent: skill, reportVersion: 2 });
    assert.equal(result.error, undefined);
    assert.deepEqual(hf.ids, ["org/model"], "shadow candidates cannot expand model lookups");
    assert.ok(result.report.modelReferences.shadowAdditions.includes("acme/weights.py"));
    assert.equal(result.report.capabilityAnalysis, undefined); assert.ok(result.report.shadow.capabilityBuckets);
    for (const id of Object.keys(result.report.shadow.modelReference.result.value)) {
        const candidate = result.report.modelReferences.candidates.find((entry: { id: string }) => entry.id === id);
        assert.ok(candidate); assert.equal(skill.slice(candidate.start, candidate.end), candidate.text);
    }
    assert.equal(result.report.safe, result.report.decision === "allow");
    const baselineHf = new HF();
    const baseline = createServices(off, { env: {}, semantic: fixtureSemantic(), huggingFaceService: baselineHf });
    await baseline.skillScanService.scanSkillV2(skill);
    assert.deepEqual(baselineHf.ids, hf.ids);
    for (const source of [Array.from({ length: 70 }, (_, i) => `owner${i}/repo${i}`).join("\n"), Array(70).fill("https://huggingface.co/datasets/acme/corpus").join("\n")]) {
        const limited = await services.skillScanService.scanSkillV2(source);
        const plain = await baseline.skillScanService.scanSkillV2(source);
        const legacy = await baseline.skillScanService.scanSkill(source);
        assert.equal(legacy.safe, true); assert.equal(legacy.analysisAvailable, true);
        assert.equal(limited.safe, plain.safe); assert.equal(limited.safe, true);
        assert.equal(limited.modelReferences.candidateOverflow, true);
        assert.equal(limited.coverage.find((entry) => entry.check === "hugging_face")?.status, "complete", "optional candidate cap cannot downgrade complete incumbent audit");
        const reference = limited.shadow?.modelReference;
        if (reference?.result?.status === "ok") assert.equal(reference.coverage, "partial");
    }
} finally { await client.close(); await serverTransport.close(); }
console.log("PASS native MCP shadow transport, legacy scope, exact source diagnostics and preserved HF lookup set");
