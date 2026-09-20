import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { PromptRejectorMCPServer } from "../../mcp/mcpServer.js";
import { createServices } from "../../bootstrap.js";
import { createApiApp } from "../../api/server.js";
import { loadAIConfig } from "../../ai/config.js";
import { SecurityService } from "../../services/SecurityService.js";
import { SkillScanService } from "../../services/SkillScanService.js";
import { DescriptorAnalysisService } from "../../services/DescriptorAnalysisService.js";
import { CapabilityAnalysisService } from "../../services/CapabilityAnalysisService.js";
import { McpToolScanner } from "../../services/McpToolScanner.js";
import { ModelReferenceService } from "../../services/ModelReferenceService.js";
import { policyFixture, unknownCapability } from "./policyFixtures.js";
import { benignFinding, fixtureSemantic } from "./fixtures.js";
for (const mode of ["enforce", "cascade"] as const) {
    const f = policyFixture({ modes: { prompt: mode, skill: mode, descriptor: "enforce", capability: "enforce", modelReference: "enforce" }, answers: { override: { type: "noul", noul: .99 } },
        resultFor: (state) => state.source ? unknownCapability : state.capabilityRequired ? { security: benignFinding, capabilities: unknownCapability, references: [] } : benignFinding });
    assert.throws(() => createServices(f.snapshot, { env: {}, patternService: f.patterns }), /Evaluation-only/);
    // This graph is constructed solely inside the fixture. The serving
    // bootstrap above refuses its private evaluation snapshot.
    const services = { ...createServices(loadAIConfig({}), { env: {}, patternService: f.patterns, semantic: fixtureSemantic() }), snapshot: f.snapshot, semantic: f.semantic, judgmentService: f.judgments,
        securityService: new SecurityService(f.patterns, f.semantic, f.judgments), skillScanService: new SkillScanService(f.patterns, undefined, f.semantic, f.judgments),
        descriptorAnalysis: new DescriptorAnalysisService(new McpToolScanner(f.patterns), f.judgments, f.semantic), capabilityAnalysis: new CapabilityAnalysisService(f.judgments, undefined, undefined, f.semantic, f.patterns), modelReferenceService: new ModelReferenceService(f.judgments) };
    const server = createApiApp(services).listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address(); assert.ok(address && typeof address === "object");
    const post = (path: string, body: unknown) => fetch(`http://127.0.0.1:${address.port}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await new PromptRejectorMCPServer(services).connect(serverTransport);
    const client = new Client({ name: "enforced-contract-fixture", version: "1" }); await client.connect(clientTransport);
    const mcp = async (name: string, args: Record<string, unknown>) => { const response = await client.callTool({ name, arguments: args }); return { error: response.isError, report: JSON.parse((response.content as Array<{ text: string }>)[0].text) }; };
    try {
        assert.equal((await client.listTools()).tools.length, 11);
        for (const [path, name, body] of [["/v2/check-prompt", "check_prompt", { prompt: "An ordinary request." }], ["/v2/scan-skill", "scan_skill", { skillContent: "An ordinary skill." }]] as const) {
            const response = await post(path, body); assert.equal(response.status, 200);
            const rest = await response.json() as Record<string, any>;
            const native = await mcp(name, { ...body, reportVersion: 2 });
            assert.equal(native.error, undefined); assert.equal(rest.decision, "block"); assert.equal(rest.safe, false);
            for (const key of ["decision", "safe", "overallSeverity", "coverage", "analysisMode", "categories"]) assert.deepEqual(native.report[key], rest[key], `${mode}:${name}:${key}`);
            assert.equal(rest.coverage.find((entry: any) => entry.check === "semantic").status, mode === "cascade" ? "not_requested" : "complete");
        }
        const descriptor = await mcp("scan_mcp_tool", { reportVersion: 2, tool: { description: "Return a public forecast." } });
        assert.equal(descriptor.report.decision, "allow"); assert.equal(descriptor.report.judgments.mode, "enforce");
        const capabilities = await mcp("check_lethal_trifecta", { reportVersion: 2, tools: ["read_file"] });
        assert.equal(capabilities.report.decision, "review"); assert.equal(capabilities.report.buckets.privateDataRead.state, "unknown");
        assert.equal((await post("/v1/check-prompt", { prompt: "Hello" })).status, 410);
        assert.equal((await mcp("check_prompt", { prompt: "Hello" })).report.schemaVersion, 2);
        assert.equal((await post("/v2/check-prompt", { prompt: "Hello", evaluationOnly: true })).status, 400);
        assert.ok((await mcp("check_prompt", { prompt: "Hello", reportVersion: 2, analysisMode: "off" })).error);
        assert.equal((await post("/v2/check-prompt", { prompt: "x".repeat(100001) })).status, 413);
    } finally {
        await client.close(); await serverTransport.close(); server.closeAllConnections();
        await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
}
console.log("PASS enforced REST/native MCP parity, migration, immutable public config and candidate bootstrap rejection");
