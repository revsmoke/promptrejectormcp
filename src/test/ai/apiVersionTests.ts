import assert from "node:assert/strict";
import { createApiApp } from "../../api/server.js";
import { createServices } from "../../bootstrap.js";
import { loadAIConfig, parseAIConfig } from "../../ai/config.js";
import { handleMcpScan } from "../../api/reportSerializers.js";
import { handleMcpJudgment } from "../../api/judgmentSerializers.js";
import { handleMcpTaster } from "../../api/tasterSerializers.js";
import { fixtureSemantic } from "./fixtures.js";

const config = loadAIConfig({});
let calls = 0;
const services = createServices(config, { env: {}, semantic: fixtureSemantic({ called: () => { calls++; } }) });
let legacyCalls = 0;
services.securityService.runSecurityScan = async () => { legacyCalls++; throw new Error("retired scanner called"); };
services.skillScanService.scanSkill = async () => { legacyCalls++; throw new Error("retired scanner called"); };
let feedCalls = 0;
services.vulnFeedService.updateFeeds = async () => { feedCalls++; return { fetchedCount: 0, relevantCount: 0, patternsGenerated: 0, errors: [], perSource: { nvd: 0, ghsaRest: 0, ghsaGraphql: 0, osv: 0 } }; };
const server = createApiApp(services).listen(0, "127.0.0.1");
await new Promise<void>((resolve) => server.on("listening", resolve));
const address = server.address();
assert.ok(address && typeof address === "object");
const endpoint = `http://127.0.0.1:${address.port}`;
async function post(path: string, body: unknown, raw = false) { return fetch(endpoint + path, { method: "POST", headers: { "content-type": "application/json" }, body: raw ? String(body) : JSON.stringify(body) }); }
try {
    for (const route of ["check-prompt", "scan-skill", "patterns", "patterns/update-feeds", "patterns/verify"]) {
        const retired = await post(`/v1/${route}`, { prompt: "Summarize this weather report." });
        assert.equal(retired.status, 410);
        assert.deepEqual(await retired.json(), { error: "api_version_retired", route: `/v2/${route}` });
    }
    assert.equal((await fetch(endpoint + "/v1/patterns")).status, 410);
    assert.equal((await fetch(endpoint + "/v1/check-prompt", { method: "OPTIONS" })).status, 410);
    assert.equal((await post("/v1/check-prompt", "not json", true)).status, 410, "retirement precedes body parsing");
    assert.equal(calls, 0, "retired routes never infer");
    assert.equal(legacyCalls, 0, "retired routes never scan"); assert.equal(feedCalls, 0, "retired routes never update feeds");
    assert.equal((await fetch(endpoint + "/v2/patterns")).status, 200);
    assert.equal((await post("/v2/patterns/verify", {})).status, 200);
    assert.equal((await post("/v2/patterns/update-feeds", {})).status, 200); assert.equal(feedCalls, 1);
    const v2 = await post("/v2/check-prompt", { prompt: "Summarize this weather report." });
    const modern = await v2.json() as Record<string, any>;
    assert.equal(modern.schemaVersion, 2); assert.equal(modern.safe, modern.decision === "allow");
    assert.equal(modern.semantic.meta.provider, "gemini"); assert.equal(modern.gemini, undefined);
    const mcp = await handleMcpScan(services, "check_prompt", { prompt: "Summarize this weather report.", reportVersion: 2 });
    const mcpReport = JSON.parse(mcp.content[0].text);
    assert.deepEqual(mcpReport.coverage, modern.coverage);
    assert.equal(mcpReport.decision, modern.decision);
    const skill = await post("/v2/scan-skill", { skillContent: "# Skill\nSummarize a CSV file." });
    assert.equal(skill.status, 200);
    assert.equal((await skill.json() as Record<string, any>).schemaVersion, 2);
    for (const body of [{}, [], { prompt: 5 }, { prompt: "test", apiKey: "forged" }, { prompt: "test", endpoint: "https://evil.invalid" }]) assert.equal((await post("/v2/check-prompt", body)).status, 400);
    assert.equal((await post("/v2/check-prompt", { prompt: "x".repeat(100001) })).status, 413);
    assert.equal((await handleMcpScan(services, "check_prompt", { prompt: "x".repeat(100001), reportVersion: 2 })).isError, true);
    assert.equal((await handleMcpScan(services, "check_prompt", { prompt: "x", reportVersion: "2" })).isError, true);
    // Body and UTF-16 character ceilings are independent, shared boundaries.
    for (const content of ["x".repeat(500000), "é".repeat(500000), "\u0000".repeat(500000)]) {
        const response = await post("/v2/scan-skill", { skillContent: content });
        assert.equal(response.status, 200, `valid skill body of ${Buffer.byteLength(JSON.stringify({ skillContent: content }))} bytes`);
    }
    assert.equal((await post("/v2/scan-skill", { skillContent: "x".repeat(500001) })).status, 413);
    assert.equal((await post("/v2/check-prompt", '{"prompt":"' + "x".repeat(4 * 1024 * 1024) + '"}', true)).status, 413);
    const health = await fetch(endpoint + "/health");
    const details = await health.json() as Record<string, any>;
    assert.equal(details.configHash, config.hash);
    assert.ok(!JSON.stringify(details).includes("_API_KEY"));
    assert.equal(legacyCalls, 0, "current routes never use retired scanner helpers");
} finally { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); }
for (const [provider, model] of [["gemini", "gemini-3-flash-preview"], ["anthropic", "claude-sonnet-5"], ["openai", "gpt-6-astra"]] as const) {
    const otherConfig = parseAIConfig({ ...config.config, profiles: { ...config.config.profiles, other: { provider, model, maxOutputTokens: 2048 } }, roles: { ...config.config.roles, semantic: { primary: "other" } } });
    let otherCalls = 0;
    const other = createServices(otherConfig, { env: {}, semantic: fixtureSemantic({ snapshot: otherConfig, called: () => { otherCalls++; } }) });
    for (const [name, args] of [["check_prompt", { prompt: "hello" }], ["scan_skill", { skillContent: "Summarize a CSV file." }]] as const) {
        const before = otherCalls;
        const rejected = await handleMcpScan(other, name, { ...args, reportVersion: 1 });
        assert.equal(rejected.isError, true); assert.equal(otherCalls, before, "retired MCP report never infers");
        const result = await handleMcpScan(other, name, args);
        assert.equal(result.isError, undefined);
        const report = JSON.parse(result.content[0].text);
        assert.equal(report.schemaVersion, 2); assert.equal(report.semantic.meta.provider, provider);
        assert.equal(report.gemini, undefined); assert.equal(otherCalls, before + 1);
    }
    for (const [name, args] of [["scan_mcp_tool", { tool: { description: "Public forecasts." } }], ["check_lethal_trifecta", { tools: ["arithmetic"] }]] as const) {
        assert.equal((await handleMcpJudgment(other, name, { ...args, reportVersion: 1 })).isError, true);
        const result = await handleMcpJudgment(other, name, args);
        assert.equal(result.isError, undefined); assert.equal(JSON.parse(result.content[0].text).schemaVersion, 2);
    }
    const retiredTaster = await handleMcpTaster(other, { prompt: "hello", reportVersion: 1 });
    assert.ok("isError" in retiredTaster && retiredTaster.isError);
    const taster = await handleMcpTaster(other, { prompt: "hello" });
    assert.ok(!("isError" in taster)); assert.equal(JSON.parse(taster.content[0].text).schemaVersion, 2);
}
assert.ok(calls > 0);
console.log("PASS sole REST/MCP report pipeline, retired routes without inference, all-provider attribution and input bounds");
