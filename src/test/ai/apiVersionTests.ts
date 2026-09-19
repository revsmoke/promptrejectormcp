import assert from "node:assert/strict";
import { createApiApp } from "../../api/server.js";
import { createServices } from "../../bootstrap.js";
import { loadAIConfig, parseAIConfig } from "../../ai/config.js";
import { handleMcpScan } from "../../api/reportSerializers.js";
import { fixtureSemantic } from "./fixtures.js";

const config = loadAIConfig({});
let calls = 0;
const services = createServices(config, { env: {}, semantic: fixtureSemantic({ called: () => { calls++; } }) });
const server = createApiApp(services).listen(0, "127.0.0.1");
await new Promise<void>((resolve) => server.on("listening", resolve));
const address = server.address();
assert.ok(address && typeof address === "object");
const endpoint = `http://127.0.0.1:${address.port}`;
async function post(path: string, body: unknown, raw = false) { return fetch(endpoint + path, { method: "POST", headers: { "content-type": "application/json" }, body: raw ? String(body) : JSON.stringify(body) }); }
try {
    const v1 = await post("/v1/check-prompt", { prompt: "Summarize this weather report." });
    assert.equal(v1.status, 200);
    const legacy = await v1.json() as { safe: boolean; geminiAvailable: boolean; overallConfidence: number };
    assert.equal(legacy.safe, true); assert.equal(legacy.geminiAvailable, true); assert.equal(legacy.overallConfidence, 0.9);
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
} finally { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); }
const otherConfig = parseAIConfig({ ...config.config, profiles: { ...config.config.profiles, other: { provider: "openai", model: "gpt-6-astra", maxOutputTokens: 2048 } }, roles: { ...config.config.roles, semantic: { primary: "other" } } });
let otherCalls = 0;
const other = createServices(otherConfig, { env: {}, semantic: fixtureSemantic({ snapshot: otherConfig, called: () => { otherCalls++; } }) });
const migration = await handleMcpScan(other, "check_prompt", { prompt: "hello" });
assert.equal(migration.isError, true); assert.equal(otherCalls, 0);
assert.equal(JSON.parse(migration.content[0].text).error, "report_version_required");
const configuredServer = createApiApp(other).listen(0, "127.0.0.1");
await new Promise<void>((resolve) => configuredServer.on("listening", resolve));
try {
    const address = configuredServer.address(); assert.ok(address && typeof address === "object");
    const migrated = await fetch(`http://127.0.0.1:${address.port}/v1/check-prompt`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ prompt: "hello" }) });
    assert.equal(migrated.status, 409); assert.equal(otherCalls, 0);
    const report = JSON.parse((await handleMcpScan(other, "check_prompt", { prompt: "hello", reportVersion: 2 })).content[0].text);
    assert.equal(report.semantic.meta.provider, "openai"); assert.equal(report.gemini, undefined); assert.equal(otherCalls, 1);
} finally { configuredServer.closeAllConnections(); await new Promise<void>((resolve) => configuredServer.close(() => resolve())); }
assert.ok(calls > 0);
console.log("PASS REST/MCP versions, attribution, compatibility and byte/character bounds");
