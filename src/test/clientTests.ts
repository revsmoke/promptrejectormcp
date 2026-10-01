import assert from "node:assert/strict";
import { createServices } from "../bootstrap.js";
import { loadAIConfig } from "../ai/config.js";
import { fixtureSemantic } from "./ai/fixtures.js";
import { createPromptRejector, PromptRejectorError, resultExitCode, commandNames } from "../client/index.js";
import { handleMcpScan } from "../api/reportSerializers.js";
import { handleMcpJudgment } from "../api/judgmentSerializers.js";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { VulnFeedService } from "../services/VulnFeedService.js";

const snapshot = loadAIConfig({});
let calls = 0;
const services = createServices(snapshot, { env: {}, semantic: fixtureSemantic({ called: () => calls++ }) });
const client = createPromptRejector({ services });
const prompt = "Summarize today's weather.";
const report = await client.run("check-prompt", { prompt });
const mcp = JSON.parse((await handleMcpScan(services, "check_prompt", { prompt })).content[0].text);
assert.equal(report.decision, "allow");
assert.equal(report.decision, mcp.decision);
assert.deepEqual(report.coverage, mcp.coverage);
assert.equal(resultExitCode("check-prompt", report), 0);
const malicious = await client.run("check-prompt", { prompt: "<script>alert('synthetic')</script>" });
assert.equal(malicious.decision, "block");
assert.equal(resultExitCode("check-prompt", malicious), 1);
const failed = createPromptRejector({ services: createServices(snapshot, { env: {}, semantic: fixtureSemantic({ unavailable: "authentication" }) }) });
assert.equal(resultExitCode("check-prompt", await failed.run("check-prompt", { prompt })), 3);
const refused = createPromptRejector({ services: createServices(snapshot, { env: {}, semantic: fixtureSemantic({ unavailable: "refusal" }) }) });
assert.equal(resultExitCode("check-prompt", await refused.run("check-prompt", { prompt })), 1);

const skill = await client.run("scan-skill", { skillContent: "# Skill\nSummarize a CSV file." });
assert.equal(skill.schemaVersion, 2);
const tool = { name: "weather", description: "Read public forecasts.", inputSchema: { type: "object" } };
const descriptor = await client.run("scan-mcp-tool", { tool });
const mcpDescriptor = JSON.parse((await handleMcpJudgment(services, "scan_mcp_tool", { tool })).content[0].text);
assert.equal(descriptor.decision, mcpDescriptor.decision);
assert.deepEqual(descriptor.coverage, mcpDescriptor.coverage);
assert.equal((await client.run("check-lethal-trifecta", { tools: ["read_file", "fetch_url", "send_email"] })).decision, "block");
assert.equal(resultExitCode("taste-test", await client.run("taste-test", { prompt })), 3);
const patterns = await client.run("list-patterns", { category: "xss" });
assert.ok(patterns.count > 0);
assert.ok(patterns.patterns.every(pattern => pattern.category === "xss"));
assert.equal((await client.run("verify-pattern-integrity", {})).valid, true);
assert.ok(Array.isArray((await client.run("query-cve", { limit: 1 })).records));
const canary = await client.run("deploy-canary", { context: "synthetic-cli-test", ttlSeconds: 60 });
assert.equal(resultExitCode("verify-canary", await client.run("verify-canary", { content: canary.token, watchHandle: canary.watchHandle })), 1);
assert.equal(resultExitCode("verify-canary", await client.run("verify-canary", { content: "No token here." })), 0);
services.canaryService.revoke(canary.watchHandle);
// Packed installs exclude mutable staging. The first feed update must create it.
const fresh = mkdtempSync(join(tmpdir(), "fresh-cli-feeds-"));
try {
    const feeds = new VulnFeedService(services.patternService, services.semantic, fresh);
    for (const method of ["fetchNVD", "fetchGitHubAdvisories", "fetchOsv", "fetchGhsaGraphql"]) (feeds as any)[method] = async () => [];
    (feeds as any).atlasService.refresh = async () => undefined;
    (feeds as any).kevFeedService.refresh = async () => undefined;
    const freshClient = createPromptRejector({ services: { ...services, vulnFeedService: feeds } });
    assert.equal(resultExitCode("update-vuln-feeds", await freshClient.run("update-vuln-feeds", {})), 0);
    assert.deepEqual(JSON.parse(readFileSync(join(fresh, "staging/pending-review.json"), "utf8")).candidates, []);
} finally { rmSync(fresh, { recursive: true, force: true }); }
let days: number | undefined;
services.vulnFeedService.updateFeeds = async lookbackDays => {
    days = lookbackDays;
    return { fetchedCount: 0, relevantCount: 0, patternsGenerated: 0, errors: [], perSource: { nvd: 0, ghsaRest: 0, ghsaGraphql: 0, osv: 0 } };
};
assert.equal(resultExitCode("update-vuln-feeds", await client.run("update-vuln-feeds", { lookbackDays: 7 })), 0);
assert.equal(days, 7);
assert.equal(resultExitCode("health", await client.run("health", {})), 3);
assert.equal(commandNames.length, 12);

const before = calls;
for (const [command, input] of [
    ["check-prompt", {}], ["check-prompt", { prompt, apiKey: "synthetic-secret" }],
    ["check-prompt", { prompt: "x".repeat(100001) }], ["scan-skill", { skillContent: "x".repeat(500001) }],
    ["scan-mcp-tool", { tool: { text: "x".repeat(100001) } }], ["check-lethal-trifecta", {}],
    ["check-lethal-trifecta", { tools: ["x".repeat(4001)] }], ["list-patterns", { enabled: "false" }],
    ["update-vuln-feeds", { lookbackDays: 0 }], ["query-cve", { limit: 201 }], ["query-cve", { severity: "bogus" }],
    ["deploy-canary", { ttlSeconds: 2592001 }], ["verify-canary", { content: "test", watchHandle: "not-a-handle" }],
    ["health", null], ["constructor", {}],
] as const) {
    await assert.rejects(() => client.run(command as any, input as any), PromptRejectorError);
}
const cyclic: Record<string, unknown> = {}; cyclic.self = cyclic;
await assert.rejects(() => client.run("scan-mcp-tool", { tool: cyclic }), (error: unknown) => error instanceof PromptRejectorError && error.code === "invalid_input");
const aborted = new AbortController(); aborted.abort();
await assert.rejects(() => client.run("check-prompt", { prompt }, { signal: aborted.signal }), (error: unknown) => error instanceof PromptRejectorError && error.code === "cancelled");
assert.equal(calls, before, "invalid and cancelled work never dispatches");
services.securityService.runSecurityScanV2 = async () => { throw new Error("synthetic-provider-secret"); };
await assert.rejects(() => client.run("check-prompt", { prompt }), (error: unknown) => error instanceof PromptRejectorError && error.message === "internal_error" && !("cause" in error));
const pendingAbort = new AbortController();
services.securityService.runSecurityScanV2 = async (_input, options) => new Promise(resolve => options?.signal?.addEventListener("abort", () => resolve(report), { once: true }));
const pending = client.run("check-prompt", { prompt }, { signal: pendingAbort.signal });
pendingAbort.abort();
await assert.rejects(() => pending, (error: unknown) => error instanceof PromptRejectorError && error.code === "cancelled");
for (const value of [null, {}, { safe: true }, { decision: "allow", safe: false }, { decision: "unavailable" }]) assert.equal(resultExitCode("check-prompt", value), 3);
assert.equal(resultExitCode("update-vuln-feeds", { errors: [{}] }), 3);
assert.equal(resultExitCode("taste-test", { available: true, coverage: { taster: "partial", monitor: "complete" }, behaviorReport: { monitorVerdict: "clean" } }), 3);
console.log("PASS typed SDK, shared report parity, all commands, fail-closed exits, input validation and cancellation");
