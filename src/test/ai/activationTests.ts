import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { loadAIConfig, parseAIConfig } from "../../ai/config.js";
import { createServices } from "../../bootstrap.js";
import { createApiApp } from "../../api/server.js";
import { PromptRejectorMCPServer } from "../../mcp/mcpServer.js";
import { describeAiConfig } from "../../scripts/checkAiConfig.js";
import { createCandidateSnapshot } from "../../evaluation/candidateConfig.js";
import { validateResolvedModel } from "../../ai/qualification.js";
import { benignFinding } from "./fixtures.js";
const base = loadAIConfig({});
const input = { ...base.config, qualificationPolicy: "optional",
    roles: Object.fromEntries(["semantic", "patternDraft", "taster", "monitor"].map((role) => [role, { primary: "legacy-gemini" }])),
    typesafe: { model: "jev-1.13.0", descriptor: "enforce", capability: "enforce", modelReference: "enforce", prompt: "cascade", skill: "cascade" } };
const snapshot = parseAIConfig(input);
assert.equal(snapshot.evaluationOnly, false);
assert.deepEqual(snapshot.qualification, { tasks: {} }, "activation must not fabricate qualification evidence");
console.log("PASS optional activation configuration accepted without fabricated evidence");
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
const active = loadAIConfig({ AI_CONFIG_PATH: resolve("config/ai.active.json"), TASTE_TESTER_ENABLED: "false" });
assert.equal(active.config.qualificationPolicy, "optional"); assert.ok(!("mcpDefaultReportVersion" in active.config));
assert.equal(active.config.typesafe.prompt, "cascade"); assert.equal(active.config.typesafe.descriptor, "enforce");
for (const role of Object.values(active.config.roles)) assert.equal(active.config.profiles[role.primary].provider, "gemini");
const exampleProfiles = JSON.parse(readFileSync("config/ai.example.json", "utf8")).profiles;
for (const name of ["claude-semantic", "openai-reasoning"]) assert.deepEqual(active.config.profiles[name], exampleProfiles[name], "active configuration includes ready-to-select alternative profiles");
assert.equal(base.config.qualificationPolicy, "required"); assert.ok(!("mcpDefaultReportVersion" in base.config));
assert.throws(() => parseAIConfig({ ...input, qualificationPolicy: "required" }), /manifest/i);
assert.throws(() => parseAIConfig({ ...input, qualificationPolicy: undefined }), /manifest/i);
assert.throws(() => parseAIConfig({ ...input, typesafe: { ...input.typesafe, model: "jev-latest" } }), /pinned/i);
for (const retiredSetting of [1, 2, 3]) assert.throws(() => parseAIConfig({ ...input, mcpDefaultReportVersion: retiredSetting }));
assert.throws(() => createServices(createCandidateSnapshot(input), { env: {} }), /Evaluation-only/);
const directory = mkdtempSync(join(tmpdir(), "activation-evidence-"));
try {
    const evidenceFile = join(directory, "invalid.json"); writeFileSync(evidenceFile, JSON.stringify({ schemaVersion: 1, manifests: [] }));
    const identity = { kind: "version_check", configuredModel: "gemini-3-flash-preview", resolvedModel: "gemini-fixture-version-1", checkedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString(), evidenceSha256: "a".repeat(64), method: "Synthetic unit fixture" };
    const withIdentity = { ...input, modelResolutions: { "legacy-gemini": identity } };
    const explicitIdentity = parseAIConfig(withIdentity);
    assert.equal(validateResolvedModel(explicitIdentity, "prompt", "gemini", "gemini-3-flash-preview", "gemini-fixture-version-1"), true);
    assert.equal(validateResolvedModel(explicitIdentity, "prompt", "gemini", "gemini-3-flash-preview", "different-model"), false);
    assert.throws(() => parseAIConfig({ ...withIdentity, modelResolutions: { "legacy-gemini": { ...identity, expiresAt: new Date(Date.now() - 1).toISOString() } } }), /identity|stale/i);
    assert.throws(() => parseAIConfig({ ...withIdentity, evaluationFile: evidenceFile }, false, { pricing: active.pricing }), /manifest/i, "optional cannot ignore supplied bad evidence");
} finally { rmSync(directory, { recursive: true, force: true }); }
assert.equal(validateResolvedModel(snapshot, "prompt", "gemini", "gemini-3-flash-preview", "gemini-3-flash-preview"), true);
assert.equal(validateResolvedModel(snapshot, "prompt", "gemini", "unconfigured-model", "anything"), false);
assert.equal(validateResolvedModel(snapshot, "prompt", "anthropic", "gemini-3-flash-preview", "anything"), false);
assert.equal(validateResolvedModel(snapshot, "prompt", "gemini", "gemini-3-flash-preview", null), false);
assert.equal(validateResolvedModel(snapshot, "prompt", "typesafe", "jev-1.13.0", "jev-1.14.0"), false);
let mode: "high" | "clean" | "failure" = "high";
const calls = { judgment: 0, semantic: 0 };
const services = createServices(snapshot, { env: { TYPESAFE_API_KEY: "fixture", GEMINI_API_KEY: "fixture", TASTE_TESTER_ENABLED: "false" }, fetch: async (url, init) => {
    const request = JSON.parse(String(init?.body));
    if (String(url).includes("typesafe.ai")) {
        calls.judgment++;
        if (mode === "failure") return new Response("{}", { status: 401 });
        const answers = Object.fromEntries(Object.entries(request.questions).map(([id, raw]) => {
            const question = raw as { type: string; criteria: Record<string, string> };
            const choice = mode === "high" && "f0" in question.criteria ? "f0" : "none";
            return [id, question.type === "choice" ? { type: "choice", choice, confidence: .99, probabilities: Object.fromEntries(Object.keys(question.criteria).map((key) => [key, key === choice ? 1 : 0])) }
                : { type: "noul", noul: mode === "high" && ["poison", "override"].includes(id) ? .99 : .01 }];
        }));
        return new Response(JSON.stringify({ model: "jev-1.13.0", answers, usage: { input_tokens: 10, output_tokens: 10 } }));
    }
    calls.semantic++;
    if (mode === "failure") return new Response("{}", { status: 401 });
    const schema = request.generationConfig.responseJsonSchema;
    const state = JSON.parse(request.contents[0].parts[0].text);
    const sourceIds = (state.sources ?? []).map((item: { id: string }) => item.id);
    const capabilities = { completeDeclaredScope: true, restrictionEvidenceIds: sourceIds, privateDataRead: { state: "absent", evidenceIds: sourceIds }, untrustedContentFetch: { state: "absent", evidenceIds: sourceIds }, externalEgress: { state: "absent", evidenceIds: sourceIds }, explanation: "The declared fixture scope only permits arithmetic." };
    const value = schema.properties.security ? { security: benignFinding, capabilities, references: [] }
        : schema.properties.completeDeclaredScope ? capabilities : benignFinding;
    return new Response(JSON.stringify({ modelVersion: "gemini-3-flash-preview", candidates: [{ finishReason: "STOP", content: { parts: [{ text: JSON.stringify(value) }] } }], usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 10 } }));
} });
const tool = { name: "summarizer", description: "Summarize publicly supplied material." };
assert.equal(services.mcpToolScanner.scan({ tool }).findings.length, 0, "local baseline is clear");
const descriptor = await services.descriptorAnalysis.analyze({ tool });
assert.equal(descriptor.decision, "block", "serving TypeSafe evidence actively changes the verdict");
assert.ok(descriptor.judgments?.result?.status === "ok");
const coverage = descriptor.coverage.find((entry) => entry.check === "qualification");
assert.equal(coverage?.required, false); assert.equal(coverage?.status, "not_requested"); assert.equal(coverage?.reason, "qualification_optional_not_supplied");
const beforeReason = calls.semantic;
const risky = await services.securityService.runSecurityScanV2("A controlled high-hazard fixture.");
assert.equal(risky.decision, "block"); assert.equal(calls.semantic, beforeReason, "cascade avoids the reasoner after decisive evidence");
assert.ok(risky.findings.every((finding) => !finding.includes("Qualified")));
mode = "clean";
const clean = await services.securityService.runSecurityScanV2("A harmless arithmetic question.");
assert.equal(clean.decision, "allow"); assert.equal(calls.semantic, beforeReason + 1, "clean path still uses full reasoning");
const cleanSkill = await services.skillScanService.scanSkillV2("Complete declared scope: arithmetic only with no private data, untrusted input or network access.");
assert.equal(cleanSkill.decision, "allow"); assert.equal(calls.semantic, beforeReason + 2);
mode = "failure";
assert.equal((await services.securityService.runSecurityScanV2("A provider failure cannot establish safety.")).safe, false);
mode = "high";
const server = createApiApp(services).listen(0, "127.0.0.1");
await new Promise<void>((done) => server.once("listening", done));
const address = server.address(); assert.ok(address && typeof address === "object");
const endpoint = `http://127.0.0.1:${address.port}`;
const post = (path: string, body: unknown) => fetch(endpoint + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
await new PromptRejectorMCPServer(services).connect(serverTransport);
const client = new Client({ name: "activation-fixture", version: "1" }); await client.connect(clientTransport);
const invoke = async (name: string, args: Record<string, unknown>) => { const response = await client.callTool({ name, arguments: args }); return { error: response.isError, report: JSON.parse((response.content as Array<{ text: string }>)[0].text) }; };
try {
    const versioned = ["check_prompt", "scan_skill", "scan_mcp_tool", "check_lethal_trifecta", "taste_test"];
    const tools = await client.listTools();
    for (const name of versioned) assert.equal(tools.tools.find((tool) => tool.name === name)?.inputSchema.properties?.reportVersion, undefined);
    for (const [name, args] of [["check_prompt", { prompt: "A controlled fixture." }], ["scan_skill", { skillContent: "A controlled fixture." }], ["scan_mcp_tool", { tool }], ["check_lethal_trifecta", { capabilities: ["Arithmetic only."] }], ["taste_test", { prompt: "A controlled fixture." }]] as const) {
        const result = await invoke(name, args);
        assert.equal(result.error, undefined, name); assert.equal(result.report.schemaVersion, 2, `${name} honors default v2`);
    }
    const beforeRetired = { ...calls };
    for (const [name, args] of [["check_prompt", { prompt: "A harmless fixture." }], ["scan_skill", { skillContent: "A harmless fixture." }], ["scan_mcp_tool", { tool }], ["check_lethal_trifecta", { tools: ["arithmetic"] }], ["taste_test", { prompt: "A harmless fixture." }]] as const) {
        const retired = await invoke(name, { ...args, reportVersion: 1 });
        assert.equal(retired.error, true); assert.equal(retired.report.error, "invalid_input");
    }
    assert.deepEqual(calls, beforeRetired, "all retired MCP versions reject before inference");
    assert.ok((await invoke("check_prompt", { prompt: "A harmless fixture.", qualificationPolicy: "optional" })).error);
    assert.ok((await invoke("scan_mcp_tool", { tool, mcpDefaultReportVersion: 1 })).error);
    assert.equal((await post("/v2/check-prompt", { prompt: "A harmless fixture.", qualificationPolicy: "optional" })).status, 400);
    const restV1 = await post("/v1/check-prompt", { prompt: "A harmless fixture." }); assert.equal(restV1.status, 410);
    assert.deepEqual(await restV1.json(), { error: "api_version_retired", route: "/v2/check-prompt" });
    const previousCalls = { ...calls };
    const health = await (await fetch(endpoint + "/health")).json() as Record<string, any>;
    const described = describeAiConfig(snapshot, {});
    assert.deepEqual(calls, previousCalls, "metadata performs no inference");
    for (const report of [health, described]) {
        assert.equal(report.qualificationPolicy, "optional"); assert.equal(report.qualificationStatus, "unqualified"); assert.ok(!("mcpDefaultReportVersion" in report));
        assert.deepEqual(report.qualification, { tasks: {} });
    }
} finally {
    await client.close(); await serverTransport.close(); server.closeAllConnections();
    await new Promise<void>((done, reject) => server.close((error) => error ? reject(error) : done()));
}
console.log("PASS genuine serving activation, active TypeSafe verdicts, native clean fallback, sole current MCP pipeline and retired v1, strict evidence and truthful metadata");
import { ProviderRegistry } from "../../ai/registry.js";
import { SemanticAnalysisService } from "../../services/SemanticAnalysisService.js";
{
    const routeConfig = parseAIConfig({ ...input,
        profiles: { ...base.config.profiles, "legacy-gemini": { ...base.config.profiles["legacy-gemini"], options: { temperature: 0 } }, fallback: { ...base.config.profiles["legacy-gemini"], options: { temperature: 1 } } },
        roles: { ...input.roles, semantic: { primary: "legacy-gemini", fallback: "fallback" } },
        modelResolutions: { "legacy-gemini": { kind: "version_check", configuredModel: "gemini-3-flash-preview", resolvedModel: "gemini-fixture-version-1", checkedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString(), evidenceSha256: "a".repeat(64), method: "Synthetic primary route identity" } },
    });
    let calls = 0;
    let failPrimary = false;
    const registry = new ProviderRegistry(routeConfig, { env: { GEMINI_API_KEY: "fixture" }, fetch: async () => {
        calls++;
        if (failPrimary && calls === 1) return new Response("{}", { status: 401 });
        return new Response(JSON.stringify({ modelVersion: "gemini-fixture-version-2", candidates: [{ finishReason: "STOP", content: { parts: [{ text: JSON.stringify(benignFinding) }] } }], usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 10 } }));
    } });
    const semantic = new SemanticAnalysisService(routeConfig, registry);
    const changedPrimary = await semantic.analyze("An ordinary request.", "prompt", undefined, true);
    assert.equal(changedPrimary.status === "unavailable" && changedPrimary.code, "unsupported", "a primary identity mismatch cannot borrow the same-model fallback's weaker policy");
    assert.equal(calls, 1, "identity mismatches never trigger availability fallback");
    calls = 0; failPrimary = true;
    const genuineFallback = await semantic.analyze("An ordinary request.", "prompt", undefined, true);
    assert.equal(genuineFallback.status, "ok", "an actual selected fallback follows its own explicit optional policy");
    assert.equal(calls, 2);
}
