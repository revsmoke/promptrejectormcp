import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { loadAIConfig, parseAIConfig } from "../../ai/config.js";
import { createServices } from "../../bootstrap.js";
import { PromptRejectorMCPServer } from "../../mcp/mcpServer.js";

const config = loadAIConfig({ OPENAI_API_KEY: "unused", TYPESAFE_API_KEY: "unused" });
assert.equal(config.config.profiles[config.config.roles.semantic.primary].provider, "gemini", "keys do not auto-select providers");
assert.equal(config.config.typesafe.prompt, "off");
assert.doesNotThrow(() => loadAIConfig({ TASTE_TESTER_ENABLED: "false", TASTE_TESTER_MODEL: "custom-disabled-model" }), "disabled Taster profiles must not block semantic/local startup");
assert.ok(Object.isFrozen(config.config.roles.semantic));
assert.ok(Object.isFrozen(config.config.profiles));
assert.equal(parseAIConfig(JSON.parse(JSON.stringify(config.config))).hash, config.hash);
const reordered = { ...config.config, profiles: Object.fromEntries(Object.entries(config.config.profiles).reverse()) };
assert.equal(parseAIConfig(reordered).hash, config.hash, "key order does not change config identity");
assert.throws(() => parseAIConfig({ ...config.config, endpoint: "https://evil.invalid" }));
assert.throws(() => parseAIConfig({ ...config.config, roles: { ...config.config.roles, semantic: { primary: "missing" } } }));
assert.throws(() => parseAIConfig({ ...config.config, profiles: { ...config.config.profiles, "legacy-gemini": { ...config.config.profiles["legacy-gemini"], options: { apiKey: "bad" } } } }));
const services = createServices(config, { env: {}, fetch: async () => { throw new Error("construction must not call providers"); } });
assert.equal(services.securityService.semantic, services.skillScanService.semantic);
assert.equal(services.securityService.semantic, services.semantic);
assert.equal(new PromptRejectorMCPServer(services).services, services);
assert.equal((await services.securityService.runSecurityScanV2("A plain summary.")).decision, "unavailable");

// A child starts in a directory containing only a synthetic .env. Its successful
// MCP initialize and model selection demonstrate dotenv-before-construction.
const temporary = mkdtempSync(join(tmpdir(), "ai-bootstrap-"));
try {
    const index = resolve("dist/index.js");
    const configPath = join(temporary, "ai.json");
    const explicit = { ...config.config, profiles: { ...config.config.profiles, "openai-fixture": { provider: "openai", model: "gpt-6-astra", maxOutputTokens: 2048, options: { reasoning: { effort: "low" } } } }, roles: { ...config.config.roles, semantic: { primary: "openai-fixture" } } };
    writeFileSync(configPath, JSON.stringify(explicit));
    writeFileSync(join(temporary, ".env"), `START_MODE=mcp\nAI_CONFIG_PATH=${configPath}\n`);
    const child = spawnSync(process.execPath, [index], { cwd: temporary, env: { PATH: process.env.PATH, HOME: temporary }, encoding: "utf8", timeout: 10000, killSignal: "SIGKILL",
        input: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "offline", version: "1" } } }) + "\n" +
            JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "check_prompt", arguments: { prompt: "hello" } } }) + "\n" });
    assert.equal(child.status, 0, child.stderr);
    const messages = child.stdout.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
    assert.ok(messages.some((message) => message.id === 1 && message.result.serverInfo.version), "stdout contains valid MCP initialization with real package version");
    const scan = messages.find((message) => message.id === 2);
    const report = JSON.parse(scan.result.content[0].text);
    assert.equal(report.schemaVersion, 2);
    assert.equal(report.semantic.meta.provider, "openai", ".env AI config was loaded before service construction");
    assert.equal(report.semantic.code, "not_configured");
    assert.ok(!child.stdout.includes("PromptRejector MCP server running"));
} finally { rmSync(temporary, { recursive: true, force: true }); }
console.log("PASS shared construction, immutable config, dotenv ordering and MCP stdout");
