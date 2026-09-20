import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const launcher = resolve(root, "dist/scripts/startMcp.js");
const temporary = mkdtempSync(join(tmpdir(), "mcp-launcher-"));
const secret = "synthetic-launcher-secret-never-print";
const initialize = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "launcher-test", version: "1" } } };
const list = { jsonrpc: "2.0", id: 2, method: "tools/list" };
try {
    const envFile = join(temporary, "private.env");
    // A caller's START_MODE must not make the stdio launcher open an API port.
    writeFileSync(envFile, `START_MODE=invalid-for-stdio\nTYPESAFE_API_KEY=${secret}\n`);
    const run = (args: string[]) => spawnSync(process.execPath, [launcher, ...args], {
        cwd: temporary, env: { PATH: process.env.PATH, HOME: temporary }, encoding: "utf8", timeout: 15000, killSignal: "SIGKILL",
        input: `${JSON.stringify(initialize)}\n${JSON.stringify(list)}\n`,
    });
    const child = run(["--env-file", envFile]);
    assert.equal(child.status, 0, child.stderr);
    const messages = child.stdout.trim().split("\n").map(line => JSON.parse(line));
    assert.ok(messages.find(message => message.id === 1)?.result.serverInfo.version);
    const tools = messages.find(message => message.id === 2)?.result.tools;
    assert.equal(tools.length, 11);
    for (const name of ["check_prompt", "scan_skill", "scan_mcp_tool", "check_lethal_trifecta", "taste_test"])
        assert.equal(tools.find((tool: any) => tool.name === name).inputSchema.properties.reportVersion.default, 2);
    assert.ok(!`${child.stdout}${child.stderr}`.includes(secret));

    const explicit = JSON.parse(readFileSync(join(root, "config/ai.active.json"), "utf8"));
    explicit.mcpDefaultReportVersion = 1;
    explicit.capabilitiesFile = join(root, "config/model-capabilities.json");
    explicit.pricingFile = join(root, "config/ai-pricing.example.json");
    const configFile = join(temporary, "explicit.json");
    writeFileSync(configFile, JSON.stringify(explicit));
    const selected = run(["--env-file", envFile, "--config", configFile]);
    assert.equal(selected.status, 0, selected.stderr);
    const selectedList = selected.stdout.trim().split("\n").map(line => JSON.parse(line)).find(message => message.id === 2).result;
    assert.equal(selectedList.tools.find((tool: any) => tool.name === "check_prompt").inputSchema.properties.reportVersion.default, 1);
    for (const args of [["--env-file", join(temporary, "missing.env")], ["--unexpected"], ["--config"]]) {
        const invalid = run(args);
        assert.notEqual(invalid.status, 0);
        assert.equal(invalid.stdout, "");
        assert.ok(!invalid.stderr.includes(secret));
    }
} finally { rmSync(temporary, { recursive: true, force: true }); }
console.log("PASS active stdio launcher, explicit configuration, arbitrary cwd and credential-free stdout");
