import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { Readable } from "node:stream";
import { MAX_INPUT_BYTES, readInput, readLines } from "../cli/input.js";

const root = process.cwd();
const launcher = resolve(root, "dist/cli/main.js");
const temporary = mkdtempSync(join(tmpdir(), "prompt rejector cli "));
const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, HOME: temporary };
// Subprocesses keep the offline guard: missing keys must never result in a request.
const guard = process.env.OFFLINE_NETWORK_LOG ? ["--require", resolve(root, "dist/scripts/offlineNetworkGuard.cjs")] : [];
const childEnv = { ...env, OFFLINE_NETWORK_LOG: process.env.OFFLINE_NETWORK_LOG, OFFLINE_ALLOW_LOOPBACK: "0" };
const run = (args: string[], input?: string, extraEnv = {}) => spawnSync(process.execPath, [...guard, launcher, ...args], { cwd: temporary, env: { ...childEnv, ...extraEnv }, input, encoding: "utf8", timeout: 15000, killSignal: "SIGKILL", maxBuffer: 10 * 1024 * 1024 });
try {
    const help = run(["--help", "--config", "missing.json"]);
    assert.equal(help.status, 0); assert.match(help.stdout, /Usage: prompt-rejector/); assert.equal(help.stderr, "");
    assert.equal(run(["--version"]).stdout.trim(), JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version);
    const commands = run(["commands"]);
    assert.equal(commands.status, 0); assert.equal(JSON.parse(commands.stdout).length, 12); assert.equal(commands.stderr, "");
    assert.equal(JSON.parse(commands.stdout).find((entry: any) => entry.command === "check-lethal-trifecta").inputSchema.minProperties, 1);
    assert.equal(JSON.parse(run(["check-lethal-trifecta", "--help"]).stdout).minProperties, 1);
    const schema = run(["check-prompt", "--help"]);
    assert.equal(JSON.parse(schema.stdout).properties.prompt.maxLength, 100000);
    const health = run(["health"]);
    assert.equal(health.status, 3); assert.equal(JSON.parse(health.stdout).typesafe.readiness, "degraded");
    const integrity = run(["verify_pattern_integrity"]);
    assert.equal(integrity.status, 0); assert.equal(JSON.parse(integrity.stdout).valid, true);
    const patterns = run(["list-patterns", "--input", '{"category":"xss"}', "--pretty"]);
    assert.equal(patterns.status, 0); assert.ok(JSON.parse(patterns.stdout).patterns.every((pattern: any) => pattern.category === "xss"));

    const prompt = "Summarize the weather.";
    writeFileSync(join(temporary, "prompt.txt"), prompt);
    for (const [args, input] of [
        [["check-prompt", "--text", prompt], undefined],
        [["check-prompt", "--file", "prompt.txt"], undefined],
        [["check-prompt", "--file", "-"], prompt],
        [["check-prompt"], prompt],
        [["check_prompt", "--input", JSON.stringify({ prompt })], undefined],
    ] as const) {
        const child = run([...args], input);
        assert.equal(child.status, 3, child.stderr);
        const report = JSON.parse(child.stdout);
        assert.equal(report.schemaVersion, 2); assert.equal(report.decision, "unavailable"); assert.equal(report.safe, false);
    }
    const attack = run(["check-prompt", "--text", "<script>alert('synthetic')</script>"]);
    assert.equal(attack.status, 1); assert.equal(JSON.parse(attack.stdout).decision, "block");
    const disabled = run(["taste-test", "--text", prompt]);
    assert.equal(disabled.status, 3); assert.equal(JSON.parse(disabled.stdout).available, false);

    const secret = "synthetic-test-secret-never-print";
    writeFileSync(join(temporary, "private.env"), `TYPESAFE_API_KEY=${secret}\nGEMINI_API_KEY=${secret}\nSTART_MODE=both\n`);
    const configured = run(["health", "--env", "private.env"]);
    assert.equal(configured.status, 0, configured.stderr);
    assert.equal(JSON.parse(configured.stdout).typesafe.readiness, "ready");
    assert.ok(!`${configured.stdout}${configured.stderr}`.includes(secret));
    const inherited = run(["health", "--env", "private.env"], undefined, { GEMINI_API_KEY: "" });
    assert.equal(inherited.status, 3, "existing environment takes precedence over dotenv");
    writeFileSync(join(temporary, "bad.json"), `{${secret}`);
    const badConfig = run(["health", "--config", "bad.json"]);
    assert.equal(badConfig.status, 3); assert.equal(badConfig.stdout, ""); assert.ok(!badConfig.stderr.includes(secret));
    const active = JSON.parse(readFileSync(join(root, "config/ai.active.json"), "utf8"));
    active.capabilitiesFile = join(root, "config/model-capabilities.json");
    active.pricingFile = join(root, "config/ai-pricing.example.json");
    writeFileSync(join(temporary, "config.json"), JSON.stringify(active));
    const explicit = run(["health", "--config", "config.json"]);
    assert.equal(explicit.status, 3);
    assert.deepEqual(JSON.parse(explicit.stdout).typesafe, JSON.parse(health.stdout).typesafe);
    assert.match(JSON.parse(explicit.stdout).configHash, /^[a-f0-9]{64}$/);

    for (const args of [
        ["missing"], ["constructor"], ["health", "--bad"], ["health", "extra"], ["health", "--config"],
        ["check-prompt", "--input", "bad-json"], ["check-prompt", "--input", '{"prompt":1}'],
        ["check-prompt", "--text", "a", "--file", "prompt.txt"], ["check-prompt", "--text", "a", "--text", "b"],
        ["health", "--text", "unexpected"], ["health", "--timeout-ms", "0"],
        ["health", "--env", ""], ["health", "--config", ""], ["health", "--file", ""],
        ["batch", "--pretty"], ["check-lethal-trifecta", "--input", "{}"],
    ]) {
        const child = run(args);
        assert.equal(child.status, 2, args.join(" ") + child.stderr); assert.equal(child.stdout, ""); assert.ok(JSON.parse(child.stderr).error);
    }
    for (const args of [["health", "--env", "missing.env"], ["check-prompt", "--file", "missing.txt"]]) {
        const child = run(args); assert.equal(child.status, 3); assert.equal(child.stdout, "");
    }
    assert.equal(run(["check-prompt"], "x".repeat(100001)).status, 2);
    assert.equal(run(["check-prompt"], "x".repeat(MAX_INPUT_BYTES + 1)).status, 2);
    assert.equal(run(["batch"], "").status, 2);
    const batchInput = [
        JSON.stringify({ id: "first", command: "verify_pattern_integrity" }),
        "bad-json",
        JSON.stringify({ id: 2, command: "check-prompt", input: { prompt } }),
        JSON.stringify({ id: "null", command: "health", input: null }),
        JSON.stringify({ id: "last", command: "query-cve", input: { limit: 1 } }),
    ].join("\r\n");
    writeFileSync(join(temporary, "batch.jsonl"), batchInput);
    for (const [args, input] of [[["batch"], batchInput], [["batch", "--file", "batch.jsonl"], undefined]] as const) {
        const batch = run([...args], input);
        assert.equal(batch.status, 3, batch.stderr);
        const rows = batch.stdout.trim().split("\n").map(text => JSON.parse(text));
        assert.deepEqual(rows.map(row => row.exitCode), [0, 2, 3, 2, 0]);
        assert.deepEqual(rows.map(row => row.line), [1, 2, 3, 4, 5]);
        assert.equal(rows[0].id, "first"); assert.equal(rows[1].error, "invalid_json"); assert.equal(rows[4].id, "last");
    }
    // Verify an output is delivered before stdin closes: this is a stream, not a buffered batch.
    const stream = spawn(process.execPath, [...guard, launcher, "batch"], { cwd: temporary, env: childEnv, stdio: ["pipe", "pipe", "pipe"] });
    stream.stderr.resume();
    try {
        const first = new Promise<string>((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error("stream did not flush")), 5000);
            stream.stdout.once("data", chunk => { clearTimeout(timer); resolve(chunk.toString()); });
        });
        stream.stdin.write('{"command":"verify-pattern-integrity"}\n');
        assert.equal(JSON.parse(await first).exitCode, 0);
    } finally { stream.stdin.end(); }
    assert.equal(await new Promise(resolve => stream.once("close", resolve)), 0);

    // Waiting for stdin is included in the explicit outer deadline.
    const timed = spawn(process.execPath, [...guard, launcher, "check-prompt", "--timeout-ms", "25"], { cwd: temporary, env: childEnv, stdio: ["pipe", "pipe", "pipe"] });
    let timedError = ""; timed.stderr.on("data", chunk => timedError += chunk); timed.stdout.resume();
    assert.equal(await new Promise(resolve => timed.once("close", resolve)), 124);
    assert.equal(JSON.parse(timedError).error, "timeout");

    const interrupted = spawn(process.execPath, [...guard, launcher, "batch"], { cwd: temporary, env: childEnv, stdio: ["pipe", "pipe", "pipe"] });
    let interruptedError = ""; interrupted.stderr.on("data", chunk => interruptedError += chunk);
    const firstInterruptResult = new Promise<void>(resolve => interrupted.stdout.once("data", () => resolve()));
    interrupted.stdin.write('{"command":"verify-pattern-integrity"}\n');
    await firstInterruptResult;
    const closed = new Promise(resolve => interrupted.once("close", resolve));
    interrupted.kill("SIGINT");
    assert.equal(await closed, 130); assert.match(interruptedError, /"error":"cancelled"/);

    const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    assert.equal(manifest.bin["prompt-rejector"], "dist/cli/main.js");
    assert.ok(readFileSync(launcher, "utf8").startsWith("#!/usr/bin/env node"));
    // Import the published package entry from a foreign cwd; no listeners, chdir, env loading or output.
    const imported = spawnSync(process.execPath, [...guard, "--input-type=module", "-e", `const cwd=process.cwd(); const env=JSON.stringify(process.env); const log=console.log; const signals=process.listenerCount('SIGINT'); const sdk=await import(${JSON.stringify(join(root, manifest.main))}); if(typeof sdk.createPromptRejector!=='function'||cwd!==process.cwd()||env!==JSON.stringify(process.env)||log!==console.log||signals!==process.listenerCount('SIGINT'))process.exit(1);`], { cwd: temporary, env: childEnv, encoding: "utf8", timeout: 10000 });
    assert.equal(imported.status, 0, imported.stderr); assert.equal(imported.stdout, ""); assert.equal(imported.stderr, "");

    const encoded = Buffer.from('é🙂\r\n{"command":"health"}');
    const lines: string[] = [];
    for await (const line of readLines(Readable.from([...encoded].map(byte => Buffer.from([byte]))))) lines.push(line);
    assert.deepEqual(lines, ["é🙂", '{"command":"health"}']);
    await assert.rejects(() => readInput(Readable.from([Buffer.alloc(MAX_INPUT_BYTES + 1)])), /input_too_large/);
    await assert.rejects(async () => { for await (const _ of readLines(Readable.from([Buffer.alloc(MAX_INPUT_BYTES + 1)]))) { /* consume */ } }, /input_too_large/);
} finally { rmSync(temporary, { recursive: true, force: true }); }
console.log("PASS CLI subprocesses, arbitrary cwd, JSON/JSONL streaming, failures, bounds, deadlines and secret redaction");
