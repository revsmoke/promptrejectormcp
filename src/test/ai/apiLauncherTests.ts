import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { request } from "node:https";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const launcher = resolve("dist/scripts/startApi.js");
const temporary = mkdtempSync(join(tmpdir(), "api-launcher-"));
const secret = "synthetic-api-launcher-secret-never-print";
const envFile = join(temporary, "private.env");
writeFileSync(envFile, `START_MODE=mcp\nPORT=1\nTYPESAFE_API_KEY=${secret}\n`);
const cert = join(temporary, "certificate.pem"), key = join(temporary, "key.pem");
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], { stdio: "ignore" });
const env = { PATH: process.env.PATH, HOME: temporary };
const read = (url: string, body?: string) => new Promise<{ status: number; value: any }>((resolve, reject) => {
    const req = request(url, { ca: readFileSync(cert), method: body ? "POST" : "GET", headers: body ? { "content-type": "application/json" } : {} }, res => {
        let text = ""; res.setEncoding("utf8"); res.on("data", part => { text += part; });
        res.on("end", () => { try { resolve({ status: res.statusCode!, value: JSON.parse(text) }); } catch (error) { reject(error); } });
    });
    req.setTimeout(5000, () => req.destroy(new Error("HTTPS test timed out"))); req.on("error", reject); req.end(body);
});
const reservation = createServer().listen(0, "127.0.0.1");
await once(reservation, "listening");
const address = reservation.address();
assert.ok(address && typeof address === "object");
const port = address.port;
await new Promise<void>(resolve => reservation.close(() => resolve()));
const args = [launcher, "--env-file", envFile, "--port", String(port), "--tls-cert", cert, "--tls-key", key];
const child = spawn(process.execPath, args, { cwd: temporary, env, stdio: ["ignore", "pipe", "pipe"] });
let output = "";
child.stdout.on("data", value => { output += value; });
child.stderr.on("data", value => { output += value; });
try {
    const ready = new Promise<void>((resolve, reject) => {
        const deadline = setTimeout(() => reject(new Error("API startup timed out")), 15000);
        const inspect = () => { if (output.includes("[API] PromptRejector API running")) { clearTimeout(deadline); resolve(); } };
        child.stderr.on("data", inspect);
        child.once("exit", () => { clearTimeout(deadline); reject(new Error("API exited before readiness")); });
        inspect();
    });
    await ready;
    const base = `https://127.0.0.1:${port}`;
    const health = (await read(`${base}/health`)).value;
    assert.equal(health.status, "ok");
    assert.equal(health.typesafe.modes.prompt, "cascade");
    assert.equal(health.typesafe.configured, true);
    assert.ok(!JSON.stringify(health).includes(secret));
    const invalid = await read(`${base}/v2/check-prompt`, "{}");
    assert.equal(invalid.status, 400);
    const missingTls = spawnSync(process.execPath, args.slice(0, 5), { cwd: temporary, env, encoding: "utf8", timeout: 15000, killSignal: "SIGKILL" });
    assert.equal(missingTls.status, 1, "missing TLS must fail without falling back to HTTP");
    const occupied = spawnSync(process.execPath, args, { cwd: temporary, env, encoding: "utf8", timeout: 15000, killSignal: "SIGKILL" });
    assert.equal(occupied.status, 1, "occupied port must fail startup");
    assert.ok(!`${occupied.stdout}${occupied.stderr}`.includes(secret));
    for (const value of ["0", "65536", "3001oops"]) {
        const invalidPort = spawnSync(process.execPath, [launcher, "--env-file", envFile, "--port", value], { cwd: temporary, env, encoding: "utf8", timeout: 15000, killSignal: "SIGKILL" });
        assert.equal(invalidPort.status, 1);
        assert.ok(!`${invalidPort.stdout}${invalidPort.stderr}`.includes(secret));
    }
    assert.ok(!output.includes(secret));
} finally {
    if (child.exitCode === null) { const exited = once(child, "exit"); child.kill("SIGTERM"); await exited; }
    rmSync(temporary, { recursive: true, force: true });
}
console.log("PASS HTTPS launcher from arbitrary cwd, verified TLS, shared active config, explicit port, quiet secrets and startup failure");
