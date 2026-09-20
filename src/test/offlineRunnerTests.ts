import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { offlineEnvironment, runSuite } from "../scripts/runOfflineTests.js";

const guard = resolve(dirname(fileURLToPath(import.meta.url)), "../scripts/offlineNetworkGuard.cjs");
const temporary = mkdtempSync(join(tmpdir(), "offline-guard-test-"));
let count = 0;

function guarded(code: string, allowLoopback = false) {
    const violations = join(temporary, `violations-${count++}.jsonl`);
    const child = spawnSync(process.execPath, ["--require", guard, "--input-type=module", "--eval", code], {
        cwd: temporary,
        env: { OFFLINE_NETWORK_LOG: violations, OFFLINE_ALLOW_LOOPBACK: allowLoopback ? "1" : "0" },
        encoding: "utf8",
        timeout: 10_000,
    });
    assert.equal(child.status, 0, child.stderr || child.error?.message);
    const recorded = existsSync(violations) ? readFileSync(violations, "utf8").trim().split("\n") : [];
    return recorded;
}

try {
    // An unmarked loopback request must be recorded even if a test swallows it
    // and calls process.exit(0). This RED case cannot contact an external host.
    assert.equal(guarded("try { await fetch('http://127.0.0.1:1'); } catch {} process.exit(0);").length, 1);
    console.log("PASS: caught forbidden fetch is recorded independently of child exit code");
    for (const code of [
        "try { await fetch('https://offline.invalid/private'); } catch {}",
        "import net from 'node:net'; try { net.connect(443, 'offline.invalid'); } catch {}",
        "import tls from 'node:tls'; try { tls.connect(443, 'offline.invalid'); } catch {}",
        "import http from 'node:http'; try { http.get('http://offline.invalid'); } catch {}",
        "import https from 'node:https'; try { https.get('https://offline.invalid'); } catch {}",
        "import { connect } from 'node:net'; try { connect({ port: 443, host: 'offline.invalid' }); } catch {}",
        "import net from 'node:net'; try { net.createServer().listen(0, '127.0.0.1'); } catch {}",
        "import dgram from 'node:dgram'; const s = dgram.createSocket('udp4'); try { s.send('test', 9, 'offline.invalid'); } catch {} s.close();",
    ]) {
        assert.equal(guarded(code + "; process.exit(0);").length, 1, code);
    }
    console.log("PASS: fetch, sockets, TLS, HTTP(S), named imports, listeners and datagrams are blocked");
    assert.equal(guarded("try { await fetch('https://offline.invalid'); } catch {}", true).length, 1);
    assert.equal(guarded("import net from 'node:net'; try { net.createServer().listen(0, '0.0.0.0'); } catch {}", true).length, 1);
    assert.equal(guarded(`
        import http from 'node:http';
        const server = http.createServer((_, response) => response.end('fixture'));
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        const response = await fetch('http://127.0.0.1:' + server.address().port);
        if (await response.text() !== 'fixture') throw new Error('Wrong local fixture');
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
    `, true).length, 0);
    console.log("PASS: explicitly marked loopback HTTP works while external traffic and wildcard binds remain blocked");
    assert.equal(guarded("globalThis.fetch = async () => new Response('mock'); await fetch('https://offline.invalid');").length, 0);
    console.log("PASS: existing in-memory fetch mocks remain usable");

    const environment = offlineEnvironment({
        PATH: "/fixture/bin", OPENAI_API_KEY: "dummy", GEMINI_API_KEY: "dummy", TYPESAFE_API_KEY: "dummy",
        ANTHROPIC_API_KEY: "dummy", UNKNOWN_PROVIDER_SECRET: "dummy", NODE_OPTIONS: "--inspect",
        DOTENV_CONFIG_PATH: "/secret/.env", HOME: "/secret/home", TMPDIR: "/host/tmp", TEMP: "/host/tmp", TMP: "/host/tmp",
    }, temporary);
    assert.equal(environment.HOME, temporary);
    assert.equal(environment.PATH, "/fixture/bin");
    for (const name of ["TMPDIR", "TEMP", "TMP"]) assert.equal(environment[name], temporary, name);
    for (const name of ["OPENAI_API_KEY", "GEMINI_API_KEY", "TYPESAFE_API_KEY", "ANTHROPIC_API_KEY", "UNKNOWN_PROVIDER_SECRET", "NODE_OPTIONS", "DOTENV_CONFIG_PATH"]) {
        assert.equal(environment[name], undefined, name);
    }
    console.log("PASS: inherited credentials and environment-based preload/dotenv configuration are removed");

    mkdirSync(join(temporary, "dist/scripts"), { recursive: true });
    mkdirSync(join(temporary, "dist/test"), { recursive: true });
    cpSync(guard, join(temporary, "dist/scripts/offlineNetworkGuard.cjs"));
    writeFileSync(join(temporary, "dist/test/caught.js"), "fetch('https://offline.invalid').catch(() => process.exit(0));");
    const result = runSuite(temporary, { file: "caught.js" });
    assert.equal(result.status, 0);
    assert.equal(result.violations.length, 1);
    assert.equal(result.passed, false);
    console.log("PASS: aggregate suite result fails despite a swallowed network error and successful process exit");

    writeFileSync(join(temporary, "dist/test/timeout.js"), `
        process.on('SIGTERM', () => {});
        console.log('SIGTERM handler installed');
        setTimeout(() => process.exit(0), 8000);
    `);
    const started = performance.now();
    // Include process/guard startup under a parallel Node matrix. The child
    // still outlives the deadline if the runner regresses to ordinary SIGTERM.
    const timedOut = runSuite(temporary, { file: "timeout.js" }, { timeoutMs: 2000 });
    assert.equal(timedOut.passed, false);
    assert.match(timedOut.error ?? "", /ETIMEDOUT/);
    assert.match(timedOut.output, /SIGTERM handler installed/);
    assert.ok(performance.now() - started < 4000, "SIGTERM-resistant child must not extend the deadline");
    console.log("PASS: suite timeout is bounded even when the child ignores SIGTERM");

    writeFileSync(join(temporary, "dist/test/tmp.cjs"), `
        const fs = require('node:fs');
        const os = require('node:os');
        const path = require('node:path');
        if (fs.realpathSync(os.tmpdir()) !== process.cwd()) throw new Error('Temporary directory escaped suite');
        fs.writeFileSync(path.join(os.tmpdir(), 'owned-fixture.json'), '{}');
    `);
    assert.equal(runSuite(temporary, { file: "tmp.cjs" }).passed, true);
    assert.equal(existsSync(join(temporary, "owned-fixture.json")), true);
    console.log("PASS: os.tmpdir fixtures stay inside the suite directory");
} finally {
    rmSync(temporary, { recursive: true, force: true });
}
assert.equal(existsSync(temporary), false, "Suite directory and its os.tmpdir fixtures are removed");
