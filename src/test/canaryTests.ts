import dotenv from "dotenv";
dotenv.config();

import { CanaryService } from "../services/CanaryService.js";
import { existsSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string) {
    if (condition) {
        console.log(`  PASS: ${message}`);
        passed++;
    } else {
        console.error(`  FAIL: ${message}`);
        failed++;
    }
}

function uniquePath(label: string): string {
    return join(tmpdir(), `canary-${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.json`);
}

function sleep(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
}

async function runTests() {
    console.log("\n=== CanaryService Tests (Pass 10) ===\n");

    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const HANDLE_RE = /^[0-9a-f]{12}$/;

    // Test 1: Issue + echo positive
    console.log("Test 1: Issue + echo positive");
    {
        const sp = uniquePath("t1");
        const svc = new CanaryService({ statePath: sp, hmacSecret: "test-secret" });
        const issued = svc.issueToken({ context: "rag-doc-42" });
        const result = svc.checkEcho(`Model echoed: ${issued.token} verbatim.`);
        assert(result.echoDetected === true, "echoDetected is true");
        assert(result.severity === "critical", "severity is 'critical'");
        assert(result.matches.length === 1, "matches has one entry");
        assert(result.matches[0].token === issued.token, "matched token equals issued token");
        assert(result.matches[0].context === "rag-doc-42", "match preserves context");
        rmSync(sp, { force: true });
    }

    // Test 2: Benign content
    console.log("Test 2: Benign content");
    {
        const sp = uniquePath("t2");
        const svc = new CanaryService({ statePath: sp, hmacSecret: "test-secret" });
        svc.issueToken();
        const result = svc.checkEcho("nothing to see here, just a normal response");
        assert(result.echoDetected === false, "echoDetected is false on benign");
        assert(result.severity === "safe", "severity is 'safe' on benign");
        assert(result.matches.length === 0, "matches is empty on benign");
        rmSync(sp, { force: true });
    }

    // Test 3: TTL expiry — ttlSeconds:0 expires immediately
    console.log("Test 3: TTL expiry");
    {
        const sp = uniquePath("t3");
        const svc = new CanaryService({ statePath: sp, hmacSecret: "test-secret" });
        const issued = svc.issueToken({ ttlSeconds: 0 });
        await sleep(50);
        const result = svc.checkEcho(`expired token here: ${issued.token}`);
        assert(result.echoDetected === false, "expired token does not match");
        assert(result.matches.length === 0, "expired token produces no matches");
        rmSync(sp, { force: true });
    }

    // Test 4: Watch handle scoping
    console.log("Test 4: Watch handle scoping");
    {
        const sp = uniquePath("t4");
        const svc = new CanaryService({ statePath: sp, hmacSecret: "test-secret" });
        const tokenA = svc.issueToken({ context: "A" });
        const tokenB = svc.issueToken({ context: "B" });
        // Content contains token A; restrict scan to handle B → no match.
        const result = svc.checkEcho(`A appears: ${tokenA.token}`, tokenB.watchHandle);
        assert(result.echoDetected === false, "handle B excludes token A even when present");
        assert(result.matches.length === 0, "no matches when handle filter mismatches");
        // Sanity: scanning with handle A finds it.
        const positive = svc.checkEcho(`A appears: ${tokenA.token}`, tokenA.watchHandle);
        assert(positive.echoDetected === true, "handle A finds token A");
        rmSync(sp, { force: true });
    }

    // Test 5: HMAC tamper detection
    // Implementation choice: constructor throws when an existing state file has
    // a bad HMAC. verifyStateIntegrity() can also be called pre-construction
    // (by writing a service against the file first via a dummy instance).
    console.log("Test 5: HMAC tamper detection");
    {
        const sp = uniquePath("t5");
        const svc = new CanaryService({ statePath: sp, hmacSecret: "tamper-secret" });
        svc.issueToken();
        // Mutate the hmac field on disk.
        const raw = readFileSync(sp, "utf-8");
        const parsed = JSON.parse(raw);
        parsed.hmac = "deadbeef".repeat(8); // 64 hex chars but wrong
        writeFileSync(sp, JSON.stringify(parsed, null, 2));

        let threw = false;
        let err: Error | null = null;
        try {
            // New instance against tampered file should refuse to load.
            new CanaryService({ statePath: sp, hmacSecret: "tamper-secret" });
        } catch (e) {
            threw = true;
            err = e as Error;
        }
        assert(threw, "constructor throws on tampered HMAC");
        assert(err !== null && /tampered|mismatch/i.test(err.message), "error message mentions tamper/mismatch");
        rmSync(sp, { force: true });
    }

    // Test 6: No-secret-mode works (warning only)
    console.log("Test 6: No-secret-mode");
    {
        // Clear secrets in env for this scope.
        const prevCanary = process.env.CANARY_HMAC_SECRET;
        const prevPattern = process.env.PATTERN_INTEGRITY_SECRET;
        delete process.env.CANARY_HMAC_SECRET;
        delete process.env.PATTERN_INTEGRITY_SECRET;

        const sp = uniquePath("t6");
        const svc = new CanaryService({ statePath: sp });
        const issued = svc.issueToken();
        const result = svc.checkEcho(`echoed: ${issued.token}`);
        assert(result.echoDetected === true, "no-secret mode still detects echoes");
        const integrity = svc.verifyStateIntegrity();
        assert(integrity.valid === true, "verifyStateIntegrity is valid in no-secret mode");
        assert(integrity.reason === "hmac not configured", "reason is 'hmac not configured'");

        // Restore env.
        if (prevCanary !== undefined) process.env.CANARY_HMAC_SECRET = prevCanary;
        if (prevPattern !== undefined) process.env.PATTERN_INTEGRITY_SECRET = prevPattern;
        rmSync(sp, { force: true });
    }

    // Test 7: revoke
    console.log("Test 7: revoke");
    {
        const sp = uniquePath("t7");
        const svc = new CanaryService({ statePath: sp, hmacSecret: "rev-secret" });
        const issued = svc.issueToken();
        const ok = svc.revoke(issued.watchHandle);
        assert(ok === true, "revoke returns true for known handle");
        const result = svc.checkEcho(`revoked token: ${issued.token}`);
        assert(result.echoDetected === false, "revoked token does not match");
        const notFound = svc.revoke("000000000000");
        assert(notFound === false, "revoke returns false for unknown handle");
        rmSync(sp, { force: true });
    }

    // Test 8: Multiple tokens, single content
    console.log("Test 8: Multiple tokens, single content");
    {
        const sp = uniquePath("t8");
        const svc = new CanaryService({ statePath: sp, hmacSecret: "multi-secret" });
        const t1 = svc.issueToken({ context: "doc1" });
        const t2 = svc.issueToken({ context: "doc2" });
        svc.issueToken({ context: "doc3" }); // not in content
        const content = `combined: ${t1.token} and also ${t2.token}`;
        const result = svc.checkEcho(content);
        assert(result.echoDetected === true, "echoDetected true for multi-match");
        assert(result.matches.length === 2, "two matches detected");
        const matchedContexts = result.matches.map((m) => m.context).sort();
        assert(JSON.stringify(matchedContexts) === JSON.stringify(["doc1", "doc2"]), "matched contexts are doc1+doc2");
        rmSync(sp, { force: true });
    }

    // Test 9: Persistence across instances
    console.log("Test 9: Persistence across instances");
    {
        const sp = uniquePath("t9");
        const svcA = new CanaryService({ statePath: sp, hmacSecret: "persist-secret" });
        const issued = svcA.issueToken({ context: "rag" });
        const svcB = new CanaryService({ statePath: sp, hmacSecret: "persist-secret" });
        const list = svcB.list();
        assert(list.length === 1, "new instance reads persisted token");
        assert(list[0].token === issued.token, "persisted token round-trips");
        // And checkEcho on instance B still works
        const echo = svcB.checkEcho(`hi ${issued.token} bye`);
        assert(echo.echoDetected === true, "instance B detects echo from instance A's token");
        rmSync(sp, { force: true });
    }

    // Test 10: Token + handle format
    console.log("Test 10: Token + handle format");
    {
        const sp = uniquePath("t10");
        const svc = new CanaryService({ statePath: sp, hmacSecret: "fmt-secret" });
        const issued = svc.issueToken();
        assert(UUID_RE.test(issued.token), "token matches UUIDv4 shape");
        assert(HANDLE_RE.test(issued.watchHandle), "watchHandle is 12 hex chars");
        rmSync(sp, { force: true });
    }

    console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
    process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((err) => {
    console.error("Test runner error:", err);
    // Best-effort: ensure leftover state files in tmpdir get cleaned up next time.
    if (existsSync("/tmp")) {
        // no-op — files are uniquely named per run
    }
    process.exit(1);
});
