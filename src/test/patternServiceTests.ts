import dotenv from "dotenv";
dotenv.config();

import { PatternService } from "../services/PatternService.js";
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, cpSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

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

// Create a temp directory with a copy of patterns for isolated testing
function createTestDir(): string {
    const dir = join(tmpdir(), `pattern-test-${Date.now()}`);
    mkdirSync(dir, { recursive: true });

    // Find project root patterns dir
    const projectPatterns = join(process.cwd(), "patterns");

    // Copy all pattern files
    const files = ["xss.json", "sqli.json", "shell-injection.json", "skill-threats.json", "prompt-injection.json", "custom.json"];
    for (const f of files) {
        const src = join(projectPatterns, f);
        if (existsSync(src)) {
            cpSync(src, join(dir, f));
        }
    }

    return dir;
}

function cleanup(dir: string) {
    rmSync(dir, { recursive: true, force: true });
}

async function runTests() {
    console.log("\n=== PatternService Tests ===\n");

    // Test 1: Initialize and load patterns from seed files
    console.log("Test 1: Initialize and load patterns");
    {
        const dir = createTestDir();
        const svc = new PatternService(dir);
        // Generate manifest for this test dir
        svc.regenerateManifest();
        // Reload with valid manifest
        const svc2 = new PatternService(dir);
        const all = svc2.list();
        assert(all.length === 39, `Expected 39 patterns, got ${all.length}`);
        assert(!svc2.isFallbackActive(), "Should not be using fallback patterns");
        cleanup(dir);
    }

    // Test 2: list() filters by category
    console.log("Test 2: list() filters by category");
    {
        const dir = createTestDir();
        const svc = new PatternService(dir);
        svc.regenerateManifest();
        const svc2 = new PatternService(dir);
        const xssPatterns = svc2.list({ category: "xss" });
        assert(xssPatterns.length === 5, `Expected 5 XSS patterns, got ${xssPatterns.length}`);
        const sqliPatterns = svc2.list({ category: "sqli" });
        assert(sqliPatterns.length === 5, `Expected 5 SQLi patterns, got ${sqliPatterns.length}`);
        cleanup(dir);
    }

    // Test 3: list() filters by scope
    console.log("Test 3: list() filters by scope");
    {
        const dir = createTestDir();
        const svc = new PatternService(dir);
        svc.regenerateManifest();
        const svc2 = new PatternService(dir);
        const general = svc2.list({ scope: "general" });
        assert(general.length === 13, `Expected 13 general patterns, got ${general.length}`);
        const skill = svc2.list({ scope: "skill" });
        assert(skill.length === 26, `Expected 26 skill patterns, got ${skill.length}`);
        cleanup(dir);
    }

    // Test 4: get() returns pattern by ID
    console.log("Test 4: get() returns pattern by ID");
    {
        const dir = createTestDir();
        const svc = new PatternService(dir);
        svc.regenerateManifest();
        const svc2 = new PatternService(dir);
        const p = svc2.get("xss-script-tag");
        assert(p !== undefined, "Pattern 'xss-script-tag' should exist");
        assert(p?.category === "xss", `Category should be 'xss', got '${p?.category}'`);
        const missing = svc2.get("nonexistent");
        assert(missing === undefined, "Nonexistent pattern should return undefined");
        cleanup(dir);
    }

    // Test 5: add() creates pattern and updates manifest
    console.log("Test 5: add() creates pattern and updates manifest");
    {
        const dir = createTestDir();
        const svc = new PatternService(dir);
        svc.regenerateManifest();
        const svc2 = new PatternService(dir);
        const entry = svc2.add({
            id: "test-new-pattern",
            name: "Test Pattern",
            pattern: "test\\d+",
            flags: "gi",
            severity: "medium",
            category: "xss",
            flagGroup: "hasXSS",
            scope: "general",
            detection: { mode: "simple" },
            enabled: true,
            source: "manual",
            cveRefs: [],
            dateAdded: "2025-01-01",
            whitelistedDomains: [],
        });
        assert(entry.id === "test-new-pattern", "Added pattern should have correct ID");

        // Verify it's in the list
        const all = svc2.list();
        assert(all.length === 40, `Expected 40 patterns after add, got ${all.length}`);

        // Verify manifest was updated
        const integrity = svc2.verify();
        assert(integrity.valid, "Manifest should be valid after add");
        cleanup(dir);
    }

    // Test 6: disable() soft-deletes (sets enabled: false)
    console.log("Test 6: disable() soft-deletes");
    {
        const dir = createTestDir();
        const svc = new PatternService(dir);
        svc.regenerateManifest();
        const svc2 = new PatternService(dir);
        const removed = svc2.disable("xss-script-tag");
        assert(removed.enabled === false, "Removed pattern should have enabled=false");
        const p = svc2.get("xss-script-tag");
        assert(p?.enabled === false, "Pattern should still exist but be disabled");
        cleanup(dir);
    }

    // Test 7: import() skips duplicate IDs
    console.log("Test 7: import() skips duplicate IDs");
    {
        const dir = createTestDir();
        const svc = new PatternService(dir);
        svc.regenerateManifest();
        const svc2 = new PatternService(dir);
        const result = svc2.import([
            {
                id: "xss-script-tag", // duplicate
                name: "Duplicate",
                pattern: "dup",
                flags: "g",
                severity: "low",
                    category: "xss",
                flagGroup: "hasXSS",
                scope: "general",
                detection: { mode: "simple" },
                enabled: true,
                cveRefs: [],
                dateAdded: "2025-01-01",
                whitelistedDomains: [],
            },
            {
                id: "import-new",
                name: "New Import",
                pattern: "newimport\\d+",
                flags: "gi",
                severity: "low",
                    category: "xss",
                flagGroup: "hasXSS",
                scope: "general",
                detection: { mode: "simple" },
                enabled: true,
                cveRefs: [],
                dateAdded: "2025-01-01",
                whitelistedDomains: [],
            },
        ]);
        assert(result.imported.length === 1, `Expected 1 imported, got ${result.imported.length}`);
        assert(result.skipped.length === 1, `Expected 1 skipped, got ${result.skipped.length}`);
        assert(result.skipped[0] === "xss-script-tag", "Duplicate should be in skipped list");
        cleanup(dir);
    }

    // Test 8: verify() returns valid when untampered
    console.log("Test 8: verify() returns valid when untampered");
    {
        const dir = createTestDir();
        const svc = new PatternService(dir);
        svc.regenerateManifest();
        const svc2 = new PatternService(dir);
        const result = svc2.verify();
        assert(result.valid, "Integrity check should pass on untampered files");
        assert(result.errors.length === 0, `Expected 0 errors, got ${result.errors.length}`);
        cleanup(dir);
    }

    // Test 9: Tamper detection — modify a pattern file → verify() fails
    console.log("Test 9: Tamper detection");
    {
        const dir = createTestDir();
        const svc = new PatternService(dir);
        svc.regenerateManifest();

        // Tamper with xss.json
        const xssPath = join(dir, "xss.json");
        const original = readFileSync(xssPath, "utf-8");
        writeFileSync(xssPath, original + "\n/* tampered */", "utf-8");

        const svc2 = new PatternService(dir);
        // svc2 should load fallback due to tamper
        assert(svc2.isFallbackActive(), "Should use fallback after tampering");

        // Direct verify call on a fresh service that hasn't initialized yet
        const svc3 = new PatternService(dir);
        assert(svc3.isFallbackActive(), "Fallback should be active after integrity failure");
        cleanup(dir);
    }

    // Test 10: HMAC test — wrong secret fails verification
    console.log("Test 10: HMAC signature verification");
    {
        const dir = createTestDir();
        // Generate manifest with a specific secret
        const origSecret = process.env.PATTERN_INTEGRITY_SECRET;
        process.env.PATTERN_INTEGRITY_SECRET = "test-secret-123";

        const svc = new PatternService(dir);
        svc.regenerateManifest();

        // Verify with same secret — should pass
        const svc2 = new PatternService(dir);
        assert(!svc2.isFallbackActive(), "Should NOT use fallback with correct secret");
        const result = svc2.verify();
        assert(result.hmacValid === true, "HMAC should be valid with correct secret");

        // Change secret — should fail
        process.env.PATTERN_INTEGRITY_SECRET = "wrong-secret";
        const svc3 = new PatternService(dir);
        assert(svc3.isFallbackActive(), "Should use fallback with wrong secret");

        // Restore
        if (origSecret !== undefined) {
            process.env.PATTERN_INTEGRITY_SECRET = origSecret;
        } else {
            delete process.env.PATTERN_INTEGRITY_SECRET;
        }
        cleanup(dir);
    }

    // Test 11: All migrated patterns compile as valid RegExp
    console.log("Test 11: All patterns compile as valid RegExp");
    {
        const dir = createTestDir();
        const svc = new PatternService(dir);
        svc.regenerateManifest();
        const svc2 = new PatternService(dir);
        const all = svc2.list();
        let allCompile = true;
        for (const p of all) {
            try {
                new RegExp(p.pattern, p.flags);
            } catch (err) {
                console.error(`  Pattern "${p.id}" failed to compile: ${err}`);
                allCompile = false;
            }
        }
        assert(allCompile, "All patterns should compile as valid RegExp");
        cleanup(dir);
    }

    // Test 12: getActivePatterns returns fresh RegExp instances
    console.log("Test 12: getActivePatterns returns fresh RegExp instances");
    {
        const dir = createTestDir();
        const svc = new PatternService(dir);
        svc.regenerateManifest();
        const svc2 = new PatternService(dir);
        const batch1 = svc2.getActivePatterns("general");
        const batch2 = svc2.getActivePatterns("general");
        assert(batch1.length > 0, "Should return active patterns");
        assert(batch1[0].regex !== batch2[0].regex, "Should return different RegExp instances");
        cleanup(dir);
    }

    // Test 13: Fallback patterns load when directory missing
    console.log("Test 13: Fallback when patterns directory missing");
    {
        const dir = join(tmpdir(), `pattern-test-missing-${Date.now()}`);
        const svc = new PatternService(dir);
        assert(svc.isFallbackActive(), "Should use fallback when directory doesn't exist");
        const all = svc.list();
        assert(all.length === 10, `Expected 10 fallback patterns, got ${all.length}`);
    }

    console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
    if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
    console.error("Test runner error:", err);
    process.exit(1);
});
