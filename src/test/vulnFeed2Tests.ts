import dotenv from "dotenv";
dotenv.config();

// Use dummy NVD key to avoid rate limiter throttling in integration test.
// IMPORTANT: do NOT default-set GITHUB_TOKEN here — one of our tests asserts
// "no token => empty result" and needs to control that env var explicitly.
process.env.NVD_API_KEY = process.env.NVD_API_KEY || "test-key-for-rate-limiter";

import { OsvFeedService } from "../services/OsvFeedService.js";
import { GhsaGraphQLService } from "../services/GhsaGraphQLService.js";
import { VulnFeedService } from "../services/VulnFeedService.js";
import { PatternService } from "../services/PatternService.js";
import { withMockedFetch, jsonResponse } from "./helpers/mockFetch.js";
import { mkdirSync, cpSync, rmSync, existsSync, writeFileSync, readFileSync } from "fs";
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

function createTestDir(): string {
    const dir = join(tmpdir(), `vulnfeed2-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(dir, { recursive: true });
    mkdirSync(join(dir, "staging"), { recursive: true });

    const projectPatterns = join(process.cwd(), "patterns");
    const files = ["xss.json", "sqli.json", "shell-injection.json", "skill-threats.json", "prompt-injection.json", "custom.json"];
    for (const f of files) {
        const src = join(projectPatterns, f);
        if (existsSync(src)) cpSync(src, join(dir, f));
    }
    writeFileSync(join(dir, "staging", "pending-review.json"), JSON.stringify({ version: 1, candidates: [] }), "utf-8");
    return dir;
}

function cleanup(dir: string) {
    rmSync(dir, { recursive: true, force: true });
}

// --- Canned fixtures ---

// OSV /v1/querybatch response — full vuln inline (per spec "Parse results[].vulns[]").
const OSV_BATCH_RESPONSE = {
    results: [
        {
            vulns: [
                {
                    id: "GHSA-aaaa-bbbb-cccc",
                    summary: "Arbitrary code execution in langchain agent loader",
                    aliases: ["CVE-2026-99001"],
                    affected: [{ package: { ecosystem: "PyPI", name: "langchain" } }],
                    severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/7.5" }],
                },
                {
                    id: "PYSEC-2026-001",
                    summary: "Path traversal in transformers tokenizer",
                    aliases: ["CVE-2026-99002"],
                    affected: [{ package: { ecosystem: "PyPI", name: "transformers" } }],
                },
            ],
        },
        {
            // Duplicate id from a second package query — must be deduped.
            vulns: [
                {
                    id: "GHSA-aaaa-bbbb-cccc",
                    summary: "duplicate",
                    affected: [{ package: { ecosystem: "PyPI", name: "langchain-core" } }],
                },
            ],
        },
    ],
};

// GHSA GraphQL response — two nodes: one in allowlist (langchain), one not (some-random-pkg).
const GHSA_GRAPHQL_RESPONSE = {
    data: {
        securityVulnerabilities: {
            nodes: [
                {
                    advisory: {
                        ghsaId: "GHSA-zzzz-yyyy-xxxx",
                        summary: "SSRF in langchain web tool",
                        description: "Detailed description.",
                        severity: "HIGH",
                        cwes: { nodes: [{ cweId: "CWE-918" }] },
                        identifiers: [{ type: "CVE", value: "CVE-2026-99100" }, { type: "GHSA", value: "GHSA-zzzz-yyyy-xxxx" }],
                        publishedAt: "2026-02-01T00:00:00Z",
                        updatedAt: "2026-02-15T00:00:00Z",
                    },
                    package: { ecosystem: "PIP", name: "langchain" },
                },
                {
                    advisory: {
                        ghsaId: "GHSA-9999-8888-7777",
                        summary: "Bug in some other package",
                        description: "Not AI related.",
                        severity: "LOW",
                        cwes: { nodes: [] },
                        identifiers: [],
                        publishedAt: "2026-02-01T00:00:00Z",
                        updatedAt: "2026-02-15T00:00:00Z",
                    },
                    package: { ecosystem: "PIP", name: "some-random-package" },
                },
            ],
        },
    },
};

async function runTests() {
    console.log("\n=== VulnFeedService Pass 6 Tests (OSV + GHSA GraphQL) ===\n");

    // --- OsvFeedService ---
    console.log("Test A1: OsvFeedService.query empty input short-circuits (no fetch)");
    {
        let fetched = false;
        await withMockedFetch(async () => { fetched = true; return jsonResponse({}); }, async () => {
            const svc = new OsvFeedService();
            const res = await svc.query([]);
            assert(res.length === 0, "empty input returns []");
            assert(!fetched, "no fetch was issued for empty input");
        });
    }

    console.log("Test A2: OsvFeedService.query parses + dedupes querybatch results");
    {
        await withMockedFetch(
            async (url: string) => {
                if (url.includes("api.osv.dev/v1/querybatch")) return jsonResponse(OSV_BATCH_RESPONSE);
                return new Response("Not Found", { status: 404 });
            },
            async () => {
                const svc = new OsvFeedService();
                const res = await svc.query([{ ecosystem: "PyPI", name: "langchain" }]);
                assert(res.length === 2, `expected 2 unique vulns after dedup, got ${res.length}`);
                const ids = new Set(res.map((v) => v.id));
                assert(ids.has("GHSA-aaaa-bbbb-cccc"), "contains GHSA-aaaa-bbbb-cccc");
                assert(ids.has("PYSEC-2026-001"), "contains PYSEC-2026-001");
            },
        );
    }

    console.log("Test A3: OsvFeedService.query throws on HTTP failure");
    {
        await withMockedFetch(
            async () => new Response("server error", { status: 500 }),
            async () => {
                const svc = new OsvFeedService();
                let threw = false;
                try {
                    await svc.query([{ ecosystem: "PyPI", name: "langchain" }]);
                } catch (e: any) {
                    threw = /OSV query failed: 500/.test(e.message);
                }
                assert(threw, "throws with descriptive message on 500");
            },
        );
    }

    // --- GhsaGraphQLService ---
    console.log("Test B1: GhsaGraphQLService.query without GITHUB_TOKEN returns [] (no fetch)");
    {
        const savedToken = process.env.GITHUB_TOKEN;
        delete process.env.GITHUB_TOKEN;
        let fetched = false;
        await withMockedFetch(async () => { fetched = true; return jsonResponse({}); }, async () => {
            const svc = new GhsaGraphQLService();
            const res = await svc.query("PIP", 10);
            assert(res.length === 0, "no-token returns []");
            assert(!fetched, "no fetch was issued without token");
        });
        if (savedToken !== undefined) process.env.GITHUB_TOKEN = savedToken;
    }

    console.log("Test B2: GhsaGraphQLService.query filters to AI allowlist");
    {
        process.env.GITHUB_TOKEN = "test-token";
        await withMockedFetch(
            async (url: string) => {
                if (url.includes("api.github.com/graphql")) return jsonResponse(GHSA_GRAPHQL_RESPONSE);
                return new Response("Not Found", { status: 404 });
            },
            async () => {
                const svc = new GhsaGraphQLService();
                const res = await svc.query("PIP", 10);
                assert(res.length === 1, `expected 1 advisory after allowlist filter, got ${res.length}`);
                assert(res[0]?.ghsaId === "GHSA-zzzz-yyyy-xxxx", "kept langchain advisory");
                assert(res[0]?.cveId === "CVE-2026-99100", "extracted CVE id from identifiers");
                assert(res[0]?.cweIds?.[0] === "CWE-918", "extracted CWE id");
            },
        );
        delete process.env.GITHUB_TOKEN;
    }

    // --- VulnFeedService integration ---
    console.log("Test C1: VulnFeedService.updateFeeds aggregates per-source counts and stages candidates");
    {
        const dir = createTestDir();
        // Ensure GHSA GraphQL has a token so it actually fetches.
        process.env.GITHUB_TOKEN = "test-token";

        const ps = new PatternService(dir);
        ps.regenerateManifest();
        const patSvc = new PatternService(dir);
        const vulnSvc = new VulnFeedService(patSvc, undefined, dir);

        await withMockedFetch(
            async (url: string) => {
                if (url.includes("nvd.nist.gov")) return jsonResponse({ vulnerabilities: [] });
                if (url.includes("api.osv.dev/v1/querybatch")) return jsonResponse(OSV_BATCH_RESPONSE);
                if (url.includes("api.github.com/graphql")) return jsonResponse(GHSA_GRAPHQL_RESPONSE);
                if (url.includes("api.github.com/advisories")) return jsonResponse([]);
                return new Response("Not Found", { status: 404 });
            },
            async () => {
                const result = await vulnSvc.updateFeeds(30);

                assert(result.perSource.osv === 2, `perSource.osv expected 2, got ${result.perSource.osv}`);
                // GHSA GraphQL is called once per ecosystem (PIP, NPM) — each returns 1 allowlisted node.
                assert(result.perSource.ghsaGraphql === 2, `perSource.ghsaGraphql expected 2, got ${result.perSource.ghsaGraphql}`);

                assert(result.patternsGenerated >= 3, `staged at least 3 ai_supply_chain candidates, got ${result.patternsGenerated}`);

                // Inspect staging file directly.
                const staged = JSON.parse(
                    readFileSync(join(dir, "staging", "pending-review.json"), "utf-8"),
                );
                const sources = new Set(staged.candidates.map((c: any) => c.source));
                assert(sources.has("osv"), "staging includes a source='osv' candidate");
                assert(sources.has("ghsa_graphql"), "staging includes a source='ghsa_graphql' candidate");
            },
        );
        delete process.env.GITHUB_TOKEN;
        cleanup(dir);
    }

    console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
    if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
    console.error("Test runner error:", err);
    process.exit(1);
});
