import dotenv from "dotenv";
dotenv.config();

// Dummy NVD key to disarm rate limiter in integration tests below.
process.env.NVD_API_KEY = process.env.NVD_API_KEY || "test-key-for-rate-limiter";

import { AtlasService } from "../services/AtlasService.js";
import { KevFeedService } from "../services/KevFeedService.js";
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

function freshDir(label: string): string {
    const dir = join(tmpdir(), `${label}-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(dir, { recursive: true });
    return dir;
}

function createPatternsTestDir(): string {
    const dir = freshDir("atlas-kev-patterns");
    mkdirSync(join(dir, "staging"), { recursive: true });
    const projectPatterns = join(process.cwd(), "patterns");
    const files = [
        "xss.json",
        "sqli.json",
        "shell-injection.json",
        "skill-threats.json",
        "prompt-injection.json",
        "custom.json",
    ];
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

// --- Canned STIX bundle (minimal, ATLAS-shaped) ---
const ATLAS_STIX_BUNDLE = {
    type: "bundle",
    objects: [
        {
            type: "attack-pattern",
            id: "attack-pattern--abc",
            name: "LLM Prompt Injection",
            description: "Canonical ATLAS description.",
            x_mitre_is_subtechnique: false,
            kill_chain_phases: [{ kill_chain_name: "mitre-atlas", phase_name: "Initial Access" }],
            external_references: [{ source_name: "mitre-atlas", external_id: "AML.T0051" }],
        },
        {
            type: "attack-pattern",
            id: "attack-pattern--def",
            name: "LLM Jailbreak",
            description: "Canonical jailbreak description.",
            x_mitre_is_subtechnique: false,
            kill_chain_phases: [{ kill_chain_name: "mitre-atlas", phase_name: "Defense Evasion" }],
            external_references: [{ source_name: "mitre-atlas", external_id: "AML.T0054" }],
        },
        // A sub-technique that must be skipped.
        {
            type: "attack-pattern",
            id: "attack-pattern--xyz",
            name: "Some sub-technique",
            x_mitre_is_subtechnique: true,
            external_references: [{ source_name: "mitre-atlas", external_id: "AML.T9999.001" }],
        },
        // Non-attack-pattern object — must be ignored.
        { type: "course-of-action", id: "x", name: "ignored" },
    ],
};

// --- Canned CISA KEV catalog (minimal) ---
const KEV_CATALOG = {
    title: "CISA Catalog of Known Exploited Vulnerabilities",
    catalogVersion: "test",
    dateReleased: "2026-05-01T00:00:00Z",
    count: 2,
    vulnerabilities: [
        {
            cveID: "CVE-2026-42208",
            vendorProject: "AcmeAI",
            product: "langchain",
            vulnerabilityName: "Agent loader RCE",
            dateAdded: "2026-04-15",
            shortDescription: "Active exploitation of langchain agent loader.",
            knownRansomwareUse: "Unknown",
        },
        {
            cveID: "CVE-2026-99999",
            vendorProject: "Other",
            product: "thing",
            vulnerabilityName: "thing bug",
            dateAdded: "2026-04-20",
            shortDescription: "—",
            knownRansomwareUse: "Unknown",
        },
    ],
};

async function runTests() {
    console.log("\n=== AtlasService + KevFeedService Tests (Pass 7) ===\n");

    // --- AtlasService ---
    console.log("Test A1: AtlasService.refresh parses STIX bundle");
    {
        const cacheDir = freshDir("atlas-cache");
        let calls = 0;
        await withMockedFetch(
            async () => {
                calls++;
                return jsonResponse(ATLAS_STIX_BUNDLE);
            },
            async () => {
                const svc = new AtlasService({ cacheDir });
                const res = await svc.refresh();
                assert(res.count >= 2, `parsed >= 2 techniques (got ${res.count})`);
                const t = svc.lookup("AML.T0051");
                assert(t !== null && t.name === "LLM Prompt Injection", "lookup returns LLM Prompt Injection");
                assert(t?.tactic === "Initial Access", "tactic resolved from kill_chain_phases");
                const t2 = svc.lookup("AML.T0054");
                assert(t2 !== null && t2.name === "LLM Jailbreak", "lookup returns LLM Jailbreak");
            },
        );
        // Cache TTL: second refresh within TTL should NOT issue a fetch.
        await withMockedFetch(
            async () => {
                calls++;
                return jsonResponse(ATLAS_STIX_BUNDLE);
            },
            async () => {
                const svc2 = new AtlasService({ cacheDir });
                const before = calls;
                await svc2.refresh();
                assert(calls === before, "second refresh within TTL did NOT re-fetch");
            },
        );
        cleanup(cacheDir);
    }

    console.log("Test A2: AtlasService falls back when no cache + fetch fails");
    {
        const cacheDir = freshDir("atlas-fallback");
        await withMockedFetch(
            async () => new Response("boom", { status: 500 }),
            async () => {
                const svc = new AtlasService({ cacheDir });
                // refresh throws; caller is expected to catch and continue.
                let threw = false;
                try {
                    await svc.refresh();
                } catch {
                    threw = true;
                }
                assert(threw, "refresh throws on hard fetch failure");
                // Built-in fallback still works.
                const t = svc.lookup("AML.T0051");
                assert(t !== null && /LLM Prompt Injection/.test(t.name), "fallback lookup returns LLM Prompt Injection");
                const t70 = svc.lookup("AML.T0070");
                assert(t70 !== null && /Publish Poisoned/i.test(t70.name), "fallback covers AML.T0070");
                const tNone = svc.lookup("AML.T9999");
                assert(tNone === null, "unknown technique returns null");
            },
        );
        cleanup(cacheDir);
    }

    // --- KevFeedService ---
    console.log("Test B1: KevFeedService.refresh ingests catalog");
    {
        const cacheDir = freshDir("kev-cache");
        await withMockedFetch(
            async () => jsonResponse(KEV_CATALOG),
            async () => {
                const svc = new KevFeedService({ cacheDir });
                const res = await svc.refresh();
                assert(res.count === 2, `refresh count expected 2, got ${res.count}`);
                assert(svc.isInKev("CVE-2026-42208"), "isInKev(CVE-2026-42208) true");
                assert(svc.isInKev("cve-2026-42208"), "isInKev case-insensitive");
                assert(!svc.isInKev("CVE-1999-9999"), "isInKev(unknown) false");
                const entry = svc.get("CVE-2026-42208");
                assert(entry?.vendorProject === "AcmeAI", "get() returns full KEV entry");
            },
        );
        cleanup(cacheDir);
    }

    console.log("Test B2: KevFeedService empty when cache absent + no refresh");
    {
        const cacheDir = freshDir("kev-empty");
        const svc = new KevFeedService({ cacheDir });
        assert(!svc.isInKev("CVE-2026-42208"), "pre-refresh KEV miss");
        assert(svc.list().length === 0, "list() empty before refresh");
        cleanup(cacheDir);
    }

    console.log("Test B3: KevFeedService.refresh aborts on timeout");
    {
        const cacheDir = freshDir("kev-timeout");
        // Handler never resolves on its own — it waits for the abort signal
        // from the AbortController. If timeout plumbing is broken, the test
        // hangs (and the surrounding runner will catch it eventually).
        await withMockedFetch(
            (_url: string, init?: RequestInit) =>
                new Promise<Response>((_resolve, reject) => {
                    const signal = init?.signal;
                    if (signal) {
                        signal.addEventListener("abort", () => {
                            // Surface as AbortError so KevFeedService's catch
                            // path classifies it as a timeout.
                            const err = new Error("aborted");
                            err.name = "AbortError";
                            reject(err);
                        });
                    }
                }),
            async () => {
                const svc = new KevFeedService({ cacheDir, timeoutMs: 1 });
                const start = Date.now();
                let threw = false;
                let msg = "";
                try {
                    // Hard outer guard: if the service's timeoutMs:1 path
                    // regresses and refresh() never settles, fail fast with a
                    // diagnostic message instead of hanging the runner.
                    await Promise.race([
                        svc.refresh(),
                        new Promise<never>((_, reject) =>
                            setTimeout(
                                () => reject(new Error("test hard guard timeout (2000ms)")),
                                2000,
                            ),
                        ),
                    ]);
                } catch (e: any) {
                    threw = true;
                    msg = e?.message || String(e);
                }
                const elapsed = Date.now() - start;
                assert(threw, "refresh threw on timeout");
                assert(/timeout/i.test(msg), `error message mentions timeout (got: ${msg})`);
                assert(elapsed < 500, `refresh aborted promptly (elapsed=${elapsed}ms)`);
            },
        );
        cleanup(cacheDir);
    }

    // --- KEV escalator in VulnFeedService ---
    console.log("Test C1: VulnFeedService escalates severity for CVEs in KEV");
    {
        const dir = createPatternsTestDir();
        const cacheDir = freshDir("vf-feed-cache");
        const ps = new PatternService(dir);
        ps.regenerateManifest();
        const patSvc = new PatternService(dir);

        const atlasSvc = new AtlasService({ cacheDir });
        const kevSvc = new KevFeedService({ cacheDir });

        // OSV vuln with MEDIUM severity that aliases CVE-2026-42208 (in KEV).
        const osvBatch = {
            results: [
                {
                    vulns: [
                        {
                            id: "GHSA-test-kev",
                            summary: "Test vuln for KEV escalator",
                            aliases: ["CVE-2026-42208"],
                            affected: [{ package: { ecosystem: "PyPI", name: "langchain" } }],
                            severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/5.5" }],
                        },
                    ],
                },
            ],
        };

        const vulnSvc = new VulnFeedService(
            patSvc,
            undefined,
            dir,
            undefined,
            undefined,
            atlasSvc,
            kevSvc,
        );

        await withMockedFetch(
            async (url: string) => {
                // ATLAS refresh
                if (url.includes("atlas-navigator-data")) return jsonResponse(ATLAS_STIX_BUNDLE);
                // KEV refresh
                if (url.includes("known_exploited_vulnerabilities.json")) return jsonResponse(KEV_CATALOG);
                // NVD / GHSA REST: empty (we only test OSV path here)
                if (url.includes("nvd.nist.gov")) return jsonResponse({ vulnerabilities: [] });
                if (url.includes("api.github.com/advisories")) return jsonResponse([]);
                if (url.includes("api.github.com/graphql")) return jsonResponse({ data: { securityVulnerabilities: { nodes: [] } } });
                if (url.includes("api.osv.dev/v1/querybatch")) return jsonResponse(osvBatch);
                return new Response("Not Found", { status: 404 });
            },
            async () => {
                const result = await vulnSvc.updateFeeds(30);
                assert(result.perSource.osv === 1, `OSV fetched 1 vuln (got ${result.perSource.osv})`);

                const staged = JSON.parse(
                    readFileSync(join(dir, "staging", "pending-review.json"), "utf-8"),
                );
                const c = staged.candidates.find((c: any) => c.cveId === "CVE-2026-42208");
                assert(!!c, "staged candidate present for CVE-2026-42208");
                assert(c.inKev === true, "candidate marked inKev=true");
                // OSV CVSS 5.5 normalizes to medium; KEV bumps to high.
                assert(c.severity === "high", `severity escalated medium->high (got ${c.severity})`);
                assert(c.atlasTechnique === "AML.T0070", `ai_supply_chain mapped to AML.T0070 (got ${c.atlasTechnique})`);
            },
        );
        cleanup(dir);
        cleanup(cacheDir);
    }

    console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
    if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
    console.error("Test runner error:", err);
    process.exit(1);
});
