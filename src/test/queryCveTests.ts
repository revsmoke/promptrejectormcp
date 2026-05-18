import { mkdirSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

import { VulnFeedService, type StagedCandidate } from "../services/VulnFeedService.js";
import { PatternService } from "../services/PatternService.js";
import { AtlasService } from "../services/AtlasService.js";
import { KevFeedService, type KevEntry } from "../services/KevFeedService.js";
import { UnifiedCveCache } from "../services/UnifiedCveCache.js";

let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string): void {
    if (condition) {
        console.log(`  PASS: ${message}`);
        passed++;
    } else {
        console.error(`  FAIL: ${message}`);
        failed++;
    }
}

/**
 * Pass 9 — UnifiedCveCache + query_cve tests.
 *
 * Strategy: hand-craft a staging file at a temp path, instantiate the service
 * graph against it, and exercise UnifiedCveCache directly. We do not boot
 * the MCP server here; the wire-up there is a one-liner and is covered by
 * the build step. KEV is stubbed so we don't hit CISA's catalog.
 */

function createTestStaging(candidates: StagedCandidate[]): string {
    const dir = join(tmpdir(), `query-cve-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
    mkdirSync(dir, { recursive: true });
    mkdirSync(join(dir, "staging"), { recursive: true });
    writeFileSync(
        join(dir, "staging", "pending-review.json"),
        JSON.stringify({ version: 1, candidates }, null, 2),
        "utf-8",
    );
    return dir;
}

function makeCandidate(overrides: Partial<StagedCandidate>): StagedCandidate {
    return {
        id: overrides.id || "test-id",
        name: overrides.name || "test name",
        pattern: overrides.pattern ?? "",
        flags: overrides.flags ?? "",
        description: overrides.description || "",
        category: overrides.category || "ai_supply_chain",
        severity: overrides.severity || "medium",
        cveId: overrides.cveId || "CVE-0000-0000",
        source: overrides.source || "osv",
        generatedAt: overrides.generatedAt || new Date().toISOString(),
        inKev: overrides.inKev,
        atlasTechnique: overrides.atlasTechnique,
    };
}

/**
 * Stub KevFeedService — overrides only the public methods UnifiedCveCache
 * touches. Keeps the test off the network and gives us a known KEV row to
 * assert against.
 */
class StubKev extends KevFeedService {
    private fakeEntries: Record<string, KevEntry>;
    constructor(fake: Record<string, KevEntry>) {
        super({ cacheDir: join(tmpdir(), `kev-stub-${Date.now()}`) });
        this.fakeEntries = fake;
    }
    override isInKev(cveId: string): boolean {
        return !!this.fakeEntries[cveId.toUpperCase()];
    }
    override get(cveId: string): KevEntry | null {
        return this.fakeEntries[cveId.toUpperCase()] || null;
    }
}

function buildCache(candidates: StagedCandidate[], kevRows: Record<string, KevEntry>) {
    const dir = createTestStaging(candidates);
    // PatternService default constructor scans the project patterns/ dir — we
    // never read patterns from it in UnifiedCveCache, so the real one is fine.
    const patternService = new PatternService();
    const atlas = new AtlasService();
    const kev = new StubKev(kevRows);
    const vfs = new VulnFeedService(patternService, undefined, dir, undefined, undefined, atlas, kev);
    const cache = new UnifiedCveCache(vfs, atlas, kev);
    return { cache, dir };
}

function fixtureCandidates(): StagedCandidate[] {
    const ts = "2026-05-13T12:00:00.000Z";
    return [
        // 1: OSV row for CVE-2026-42208 (PyPI:litellm) — KEV + ATLAS
        makeCandidate({
            id: "osv-1",
            name: "GHSA-aaaa-aaaa-aaa1 (PyPI:litellm)",
            description: "litellm prompt-injection bypass vulnerability",
            category: "ai_supply_chain",
            severity: "high",
            cveId: "CVE-2026-42208",
            source: "osv",
            generatedAt: ts,
            inKev: true,
            atlasTechnique: "AML.T0070",
        }),
        // 2: GHSA GraphQL duplicate — critical severity (so merged max becomes critical)
        makeCandidate({
            id: "ghsa-1",
            name: "GHSA-bbbb-bbbb-bbb2 (PyPI:litellm)",
            description: "litellm advisory from GHSA — critical-severity duplicate",
            category: "ai_supply_chain",
            severity: "critical",
            cveId: "CVE-2026-42208",
            source: "ghsa_graphql",
            generatedAt: ts,
            inKev: true,
            atlasTechnique: "AML.T0070",
        }),
        // 3: NVD xss, no KEV, no ATLAS
        makeCandidate({
            id: "nvd-1",
            name: "CVE-2026-1001: reflected XSS",
            description: "Reflected XSS in some web app",
            category: "xss",
            severity: "medium",
            cveId: "CVE-2026-1001",
            source: "nvd",
            generatedAt: ts,
        }),
        // 4: OSV npm langchain, low
        makeCandidate({
            id: "osv-2",
            name: "GHSA-cccc-cccc-cc03 (npm:langchain)",
            description: "langchain advisory (low)",
            category: "ai_supply_chain",
            severity: "low",
            cveId: "CVE-2026-2002",
            source: "osv",
            generatedAt: ts,
        }),
        // 5: GHSA REST with ATLAS T0051 (LLM Prompt Injection)
        makeCandidate({
            id: "ghsa-rest-1",
            name: "CVE-2025-9999: prompt injection",
            description: "Prompt-injection vector",
            category: "prompt_injection",
            severity: "high",
            cveId: "CVE-2025-9999",
            source: "github_advisory",
            generatedAt: ts,
            atlasTechnique: "AML.T0051",
        }),
        // 6: NVD low
        makeCandidate({
            id: "nvd-2",
            name: "CVE-2025-8888: minor issue",
            description: "Some minor issue",
            category: "xss",
            severity: "low",
            cveId: "CVE-2025-8888",
            source: "nvd",
            generatedAt: ts,
        }),
    ];
}

const KEV_FIXTURE: Record<string, KevEntry> = {
    "CVE-2026-42208": {
        cveID: "CVE-2026-42208",
        vendorProject: "BerriAI",
        product: "litellm",
        vulnerabilityName: "LiteLLM Prompt Injection",
        dateAdded: "2026-05-01",
        shortDescription: "Active exploitation observed.",
        knownRansomwareUse: "Unknown",
    },
};

function run() {
    console.log("UnifiedCveCache / query_cve tests");
    console.log("==================================");

    // --- Test 1: rebuild merges duplicates -----------------------------------
    {
        const { cache, dir } = buildCache(fixtureCandidates(), KEV_FIXTURE);
        try {
            const records = cache.rebuild();
            assert(records.length === 5, "rebuild returns 5 unified records from 6 candidates (CVE-2026-42208 merged)");

            const merged = records.find((r) => r.cveId === "CVE-2026-42208");
            assert(!!merged, "merged record for CVE-2026-42208 exists");
            if (merged) {
                assert(merged.sourceCandidates === 2, "merged record reports sourceCandidates=2");
                assert(merged.sources.includes("osv"), "merged sources include osv");
                assert(merged.sources.includes("ghsa_graphql"), "merged sources include ghsa_graphql");
                assert(merged.sources.includes("kev"), "merged sources include kev");
                assert(merged.sources.includes("atlas"), "merged sources include atlas");
                assert(merged.severity === "critical", "merged severity is critical (max across group)");
                assert(merged.inKev === true, "merged inKev=true");
                assert(!!merged.kevEntry && merged.kevEntry.product === "litellm", "merged kevEntry populated from KEV stub");
                assert(merged.atlasTechniques.length === 1 && merged.atlasTechniques[0].id === "AML.T0070", "merged ATLAS technique resolved");
                assert(merged.ecosystem === "PyPI", "merged ecosystem parsed as PyPI");
                assert(merged.affectedPackages.some((p) => p.name === "PyPI:litellm"), "affectedPackages contains PyPI:litellm");
            }
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    }

    // --- Test 2: inKev filter ------------------------------------------------
    {
        const { cache, dir } = buildCache(fixtureCandidates(), KEV_FIXTURE);
        try {
            const inKevTrue = cache.query({ inKev: true });
            assert(inKevTrue.matched === 1 && inKevTrue.records[0].cveId === "CVE-2026-42208", "query({inKev:true}) returns 1 record (CVE-2026-42208)");
            const inKevFalse = cache.query({ inKev: false });
            assert(inKevFalse.matched === 4, "query({inKev:false}) returns 4 records");
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    }

    // --- Test 3: severity filter --------------------------------------------
    {
        const { cache, dir } = buildCache(fixtureCandidates(), KEV_FIXTURE);
        try {
            const high = cache.query({ severity: "high" });
            // CVE-2026-42208 merged to critical, so the only "high" left is CVE-2025-9999.
            assert(high.matched === 1 && high.records[0].cveId === "CVE-2025-9999", "query({severity:'high'}) returns only CVE-2025-9999");
            const critical = cache.query({ severity: "critical" });
            assert(critical.matched === 1 && critical.records[0].cveId === "CVE-2026-42208", "query({severity:'critical'}) returns merged CVE-2026-42208");
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    }

    // --- Test 4: atlasTechnique filter --------------------------------------
    {
        const { cache, dir } = buildCache(fixtureCandidates(), KEV_FIXTURE);
        try {
            const t0051 = cache.query({ atlasTechnique: "AML.T0051" });
            assert(t0051.matched === 1 && t0051.records[0].cveId === "CVE-2025-9999", "query({atlasTechnique:'AML.T0051'}) returns CVE-2025-9999");
            // case-insensitive match
            const lower = cache.query({ atlasTechnique: "aml.t0070" });
            assert(lower.matched === 1 && lower.records[0].cveId === "CVE-2026-42208", "atlasTechnique filter is case-insensitive");
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    }

    // --- Test 5: keyword filter ---------------------------------------------
    {
        const { cache, dir } = buildCache(fixtureCandidates(), KEV_FIXTURE);
        try {
            const kw = cache.query({ keyword: "litellm" });
            assert(kw.matched === 1 && kw.records[0].cveId === "CVE-2026-42208", "query({keyword:'litellm'}) returns CVE-2026-42208");
            const kw2 = cache.query({ keyword: "PROMPT" });
            assert(kw2.matched >= 1, "keyword search is case-insensitive");
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    }

    // --- Test 6: ecosystem filter -------------------------------------------
    {
        const { cache, dir } = buildCache(fixtureCandidates(), KEV_FIXTURE);
        try {
            const npm = cache.query({ ecosystem: "npm" });
            assert(npm.matched === 1 && npm.records[0].cveId === "CVE-2026-2002", "query({ecosystem:'npm'}) returns CVE-2026-2002 (langchain)");
            const pypi = cache.query({ ecosystem: "PyPI" });
            assert(pypi.matched === 1 && pypi.records[0].cveId === "CVE-2026-42208", "query({ecosystem:'PyPI'}) returns CVE-2026-42208");
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    }

    // --- Test 7: limit cap --------------------------------------------------
    {
        const { cache, dir } = buildCache(fixtureCandidates(), KEV_FIXTURE);
        try {
            const limited = cache.query({ limit: 2 });
            assert(limited.total === 5, "limited query reports total=5 (unfiltered count)");
            assert(limited.matched === 5, "limited.matched reports total matches before slicing");
            assert(limited.records.length === 2, "records array is capped at 2 via limit");
            // explicit oversize limit must clamp to MAX 200
            const huge = cache.query({ limit: 9999 });
            assert(huge.records.length === 5, "limit above max returns all available records");
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    }

    // --- Test 8: empty query default limit ----------------------------------
    {
        const { cache, dir } = buildCache(fixtureCandidates(), KEV_FIXTURE);
        try {
            const all = cache.query({});
            assert(all.total === 5 && all.records.length === 5, "empty query returns up to default-50 records (we have 5)");
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    }

    // --- Test 9: combined filters (AND) -------------------------------------
    {
        const { cache, dir } = buildCache(fixtureCandidates(), KEV_FIXTURE);
        try {
            const combined = cache.query({ severity: "critical", inKev: true });
            assert(combined.matched === 1 && combined.records[0].cveId === "CVE-2026-42208", "severity+inKev are AND-combined");
            const empty = cache.query({ severity: "low", inKev: true });
            assert(empty.matched === 0, "severity=low + inKev=true returns no rows");
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    }

    // --- Test 10: no staging file → graceful empty --------------------------
    {
        const dir = join(tmpdir(), `query-cve-empty-${Date.now()}`);
        mkdirSync(dir, { recursive: true });
        // intentionally do NOT create staging/pending-review.json
        const patternService = new PatternService();
        const atlas = new AtlasService();
        const kev = new StubKev({});
        const vfs = new VulnFeedService(patternService, undefined, dir, undefined, undefined, atlas, kev);
        const cache = new UnifiedCveCache(vfs, atlas, kev);
        try {
            const result = cache.query({});
            assert(result.total === 0 && result.records.length === 0, "missing staging file → empty result, no throw");
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    }

    console.log("==================================");
    console.log(`Passed: ${passed}, Failed: ${failed}`);
    if (failed > 0) process.exit(1);
}

run();
