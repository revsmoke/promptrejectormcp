import { readFileSync, writeFileSync, existsSync, renameSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { PatternService } from "./PatternService.js";
import { GeminiService } from "./GeminiService.js";
import { OsvFeedService, type OsvVuln } from "./OsvFeedService.js";
import { GhsaGraphQLService, type GhsaAdvisory } from "./GhsaGraphQLService.js";
import { AI_PACKAGE_ALLOWLIST, ECOSYSTEMS_FOR_GHSA } from "./aiPackageAllowlist.js";
import type { PatternEntry } from "../schemas/PatternSchemas.js";

interface StagedCandidate {
    id: string;
    name: string;
    pattern: string;
    flags: string;
    description: string;
    category: string;
    severity: string;
    cveId: string;
    source: "nvd" | "github_advisory" | "ghsa_graphql" | "osv";
    generatedAt: string;
}

interface StagingFile {
    version: 1;
    candidates: StagedCandidate[];
}

export interface VulnFeedError {
    source: "nvd" | "github" | "gemini" | "ghsa_graphql" | "osv";
    cveId?: string;
    message: string;
}

export interface VulnFeedPerSourceCounts {
    nvd: number;
    ghsaRest: number;
    ghsaGraphql: number;
    osv: number;
}

export interface VulnFeedResult {
    fetchedCount: number;
    relevantCount: number;
    patternsGenerated: number;
    errors: VulnFeedError[];
    perSource: VulnFeedPerSourceCounts;
}

// Simple sliding-window rate limiter
class RateLimiter {
    private timestamps: number[] = [];
    constructor(
        private maxRequests: number,
        private windowMs: number,
    ) {}

    async waitForSlot(): Promise<void> {
        const now = Date.now();
        this.timestamps = this.timestamps.filter((t) => now - t < this.windowMs);

        if (this.timestamps.length >= this.maxRequests) {
            const oldest = this.timestamps[0];
            const waitMs = this.windowMs - (now - oldest) + 50; // 50ms buffer
            await new Promise((resolve) => setTimeout(resolve, waitMs));
            return this.waitForSlot();
        }

        this.timestamps.push(Date.now());
    }
}

// CWE IDs we care about
const TARGET_CWES: Record<string, string> = {
    "CWE-79": "xss",
    "CWE-89": "sqli",
    "CWE-78": "shell_injection",
    "CWE-22": "directory_traversal",
    "CWE-918": "ssrf",
};

const NVD_SEARCH_KEYWORDS = [
    "xss",
    "sql injection",
    "command injection",
    "path traversal",
    "ssrf",
];

export class VulnFeedService {
    private patternService: PatternService;
    private geminiService: GeminiService | null;
    private osvFeedService: OsvFeedService;
    private ghsaGraphqlService: GhsaGraphQLService;
    private stagingPath: string;
    private githubToken: string | null;
    private nvdApiKey: string | null;
    private nvdLimiter: RateLimiter;
    private githubLimiter: RateLimiter;

    constructor(
        patternService: PatternService,
        geminiService?: GeminiService,
        patternsDir?: string,
        osvFeedService?: OsvFeedService,
        ghsaGraphqlService?: GhsaGraphQLService,
    ) {
        this.patternService = patternService;
        // Lazy: only create GeminiService if provided or API key is available
        if (geminiService) {
            this.geminiService = geminiService;
        } else if (process.env.GEMINI_API_KEY) {
            this.geminiService = new GeminiService();
        } else {
            this.geminiService = null;
        }

        this.osvFeedService = osvFeedService || new OsvFeedService();
        this.ghsaGraphqlService = ghsaGraphqlService || new GhsaGraphQLService();

        this.githubToken = process.env.GITHUB_TOKEN || null;
        this.nvdApiKey = process.env.NVD_API_KEY || null;

        // NVD: 5 req/30s without key, 50 req/30s with key
        this.nvdLimiter = new RateLimiter(
            this.nvdApiKey ? 50 : 5,
            30_000,
        );

        // GitHub: 60 req/hr unauth, 5000 req/hr with token
        this.githubLimiter = new RateLimiter(
            this.githubToken ? 83 : 1, // per-minute approximation
            60_000,
        );

        // Resolve staging path
        if (patternsDir) {
            this.stagingPath = join(patternsDir, "staging", "pending-review.json");
        } else {
            const thisFile = fileURLToPath(import.meta.url);
            let dir = dirname(thisFile);
            while (dir !== "/" && !existsSync(join(dir, "package.json"))) {
                dir = dirname(dir);
            }
            this.stagingPath = join(dir, "patterns", "staging", "pending-review.json");
        }
    }

    async updateFeeds(lookbackDays = 30): Promise<VulnFeedResult> {
        const result: VulnFeedResult = {
            fetchedCount: 0,
            relevantCount: 0,
            patternsGenerated: 0,
            errors: [],
            perSource: { nvd: 0, ghsaRest: 0, ghsaGraphql: 0, osv: 0 },
        };

        // Fetch from all four sources in parallel via allSettled — one failure
        // shouldn't kill the rest. Each branch returns its own typed payload.
        const settled = await Promise.allSettled([
            this.fetchNVD(lookbackDays),
            this.fetchGitHubAdvisories(lookbackDays),
            this.fetchOsv(),
            this.fetchGhsaGraphql(),
        ]);

        const nvdVulns: CVEEntry[] = this.unwrapSettled(settled[0], "nvd", result, [] as CVEEntry[]);
        const ghVulns: CVEEntry[] = this.unwrapSettled(settled[1], "github", result, [] as CVEEntry[]);
        const osvVulns: OsvVuln[] = this.unwrapSettled(settled[2], "osv", result, [] as OsvVuln[]);
        const ghsaGqlVulns: GhsaAdvisory[] = this.unwrapSettled(settled[3], "ghsa_graphql", result, [] as GhsaAdvisory[]);

        result.perSource.nvd = nvdVulns.length;
        result.perSource.ghsaRest = ghVulns.length;
        result.perSource.osv = osvVulns.length;
        result.perSource.ghsaGraphql = ghsaGqlVulns.length;

        // --- Existing CWE-based path (NVD + GHSA REST) — Gemini regex generation ---
        const allCveLikeVulns = [...nvdVulns, ...ghVulns];
        result.fetchedCount = allCveLikeVulns.length + osvVulns.length + ghsaGqlVulns.length;

        const unique = new Map<string, CVEEntry>();
        for (const v of allCveLikeVulns) {
            if (!unique.has(v.cveId)) unique.set(v.cveId, v);
        }
        const relevant = Array.from(unique.values());

        const staging = this.loadStaging();
        const existingPatternStrings = new Set(
            this.patternService.list().map((p) => p.pattern),
        );
        const existingStagedPatterns = new Set(
            staging.candidates.map((c) => c.pattern),
        );
        const existingStagedIds = new Set(staging.candidates.map((c) => c.id));

        for (const vuln of relevant) {
            try {
                const candidates = await this.generatePatternsFromCVE(vuln);
                for (const candidate of candidates) {
                    if (
                        existingPatternStrings.has(candidate.pattern) ||
                        existingStagedPatterns.has(candidate.pattern)
                    ) {
                        continue;
                    }
                    staging.candidates.push(candidate);
                    existingStagedPatterns.add(candidate.pattern);
                    existingStagedIds.add(candidate.id);
                    result.patternsGenerated++;
                }
            } catch (err: any) {
                result.errors.push({ source: "gemini", cveId: vuln.cveId, message: `Pattern generation error: ${err.message}` });
            }
        }

        // --- AI-supply-chain path (OSV + GHSA GraphQL) ---
        // These vulns are code-level (dependencies), not prompt patterns. We
        // stage them with empty pattern/flags + category "ai_supply_chain"
        // so Pass 9's query_cve can surface them without running regex.
        const relevant2 = result.relevantCount;
        for (const v of osvVulns) {
            const cand = this.osvVulnToCandidate(v);
            if (cand && !existingStagedIds.has(cand.id)) {
                staging.candidates.push(cand);
                existingStagedIds.add(cand.id);
                result.patternsGenerated++;
            }
        }
        for (const a of ghsaGqlVulns) {
            const cand = this.ghsaAdvisoryToCandidate(a);
            if (cand && !existingStagedIds.has(cand.id)) {
                staging.candidates.push(cand);
                existingStagedIds.add(cand.id);
                result.patternsGenerated++;
            }
        }
        result.relevantCount = relevant.length + osvVulns.length + ghsaGqlVulns.length;
        void relevant2; // (kept for clarity; relevantCount is now total across all sources)

        this.saveStaging(staging);
        return result;
    }

    /**
     * Drain a Promise.allSettled result. Pushes any rejection onto result.errors
     * tagged with the given source and returns the fallback value. Centralized
     * here so the parallel fetch block stays readable.
     */
    private unwrapSettled<T>(
        s: PromiseSettledResult<T>,
        source: VulnFeedError["source"],
        result: VulnFeedResult,
        fallback: T,
    ): T {
        if (s.status === "fulfilled") return s.value;
        const msg = s.reason instanceof Error ? s.reason.message : String(s.reason);
        result.errors.push({ source, message: `${source} fetch error: ${msg}` });
        return fallback;
    }

    /** OSV: query the AI-package allowlist. */
    private async fetchOsv(): Promise<OsvVuln[]> {
        return this.osvFeedService.query(AI_PACKAGE_ALLOWLIST);
    }

    /** GHSA GraphQL: walk ecosystems we care about, flatten. */
    private async fetchGhsaGraphql(): Promise<GhsaAdvisory[]> {
        const all: GhsaAdvisory[] = [];
        for (const eco of ECOSYSTEMS_FOR_GHSA) {
            try {
                const advs = await this.ghsaGraphqlService.query(eco, 50);
                all.push(...advs);
            } catch (err: any) {
                // Per-ecosystem failures are non-fatal; recorded but we keep going.
                // We let updateFeeds() top-level allSettled record nothing extra,
                // but surface it here via stderr.
                console.error(`[VulnFeedService] GHSA GraphQL ${eco} failed:`, err?.message || err);
            }
        }
        return all;
    }

    /** Map an OSV vuln to a staged candidate with empty regex (ai_supply_chain). */
    private osvVulnToCandidate(v: OsvVuln): StagedCandidate | null {
        // Prefer a CVE alias for cveId if present; otherwise fall back to the OSV id.
        const cveAlias = (v.aliases || []).find((a) => /^CVE-/i.test(a));
        const cveId = cveAlias || v.id;
        const id = `osv-${v.id.toLowerCase().replace(/[^a-z0-9]/g, "-")}`;
        const sev = this.osvSeverityToLevel(v.severity);
        const pkg = v.affected?.[0]?.package;
        const pkgLabel = pkg ? `${pkg.ecosystem}:${pkg.name}` : "unknown";
        return {
            id,
            name: `${v.id} (${pkgLabel})`,
            pattern: "",
            flags: "",
            description: v.summary || v.details?.slice(0, 200) || "OSV advisory (no regex pattern)",
            category: "ai_supply_chain",
            severity: sev,
            cveId,
            source: "osv",
            generatedAt: new Date().toISOString(),
        };
    }

    /** Map a GHSA GraphQL advisory to a staged candidate with empty regex. */
    private ghsaAdvisoryToCandidate(a: GhsaAdvisory): StagedCandidate | null {
        const id = `ghsa-${a.ghsaId.toLowerCase().replace(/[^a-z0-9]/g, "-")}`;
        const cveId = a.cveId || a.ghsaId;
        const pkg = a.vulnerablePackage;
        const pkgLabel = pkg ? `${pkg.ecosystem}:${pkg.name}` : "unknown";
        return {
            id,
            name: `${a.ghsaId} (${pkgLabel})`,
            pattern: "",
            flags: "",
            description: a.summary || a.description?.slice(0, 200) || "GHSA advisory (no regex pattern)",
            category: "ai_supply_chain",
            severity: a.severity.toLowerCase() === "moderate" ? "medium" : a.severity.toLowerCase(),
            cveId,
            source: "ghsa_graphql",
            generatedAt: new Date().toISOString(),
        };
    }

    /** Map OSV severity array to our 4-level scale. Best-effort; defaults to medium. */
    private osvSeverityToLevel(sev?: OsvVuln["severity"]): string {
        if (!sev || sev.length === 0) return "medium";
        // OSV severity entries can be CVSS_V3 vectors; try to extract a base score.
        for (const s of sev) {
            const m = s.score?.match(/CVSS:[0-9.]+\/.*?(\d+(?:\.\d+)?)/) || s.score?.match(/^(\d+(?:\.\d+)?)$/);
            if (m) {
                const score = parseFloat(m[1]);
                if (score >= 9.0) return "critical";
                if (score >= 7.0) return "high";
                if (score >= 4.0) return "medium";
                return "low";
            }
        }
        return "medium";
    }

    promote(candidateId: string): PatternEntry {
        const staging = this.loadStaging();
        const idx = staging.candidates.findIndex((c) => c.id === candidateId);
        if (idx === -1) {
            throw new Error(`Staged candidate "${candidateId}" not found`);
        }

        const candidate = staging.candidates[idx];

        const entry = this.patternService.add({
            id: candidate.id,
            name: candidate.name,
            description: candidate.description,
            pattern: candidate.pattern,
            flags: candidate.flags,
            severity: candidate.severity as PatternEntry["severity"],
            category: candidate.category,
            flagGroup: this.categoryToFlagGroup(candidate.category),
            scope: "general",
            detection: { mode: "simple" },
            enabled: true,
            source: candidate.source,
            cveRefs: [candidate.cveId],
            dateAdded: new Date().toISOString().split("T")[0],
            whitelistedDomains: [],
        });

        // Remove from staging
        staging.candidates.splice(idx, 1);
        this.saveStaging(staging);

        return entry;
    }

    // --- Private: NVD API ---

    private async fetchNVD(lookbackDays: number): Promise<CVEEntry[]> {
        const results: CVEEntry[] = [];
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - lookbackDays);

        const pubStartDate = startDate.toISOString().replace(/\.\d{3}Z$/, "");
        const pubEndDate = endDate.toISOString().replace(/\.\d{3}Z$/, "");

        for (const keyword of NVD_SEARCH_KEYWORDS) {
            await this.nvdLimiter.waitForSlot();

            const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
            url.searchParams.set("keywordSearch", keyword);
            url.searchParams.set("pubStartDate", pubStartDate);
            url.searchParams.set("pubEndDate", pubEndDate);
            url.searchParams.set("resultsPerPage", "20");

            const headers: Record<string, string> = {};
            if (this.nvdApiKey) {
                headers["apiKey"] = this.nvdApiKey;
            }

            try {
                const resp = await fetch(url.toString(), { headers });

                if (resp.status === 429) {
                    const retryAfter = resp.headers.get("Retry-After");
                    const waitMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : 30_000;
                    await new Promise((resolve) => setTimeout(resolve, waitMs));
                    continue;
                }

                if (!resp.ok) {
                    continue;
                }

                const data = (await resp.json()) as NVDResponse;
                if (!data.vulnerabilities) continue;

                for (const item of data.vulnerabilities) {
                    const cve = item.cve;
                    const cweIds = this.extractCWEIds(cve);
                    const relevantCWEs = cweIds.filter((id) => id in TARGET_CWES);

                    if (relevantCWEs.length === 0) continue;

                    const desc =
                        cve.descriptions?.find((d: any) => d.lang === "en")?.value || "";

                    results.push({
                        cveId: cve.id,
                        cweIds: relevantCWEs,
                        description: desc,
                        source: "nvd",
                    });
                }
            } catch {
                // Silently skip network errors
            }
        }

        return results;
    }

    private extractCWEIds(cve: any): string[] {
        const cwes: string[] = [];
        if (cve.weaknesses) {
            for (const w of cve.weaknesses) {
                if (w.description) {
                    for (const d of w.description) {
                        if (d.value && d.value.startsWith("CWE-")) {
                            cwes.push(d.value);
                        }
                    }
                }
            }
        }
        return cwes;
    }

    // --- Private: GitHub Advisory API ---

    private async fetchGitHubAdvisories(lookbackDays: number): Promise<CVEEntry[]> {
        const results: CVEEntry[] = [];
        const since = new Date();
        since.setDate(since.getDate() - lookbackDays);
        const updatedSince = since.toISOString();

        for (const cweId of Object.keys(TARGET_CWES)) {
            await this.githubLimiter.waitForSlot();

            const url = new URL("https://api.github.com/advisories");
            url.searchParams.set("cwe_id", cweId);
            url.searchParams.set("updated", updatedSince);
            url.searchParams.set("per_page", "20");

            const headers: Record<string, string> = {
                Accept: "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            };
            if (this.githubToken) {
                headers["Authorization"] = `Bearer ${this.githubToken}`;
            }

            try {
                const resp = await fetch(url.toString(), { headers });
                if (!resp.ok) continue;

                const advisories = (await resp.json()) as any[];
                for (const adv of advisories) {
                    const cveId = adv.cve_id;
                    if (!cveId) continue;

                    results.push({
                        cveId,
                        cweIds: (adv.cwes || []).map((c: any) => c.cwe_id).filter(Boolean),
                        description: adv.summary || adv.description || "",
                        source: "github_advisory",
                    });
                }
            } catch {
                // Silently skip network errors
            }
        }

        return results;
    }

    // --- Private: Gemini pattern generation ---

    private async generatePatternsFromCVE(cve: CVEEntry): Promise<StagedCandidate[]> {
        if (!this.geminiService) {
            return []; // No Gemini API key configured
        }

        const prompt = `You are a security researcher. Given this vulnerability:
- ID: ${cve.cveId}
- CWEs: ${cve.cweIds.join(", ")}
- Description: ${cve.description}

Generate regex patterns that detect this attack vector in user input.
Return JSON: { "patterns": [{ "pattern": "...", "flags": "gi", "description": "...", "category": "xss|sqli|shell_injection|directory_traversal|ssrf", "severity": "low|medium|high|critical" }] }
If the vulnerability doesn't lend itself to regex detection, return { "patterns": [] }.`;

        const candidates: StagedCandidate[] = [];

        try {
            const responseText = await this.geminiService.generateRaw(prompt);
            let parsed = JSON.parse(responseText);

            if (Array.isArray(parsed)) {
                parsed = parsed[0] || {};
            }

            const patterns = parsed.patterns || [];

            for (const p of patterns) {
                if (!p.pattern || !p.category) continue;

                // Validate regex compiles
                try {
                    new RegExp(p.pattern, p.flags || "gi");
                } catch {
                    continue; // Skip invalid regex
                }

                const validCategories = [
                    "xss",
                    "sqli",
                    "shell_injection",
                    "directory_traversal",
                    "ssrf",
                ];
                if (!validCategories.includes(p.category)) continue;

                const id = `vuln-${cve.cveId.toLowerCase().replace(/[^a-z0-9]/g, "-")}-${candidates.length}`;

                candidates.push({
                    id,
                    name: `${cve.cveId}: ${p.description || p.category}`,
                    pattern: p.pattern,
                    flags: p.flags || "gi",
                    description: p.description || "",
                    category: p.category,
                    severity: p.severity || "medium",
                    cveId: cve.cveId,
                    source: cve.source,
                    generatedAt: new Date().toISOString(),
                });
            }
        } catch {
            // Gemini error or parse error — skip
        }

        return candidates;
    }

    // --- Private: Staging file I/O ---

    private loadStaging(): StagingFile {
        if (!existsSync(this.stagingPath)) {
            return { version: 1, candidates: [] };
        }
        const raw = readFileSync(this.stagingPath, "utf-8");
        return JSON.parse(raw);
    }

    private saveStaging(staging: StagingFile): void {
        this.atomicWrite(this.stagingPath, JSON.stringify(staging, null, 2));
    }

    private atomicWrite(filePath: string, content: string): void {
        const tmpPath = filePath + ".tmp";
        writeFileSync(tmpPath, content, "utf-8");
        renameSync(tmpPath, filePath);
    }

    private categoryToFlagGroup(category: string): string {
        const map: Record<string, string> = {
            xss: "hasXSS",
            sqli: "hasSQLi",
            shell_injection: "hasShellInjection",
            directory_traversal: "hasShellInjection",
            ssrf: "hasNetworkExfiltration",
        };
        return map[category] || "hasShellInjection";
    }
}

// --- Internal types ---

interface CVEEntry {
    cveId: string;
    cweIds: string[];
    description: string;
    source: "nvd" | "github_advisory";
}

interface NVDResponse {
    vulnerabilities?: Array<{
        cve: {
            id: string;
            descriptions?: Array<{ lang: string; value: string }>;
            weaknesses?: Array<{
                description?: Array<{ lang: string; value: string }>;
            }>;
        };
    }>;
}
