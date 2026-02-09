import { readFileSync, writeFileSync, existsSync, renameSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { PatternService } from "./PatternService.js";
import { GeminiService } from "./GeminiService.js";
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
    source: "nvd" | "github_advisory";
    generatedAt: string;
}

interface StagingFile {
    version: 1;
    candidates: StagedCandidate[];
}

export interface VulnFeedError {
    source: "nvd" | "github" | "gemini";
    cveId?: string;
    message: string;
}

export interface VulnFeedResult {
    fetchedCount: number;
    relevantCount: number;
    patternsGenerated: number;
    errors: VulnFeedError[];
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
    private stagingPath: string;
    private githubToken: string | null;
    private nvdApiKey: string | null;
    private nvdLimiter: RateLimiter;
    private githubLimiter: RateLimiter;

    constructor(patternService: PatternService, geminiService?: GeminiService, patternsDir?: string) {
        this.patternService = patternService;
        // Lazy: only create GeminiService if provided or API key is available
        if (geminiService) {
            this.geminiService = geminiService;
        } else if (process.env.GEMINI_API_KEY) {
            this.geminiService = new GeminiService();
        } else {
            this.geminiService = null;
        }

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
        };

        // Fetch from both sources in parallel
        const [nvdVulns, ghVulns] = await Promise.all([
            this.fetchNVD(lookbackDays).catch((err) => {
                result.errors.push({ source: "nvd", message: `NVD fetch error: ${err.message}` });
                return [] as CVEEntry[];
            }),
            this.fetchGitHubAdvisories(lookbackDays).catch((err) => {
                result.errors.push({ source: "github", message: `GitHub Advisory fetch error: ${err.message}` });
                return [] as CVEEntry[];
            }),
        ]);

        const allVulns = [...nvdVulns, ...ghVulns];
        result.fetchedCount = allVulns.length;

        // Deduplicate by CVE ID
        const unique = new Map<string, CVEEntry>();
        for (const v of allVulns) {
            if (!unique.has(v.cveId)) {
                unique.set(v.cveId, v);
            }
        }

        const relevant = Array.from(unique.values());
        result.relevantCount = relevant.length;

        // Generate patterns for each CVE using Gemini
        const staging = this.loadStaging();
        const existingPatternStrings = new Set(
            this.patternService.list().map((p) => p.pattern),
        );
        const existingStagedPatterns = new Set(
            staging.candidates.map((c) => c.pattern),
        );

        for (const vuln of relevant) {
            try {
                const candidates = await this.generatePatternsFromCVE(vuln);
                for (const candidate of candidates) {
                    // Skip duplicates
                    if (
                        existingPatternStrings.has(candidate.pattern) ||
                        existingStagedPatterns.has(candidate.pattern)
                    ) {
                        continue;
                    }

                    staging.candidates.push(candidate);
                    existingStagedPatterns.add(candidate.pattern);
                    result.patternsGenerated++;
                }
            } catch (err: any) {
                result.errors.push({ source: "gemini", cveId: vuln.cveId, message: `Pattern generation error: ${err.message}` });
            }
        }

        this.saveStaging(staging);
        return result;
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
