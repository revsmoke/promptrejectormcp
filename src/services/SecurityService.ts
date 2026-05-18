import { GeminiService, GeminiCheckResult } from "./GeminiService.js";
import { StaticCheckService, StaticCheckResult } from "./StaticCheckService.js";
import { mapGeminiCategoriesToAtlas } from "./SkillScanService.js";
import type { PatternService } from "./PatternService.js";

export interface SecurityReport {
    safe: boolean;
    overallConfidence: number;
    overallSeverity: "low" | "medium" | "high" | "critical";
    categories: string[];
    geminiAvailable: boolean;
    gemini: GeminiCheckResult;
    static: StaticCheckResult;
    /** Pass 7: MITRE ATLAS technique IDs aggregated across static + Gemini. */
    atlasTechniques: string[];
    timestamp: string;
}

/**
 * Dual-layer security aggregator for `check_prompt`.
 *
 * Runs the {@link GeminiService} semantic check and the
 * {@link StaticCheckService} pattern check in parallel, then
 * takes the maximum severity, dedupes categories, and applies the
 * safety-decision rule:
 *
 *   unsafe = overallSeverity ∈ {critical, high}
 *         OR (gemini.isInjection && gemini.confidence > 0.6)
 *
 * v1.1 additions: aggregates `atlasTechniques[]` across both layers
 * via {@link mapGeminiCategoriesToAtlas} (Gemini→ATLAS heuristic) and
 * the pattern-level `atlasTechnique` field set during static matching.
 *
 * Environment variables: none consumed directly. The Gemini key
 * (`GEMINI_API_KEY`) is handled by {@link GeminiService}.
 *
 * @example
 * ```ts
 * const svc = new SecurityService(patternService);
 * const report = await svc.runSecurityScan("ignore all previous...");
 * if (!report.safe) throw new Error(`blocked: ${report.overallSeverity}`);
 * ```
 */
export class SecurityService {
    private geminiService: GeminiService;
    private staticCheckService: StaticCheckService;

    constructor(patternService?: PatternService) {
        this.geminiService = new GeminiService();
        this.staticCheckService = new StaticCheckService(patternService);
    }

    /**
     * Run both detection layers against `prompt` and return the merged report.
     *
     * @param prompt - Untrusted user input to evaluate. Caller should bound length.
     * @returns A {@link SecurityReport} with merged severity, categories, ATLAS
     *   tags, and the underlying per-layer results. `safe: false` indicates
     *   the prompt should be blocked or escalated.
     */
    async runSecurityScan(prompt: string): Promise<SecurityReport> {
        const [geminiResult, staticResult] = await Promise.all([
            this.geminiService.checkPrompt(prompt),
            Promise.resolve(this.staticCheckService.check(prompt))
        ]);

        // Aggregate severity
        const severities: ("low" | "medium" | "high" | "critical")[] = ["low", "medium", "high", "critical"];
        const geminiSevIdx = severities.indexOf(geminiResult.severity);
        const staticSevIdx = severities.indexOf(staticResult.severity);
        const overallSeverity = severities[Math.max(geminiSevIdx, staticSevIdx)];

        // Aggregate categories
        const categories = Array.from(new Set([...geminiResult.categories, ...staticResult.categories]));

        // Decide "safe" status
        // Safe if overall severity is low OR (medium but confidence is low)
        // CRITICAL: If gemini is sure it's an injection (isInjection: true, high confidence), it's NOT safe.
        const isDangerous = overallSeverity === "critical" ||
            overallSeverity === "high" ||
            (geminiResult.isInjection && geminiResult.confidence > 0.6);

        const safe = !isDangerous;

        // Pass 7: union ATLAS techniques from static-pattern matches and the
        // Gemini-category heuristic mapping. Deduped via Set.
        const atlasTechniques = Array.from(new Set([
            ...(staticResult.atlasTechniques || []),
            ...mapGeminiCategoriesToAtlas(geminiResult.categories || []),
        ]));

        return {
            safe,
            overallConfidence: geminiResult.confidence,
            overallSeverity,
            categories,
            geminiAvailable: !geminiResult.error,
            gemini: geminiResult,
            static: staticResult,
            atlasTechniques,
            timestamp: new Date().toISOString()
        };
    }
}
