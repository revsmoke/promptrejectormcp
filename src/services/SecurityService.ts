import { GeminiService, GeminiCheckResult } from "./GeminiService.js";
import { StaticCheckService, StaticCheckResult } from "./StaticCheckService.js";
import type { PatternService } from "./PatternService.js";

export interface SecurityReport {
    safe: boolean;
    overallConfidence: number;
    overallSeverity: "low" | "medium" | "high" | "critical";
    categories: string[];
    geminiAvailable: boolean;
    gemini: GeminiCheckResult;
    static: StaticCheckResult;
    timestamp: string;
}

export class SecurityService {
    private geminiService: GeminiService;
    private staticCheckService: StaticCheckService;

    constructor(patternService?: PatternService) {
        this.geminiService = new GeminiService();
        this.staticCheckService = new StaticCheckService(patternService);
    }

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

        return {
            safe,
            overallConfidence: geminiResult.confidence,
            overallSeverity,
            categories,
            geminiAvailable: !geminiResult.error,
            gemini: geminiResult,
            static: staticResult,
            timestamp: new Date().toISOString()
        };
    }
}
