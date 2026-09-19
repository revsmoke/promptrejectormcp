import { type GeminiCheckResult, toLegacyGemini } from "./GeminiService.js";
import { StaticCheckService, type StaticCheckResult } from "./StaticCheckService.js";
import { mapSecurityCategoriesToAtlas } from "./securityTaxonomy.js";
import type { PatternService } from "./PatternService.js";
import { SemanticAnalysisService } from "./SemanticAnalysisService.js";
import { completedCheck, semanticCoverage } from "./AnalysisCoverage.js";
import { decide, blockingSeverity, maximumSeverity, POLICY_VERSION } from "./DecisionPolicy.js";
import { promptAnalysisReportSchema, type PromptAnalysisReport } from "../schemas/AnalysisReportSchemas.js";
import { promptInputSchema } from "../ai/schemas.js";

export interface SecurityReport {
    safe: boolean;
    overallConfidence: number;
    overallSeverity: "low" | "medium" | "high" | "critical";
    categories: string[];
    geminiAvailable: boolean;
    gemini: GeminiCheckResult;
    static: StaticCheckResult;
    atlasTechniques: string[];
    timestamp: string;
}
export class ReportVersionRequiredError extends Error {
    readonly code = "report_version_required";
    constructor() { super("Selected semantic profiles require report version 2"); }
}
/** The v1 compatibility mapper and v2 policy share the same single analysis. */
export class SecurityService {
    private readonly staticCheckService: StaticCheckService;
    constructor(patternService?: PatternService, readonly semantic: SemanticAnalysisService = new SemanticAnalysisService()) {
        this.staticCheckService = new StaticCheckService(patternService);
    }
    get supportsV1(): boolean { return this.semantic.supportsV1; }
    async runSecurityScan(prompt: string, options: { signal?: AbortSignal } = {}): Promise<SecurityReport> {
        if (!this.supportsV1) throw new ReportVersionRequiredError();
        const { report, gemini } = await this.analyze(prompt, options.signal);
        const overallSeverity = maximumSeverity(report.static.severity, gemini.severity);
        return { safe: !gemini.error && !blockingSeverity(overallSeverity) && !(gemini.isInjection && gemini.confidence > 0.6),
            overallConfidence: gemini.confidence, overallSeverity,
            categories: [...new Set([...gemini.categories, ...report.static.categories])],
            geminiAvailable: !gemini.error, gemini, static: report.static as StaticCheckResult,
            atlasTechniques: report.atlasTechniques, timestamp: report.timestamp };
    }
    async runSecurityScanV2(prompt: string, options: { signal?: AbortSignal } = {}): Promise<PromptAnalysisReport> {
        return (await this.analyze(prompt, options.signal)).report;
    }
    private async analyze(prompt: string, signal?: AbortSignal) {
        promptInputSchema.parse({ prompt });
        const context = this.semantic.createContext("prompt", signal);
        const local = this.staticCheckService.check(prompt);
        const semantic = await this.semantic.analyze(prompt, "prompt", context);
        const coverage = [completedCheck("local", prompt.length), semanticCoverage(semantic, prompt.length)];
        const outcome = decide({ task: "prompt", coverage, semantic, localBlocking: blockingSeverity(local.severity) });
        const finding = semantic.status === "ok" ? semantic.value : null;
        const categories = [...new Set([...local.categories, ...(finding?.categories ?? [])])];
        const report = promptAnalysisReportSchema.parse({
            schemaVersion: 2, task: "prompt", ...outcome,
            overallSeverity: maximumSeverity(local.severity, finding?.severity ?? "low"), categories,
            findings: [...local.findings], atlasTechniques: [...new Set([...local.atlasTechniques, ...mapSecurityCategoriesToAtlas(finding?.categories ?? [])])],
            timestamp: new Date().toISOString(), coverage, semantic, judgments: null,
            analysisMode: this.semantic.snapshot.config.typesafe.prompt, policyVersion: POLICY_VERSION, configHash: context.configHash,
            routing: context.routing ?? [], timings: { totalMs: Date.now() - context.budget.startedAt }, usage: context.budget.usage.summary(), static: local,
        });
        return { report, gemini: toLegacyGemini(semantic) };
    }
}
