import { type GeminiCheckResult, toLegacyGemini } from "./GeminiService.js";
import { StaticCheckService, type StaticCheckResult } from "./StaticCheckService.js";
import { mapSecurityCategoriesToAtlas } from "./securityTaxonomy.js";
import type { PatternService } from "./PatternService.js";
import { SemanticAnalysisService } from "./SemanticAnalysisService.js";
import { completedCheck, semanticCoverage, qualificationCoverage, skippedCheck } from "./AnalysisCoverage.js";
import { decide, decisiveIntent, blockingSeverity, maximumSeverity, POLICY_VERSION } from "./DecisionPolicy.js";
import { validateQualifiedPatterns } from "../ai/qualification.js";
import type { JudgmentObservation } from "./JudgmentService.js";
import type { CallResult } from "../ai/contracts.js";
import type { SemanticFinding } from "../ai/taskSchemas.js";
import { promptAnalysisReportSchema, type PromptAnalysisReport } from "../schemas/AnalysisReportSchemas.js";
import { promptInputSchema } from "../ai/schemas.js";
import { JudgmentService } from "./JudgmentService.js";
import { promptJudgmentRequest } from "../ai/rubrics/prompt.js";
import { judgmentCoverage, judgmentRouting } from "../schemas/JudgmentReportSchemas.js";

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
    constructor(private readonly patternService?: PatternService, readonly semantic: SemanticAnalysisService = new SemanticAnalysisService(), readonly judgmentService = new JudgmentService(semantic.snapshot)) {
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
        if (["enforce", "cascade"].includes(this.semantic.snapshot.config.typesafe.prompt)) return this.analyzeEnforced(prompt, options.signal);
        return (await this.analyze(prompt, options.signal, true)).report;
    }
    private async analyzeEnforced(prompt: string, signal?: AbortSignal): Promise<PromptAnalysisReport> {
        promptInputSchema.parse({ prompt });
        const context = this.semantic.createContext("prompt", signal);
        const snapshot = this.semantic.snapshot;
        const mode = snapshot.config.typesafe.prompt;
        const qualified = () => !!this.patternService && validateQualifiedPatterns(snapshot, "prompt", this.patternService);
        const before = qualified();
        const local = this.staticCheckService.check(prompt);
        const localBlock = blockingSeverity(local.severity);
        let intent: JudgmentObservation | null = null;
        let semantic: CallResult<SemanticFinding> | null = null;
        const coverage = [completedCheck("local", prompt.length)];
        if (!localBlock && before) {
            intent = await this.judgmentService.evaluate("prompt", promptJudgmentRequest(prompt, "prompt", snapshot.config.typesafe.model), context, { completeSource: true });
            coverage.push(judgmentCoverage("intent_judgment", intent, prompt.length, 1));
            context.routing?.push(judgmentRouting(intent, snapshot.config.typesafe.model));
            if (!(mode === "cascade" && decisiveIntent(intent))) {
                semantic = await this.semantic.analyze(prompt, "prompt", context, true);
                coverage.push(semanticCoverage(semantic, prompt.length));
                coverage[1] = { ...coverage[1], required: false, reason: "full_reasoning_retained" };
            }
        }
        if (!semantic) coverage.push(skippedCheck("semantic", localBlock || decisiveIntent(intent) ? "conclusive_block" : "qualification_changed"));
        if (!intent) coverage.push(skippedCheck("intent_judgment", localBlock ? "conclusive_block" : "qualification_changed"));
        const current = before && qualified();
        coverage.push(qualificationCoverage(current));
        const hazardBlock = current && decisiveIntent(intent);
        const outcome = !current && !localBlock ? { decision: "unavailable" as const, safe: false }
            : decide({ task: "prompt", mode, coverage, semantic: semantic ?? undefined, localBlocking: localBlock || hazardBlock });
        const finding = semantic?.status === "ok" ? semantic.value : null;
        return promptAnalysisReportSchema.parse({ schemaVersion: 2, task: "prompt", ...outcome,
            overallSeverity: maximumSeverity(local.severity, finding?.severity ?? "low", hazardBlock ? "high" : "low"),
            categories: [...new Set([...local.categories, ...finding?.categories ?? [], ...(hazardBlock ? ["prompt_injection"] : [])])],
            findings: [...local.findings, ...(hazardBlock ? ["Qualified operative override or private-data disclosure signal."] : [])],
            atlasTechniques: [...new Set([...local.atlasTechniques, ...mapSecurityCategoriesToAtlas(finding?.categories ?? [])])],
            timestamp: new Date().toISOString(), coverage, semantic, judgments: { intent, capability: null, modelReference: null, capabilityBuckets: null }, shadow: null,
            analysisMode: mode, policyVersion: POLICY_VERSION, configHash: context.configHash, routing: context.routing ?? [],
            timings: { totalMs: Date.now() - context.budget.startedAt }, usage: context.budget.usage.summary(), static: local });
    }
    private async analyze(prompt: string, signal?: AbortSignal, v2 = false) {
        promptInputSchema.parse({ prompt });
        const context = this.semantic.createContext("prompt", signal);
        const local = this.staticCheckService.check(prompt);
        const semantic = await this.semantic.analyze(prompt, "prompt", context);
        const coverage = [completedCheck("local", prompt.length), semanticCoverage(semantic, prompt.length)];
        const outcome = decide({ task: "prompt", coverage, semantic, localBlocking: blockingSeverity(local.severity) });
        context.budget.authorizeShadow({ requiredWorkComplete: true });
        const intent = v2 ? await this.judgmentService.evaluate("prompt", promptJudgmentRequest(prompt, "prompt", this.semantic.snapshot.config.typesafe.model), context, { completeSource: true }) : null;
        if (intent) { coverage.push(judgmentCoverage("intent_judgment", intent, prompt.length, 1)); context.routing?.push(judgmentRouting(intent, this.semantic.snapshot.config.typesafe.model)); }
        const finding = semantic.status === "ok" ? semantic.value : null;
        const categories = [...new Set([...local.categories, ...(finding?.categories ?? [])])];
        const report = promptAnalysisReportSchema.parse({
            schemaVersion: 2, task: "prompt", ...outcome,
            overallSeverity: maximumSeverity(local.severity, finding?.severity ?? "low"), categories,
            findings: [...local.findings], atlasTechniques: [...new Set([...local.atlasTechniques, ...mapSecurityCategoriesToAtlas(finding?.categories ?? [])])],
            timestamp: new Date().toISOString(), coverage, semantic, judgments: null, shadow: intent?.mode === "shadow" ? { intent, capability: null, modelReference: null, capabilityBuckets: null } : null,
            analysisMode: this.semantic.snapshot.config.typesafe.prompt, policyVersion: POLICY_VERSION, configHash: context.configHash,
            routing: context.routing ?? [], timings: { totalMs: Date.now() - context.budget.startedAt }, usage: context.budget.usage.summary(), static: local,
        });
        return { report, gemini: toLegacyGemini(semantic) };
    }
}
