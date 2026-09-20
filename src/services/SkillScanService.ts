import { type GeminiCheckResult, toLegacyGemini } from "./GeminiService.js";
import { SemanticAnalysisService } from "./SemanticAnalysisService.js";
import { ReportVersionRequiredError } from "./SecurityService.js";
import { mapSecurityCategoriesToAtlas } from "./securityTaxonomy.js";
import { completedCheck, semanticCoverage, qualificationCoverage, skippedCheck, type CoverageEntry } from "./AnalysisCoverage.js";
import { decide, decisiveIntent, blockingSeverity, maximumSeverity, POLICY_VERSION } from "./DecisionPolicy.js";
import { skillAnalysisReportSchema, type SkillAnalysisReport } from "../schemas/AnalysisReportSchemas.js";
import { skillInputSchema } from "../ai/schemas.js";
import { withDeadline } from "../ai/transport.js";
import { JudgmentService, effectiveJudgmentMode, type JudgmentObservation } from "./JudgmentService.js";
import { promptJudgmentRequest } from "../ai/rubrics/prompt.js";
import { judgmentCoverage, judgmentRouting } from "../schemas/JudgmentReportSchemas.js";
import { CapabilityAnalysisService, type CapabilityStates } from "./CapabilityAnalysisService.js";
import type { CallResult } from "../ai/contracts.js";
import type { SemanticFinding } from "../ai/taskSchemas.js";
import { validateQualifiedPatterns } from "../ai/qualification.js";
import type { TrustedCapabilityContext } from "./TrustedCapabilityResolver.js";
import { ModelReferenceService } from "./ModelReferenceService.js";
import { StaticCheckService } from "./StaticCheckService.js";
import type { PatternService, ActivePattern } from "./PatternService.js";
import { TrifectaAnalyzer, type TrifectaResult } from "./TrifectaAnalyzer.js";
import { HuggingFaceService, type HuggingFaceModelFlag, type HuggingFaceModelReport } from "./HuggingFaceService.js";

export interface SkillScanResult {
    safe: boolean;
    geminiAvailable: boolean;
    analysisAvailable: boolean;
    geminiConfidence: number; // Confidence score from LLM analysis only
    overallSeverity: "low" | "medium" | "high" | "critical";
    categories: string[];
    skillSpecific: SkillSpecificFindings;
    gemini: GeminiCheckResult;
    static: {
        hasXSS: boolean;
        hasSQLi: boolean;
        hasShellInjection: boolean;
        severity: "low" | "medium" | "high" | "critical";
        categories: string[];
        findings: string[];
        atlasTechniques?: string[];
    };
    // Pass 5: Lethal-trifecta capability analysis (Willison).
    hasLethalTrifecta: boolean;
    trifectaResult: TrifectaResult;
    /** Pass 7: Aggregated MITRE ATLAS technique IDs across all sub-checks. */
    atlasTechniques: string[];
    /** Pass 8: Flat list of HF security findings across all detected model IDs. */
    huggingFaceSecurityFlags: HuggingFaceModelFlag[];
    /** Pass 8: Per-model reports for richer downstream consumers. */
    huggingFaceReports: HuggingFaceModelReport[];
    timestamp: string;
}

export interface SkillSpecificFindings {
    hasHiddenInstructions: boolean;
    hasDangerousToolUsage: boolean;
    hasSensitiveFileAccess: boolean;
    hasObfuscation: boolean;
    hasSocialEngineering: boolean;
    hasNetworkExfiltration: boolean;
    findings: string[];
    severity: "low" | "medium" | "high" | "critical";
    categories: string[];
}

const SEVERITIES: readonly ("low" | "medium" | "high" | "critical")[] = ["low", "medium", "high", "critical"];

function severityIdx(s: string): number {
    return SEVERITIES.indexOf(s as any);
}

/**
 * Pass 7: map Gemini's category vocabulary to MITRE ATLAS technique IDs.
 * Mirrors SPEC §7. Categories that pre-date ATLAS or aren't AI-specific
 * (xss, sqli, shell, social_engineering, multilingual) are intentionally
 * absent — we'd rather report no tag than a misleading one.
 */
export function mapGeminiCategoriesToAtlas(categories: string[]): string[] {
    return mapSecurityCategoriesToAtlas(categories);
}

/**
 * Multi-layer scanner for SKILL.md content.
 *
 * Aggregates results from four sub-services into a single
 * {@link SkillScanResult}:
 * - {@link GeminiService} — semantic LLM classification
 * - {@link StaticCheckService} — regex/pattern detection (general + skill-scoped)
 * - {@link TrifectaAnalyzer} — Willison's lethal-trifecta capability analysis
 * - {@link HuggingFaceService} — security signals for any HF model IDs referenced
 *
 * Round-2 semantic fix: a 3-of-3 lethal trifecta now forces
 * `overallSeverity = "critical"` and `isDangerous = true`. Previously the
 * trifecta result was reported on `hasLethalTrifecta` but did not bubble up
 * into the safe/unsafe decision. 2-of-3 contributes `medium` severity but
 * does not add the synthetic `lethal_trifecta` category or force unsafe.
 *
 * v1.1 result-type additions: `hasLethalTrifecta`, `trifectaResult`,
 * `huggingFaceSecurityFlags`, `huggingFaceReports`, `atlasTechniques[]`.
 *
 * HF integration: extracts model IDs from skill content via
 * {@link HuggingFaceService.extractModelIds}, then fans out to
 * `checkModel()` in parallel (`Promise.allSettled`) and rolls severity
 * into the final result.
 *
 * Also exports {@link mapGeminiCategoriesToAtlas} as a top-level helper
 * shared with {@link SecurityService}.
 *
 * Environment variables: none consumed directly (delegates to sub-services).
 */
export class SkillScanService {
    private staticCheckService: StaticCheckService;
    private patternService: PatternService | null;
    private trifectaAnalyzer: TrifectaAnalyzer;
    private huggingFaceService: HuggingFaceService;

    constructor(patternService?: PatternService, huggingFaceService?: HuggingFaceService, readonly semantic: SemanticAnalysisService = new SemanticAnalysisService(), readonly judgmentService = new JudgmentService(semantic.snapshot), readonly capabilityAnalysis = new CapabilityAnalysisService(judgmentService), readonly modelReferences = new ModelReferenceService(judgmentService)) {
        this.patternService = patternService ?? null;
        this.staticCheckService = new StaticCheckService(patternService);
        this.trifectaAnalyzer = new TrifectaAnalyzer();
        // Pass 8: HF security signals. Default keeps existing call sites working;
        // mcpServer passes a shared instance so the in-memory cache is reused
        // across scans.
        this.huggingFaceService = huggingFaceService ?? new HuggingFaceService();
    }

    get supportsV1(): boolean { return this.semantic.supportsV1; }

    async scanSkill(skillContent: string, options: { signal?: AbortSignal } = {}): Promise<SkillScanResult> {
        if (!this.supportsV1) throw new ReportVersionRequiredError();
        return (await this.analyze(skillContent, options.signal)).legacy;
    }

    async scanSkillV2(skillContent: string, options: { signal?: AbortSignal; trustedContext?: TrustedCapabilityContext } = {}): Promise<SkillAnalysisReport> {
        if (["enforce", "cascade"].includes(this.semantic.snapshot.config.typesafe.skill)) return this.analyzeEnforced(skillContent, options.signal, options.trustedContext);
        return (await this.analyze(skillContent, options.signal, true)).report;
    }

    private async analyzeEnforced(skillContent: string, signal?: AbortSignal, trustedContext?: TrustedCapabilityContext): Promise<SkillAnalysisReport> {
        skillInputSchema.parse({ skillContent });
        const context = this.semantic.createContext("skill", signal);
        const snapshot = this.semantic.snapshot;
        const mode = snapshot.config.typesafe.skill;
        const capabilityMode = effectiveJudgmentMode(snapshot, "capability", "skill");
        const referenceMode = effectiveJudgmentMode(snapshot, "modelReference", "skill");
        const qualified = () => !!this.patternService && ["skill", ...(capabilityMode === "enforce" ? ["capability"] : []), ...(referenceMode === "enforce" ? ["modelReference"] : [])].every((task) => validateQualifiedPatterns(snapshot, task as "skill" | "capability" | "modelReference", this.patternService!));
        const before = qualified();
        const local = this.staticCheckService.check(skillContent);
        const skillSpecific = this.runSkillSpecificChecks(skillContent);
        const trifecta = this.trifectaAnalyzer.analyze({ skillContent });
        const references = this.modelReferences.extract(skillContent);
        const localSeverity = maximumSeverity(local.severity, skillSpecific.severity, trifecta.severity === "safe" ? "low" : trifecta.severity);
        const localBlock = blockingSeverity(localSeverity) || skillSpecific.hasDangerousToolUsage || skillSpecific.hasNetworkExfiltration || trifecta.trifectaPresent;
        const coverage: CoverageEntry[] = [completedCheck("local", skillContent.length), completedCheck("skill", skillContent.length)];
        let intent: JudgmentObservation | null = null;
        let capability: Awaited<ReturnType<CapabilityAnalysisService["observe"]>> | null = null;
        let reference: Awaited<ReturnType<ModelReferenceService["observe"]>> | null = null;
        let semantic: CallResult<SemanticFinding> | null = null;
        let capabilityStates: CapabilityStates | null = null;
        let hfReports: HuggingFaceModelReport[] = [];
        let lookupIds = references.baselineIds;
        let unresolvedIds: string[] = [];
        let capabilityReview = [trifecta.privateDataRead, trifecta.untrustedContentFetch, trifecta.externalEgress].filter((bucket) => bucket.present).length === 2;
        let capabilityBlock = false;
        let failedLookups = false;
        let referenceComplete = true;
        if (!localBlock && before) {
            intent = await this.judgmentService.evaluate("skill", promptJudgmentRequest(skillContent, "skill", snapshot.config.typesafe.model), context, { completeSource: true });
            if (!(mode === "cascade" && decisiveIntent(intent))) {
                // Only required children run before the reasoner. Optional
                // children wait until all authoritative spend is complete.
                [capability, reference] = await Promise.all([
                    capabilityMode === "enforce" ? this.capabilityAnalysis.observe({ skillContent }, context, { parentTask: "skill", trustedContext }) : Promise.resolve(null),
                    referenceMode === "enforce" ? this.modelReferences.observe(skillContent, references, context, "skill") : Promise.resolve(null),
                ]);
                capabilityStates = capability?.buckets ?? null;
                lookupIds = reference?.lookupIds ?? lookupIds;
                unresolvedIds = reference?.unresolvedIds ?? [];
                const capabilityRequired = !!capabilityStates && this.capabilityAnalysis.outcome(capabilityStates).review;
                const unresolvedCandidates = references.candidates.filter((candidate) => unresolvedIds.includes(candidate.id));
                if (capabilityRequired || unresolvedCandidates.length) {
                    const assessed = await this.semantic.analyzeSkill(skillContent, this.capabilityAnalysis.sources({ skillContent }), capabilityStates, unresolvedCandidates, context, capabilityRequired);
                    semantic = assessed.status === "ok" ? { ...assessed, value: assessed.value.security } : assessed;
                    if (assessed.status === "ok") {
                        if (capabilityStates) capabilityStates = this.capabilityAnalysis.resolve(capabilityStates, assessed.value.capabilities);
                        // Context may establish that an unresolved span is not a
                        // model. It cannot remove incumbents or invent additions.
                        const excluded = new Set(assessed.value.references.filter((item) => item.classification === "not_model").map((item) => item.id));
                        unresolvedIds = unresolvedIds.filter((id) => !excluded.has(id));
                    }
                } else semantic = await this.semantic.analyze(skillContent, "skill", context, true);
                if (capabilityStates) {
                    const derived = this.capabilityAnalysis.outcome(capabilityStates);
                    capabilityBlock = derived.block;
                    capabilityReview = derived.review;
                }
                referenceComplete = referenceMode !== "enforce" || (!references.candidateOverflow && unresolvedIds.length === 0);
                const settled = await Promise.allSettled(lookupIds.slice(0, 16).map((id) => withDeadline((hfSignal) => this.huggingFaceService.checkModel(id, { signal: hfSignal, deadlineMs: context.deadlineMs }), context.deadlineMs, signal)));
                hfReports = settled.filter((result): result is PromiseFulfilledResult<HuggingFaceModelReport> => result.status === "fulfilled").map((result) => result.value);
                failedLookups = settled.some((result) => result.status === "rejected") || hfReports.some((report) => report.flags.some((flag) => flag.class === "lookup_failed"));
                context.budget.authorizeShadow({ requiredWorkComplete: true });
                if (capabilityMode === "shadow") capability = await this.capabilityAnalysis.observe({ skillContent }, context, { parentTask: "skill", trustedContext });
                if (referenceMode === "shadow") reference = await this.modelReferences.observe(skillContent, references, context, "skill");
            }
        }
        const conclusiveSkip = localBlock || (mode === "cascade" && decisiveIntent(intent));
        const skippedReason = conclusiveSkip ? "conclusive_block" : "qualification_changed";
        if (semantic) coverage.push(semanticCoverage(semantic, skillContent.length));
        else coverage.push(skippedCheck("semantic", conclusiveSkip ? "conclusive_block" : "qualification_changed"));
        for (const [check, observation] of [["intent_judgment", intent], ["capability_judgment", capability?.judgments], ["reference_judgment", reference?.judgments]] as const) {
            if (!observation) {
                const enabled = check === "intent_judgment" || check === "capability_judgment" && capabilityMode === "enforce" || check === "reference_judgment" && referenceMode === "enforce";
                if (enabled && (conclusiveSkip || !before)) coverage.push(skippedCheck(check, skippedReason));
                continue;
            }
            const entry = judgmentCoverage(check, observation, skillContent.length, 1);
            // Full reasoning resolves uncertainty after a failed small-model
            // judgment. Its own coverage remains required independently.
            if (semantic && entry.required) { entry.required = false; entry.reason = "full_reasoning_retained"; }
            coverage.push(entry);
            context.routing?.push(judgmentRouting(observation, snapshot.config.typesafe.model));
        }
        coverage.push(conclusiveSkip || !before ? skippedCheck("capability", skippedReason) : { ...completedCheck("capability", skillContent.length, "declared"), status: capabilityMode === "enforce" && capabilityReview ? "partial" : "complete", reason: capabilityReview ? "unknown_scope" : "declared_scope" });
        const hfComplete = !failedLookups && lookupIds.length <= 16 && referenceComplete;
        coverage.push(conclusiveSkip || !before ? skippedCheck("hugging_face", skippedReason) : { ...completedCheck("hugging_face", skillContent.length, "external"), inspectedFields: hfReports.length,
            status: hfComplete ? "complete" : "partial", reason: lookupIds.length > 16 ? "reference_limit" : !referenceComplete ? references.candidateOverflow ? "candidate_limit" : "unresolved_references" : failedLookups ? "lookup_failed" : null });
        const current = before && qualified();
        coverage.push(qualificationCoverage(current));
        const flags = hfReports.flatMap((report) => report.flags);
        const hfSeverity = maximumSeverity(...hfReports.map((report) => report.severity === "safe" ? "low" : report.severity));
        const hazardBlock = current && decisiveIntent(intent);
        const finding = semantic?.status === "ok" ? semantic.value : null;
        // Qualification drift disables new model decisions, but cannot erase
        // an independently observed local or Hugging Face blocking finding.
        const incumbentBlock = localBlock || blockingSeverity(hfSeverity);
        const outcome = !current && !incumbentBlock ? { decision: "unavailable" as const, safe: false }
            : decide({ task: "skill", mode, coverage, semantic: semantic ?? undefined, needsReview: capabilityReview || unresolvedIds.length > 0,
                localBlocking: incumbentBlock || hazardBlock || current && capabilityBlock });
        const allTrifecta = trifecta.trifectaPresent || (current && capabilityBlock);
        return skillAnalysisReportSchema.parse({ schemaVersion: 2, task: "skill", ...outcome,
            overallSeverity: maximumSeverity(localSeverity, hfSeverity, finding?.severity ?? "low", hazardBlock ? "high" : "low", allTrifecta ? "critical" : "low"),
            categories: [...new Set([...local.categories, ...skillSpecific.categories, ...finding?.categories ?? [], ...(allTrifecta ? ["lethal_trifecta"] : []), ...(hazardBlock ? ["prompt_injection"] : [])])],
            findings: [...local.findings, ...skillSpecific.findings, ...flags.map((flag) => flag.note), ...(hazardBlock ? ["Qualified operative override or private-data disclosure signal."] : []), ...(capabilityBlock ? ["Three supported capability buckets form a lethal trifecta."] : [])],
            atlasTechniques: [...new Set([...local.atlasTechniques, ...mapSecurityCategoriesToAtlas(finding?.categories ?? []), ...(allTrifecta ? ["AML.T0024", "AML.T0051"] : [])])],
            timestamp: new Date().toISOString(), coverage, semantic, judgments: { intent, capability: capabilityMode === "enforce" ? capability?.judgments ?? null : null, modelReference: referenceMode === "enforce" ? reference?.judgments ?? null : null, capabilityBuckets: capabilityStates },
            shadow: capabilityMode === "shadow" || referenceMode === "shadow" ? { intent: null, capability: capabilityMode === "shadow" ? capability?.judgments ?? null : null, modelReference: referenceMode === "shadow" ? reference?.judgments ?? null : null, capabilityBuckets: capabilityMode === "shadow" ? capability?.buckets ?? null : null } : null,
            modelReferences: { candidates: references.candidates, candidateCount: references.candidateCount, candidateOverflow: references.candidateOverflow, parserCorrections: references.parserCorrections, baselineIds: references.baselineIds, lookupIds, unresolvedIds, shadowAdditions: referenceMode === "shadow" ? reference?.additions ?? [] : [] },
            analysisMode: mode, policyVersion: POLICY_VERSION, configHash: context.configHash, routing: context.routing ?? [], timings: { totalMs: Date.now() - context.budget.startedAt }, usage: context.budget.usage.summary(),
            static: local, skillSpecific, trifectaResult: trifecta, hasLethalTrifecta: allTrifecta, huggingFaceSecurityFlags: flags, huggingFaceReports: hfReports });
    }

    private async analyze(skillContent: string, signal?: AbortSignal, v2 = false) {
        skillInputSchema.parse({ skillContent });
        const context = this.semantic.createContext("skill", signal);
        // Pass 8: extract HF model ids first (sync, cheap) so we can fan out
        // network requests in parallel with the LLM + static checks.
        const references = this.modelReferences.extract(skillContent);
        const allModelIds = references.baselineIds;
        const modelIds = allModelIds.slice(0, 16);
        let failedHfLookups = 0;
        const hfCheckPromise = modelIds.length === 0
            ? Promise.resolve([] as HuggingFaceModelReport[])
            : Promise.allSettled(modelIds.map((id) => withDeadline((hfSignal) => this.huggingFaceService.checkModel(id, { signal: hfSignal, deadlineMs: context.deadlineMs }), context.deadlineMs, signal)))
                  .then((settled) => {
                      failedHfLookups = settled.filter((item) => item.status === "rejected").length;
                      return settled
                          .filter((s): s is PromiseFulfilledResult<HuggingFaceModelReport> => s.status === "fulfilled")
                          .map((s) => s.value);
                  });

        const [semanticResult, staticResult, skillSpecificResult, hfReports] = await Promise.all([
            this.semantic.analyze(skillContent, "skill", context),
            Promise.resolve(this.staticCheckService.check(skillContent)),
            Promise.resolve(this.runSkillSpecificChecks(skillContent)),
            hfCheckPromise,
        ]);
        const geminiResult = toLegacyGemini(semanticResult);
        const hfComplete = allModelIds.length <= 16 && failedHfLookups === 0 && !hfReports.some((report) => report.flags.some((flag) => flag.class === "lookup_failed"));

        // Pass 5: lethal-trifecta capability classification (sync, cheap).
        const trifectaResult = this.trifectaAnalyzer.analyze({ skillContent });

        // Pass 8: flatten HF flags + compute their severity contribution.
        const huggingFaceSecurityFlags: HuggingFaceModelFlag[] = [];
        for (const r of hfReports) huggingFaceSecurityFlags.push(...r.flags);
        // Map HF severity ladder (safe/low/medium/high/critical) onto the
        // 4-level skill scan ladder. "safe" → "low" (we don't have a safer level).
        const HF_TO_SKILL_SEV: Record<HuggingFaceModelReport["severity"], "low" | "medium" | "high" | "critical"> = {
            safe: "low",
            low: "low",
            medium: "medium",
            high: "high",
            critical: "critical",
        };
        let hfSeverity: "low" | "medium" | "high" | "critical" = "low";
        for (const r of hfReports) {
            const mapped = HF_TO_SKILL_SEV[r.severity];
            if (SEVERITIES.indexOf(mapped) > SEVERITIES.indexOf(hfSeverity)) {
                hfSeverity = mapped;
            }
        }

        // Aggregate severity
        // why: TrifectaAnalyzer reports its own severity ladder ("safe" | "medium" | "critical").
        // SPEC §2 + §7 list lethal_trifecta as a composite critical-severity category, so the
        // final rollup must fold the trifecta result in — otherwise a 3-of-3 skill (read+fetch+egress)
        // can slip through as `safe: true` when no other sub-check fires high/critical.
        const TRIFECTA_TO_SKILL_SEV: Record<TrifectaResult["severity"], "low" | "medium" | "high" | "critical"> = {
            safe: "low",
            medium: "medium",
            critical: "critical",
        };
        const trifectaSeverityMapped = TRIFECTA_TO_SKILL_SEV[trifectaResult.severity];
        const geminiSevIdx = SEVERITIES.indexOf(geminiResult.severity);
        const staticSevIdx = SEVERITIES.indexOf(staticResult.severity);
        const skillSevIdx = SEVERITIES.indexOf(skillSpecificResult.severity);
        const hfSevIdx = SEVERITIES.indexOf(hfSeverity);
        const trifectaSevIdx = SEVERITIES.indexOf(trifectaSeverityMapped);
        const overallSeverity = SEVERITIES[Math.max(geminiSevIdx, staticSevIdx, skillSevIdx, hfSevIdx, trifectaSevIdx)];

        // Aggregate categories. When trifectaPresent we add a synthetic
        // `lethal_trifecta` category so downstream consumers can see *why* the
        // composite severity bumped to critical without re-running the analyzer.
        const categories = Array.from(new Set([
            ...geminiResult.categories,
            ...staticResult.categories,
            ...skillSpecificResult.categories,
            ...(trifectaResult.trifectaPresent ? ["lethal_trifecta"] : []),
        ]));

        // Decide "safe" status. trifectaPresent OR'd in so all-three-buckets
        // forces dangerous even when each sub-check on its own stayed low/medium.
        const isDangerous =
            overallSeverity === "critical" ||
            overallSeverity === "high" ||
            (geminiResult.isInjection && geminiResult.confidence > 0.6) ||
            skillSpecificResult.hasDangerousToolUsage ||
            skillSpecificResult.hasNetworkExfiltration ||
            trifectaResult.trifectaPresent;

        const safe = !isDangerous && !geminiResult.error && hfComplete;

        // Pass 7: aggregate ATLAS techniques across static + Gemini (skill-specific
        // checks don't carry pattern entries today; future ATLAS hooks can fold in here).
        // SPEC §7 maps `lethal_trifecta → AML.T0024 + AML.T0051` (composite). Add both
        // when the trifecta is present; Set dedup handles overlap with other sub-checks.
        const atlasTechniques = Array.from(new Set([
            ...(staticResult.atlasTechniques || []),
            ...mapGeminiCategoriesToAtlas(geminiResult.categories || []),
            ...(trifectaResult.trifectaPresent ? ["AML.T0024", "AML.T0051"] : []),
        ]));

        const legacy: SkillScanResult = {
            safe,
            geminiAvailable: !geminiResult.error,
            analysisAvailable: !geminiResult.error && hfComplete,
            geminiConfidence: geminiResult.confidence,
            overallSeverity,
            categories,
            skillSpecific: skillSpecificResult,
            gemini: geminiResult,
            static: staticResult,
            hasLethalTrifecta: trifectaResult.trifectaPresent,
            trifectaResult,
            atlasTechniques,
            huggingFaceSecurityFlags,
            huggingFaceReports: hfReports,
            timestamp: new Date().toISOString()
        };
        const capabilityNeedsReview = [trifectaResult.privateDataRead, trifectaResult.untrustedContentFetch, trifectaResult.externalEgress].filter((bucket) => bucket.present).length === 2;
        const hfCoverage: CoverageEntry = { ...completedCheck("hugging_face", skillContent.length, "external"),
            inspectedFields: hfReports.length, status: hfComplete ? "complete" : "partial",
            reason: allModelIds.length > 16 ? "reference_limit" : !hfComplete ? "lookup_failed" : null };
        const coverage = [completedCheck("local", skillContent.length), completedCheck("skill", skillContent.length),
            { ...completedCheck("capability", skillContent.length, "declared"), reason: "local_declared_scope" },
            hfCoverage, semanticCoverage(semanticResult, skillContent.length)];
        const localSeverity = maximumSeverity(staticResult.severity, skillSpecificResult.severity, hfSeverity, trifectaSeverityMapped);
        const outcome = decide({ task: "skill", coverage, semantic: semanticResult, needsReview: capabilityNeedsReview,
            localBlocking: blockingSeverity(localSeverity) || skillSpecificResult.hasDangerousToolUsage || skillSpecificResult.hasNetworkExfiltration || trifectaResult.trifectaPresent });
        context.budget.authorizeShadow({ requiredWorkComplete: true });
        const [intent, capabilityObservation, referenceObservation] = v2 ? await Promise.all([
            this.judgmentService.evaluate("skill", promptJudgmentRequest(skillContent, "skill", this.semantic.snapshot.config.typesafe.model), context, { completeSource: true }),
            this.capabilityAnalysis.observe({ skillContent }, context, { parentTask: "skill" }),
            this.modelReferences.observe(skillContent, references, context, "skill"),
        ]) : [null, null, null];
        for (const [check, observation] of [["intent_judgment", intent], ["capability_judgment", capabilityObservation?.judgments], ["reference_judgment", referenceObservation?.judgments]] as const) {
            if (observation) { coverage.push(judgmentCoverage(check, observation, skillContent.length, 1)); context.routing?.push(judgmentRouting(observation, this.semantic.snapshot.config.typesafe.model)); }
        }
        const finding = semanticResult.status === "ok" ? semanticResult.value : null;
        const v2Categories = [...new Set([...staticResult.categories, ...skillSpecificResult.categories, ...(finding?.categories ?? []), ...(trifectaResult.trifectaPresent ? ["lethal_trifecta"] : [])])];
        const report = skillAnalysisReportSchema.parse({
            schemaVersion: 2, task: "skill", ...outcome, overallSeverity: maximumSeverity(localSeverity, finding?.severity ?? "low"),
            categories: v2Categories, findings: [...staticResult.findings, ...skillSpecificResult.findings, ...huggingFaceSecurityFlags.map((flag) => flag.note)],
            atlasTechniques: [...new Set([...staticResult.atlasTechniques, ...mapSecurityCategoriesToAtlas(finding?.categories ?? []), ...(trifectaResult.trifectaPresent ? ["AML.T0024", "AML.T0051"] : [])])],
            timestamp: legacy.timestamp, coverage, semantic: semanticResult, judgments: null, shadow: intent?.mode === "shadow" ? { intent, capability: capabilityObservation?.judgments ?? null, modelReference: referenceObservation?.judgments ?? null, capabilityBuckets: capabilityObservation?.judgments.mode === "shadow" ? capabilityObservation.buckets : null } : null,
            modelReferences: { baselineIds: allModelIds, candidates: references.candidates, candidateCount: references.candidateCount, candidateOverflow: references.candidateOverflow, parserCorrections: references.parserCorrections, shadowAdditions: referenceObservation?.judgments?.mode === "shadow" ? referenceObservation.additions : [] },
            analysisMode: this.semantic.snapshot.config.typesafe.skill, policyVersion: POLICY_VERSION, configHash: context.configHash,
            routing: context.routing ?? [], timings: { totalMs: Date.now() - context.budget.startedAt }, usage: context.budget.usage.summary(),
            static: staticResult, skillSpecific: skillSpecificResult, trifectaResult, hasLethalTrifecta: trifectaResult.trifectaPresent,
            huggingFaceSecurityFlags, huggingFaceReports: hfReports,
        });
        return { legacy, report };
    }

    private runSkillSpecificChecks(content: string): SkillSpecificFindings {
        if (this.patternService) {
            return this.runSkillChecksWithPatternService(content);
        }
        return this.runSkillChecksWithHardcoded(content);
    }

    private runSkillChecksWithPatternService(content: string): SkillSpecificFindings {
        const findings: string[] = [];
        const categories: string[] = [];
        let severity: "low" | "medium" | "high" | "critical" = "low";

        const patterns = this.patternService!.getActivePatterns("skill");

        // Group patterns by flagGroup
        const groups = new Map<string, ActivePattern[]>();
        for (const p of patterns) {
            const group = groups.get(p.entry.flagGroup) || [];
            group.push(p);
            groups.set(p.entry.flagGroup, group);
        }

        const flags: Record<string, boolean> = {
            hasHiddenInstructions: false,
            hasDangerousToolUsage: false,
            hasSensitiveFileAccess: false,
            hasObfuscation: false,
            hasSocialEngineering: false,
            hasNetworkExfiltration: false,
        };

        for (const [flagGroup, groupPatterns] of groups) {
            for (const { entry, regex } of groupPatterns) {
                let triggered = false;

                if (entry.detection.mode === "threshold") {
                    const matches = content.match(regex);
                    if (matches) {
                        const countThreshold = entry.detection.countThreshold;
                        const singleMatchLength = entry.detection.singleMatchLength;

                        const exceedsCount = countThreshold !== undefined && matches.length > countThreshold;
                        const exceedsLength = singleMatchLength !== undefined && matches.some(m => m.length >= singleMatchLength);

                        triggered = exceedsCount || exceedsLength;
                    }
                } else {
                    triggered = regex.test(content);
                }

                if (triggered) {
                    // Build finding message based on flag group
                    if (flagGroup === "hasHiddenInstructions") {
                        findings.push("Hidden instructions detected in HTML comments");
                    } else if (flagGroup === "hasDangerousToolUsage") {
                        findings.push(`Dangerous tool usage detected: ${entry.pattern}`);
                    } else if (flagGroup === "hasSensitiveFileAccess") {
                        findings.push(`Sensitive file access detected: ${entry.pattern}`);
                    } else if (flagGroup === "hasObfuscation") {
                        findings.push("Obfuscation detected: potential encoded content");
                    } else if (flagGroup === "hasSocialEngineering") {
                        findings.push("Social engineering indicators detected");
                    } else if (flagGroup === "hasNetworkExfiltration") {
                        findings.push(`Potential data exfiltration detected: ${entry.pattern}`);
                    }

                    if (!categories.includes(entry.category)) {
                        categories.push(entry.category);
                    }

                    if (severityIdx(entry.severity) > severityIdx(severity)) {
                        severity = entry.severity;
                    }

                    if (flagGroup in flags) {
                        flags[flagGroup] = true;
                    }

                    break; // first match per flag group
                }
            }
        }

        return {
            hasHiddenInstructions: flags.hasHiddenInstructions,
            hasDangerousToolUsage: flags.hasDangerousToolUsage,
            hasSensitiveFileAccess: flags.hasSensitiveFileAccess,
            hasObfuscation: flags.hasObfuscation,
            hasSocialEngineering: flags.hasSocialEngineering,
            hasNetworkExfiltration: flags.hasNetworkExfiltration,
            findings,
            severity,
            categories: Array.from(new Set(categories)),
        };
    }

    private runSkillChecksWithHardcoded(content: string): SkillSpecificFindings {
        const findings: string[] = [];
        const categories: string[] = [];
        let severity: "low" | "medium" | "high" | "critical" = "low";

        // 1. Hidden instructions
        const hiddenInstructionPatterns = [
            /<!--[\s\S]*?(ignore|override|bypass|secret|hidden)[\s\S]*?-->/gi,
            /<!--[\s\S]*?(curl|wget|bash|exec|eval)[\s\S]*?-->/gi,
        ];

        const hasHiddenInstructions = hiddenInstructionPatterns.some(pattern => {
            if (pattern.test(content)) {
                findings.push(`Hidden instructions detected in HTML comments`);
                categories.push("obfuscation");
                if (severity === "low") severity = "medium";
                return true;
            }
            return false;
        });

        // 2. Dangerous tool usage
        const dangerousToolPatterns = [
            /bash.*?(curl|wget)\s+.*?https?:\/\/(?!(?:localhost|127\.0\.0\.1|github\.com|npmjs\.com))/gi,
            /bash.*?(rm\s+-rf|dd\s+if=|mkfs|format)/gi,
            /bash.*?(sudo|su\s+|chmod\s+777|chown)/gi,
            /bash.*?(kill\s+-9|killall|pkill)/gi,
            /(?:^|\s|```)(bash|sh|zsh)?\s*(curl|wget)\s+.*?https?:\/\/(?!(?:localhost|127\.0\.0\.1|github\.com|npmjs\.com))/gim,
            /(?:^|\s|```)(bash|sh|zsh)?\s*(rm\s+-rf|dd\s+if=|mkfs|format)/gim,
            /(?:^|\s|```)(bash|sh|zsh)?\s*(sudo|su\s+|chmod\s+777|chown)/gim,
            /(?:^|\s|```)(bash|sh|zsh)?\s*(kill\s+-9|killall|pkill)/gim,
        ];

        const hasDangerousToolUsage = dangerousToolPatterns.some(pattern => {
            if (pattern.test(content)) {
                findings.push(`Dangerous tool usage detected: ${pattern.source}`);
                categories.push("shell_injection");
                severity = "critical";
                return true;
            }
            return false;
        });

        // 3. Sensitive file access
        const sensitiveFilePatterns = [
            /\/etc\/(passwd|shadow|sudoers)/gi,
            /~?\/.ssh\/(id_rsa|id_ed25519|authorized_keys)/gi,
            /~?\/.aws\/(credentials|config)/gi,
            /(?:^|\/|\\|~\/|\.\/|['"`\s])\.env(?:\.local|\.production|\.development)?(?:$|\s|['"`]|\/)/gim,
            /\.git\/config/gi,
        ];

        const hasSensitiveFileAccess = sensitiveFilePatterns.some(pattern => {
            if (pattern.test(content)) {
                findings.push(`Sensitive file access detected: ${pattern.source}`);
                categories.push("data_exfiltration");
                if (severity !== "critical") severity = "high";
                return true;
            }
            return false;
        });

        // 4. Obfuscation
        const obfuscationPatterns = [
            /[A-Za-z0-9+/]{40,}={0,2}/g,
            /\\x[0-9a-fA-F]{2}/g,
            /\\u[0-9a-fA-F]{4}/g,
            /[\u200B-\u200D\uFEFF]/g,
        ];

        const hasObfuscation = obfuscationPatterns.some(pattern => {
            const matches = content.match(pattern);
            const hasMultipleMatches = matches && matches.length > 5;
            const hasSingleLargeBlob = matches && matches.some(m => m.length >= 200);

            if (hasMultipleMatches || hasSingleLargeBlob) {
                findings.push(`Obfuscation detected: potential encoded content`);
                categories.push("obfuscation");
                if (severity === "low") severity = "medium";
                return true;
            }
            return false;
        });

        // 5. Social engineering
        const socialEngineeringPatterns = [
            /\b(official|urgent|critical|immediate|security update|required|mandatory)\b/gi,
            /\b(from Anthropic|from Claude|from OpenAI|authorized by|approved by)\b/gi,
            /\b(trust me|don't worry|safe to|guaranteed|certified)\b/gi,
        ];

        const hasSocialEngineering = socialEngineeringPatterns.some(pattern => {
            const matches = content.match(pattern);
            if (matches && matches.length > 2) {
                findings.push(`Social engineering indicators detected`);
                categories.push("social_engineering");
                if (severity === "low") severity = "medium";
                return true;
            }
            return false;
        });

        // 6. Network exfiltration
        const exfiltrationPatterns = [
            /https?:\/\/(?!(?:localhost|127\.0\.0\.1|github\.com|npmjs\.com|api\.github\.com))[\w.-]+.*?[\?&](data|key|token|secret|password)=/gi,
            /(curl|wget).*?(-d|--data|--data-binary).*?(key|token|secret|password|env)/gi,
            /nslookup.*?\$\(/gi,
        ];

        const hasNetworkExfiltration = exfiltrationPatterns.some(pattern => {
            if (pattern.test(content)) {
                findings.push(`Potential data exfiltration detected: ${pattern.source}`);
                categories.push("data_exfiltration");
                severity = "critical";
                return true;
            }
            return false;
        });

        return {
            hasHiddenInstructions,
            hasDangerousToolUsage,
            hasSensitiveFileAccess,
            hasObfuscation,
            hasSocialEngineering,
            hasNetworkExfiltration,
            findings,
            severity,
            categories: Array.from(new Set(categories))
        };
    }
}
