import { randomUUID } from "node:crypto";
import type { McpToolScanner } from "./McpToolScanner.js";
import type { JudgmentService } from "./JudgmentService.js";
import { AnalysisBudget } from "../ai/budget.js";
import { descriptorFields, descriptorRequest } from "../ai/rubrics/descriptor.js";
import { completedCheck, qualificationCoverage, semanticCoverage } from "./AnalysisCoverage.js";
import { decide, POLICY_VERSION, maximumSeverity, blockingSeverity } from "./DecisionPolicy.js";
import { judgmentCoverage, judgmentRouting } from "../schemas/JudgmentReportSchemas.js";
import { descriptorReportSchema, type DescriptorReport } from "../schemas/DescriptorReportSchema.js";
import { QUALIFICATION_THRESHOLDS, validateQualifiedPatterns } from "../ai/qualification.js";
import type { CallResult } from "../ai/contracts.js";
import type { SemanticFinding } from "../ai/taskSchemas.js";
import type { SemanticAnalysisService } from "./SemanticAnalysisService.js";
export class DescriptorAnalysisService {
    constructor(readonly local: McpToolScanner, readonly judgments: JudgmentService, readonly semantic?: SemanticAnalysisService) {}
    async analyze(input: { tool: Record<string, unknown>; priorHash?: string }, options: { signal?: AbortSignal } = {}): Promise<DescriptorReport> {
        // Validate bounds before the incumbent recursive walker or any provider.
        descriptorFields(input.tool);
        const source = structuredClone(input.tool);
        const { request, fields } = descriptorRequest(source, this.judgments.snapshot.config.typesafe.model);
        const context = this.semantic?.createContext("descriptor", options.signal);
        const budget = context?.budget ?? new AnalysisBudget("descriptor", this.judgments.snapshot.config.limits);
        const local = this.local.scan({ tool: source, priorHash: input.priorHash });
        const coverage = [{ ...completedCheck("local", JSON.stringify(source).length), inspectedFields: fields.length }];
        const mode = this.judgments.snapshot.config.typesafe.descriptor;
        const enforced = mode === "enforce";
        const qualified = () => !!this.local.qualificationPatterns && validateQualifiedPatterns(this.judgments.snapshot, "descriptor", this.local.qualificationPatterns);
        const qualifiedBefore = !enforced || qualified();
        if (!enforced) budget.authorizeShadow({ requiredWorkComplete: true });
        const observation = await this.judgments.evaluate("descriptor", request, context ?? { budget, deadlineMs: budget.deadlineMs, signal: options.signal,
            runId: randomUUID(), role: "judgment", configHash: this.judgments.snapshot.hash }, { completeSource: true, coverage: { fields: fields.length, characters: request.state.length } });
        coverage.push(judgmentCoverage("descriptor_judgment", observation, JSON.stringify(source).length, fields.length));
        const answers = observation.result?.status === "ok" ? observation.result.value : null;
        const choice = answers?.evidence.type === "choice" ? answers.evidence.choice : null;
        const evidence = answers?.poison.type === "noul" && answers.poison.noul >= .8
            ? fields.find((field) => field.id === choice) ?? null : null;
        let semantic: CallResult<SemanticFinding> | null = null;
        let addedBlock = false;
        let contextualReview = false;
        let lowQualified = false;
        let validatedEvidence = evidence;
        if (enforced) {
            const poison = answers?.poison.type === "noul" ? answers.poison.noul : null;
            const selected = answers?.evidence.type === "choice" ? answers.evidence : null;
            const strongEvidence = selected && selected.confidence >= QUALIFICATION_THRESHOLDS.choiceEvidence;
            validatedEvidence = strongEvidence ? fields.find((field) => field.id === selected.choice) ?? null : null;
            const high = poison !== null && poison >= QUALIFICATION_THRESHOLDS.high;
            addedBlock = qualifiedBefore && observation.coverage === "complete" && high && !!validatedEvidence;
            lowQualified = qualifiedBefore && observation.coverage === "complete" && poison !== null && poison <= QUALIFICATION_THRESHOLDS.low && !!strongEvidence && choice === "none";
            if (!local.findings.length && !addedBlock && !lowQualified && this.semantic && context && qualifiedBefore) {
                semantic = await this.semantic.analyzeDescriptor(source, fields, context);
                coverage.push(semanticCoverage(semantic, JSON.stringify(source).length));
                // A complete contextual assessment replaces the fast judgment
                // requirement, including descriptors with >254 source strings.
                coverage[1] = { ...coverage[1], required: false, reason: "contextual_reasoning_requested" };
            }
            contextualReview = high && !addedBlock;
            coverage.push(qualificationCoverage(qualifiedBefore && qualified(), this.judgments.snapshot));
        }
        const contextWithoutEvidence = semantic?.status === "ok" && semantic.value.evidenceIds.length === 0 &&
            (semantic.value.verdict === "malicious" || blockingSeverity(semantic.value.severity) || semantic.value.isInjection);
        // A full reasoner is also required to cite one of the generated source
        // fields before it can add a descriptor poisoning block.
        const eligibleSemantic = contextWithoutEvidence ? undefined : semantic ?? undefined;
        const current = !enforced || qualifiedBefore && qualified();
        const outcome = !current && !local.findings.length ? { decision: "unavailable" as const, safe: false }
            : decide({ task: "descriptor", mode, coverage, localBlocking: local.findings.length > 0 || addedBlock,
            semantic: eligibleSemantic, needsReview: contextualReview || contextWithoutEvidence, descriptorQualifiedLow: lowQualified, descriptorEvidenceNone: choice === "none" });
        return descriptorReportSchema.parse({ schemaVersion: 2, task: "descriptor", ...outcome,
            overallSeverity: maximumSeverity(local.severity === "safe" ? "low" : local.severity, addedBlock ? "high" : semantic?.status === "ok" ? semantic.value.severity : "low"), categories: [...new Set([...local.findings.map((finding) => finding.category), ...(addedBlock ? ["mcp_tool_poisoning"] : []), ...(semantic?.status === "ok" ? semantic.value.categories : [])])],
            findings: [...local.findings.map((finding) => `${finding.field}: ${finding.note ?? finding.category}`), ...(addedBlock ? [`${validatedEvidence!.path}: validated descriptor poisoning`] : [])], local,
            timestamp: new Date().toISOString(), coverage, judgments: enforced ? observation : null, ...(enforced ? { semantic, evidence: validatedEvidence } : {}), shadow: mode === "shadow" ? { judgments: observation, evidence } : null,
            analysisMode: mode, policyVersion: POLICY_VERSION, configHash: this.judgments.snapshot.hash,
            routing: [...context?.routing ?? [], judgmentRouting(observation, request.model)],
            timings: { totalMs: Date.now() - budget.startedAt }, usage: budget.usage.summary() });
    }
}
