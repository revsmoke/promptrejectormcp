import { randomUUID } from "node:crypto";
import type { McpToolScanner } from "./McpToolScanner.js";
import type { JudgmentService } from "./JudgmentService.js";
import { AnalysisBudget } from "../ai/budget.js";
import { descriptorFields, descriptorRequest } from "../ai/rubrics/descriptor.js";
import { completedCheck } from "./AnalysisCoverage.js";
import { decide, POLICY_VERSION } from "./DecisionPolicy.js";
import { judgmentCoverage, judgmentRouting } from "../schemas/JudgmentReportSchemas.js";
import { descriptorReportSchema, type DescriptorReport } from "../schemas/DescriptorReportSchema.js";
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
        budget.authorizeShadow({ requiredWorkComplete: true });
        const observation = await this.judgments.evaluate("descriptor", request, context ?? { budget, deadlineMs: budget.deadlineMs, signal: options.signal,
            runId: randomUUID(), role: "judgment", configHash: this.judgments.snapshot.hash }, { completeSource: true, coverage: { fields: fields.length, characters: request.state.length } });
        coverage.push(judgmentCoverage("descriptor_judgment", observation, JSON.stringify(source).length, fields.length));
        const answers = observation.result?.status === "ok" ? observation.result.value : null;
        const choice = answers?.evidence.type === "choice" ? answers.evidence.choice : null;
        const evidence = answers?.poison.type === "noul" && answers.poison.noul >= .8
            ? fields.find((field) => field.id === choice) ?? null : null;
        return descriptorReportSchema.parse({ schemaVersion: 2, task: "descriptor", ...decide({ task: "descriptor", mode, coverage, localBlocking: local.findings.length > 0 }),
            overallSeverity: local.severity === "safe" ? "low" : local.severity, categories: [...new Set(local.findings.map((finding) => finding.category))],
            findings: local.findings.map((finding) => `${finding.field}: ${finding.note ?? finding.category}`), local,
            timestamp: new Date().toISOString(), coverage, judgments: null, shadow: mode === "shadow" ? { judgments: observation, evidence } : null,
            analysisMode: mode, policyVersion: POLICY_VERSION, configHash: this.judgments.snapshot.hash,
            routing: [judgmentRouting(observation, request.model)],
            timings: { totalMs: Date.now() - budget.startedAt }, usage: budget.usage.summary() });
    }
}
