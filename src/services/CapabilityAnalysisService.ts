import { randomUUID } from "node:crypto";
import { z } from "zod";
import { AnalysisBudget } from "../ai/budget.js";
import type { CallContext, CallResult } from "../ai/contracts.js";
import { capabilityJudgmentRequest } from "../ai/rubrics/capability.js";
import { judgmentCoverage, judgmentRouting } from "../schemas/JudgmentReportSchemas.js";
import { TrifectaAnalyzer, type TrifectaInput } from "./TrifectaAnalyzer.js";
import { JudgmentService, type JudgmentObservation } from "./JudgmentService.js";
import { TrustedCapabilityResolver, type CapabilityBucket, type TrustedCapabilityContext } from "./TrustedCapabilityResolver.js";
import { completedCheck, qualificationCoverage, semanticCoverage } from "./AnalysisCoverage.js";
import { POLICY_VERSION } from "./DecisionPolicy.js";
import { capabilityReportSchema } from "../schemas/CapabilityReportSchema.js";
import { capabilityBuckets, type CapabilityAssessment } from "../ai/taskSchemas.js";
import { QUALIFICATION_THRESHOLDS, validateQualifiedPatterns } from "../ai/qualification.js";
import type { PatternService } from "./PatternService.js";
import type { SemanticAnalysisService } from "./SemanticAnalysisService.js";

export const capabilityInputSchema = z.strictObject({ tools: z.array(z.string().max(4000)).max(512).optional(), capabilities: z.array(z.string().max(4000)).max(512).optional(), skillContent: z.string().max(500000).optional() }).superRefine((input, ctx) => {
    if ([...input.tools ?? [], ...input.capabilities ?? [], input.skillContent ?? ""].reduce((sum, text) => sum + text.length, 0) > 500000) ctx.addIssue({ code: "too_big", origin: "string", maximum: 500000, inclusive: true, message: "Capability input too large" });
});
export interface CapabilityState { state: "present" | "absent" | "unknown"; provenance: "declared" | "inferred" | "verified_runtime"; evidence: string[] }
export type CapabilityStates = Record<CapabilityBucket, CapabilityState>;
const buckets = capabilityBuckets;
const questionIds = { privateDataRead: "private", untrustedContentFetch: "untrusted", externalEgress: "egress" } as const;
export class CapabilityAnalysisService {
    constructor(readonly judgments: JudgmentService, readonly local = new TrifectaAnalyzer(), readonly trusted = new TrustedCapabilityResolver(judgments.snapshot.hash), readonly semantic?: SemanticAnalysisService, readonly patterns?: PatternService) {}
    async observe(input: TrifectaInput, context: CallContext, options: { parentTask?: "skill"; trustedContext?: TrustedCapabilityContext } = {}): Promise<{ judgments: JudgmentObservation; buckets: CapabilityStates }> {
        const source = capabilityInputSchema.parse(input);
        const facts = this.trusted.resolve(options.trustedContext);
        const observation = await this.judgments.evaluate("capability", capabilityJudgmentRequest(source, this.judgments.snapshot.config.typesafe.model), context,
            { parentTask: options.parentTask, completeSource: true, trustedContext: facts, coverage: { fullConfiguration: true } });
        const answers = observation.result?.status === "ok" ? observation.result.value : null;
        const states = Object.fromEntries(buckets.map((bucket) => {
            const fact = facts.find((item) => item.bucket === bucket);
            const answer = answers?.[questionIds[bucket]];
            const state: CapabilityState = fact ? { state: fact.state, provenance: "verified_runtime", evidence: [fact.evidenceId] }
                : { state: answer?.type === "noul" && answer.noul >= QUALIFICATION_THRESHOLDS.high ? "present" : "unknown", provenance: answer ? "inferred" : "declared", evidence: answer?.type === "noul" && answer.noul >= QUALIFICATION_THRESHOLDS.high ? [questionIds[bucket]] : [] };
            return [bucket, state];
        })) as CapabilityStates;
        return { judgments: observation, buckets: states };
    }
    sources(input: TrifectaInput): Array<{ id: string; text: string }> {
        return [...(input.tools ?? []).map((text, i) => ({ id: `tools:${i}`, text })), ...(input.capabilities ?? []).map((text, i) => ({ id: `capabilities:${i}`, text })),
            ...(input.skillContent === undefined ? [] : [{ id: "skillContent", text: input.skillContent }])];
    }
    resolve(states: CapabilityStates, assessment: CapabilityAssessment | null): CapabilityStates {
        return Object.fromEntries(buckets.map((bucket) => {
            const current = states[bucket];
            if (current.provenance === "verified_runtime" || current.state === "present" || !assessment) return [bucket, current];
            const assessed = assessment[bucket];
            const supported = assessed.evidenceIds.length > 0;
            if (assessed.state === "present" && supported) return [bucket, { state: "present", provenance: "inferred", evidence: assessed.evidenceIds }];
            if (assessed.state === "absent" && supported && assessment.completeDeclaredScope && assessment.restrictionEvidenceIds.length > 0)
                return [bucket, { state: "absent", provenance: "declared", evidence: [...new Set([...assessed.evidenceIds, ...assessment.restrictionEvidenceIds])] }];
            return [bucket, { ...current, state: "unknown" }];
        })) as CapabilityStates;
    }
    outcome(states: CapabilityStates): { block: boolean; review: boolean; complete: boolean } {
        const values = Object.values(states);
        const block = values.every((bucket) => bucket.state === "present");
        const verifiedBreak = values.some((bucket) => bucket.state === "absent" && bucket.provenance === "verified_runtime");
        const complete = verifiedBreak || values.every((bucket) => bucket.state !== "unknown");
        return { block, review: !complete, complete };
    }
    async analyze(input: TrifectaInput, options: { signal?: AbortSignal; trustedContext?: TrustedCapabilityContext } = {}) {
        const source = capabilityInputSchema.parse(input);
        const serialized = JSON.stringify(source);
        const local = this.local.analyze(source);
        const inherited = this.semantic?.createContext("capability", options.signal);
        const budget = inherited?.budget ?? new AnalysisBudget("capability", this.judgments.snapshot.config.limits);
        const context: CallContext = inherited ?? { budget, deadlineMs: budget.deadlineMs, signal: options.signal, role: "judgment", runId: randomUUID(), configHash: this.judgments.snapshot.hash, routing: [] };
        const enforced = this.judgments.snapshot.config.typesafe.capability === "enforce";
        const qualified = () => !!this.patterns && validateQualifiedPatterns(this.judgments.snapshot, "capability", this.patterns);
        const before = !enforced || qualified();
        if (!enforced) budget.authorizeShadow({ requiredWorkComplete: true });
        const observed = await this.observe(source, context, options);
        let states = observed.buckets;
        let semantic: CallResult<CapabilityAssessment> | null = null;
        const coverage = [{ ...completedCheck("local", serialized.length, "declared"), reason: "local_declared_scope" }, judgmentCoverage("capability_judgment", observed.judgments, serialized.length, 3)];
        if (enforced && before && !local.trifectaPresent && this.outcome(states).review && this.semantic) {
            semantic = await this.semantic.analyzeCapabilities(source, this.sources(source), states, context);
            states = this.resolve(states, semantic.status === "ok" ? semantic.value : null);
            coverage.push(semanticCoverage(semantic, serialized.length));
            coverage[1] = { ...coverage[1], required: false, reason: "contextual_reasoning_requested" };
        }
        const derived = this.outcome(states);
        if (enforced) {
            // A fully verified break or three supported presences requires no
            // assertion of absence from the low Noul values.
            if (!derived.review) coverage[1] = { ...coverage[1], required: false, reason: "capability_states_resolved" };
            coverage.push({ ...completedCheck("capability", serialized.length, "declared"), status: derived.complete ? "complete" : "partial", reason: derived.complete ? "explicit_scope" : "unknown_scope" });
            coverage.push(qualificationCoverage(before && qualified(), this.judgments.snapshot));
        }
        const localPresent = buckets.filter((bucket) => local[bucket].present).length;
        const unavailable = semantic?.status === "unavailable" && !["refusal", "incomplete"].includes(semantic.code);
        const decision = local.trifectaPresent ? "block" : !enforced ? localPresent === 2 ? "review" : "allow"
            : !before || !qualified() ? "unavailable" : derived.block ? "block" : unavailable ? "unavailable" : derived.review ? "review" : "allow";
        return capabilityReportSchema.parse({ schemaVersion: 2 as const, task: "capability" as const, safe: decision === "allow", decision, overallSeverity: decision === "block" ? "critical" : local.severity === "safe" ? "low" : local.severity,
            categories: decision === "block" ? ["lethal_trifecta"] : [], findings: decision === "block" ? [local.trifectaPresent ? local.recommendation : "Three supported capability buckets form a lethal trifecta."] : [], local,
            buckets: enforced ? states : Object.fromEntries(buckets.map((bucket) => [bucket, { state: local[bucket].present ? "present" : "unknown", provenance: "declared", evidence: local[bucket].evidence.map((item) => item.match) }])) as CapabilityStates,
            judgments: enforced ? observed.judgments : null, ...(enforced ? { semantic } : {}), shadow: observed.judgments.mode === "shadow" ? observed : null,
            coverage, timestamp: new Date().toISOString(), analysisMode: observed.judgments.mode, policyVersion: POLICY_VERSION, configHash: context.configHash,
            routing: [...context.routing ?? [], judgmentRouting(observed.judgments, this.judgments.snapshot.config.typesafe.model)], timings: { totalMs: Date.now() - budget.startedAt }, usage: budget.usage.summary() });
    }
}
