import { randomUUID } from "node:crypto";
import { z } from "zod";
import { AnalysisBudget } from "../ai/budget.js";
import type { CallContext } from "../ai/contracts.js";
import { capabilityJudgmentRequest } from "../ai/rubrics/capability.js";
import { judgmentCoverage, judgmentRouting } from "../schemas/JudgmentReportSchemas.js";
import { TrifectaAnalyzer, type TrifectaInput } from "./TrifectaAnalyzer.js";
import { JudgmentService, type JudgmentObservation } from "./JudgmentService.js";
import { TrustedCapabilityResolver, type CapabilityBucket, type TrustedCapabilityContext } from "./TrustedCapabilityResolver.js";
import { completedCheck } from "./AnalysisCoverage.js";
import { POLICY_VERSION } from "./DecisionPolicy.js";
import { capabilityReportSchema } from "../schemas/CapabilityReportSchema.js";

export const capabilityInputSchema = z.strictObject({ tools: z.array(z.string().max(4000)).max(512).optional(), capabilities: z.array(z.string().max(4000)).max(512).optional(), skillContent: z.string().max(500000).optional() }).superRefine((input, ctx) => {
    if ([...input.tools ?? [], ...input.capabilities ?? [], input.skillContent ?? ""].reduce((sum, text) => sum + text.length, 0) > 500000) ctx.addIssue({ code: "too_big", origin: "string", maximum: 500000, inclusive: true, message: "Capability input too large" });
});
export interface CapabilityState { state: "present" | "absent" | "unknown"; provenance: "declared" | "inferred" | "verified_runtime"; evidence: string[] }
export type CapabilityStates = Record<CapabilityBucket, CapabilityState>;
const buckets = ["privateDataRead", "untrustedContentFetch", "externalEgress"] as const;
const questionIds = { privateDataRead: "private", untrustedContentFetch: "untrusted", externalEgress: "egress" } as const;
export class CapabilityAnalysisService {
    constructor(readonly judgments: JudgmentService, readonly local = new TrifectaAnalyzer(), readonly trusted = new TrustedCapabilityResolver(judgments.snapshot.hash)) {}
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
                : { state: answer?.type === "noul" && answer.noul >= .9 ? "present" : "unknown", provenance: answer ? "inferred" : "declared", evidence: answer?.type === "noul" && answer.noul >= .9 ? [questionIds[bucket]] : [] };
            return [bucket, state];
        })) as CapabilityStates;
        return { judgments: observation, buckets: states };
    }
    async analyze(input: TrifectaInput, options: { signal?: AbortSignal; trustedContext?: TrustedCapabilityContext } = {}) {
        const source = capabilityInputSchema.parse(input);
        const serialized = JSON.stringify(source);
        const local = this.local.analyze(source);
        const budget = new AnalysisBudget("capability", this.judgments.snapshot.config.limits);
        const context: CallContext = { budget, deadlineMs: budget.deadlineMs, signal: options.signal, role: "judgment", runId: randomUUID(), configHash: this.judgments.snapshot.hash };
        budget.authorizeShadow({ requiredWorkComplete: true });
        const observed = await this.observe(source, context, options);
        const present = buckets.filter((bucket) => local[bucket].present).length;
        const decision = local.trifectaPresent ? "block" : present === 2 ? "review" : "allow";
        return capabilityReportSchema.parse({ schemaVersion: 2 as const, task: "capability" as const, safe: decision === "allow", decision, overallSeverity: local.severity === "safe" ? "low" : local.severity,
            categories: local.trifectaPresent ? ["lethal_trifecta"] : [], findings: local.trifectaPresent ? [local.recommendation] : [], local,
            buckets: Object.fromEntries(buckets.map((bucket) => [bucket, { state: local[bucket].present ? "present" : "unknown", provenance: "declared", evidence: local[bucket].evidence.map((item) => item.match) }])) as CapabilityStates,
            judgments: null, shadow: observed.judgments.mode === "shadow" ? observed : null,
            coverage: [{ ...completedCheck("local", serialized.length, "declared"), reason: "local_declared_scope" }, judgmentCoverage("capability_judgment", observed.judgments, serialized.length, 3)],
            timestamp: new Date().toISOString(), analysisMode: observed.judgments.mode, policyVersion: POLICY_VERSION, configHash: context.configHash,
            routing: [judgmentRouting(observed.judgments, this.judgments.snapshot.config.typesafe.model)], timings: { totalMs: Date.now() - budget.startedAt }, usage: budget.usage.summary() });
    }
}
