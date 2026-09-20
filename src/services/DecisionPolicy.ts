import type { CallResult, Severity } from "../ai/contracts.js";
import type { SemanticFinding } from "../ai/taskSchemas.js";
import type { CoverageEntry } from "./AnalysisCoverage.js";
import type { JudgmentObservation } from "./JudgmentService.js";
import { QUALIFICATION_THRESHOLDS } from "../ai/qualification.js";

export const POLICY_VERSION = "security-policy-v2.1";
export type Decision = "allow" | "block" | "review" | "unavailable";
interface DecisionInput {
    task: "prompt" | "skill" | "descriptor" | "capability";
    mode?: "off" | "shadow" | "enforce" | "cascade";
    coverage: readonly CoverageEntry[];
    localBlocking?: boolean;
    semantic?: CallResult<SemanticFinding>;
    needsReview?: boolean;
    descriptorQualifiedLow?: boolean;
    descriptorEvidenceNone?: boolean;
    capabilityResolved?: boolean;
}
export function decide(input: DecisionInput): { decision: Decision; safe: boolean } {
    const result = (decision: Decision) => ({ decision, safe: decision === "allow" });
    const localOnly = ["descriptor", "capability"].includes(input.task) && ["off", "shadow"].includes(input.mode ?? "off");
    const semantic = localOnly ? undefined : input.semantic;
    const finding = semantic?.status === "ok" ? semantic.value : undefined;
    if (input.localBlocking || (finding && (blockingSeverity(finding.severity) || finding.verdict === "malicious" || (finding.isInjection && (finding.selfReportedConfidence ?? 0) > 0.6)))) return result("block");
    if (!localOnly && (input.needsReview || (finding && finding.verdict !== "benign") || (semantic?.status === "unavailable" && ["refusal", "incomplete"].includes(semantic.code)))) return result("review");
    const required = input.task === "prompt" ? ["local", "semantic"] : input.task === "skill" ? ["local", "semantic", "skill", "capability", "hugging_face"] : ["local"];
    if (required.some((check) => !input.coverage.some((entry) => entry.check === check && entry.required && entry.status === "complete")) || input.coverage.some((entry) => entry.required && entry.status !== "complete")) return result("unavailable");
    if (localOnly) return result("allow");
    if (input.task === "prompt" || input.task === "skill") return result(finding?.verdict === "benign" ? "allow" : "unavailable");
    if (input.task === "descriptor") {
        if (finding?.verdict === "benign" || (input.descriptorQualifiedLow && input.descriptorEvidenceNone)) return result("allow");
        return result(semantic?.status === "unavailable" ? "unavailable" : "review");
    }
    return result(input.capabilityResolved ? "allow" : "review");
}
export function blockingSeverity(severity: Severity): boolean { return severity === "high" || severity === "critical"; }
export function maximumSeverity(...severities: Severity[]): Severity {
    const order: Severity[] = ["low", "medium", "high", "critical"];
    return order[Math.max(0, ...severities.map((severity) => order.indexOf(severity)))];
}
export function decideBehavior(complete: boolean, verdict: "clean" | "suspicious" | "malicious" | "undetermined"): typeof verdict {
    return !complete && verdict === "clean" ? "undetermined" : verdict;
}
/** Consequential activity requires contextual authorization analysis; it can
 * never make this early block predicate true by itself. */
export function decisiveIntent(observation: JudgmentObservation | null): boolean {
    if (!observation || !["enforce", "cascade"].includes(observation.mode) || observation.coverage !== "complete" || observation.result?.status !== "ok") return false;
    return ["override", "disclosure"].some((id) => {
        const answer = observation.result!.status === "ok" ? observation.result!.value[id] : null;
        return answer?.type === "noul" && answer.noul >= QUALIFICATION_THRESHOLDS.high;
    });
}
