import type { CallResult, ProviderId } from "../ai/contracts.js";

export interface CoverageEntry {
    check: string;
    required: boolean;
    status: "complete" | "partial" | "unavailable" | "not_requested";
    reason: string | null;
    inspectedCharacters: number;
    inspectedFields: number;
    scope: "local" | "full_input" | "declared" | "external";
    provider: ProviderId | null;
    model: string | null;
    rubricVersion: string | null;
}
export function completedCheck(check: string, characters: number, scope: CoverageEntry["scope"] = "local"): CoverageEntry {
    return { check, required: true, status: "complete", reason: null, inspectedCharacters: characters,
        inspectedFields: 1, scope, provider: null, model: null, rubricVersion: null };
}
export function semanticCoverage(result: CallResult<unknown>, characters: number): CoverageEntry {
    return { check: "semantic", required: true, status: result.status === "ok" ? "complete" : "unavailable",
        reason: result.status === "ok" ? null : result.code,
        inspectedCharacters: result.status === "ok" ? characters : 0, inspectedFields: result.status === "ok" ? 1 : 0,
        scope: "full_input", provider: result.meta.provider, model: result.meta.resolvedModel ?? result.meta.requestedModel,
        rubricVersion: result.meta.rubricVersion };
}
export function skippedCheck(check: string, reason: string): CoverageEntry {
    return { ...completedCheck(check, 0, "full_input"), status: "not_requested", reason, inspectedFields: 0 };
}
export function qualificationCoverage(valid: boolean): CoverageEntry {
    return { ...completedCheck("qualification", 0), status: valid ? "complete" : "unavailable", reason: valid ? null : "qualification_changed", inspectedFields: 0 };
}
export class AnalysisCoverage {
    private checks = new Map<string, CoverageEntry>();
    record(entry: CoverageEntry): void { this.checks.set(entry.check, { ...entry }); }
    entries(): CoverageEntry[] { return [...this.checks.values()].map((entry) => ({ ...entry })); }
    get complete(): boolean { return [...this.checks.values()].every((entry) => !entry.required || entry.status === "complete"); }
}
