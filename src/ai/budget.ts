import { randomUUID } from "node:crypto";
import type { AnalysisTask, FailureCode } from "./contracts.js";
import type { AnalysisLimits } from "./config.js";
import { UsageLedger } from "./usage.js";

export type Reservation = { ok: true; id: string } | { ok: false; code: FailureCode };
export class AnalysisBudget {
    readonly deadlineMs: number;
    readonly startedAt = Date.now();
    readonly usage = new UsageLedger();
    readonly maxAttempts: number;
    private requiredAttempts = 0;
    private optionalAttempts = 0;
    private shadowAuthorized = false;
    private reservations = new Map<string, number | null>();
    private readonly maxUsd?: number;
    private readonly maxShadowAttempts: number;
    constructor(task: AnalysisTask, limits: AnalysisLimits, options: { deadlineMs?: number; maxUsd?: number; tasterTurns?: number } = {}) {
        this.deadlineMs = Math.min(options.deadlineMs ?? Infinity, this.startedAt + (task === "taster" ? 60000 : limits.analysisDeadlineMs));
        this.maxAttempts = task === "taster" ? (options.tasterTurns ?? 5) + 2 : limits.maxInferenceAttempts[task];
        this.maxShadowAttempts = limits.maxShadowAttempts;
        if (options.maxUsd !== undefined && (!Number.isFinite(options.maxUsd) || options.maxUsd <= 0)) throw new Error("Invalid monetary budget");
        this.maxUsd = options.maxUsd;
    }
    get attempts(): number { return this.requiredAttempts + this.optionalAttempts; }
    get remainingMs(): number { return Math.max(0, this.deadlineMs - Date.now()); }
    /** Call only after scheduling/reserving the authoritative work. Optional
     * attempts never consume the required pool. A capped run must additionally
     * reserve its required monetary upper bound before authorizing shadow. */
    authorizeShadow(): void { this.shadowAuthorized = true; }
    reserveAttempt(options: { optional?: boolean; estimatedUsd?: number | null } = {}): Reservation {
        if (this.remainingMs === 0) return { ok: false, code: "timeout" };
        if (options.optional ? !this.shadowAuthorized || this.optionalAttempts >= this.maxShadowAttempts : this.requiredAttempts >= this.maxAttempts) return { ok: false, code: "budget_exceeded" };
        const estimate = options.estimatedUsd ?? null;
        if (estimate !== null && (!Number.isFinite(estimate) || estimate < 0)) return { ok: false, code: "budget_exceeded" };
        if (this.maxUsd !== undefined) {
            if (estimate === null || [...this.reservations.values()].some((value) => value === null)) return { ok: false, code: "budget_exceeded" };
            const reserved = [...this.reservations.values()].reduce<number>((sum, value) => sum + (value ?? 0), 0);
            if (reserved + estimate > this.maxUsd) return { ok: false, code: "budget_exceeded" };
            // Until an explicit required-spend reservation exists, monetary
            // bounded runs shed optional work rather than spend needed funds.
            if (options.optional) return { ok: false, code: "budget_exceeded" };
        }
        const id = randomUUID();
        this.reservations.set(id, estimate);
        if (options.optional) this.optionalAttempts++; else this.requiredAttempts++;
        return { ok: true, id };
    }
    reconcile(id: string, actualUsd: number | null): void {
        // Unknown actual usage keeps the conservative reservation. Reconciliation
        // can increase it when providers report more than the estimate, stopping
        // subsequent calls instead of silently forgiving an overrun.
        if (this.reservations.has(id) && actualUsd !== null && Number.isFinite(actualUsd) && actualUsd >= 0) this.reservations.set(id, actualUsd);
    }
}
