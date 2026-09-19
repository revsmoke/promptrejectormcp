import { randomUUID } from "node:crypto";
import type { AnalysisTask, FailureCode } from "./contracts.js";
import type { AnalysisLimits } from "./config.js";
import { UsageLedger } from "./usage.js";

export type Reservation = { ok: true; id: string } | { ok: false; code: FailureCode };
export type SharedCallEnvelope = { ok: true; budget: AnalysisBudget; release(): void } | { ok: false; code: FailureCode };
export class AnalysisBudget {
    readonly deadlineMs: number;
    readonly startedAt = Date.now();
    readonly usage = new UsageLedger();
    readonly maxAttempts: number;
    private requiredAttempts = 0;
    private optionalAttempts = 0;
    private heldRequiredAttempts = 0;
    private heldOptionalAttempts = 0;
    private shadowAuthorized = false;
    private requiredWorkComplete = false;
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
    /** Hold capacity before starting a coalesced call. The call owns its own
     * short provider deadline while all actual attempts and usage are charged
     * once to this originating budget, even if its first waiter leaves. */
    reserveSharedCall(limits: AnalysisLimits, options: { deadlineMs: number; maxAttempts?: number; optional?: boolean; estimatedUsd?: number | null }): SharedCallEnvelope {
        const now = Date.now();
        if (!this.remainingMs || options.deadlineMs <= now) return { ok: false, code: "timeout" };
        if (!Number.isFinite(options.deadlineMs) || options.deadlineMs > now + limits.judgmentTimeoutMs) return { ok: false, code: "unsupported" };
        const count = options.maxAttempts ?? 2;
        const estimate = options.estimatedUsd ?? null;
        if (!Number.isSafeInteger(count) || count < 1 || count > 2 || (estimate !== null && (!Number.isFinite(estimate) || estimate < 0))) return { ok: false, code: "budget_exceeded" };
        const optional = options.optional ?? false;
        const slots: string[] = [];
        for (let i = 0; i < count; i++) {
            if (!this.capacityAvailable(optional, estimate)) break;
            const id = randomUUID();
            this.reservations.set(id, estimate);
            slots.push(id);
            if (optional) this.heldOptionalAttempts++; else this.heldRequiredAttempts++;
        }
        if (!slots.length) return { ok: false, code: "budget_exceeded" };
        const available = [...slots];
        let released = false;
        const releaseHold = () => { if (optional) this.heldOptionalAttempts--; else this.heldRequiredAttempts--; };
        const budget = new PrepaidJudgmentBudget(limits, options.deadlineMs, this.usage, slots.length, (attempt) => {
            if (released || !available.length || !!attempt.optional !== optional) return { ok: false, code: "budget_exceeded" };
            if (this.maxUsd !== undefined && !this.withinMonetaryLimit()) return { ok: false, code: "budget_exceeded" };
            // An adapter cannot spend more than the preflight price envelope.
            if (estimate !== null && (attempt.estimatedUsd == null || attempt.estimatedUsd > estimate)) return { ok: false, code: "budget_exceeded" };
            const id = available.shift()!;
            releaseHold();
            if (optional) this.optionalAttempts++; else this.requiredAttempts++;
            return { ok: true, id };
        }, (id, actual) => this.reconcile(id, actual));
        return { ok: true, budget, release: () => {
            if (released) return;
            released = true;
            for (const id of available.splice(0)) { this.reservations.delete(id); releaseHold(); }
        } };
    }
    /** Call only after scheduling/reserving the authoritative work. Optional
     * attempts never consume the required pool. A capped run must additionally
     * reserve its required monetary upper bound before authorizing shadow. */
    authorizeShadow(options: { requiredWorkComplete?: boolean } = {}): void {
        this.shadowAuthorized = true;
        if (options.requiredWorkComplete) {
            if (this.heldRequiredAttempts) throw new Error("Required shared work still reserved");
            this.requiredWorkComplete = true;
        }
    }
    reserveAttempt(options: { optional?: boolean; estimatedUsd?: number | null } = {}): Reservation {
        if (this.remainingMs === 0) return { ok: false, code: "timeout" };
        const estimate = options.estimatedUsd ?? null;
        if (!this.capacityAvailable(options.optional ?? false, estimate)) return { ok: false, code: "budget_exceeded" };
        const id = randomUUID();
        this.reservations.set(id, estimate);
        if (options.optional) this.optionalAttempts++; else this.requiredAttempts++;
        return { ok: true, id };
    }
    private capacityAvailable(optional: boolean, estimate: number | null): boolean {
        if (!optional && this.requiredWorkComplete) return false;
        if (optional ? !this.shadowAuthorized || this.optionalAttempts + this.heldOptionalAttempts >= this.maxShadowAttempts : this.requiredAttempts + this.heldRequiredAttempts >= this.maxAttempts) return false;
        if (estimate !== null && (!Number.isFinite(estimate) || estimate < 0)) return false;
        if (this.maxUsd !== undefined) {
            if (estimate === null || [...this.reservations.values()].some((value) => value === null)) return false;
            if (!this.withinMonetaryLimit(estimate)) return false;
            // A bounded shadow run can spend the remainder only once the
            // orchestrator closes the required-work pool. Future required
            // dispatch is then forbidden, preventing accidental competition.
            if (optional && !this.requiredWorkComplete) return false;
        }
        return true;
    }
    private withinMonetaryLimit(additional = 0): boolean {
        if (this.maxUsd === undefined) return true;
        if ([...this.reservations.values()].some((value) => value === null)) return false;
        const total = [...this.reservations.values()].reduce<number>((sum, value) => sum + (value ?? 0), additional);
        // Only relative floating-point roundoff, never a fixed dollar allowance.
        return total - this.maxUsd <= Number.EPSILON * Math.max(total, this.maxUsd) * 8;
    }
    reconcile(id: string, actualUsd: number | null): void {
        // Unknown actual usage keeps the conservative reservation. Reconciliation
        // can increase it when providers report more than the estimate, stopping
        // subsequent calls instead of silently forgiving an overrun.
        if (this.reservations.has(id) && actualUsd !== null && Number.isFinite(actualUsd) && actualUsd >= 0) this.reservations.set(id, actualUsd);
    }
}

/** Not exported: only the parent can mint prepaid attempt IDs. */
class PrepaidJudgmentBudget extends AnalysisBudget {
    override readonly deadlineMs: number;
    override readonly usage: UsageLedger;
    override readonly maxAttempts: number;
    private consumed = 0;
    constructor(limits: AnalysisLimits, deadlineMs: number, usage: UsageLedger, maxAttempts: number,
        private readonly consume: (options: { optional?: boolean; estimatedUsd?: number | null }) => Reservation,
        private readonly settle: (id: string, actualUsd: number | null) => void) {
        super("descriptor", limits, { deadlineMs });
        // This deadline was validated against the provider cap by the parent;
        // it belongs to shared work, not the first request's duration setting.
        this.deadlineMs = deadlineMs;
        this.usage = usage;
        this.maxAttempts = maxAttempts;
    }
    override get attempts(): number { return this.consumed; }
    override reserveAttempt(options: { optional?: boolean; estimatedUsd?: number | null } = {}): Reservation {
        if (!this.remainingMs) return { ok: false, code: "timeout" };
        const reservation = this.consume(options);
        if (reservation.ok) this.consumed++;
        return reservation;
    }
    override reconcile(id: string, actualUsd: number | null): void { this.settle(id, actualUsd); }
    override reserveSharedCall(): SharedCallEnvelope { return { ok: false, code: "unsupported" }; }
}
