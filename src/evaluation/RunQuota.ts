import { randomUUID } from "node:crypto";
import { AnalysisBudget } from "../ai/budget.js";
import type { ConfigSnapshot } from "../ai/config.js";
import type { AnalysisTask, CallContext } from "../ai/contracts.js";
/** A serial evaluation run, with each case retaining its ordinary task limits.
 * Unknown outcome usage retains the reservation before another case starts. */
export class RunQuota {
    private active?: AnalysisBudget;
    attempts = 0;
    reservedUsd = 0;
    unknownSpend = false;
    constructor(readonly maxRequests: number, readonly maxUsd: number) {
        if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 || !Number.isFinite(maxUsd) || maxUsd <= 0) throw new Error("Explicit positive request and USD limits required");
    }
    get exhausted(): boolean { return this.unknownSpend || this.attempts >= this.maxRequests || this.reservedUsd >= this.maxUsd; }
    context(snapshot: ConfigSnapshot, task: AnalysisTask, signal?: AbortSignal, tasterTurns?: number): CallContext {
        if (this.active) throw new Error("Evaluation cases must be sequential");
        if (this.exhausted) throw new Error("Evaluation budget exhausted");
        const budget = new AnalysisBudget(task, snapshot.config.limits, { maxUsd: this.maxUsd - this.reservedUsd, maxTotalAttempts: this.maxRequests - this.attempts, tasterTurns });
        this.active = budget;
        return { budget, deadlineMs: budget.deadlineMs, signal, runId: randomUUID(), role: "semantic", configHash: snapshot.hash, routing: [] };
    }
    finish() {
        const budget = this.active;
        if (!budget) return;
        this.attempts += budget.attempts;
        const reserved = budget.reservedUsd;
        if (reserved === null) this.unknownSpend = true; else this.reservedUsd += reserved;
        this.active = undefined;
    }
}
