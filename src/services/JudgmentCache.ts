import type { CallResult, FailureCode, JudgmentAnswers, JudgmentRequest } from "../ai/contracts.js";
import { hashConfiguration } from "../ai/modelProfiles.js";
import { deadlineTimer } from "../ai/transport.js";

export type CacheDisposition = "miss" | "hit" | "shared";
export interface CachedJudgment { result: CallResult<JudgmentAnswers>; cache: CacheDisposition; ageMs: number }
export interface JudgmentCacheIdentity {
    task: "descriptor" | "capability";
    request: JudgmentRequest;
    trustedContext: unknown;
    coverage: unknown;
    profileOptions?: unknown;
}
export function judgmentCacheKey(identity: JudgmentCacheIdentity): string { return hashConfiguration(identity); }
export class JudgmentCacheError extends Error {
    constructor(readonly code: FailureCode) { super(code); }
}
interface Entry { result: CallResult<JudgmentAnswers>; storedAt: number }
export interface JudgmentProgress { callId: string; started: number; attempts: number }
interface InFlight { controller: AbortController; promise: Promise<CallResult<JudgmentAnswers>>; waiters: number; progress?: JudgmentProgress }
export class JudgmentCache {
    private readonly entries = new Map<string, Entry>();
    private readonly pending = new Map<string, InFlight>();
    private readonly maxEntries: number;
    private readonly ttlMs: number;
    private readonly providerTimeoutMs: number;
    private readonly maxInFlight: number;
    constructor(options: { maxEntries?: number; ttlMs?: number; providerTimeoutMs?: number; maxInFlight?: number } = {}) {
        this.maxEntries = options.maxEntries ?? 1000;
        this.ttlMs = options.ttlMs ?? 600_000;
        this.providerTimeoutMs = options.providerTimeoutMs ?? 2000;
        this.maxInFlight = options.maxInFlight ?? 64;
        if (![this.maxEntries, this.ttlMs, this.providerTimeoutMs, this.maxInFlight].every((value) => Number.isSafeInteger(value) && value > 0)) throw new Error("Invalid cache limits");
    }
    async run(key: string, waiter: { deadlineMs: number; signal?: AbortSignal; onJoin?: (progress: JudgmentProgress, disposition: CacheDisposition) => void }, operation: (signal: AbortSignal, deadlineMs: number) => Promise<CallResult<JudgmentAnswers>>, progress?: JudgmentProgress): Promise<CachedJudgment> {
        if (waiter.signal?.aborted) throw new JudgmentCacheError("cancelled");
        if (waiter.deadlineMs <= Date.now()) throw new JudgmentCacheError("timeout");
        const previous = this.entries.get(key);
        if (previous) {
            this.entries.delete(key);
            if (Date.now() - previous.storedAt < this.ttlMs) {
                this.entries.set(key, previous);
                return { result: structuredClone(previous.result), cache: "hit", ageMs: Date.now() - previous.storedAt };
            }
        }
        let entry = this.pending.get(key);
        const disposition: CacheDisposition = entry ? "shared" : "miss";
        if (!entry) {
            if (this.pending.size >= this.maxInFlight) throw new JudgmentCacheError("budget_exceeded");
            const controller = new AbortController();
            const deadlineMs = Date.now() + this.providerTimeoutMs;
            entry = { controller, waiters: 0, promise: Promise.resolve(null as never), progress };
            const ownEntry = entry;
            let timedOut = false;
            const clearDeadline = deadlineTimer(deadlineMs, () => { timedOut = true; controller.abort(); });
            entry.promise = new Promise<CallResult<JudgmentAnswers>>((resolve, reject) => {
                const abort = () => reject(new JudgmentCacheError(timedOut ? "timeout" : "cancelled"));
                controller.signal.addEventListener("abort", abort, { once: true });
                Promise.resolve().then(() => {
                    if (controller.signal.aborted) throw new JudgmentCacheError("cancelled");
                    return operation(controller.signal, deadlineMs);
                }).then(resolve, () => reject(new JudgmentCacheError("transport"))).finally(() => controller.signal.removeEventListener("abort", abort));
            }).then((result) => {
                // Microtasks can run before an overdue timer after the event
                // loop was occupied. Absolute deadlines remain authoritative.
                if (Date.now() >= deadlineMs) { controller.abort(); throw new JudgmentCacheError("timeout"); }
                if (result.status === "ok" && !controller.signal.aborted && this.pending.get(key) === ownEntry) {
                    this.entries.set(key, { result: structuredClone(result), storedAt: Date.now() });
                    while (this.entries.size > this.maxEntries) this.entries.delete(this.entries.keys().next().value!);
                }
                return result;
            }).finally(() => {
                clearDeadline();
                if (this.pending.get(key) === ownEntry) this.pending.delete(key);
            });
            this.pending.set(key, entry);
        }
        const current = entry;
        if (current.progress) waiter.onJoin?.(current.progress, disposition);
        current.waiters++;
        return new Promise<CachedJudgment>((resolve, reject) => {
            let settled = false;
            const finish = (error?: JudgmentCacheError, result?: CallResult<JudgmentAnswers>) => {
                if (settled) return;
                if (!error && waiter.signal?.aborted) error = new JudgmentCacheError("cancelled");
                if (!error && Date.now() >= waiter.deadlineMs) error = new JudgmentCacheError("timeout");
                settled = true;
                clearDeadline();
                waiter.signal?.removeEventListener("abort", abort);
                current.waiters--;
                if (!current.waiters && this.pending.get(key) === current) {
                    this.pending.delete(key);
                    current.controller.abort();
                }
                if (error) reject(error);
                else resolve({ result: structuredClone(result!), cache: disposition, ageMs: 0 });
            };
            const abort = () => finish(new JudgmentCacheError("cancelled"));
            const clearDeadline = deadlineTimer(waiter.deadlineMs, () => finish(new JudgmentCacheError("timeout")));
            waiter.signal?.addEventListener("abort", abort, { once: true });
            current.promise.then((result) => finish(undefined, result), (error: unknown) => finish(error instanceof JudgmentCacheError ? error : new JudgmentCacheError("transport")));
        });
    }
}
