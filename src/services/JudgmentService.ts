import { randomUUID } from "node:crypto";
import type { CallContext, CallResult, FailureCode, JudgmentAnswers, JudgmentProvider, JudgmentRequest } from "../ai/contracts.js";
import type { ConfigSnapshot } from "../ai/config.js";
import { NativeTransport, withDeadline, type FetchLike } from "../ai/transport.js";
import { emptyUsage, reserveCost, type TokenPrices } from "../ai/usage.js";
import { hashConfiguration } from "../ai/modelProfiles.js";
import { TypeSafeAdapter, typeSafePreflight } from "../ai/providers/TypeSafeAdapter.js";
import { JudgmentCache, JudgmentCacheError, judgmentCacheKey } from "./JudgmentCache.js";
export type JudgmentTask = "descriptor" | "prompt" | "skill" | "capability" | "modelReference";
export type JudgmentMode = "off" | "shadow" | "enforce" | "cascade";
export interface JudgmentObservation { mode: JudgmentMode; cache: "disabled" | "miss" | "hit" | "shared"; ageMs: number; sourceHash: string; completion: "completed" | "waiter_timed_out" | "waiter_cancelled" | "not_requested"; coverage: "complete" | "partial" | "unavailable" | "not_requested"; result: CallResult<JudgmentAnswers> | null }
export interface JudgmentOptions { parentTask?: "skill"; cache?: boolean; trustedContext?: unknown; completeSource?: boolean; coverage?: unknown }
export function effectiveJudgmentMode(snapshot: ConfigSnapshot, task: JudgmentTask, parentTask?: "skill"): JudgmentMode {
    const selected = snapshot.config.typesafe[task];
    if (parentTask !== "skill" || !["capability", "modelReference"].includes(task)) return selected;
    const parent = snapshot.config.typesafe.skill;
    if (parent === "off" || selected === "off") return "off";
    return parent === "shadow" ? "shadow" : selected;
}
export class JudgmentService {
    private readonly provider: JudgmentProvider;
    private readonly cache: JudgmentCache;
    private readonly prices?: TokenPrices;
    constructor(readonly snapshot: ConfigSnapshot, options: { provider?: JudgmentProvider; apiKey?: string; fetch?: FetchLike; prices?: TokenPrices } = {}) {
        const limits = snapshot.config.limits;
        this.prices = options.prices;
        this.provider = options.provider ?? new TypeSafeAdapter({ apiKey: options.apiKey, prices: options.prices, timeoutMs: limits.judgmentTimeoutMs,
            transport: new NativeTransport({ fetch: options.fetch, maxConcurrent: limits.maxConcurrentJudgments, maxQueue: limits.maxQueue }) });
        this.cache = new JudgmentCache({ providerTimeoutMs: limits.judgmentTimeoutMs, maxInFlight: limits.maxConcurrentJudgments + limits.maxQueue });
    }
    async evaluate(task: JudgmentTask, input: JudgmentRequest, context: CallContext, options: JudgmentOptions = {}): Promise<JudgmentObservation> {
        options = freeze(structuredClone(options));
        const mode = effectiveJudgmentMode(this.snapshot, task, options.parentTask);
        const observation: JudgmentObservation = { mode, cache: "disabled", ageMs: 0, sourceHash: hashConfiguration(input.state), completion: "not_requested", coverage: "not_requested", result: null };
        if (mode === "off") return observation;
        const request = freeze(structuredClone(input));
        let operation = { callId: randomUUID() as string, attempts: 0, started: Date.now() };
        const failed = (code: FailureCode): CallResult<JudgmentAnswers> => ({ status: "unavailable", code, meta: { callId: operation.callId, provider: "typesafe", requestedModel: request.model, resolvedModel: null,
            profileHash: hashConfiguration({ provider: "typesafe", model: request.model }), rubricVersion: request.rubricVersion, schemaVersion: request.schemaVersion,
            elapsedMs: Date.now() - operation.started, attempts: operation.attempts, usage: emptyUsage(), failureCode: code } });
        const call: CallContext = { ...context, role: "judgment", optional: mode === "shadow", deadlineMs: Math.min(context.deadlineMs, context.budget.deadlineMs) };
        const finish = (result: CallResult<JudgmentAnswers>): JudgmentObservation => ({ ...observation, result, completion: "completed", coverage: result.status !== "ok" ? "unavailable" : options.completeSource ? "complete" : "partial" });
        if (request.model !== this.snapshot.config.typesafe.model) return finish(failed("unsupported"));
        const preflight = typeSafePreflight(request);
        if (preflight) return finish(failed(preflight));
        if (call.signal?.aborted) return finish(failed("cancelled"));
        if (Date.now() >= call.deadlineMs) return finish(failed("timeout"));
        const invoke = async (providerCall: CallContext): Promise<CallResult<JudgmentAnswers>> => {
            const deadlineMs = Math.min(providerCall.deadlineMs, providerCall.budget.deadlineMs, Date.now() + this.snapshot.config.limits.judgmentTimeoutMs);
            try {
                return await withDeadline((signal) => this.provider.evaluate(request, { ...providerCall, signal, deadlineMs, callId: operation.callId, onAttempt: () => { operation.attempts++; } }), deadlineMs, providerCall.signal);
            } catch { return failed(providerCall.signal?.aborted ? "cancelled" : Date.now() >= deadlineMs ? "timeout" : "transport"); }
        };
        if (!options.completeSource || options.cache === false || (task !== "descriptor" && task !== "capability")) return finish(await invoke(call));
        const key = judgmentCacheKey({ task, request, trustedContext: options.trustedContext ?? { origin: "unspecified", authorization: "unverified" }, coverage: options.coverage ?? { completeSource: true } });
        try {
            const cached = await this.cache.run(key, { deadlineMs: call.deadlineMs, signal: call.signal, onJoin: (shared, disposition) => { operation = shared; observation.cache = disposition; } }, async (signal, deadlineMs) => {
                const estimatedUsd = reserveCost(Buffer.byteLength(JSON.stringify({ model: request.model, state: request.state, questions: request.questions })), 0, this.prices);
                // Skill shadow schedules three independent batches. Hold one
                // slot for this child so a speculative retry cannot starve a
                // sibling before that sibling has made its first attempt.
                const envelope = context.budget.reserveSharedCall(this.snapshot.config.limits, { deadlineMs, estimatedUsd, optional: call.optional, maxAttempts: options.parentTask === "skill" && call.optional ? 1 : 2 });
                if (!envelope.ok) return failed(envelope.code);
                try { return await invoke({ ...call, signal, deadlineMs, budget: envelope.budget }); }
                finally { envelope.release(); }
            }, operation);
            return { ...finish(cached.result), cache: cached.cache, ageMs: cached.ageMs };
        } catch (error) {
            const result = finish(failed(error instanceof JudgmentCacheError ? error.code : "transport"));
            // A waiter may leave while another still consumes the shared
            // operation. Do not label that as the provider's final outcome.
            if (call.signal?.aborted) result.completion = "waiter_cancelled";
            else if (Date.now() >= call.deadlineMs) result.completion = "waiter_timed_out";
            return result;
        }
    }
}
function freeze<T>(value: T): T {
    if (value && typeof value === "object") { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
    return value;
}
