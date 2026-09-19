import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { CallContext, CallMeta, CallResult, FailureCode, JudgmentAnswers, JudgmentProvider, JudgmentRequest } from "../contracts.js";
import { NativeTransport } from "../transport.js";
import { emptyUsage, estimateCost, reserveCost, type TokenPrices } from "../usage.js";
import { hashConfiguration } from "../modelProfiles.js";

export const PROBABILITY_SUM_TOLERANCE = 0.005;
export const TYPESAFE_LIMITS = Object.freeze({ stateAndLongestQuestionBytes: 24_000, totalBytes: 48_000, choiceOptions: 255 });
const probability = z.number().finite().min(0).max(1);
const answerSchema = z.discriminatedUnion("type", [
    z.strictObject({ type: z.literal("noul"), noul: probability }),
    z.strictObject({ type: z.literal("choice"), choice: z.string(), confidence: probability, probabilities: z.record(z.string(), probability) }),
]);
const envelopeSchema = z.strictObject({ model: z.string(), answers: z.record(z.string(), answerSchema),
    usage: z.strictObject({ input_tokens: z.number().int().nonnegative().safe(), output_tokens: z.number().int().nonnegative().safe() }),
});
const instructions = z.union([z.string().min(1), z.record(z.string(), z.unknown())]);
const questionSchema = z.discriminatedUnion("type", [
    z.strictObject({ type: z.literal("noul"), instructions, criteria: z.strictObject({ true: z.string(), false: z.string() }) }),
    z.strictObject({ type: z.literal("choice"), instructions, criteria: z.record(z.string().min(1), z.string()).refine((value) => Object.keys(value).length >= 2 && Object.keys(value).length <= TYPESAFE_LIMITS.choiceOptions) }),
]);

/** Conservative byte bounds leave room beneath the documented token limits.
 * Never truncate state or remove options to make a request fit. */
export function typeSafePreflight(request: JudgmentRequest): FailureCode | null {
    if (!/^jev-\d+\.\d+\.\d+$/.test(request.model) && !["jev-latest", "jev-preview"].includes(request.model)) return "unsupported";
    const questions = Object.values(request.questions);
    if (!questions.length || typeof request.state !== "string") return "unsupported";
    if (questions.some((question) => !questionSchema.safeParse(question).success)) return "unsupported";
    try {
        const stateBytes = Buffer.byteLength(JSON.stringify(request.state));
        const sizes = questions.map((question) => Buffer.byteLength(JSON.stringify(question)));
        if (stateBytes + Math.max(...sizes) > TYPESAFE_LIMITS.stateAndLongestQuestionBytes ||
            Buffer.byteLength(JSON.stringify({ model: request.model, state: request.state, questions: request.questions })) > TYPESAFE_LIMITS.totalBytes) return "context_limit";
    } catch { return "unsupported"; }
    return null;
}

export function parseTypeSafeAnswers(value: unknown, request: JudgmentRequest): { answers: JudgmentAnswers; resolvedModel: string; inputTokens: number; outputTokens: number } {
    const response = envelopeSchema.parse(value);
    const alias = ["jev-latest", "jev-preview"].includes(request.model);
    if ((alias ? !/^jev-\d+\.\d+\.\d+$/.test(response.model) : response.model !== request.model) || !sameKeys(response.answers, request.questions)) throw new Error("Mismatched batch");
    for (const [id, question] of Object.entries(request.questions)) {
        const answer = response.answers[id];
        if (answer.type !== question.type) throw new Error("Mismatched primitive");
        if (answer.type === "choice" && question.type === "choice") {
            if (!sameKeys(answer.probabilities, question.criteria) || !Object.prototype.hasOwnProperty.call(answer.probabilities, answer.choice)) throw new Error("Mismatched options");
            const values = Object.values(answer.probabilities);
            if (Math.abs(values.reduce((sum, number) => sum + number, 0) - 1) > PROBABILITY_SUM_TOLERANCE ||
                Math.max(...values) - answer.probabilities[answer.choice] > PROBABILITY_SUM_TOLERANCE) throw new Error("Invalid probability distribution");
        }
    }
    return { answers: response.answers, resolvedModel: response.model, inputTokens: response.usage.input_tokens, outputTokens: response.usage.output_tokens };
}
function sameKeys(left: object, right: object): boolean {
    const keys = Object.keys(left);
    return keys.length === Object.keys(right).length && keys.every((key) => Object.prototype.hasOwnProperty.call(right, key));
}

export class TypeSafeAdapter implements JudgmentProvider {
    private readonly transport: NativeTransport;
    private readonly timeoutMs: number;
    constructor(private readonly options: { apiKey?: string; transport?: NativeTransport; prices?: TokenPrices; timeoutMs?: number } = {}) {
        this.transport = options.transport ?? new NativeTransport();
        this.timeoutMs = options.timeoutMs ?? 2000;
    }
    async evaluate(request: JudgmentRequest, call: CallContext): Promise<CallResult<JudgmentAnswers>> {
        const started = Date.now();
        const meta: CallMeta = { callId: call.callId ?? randomUUID(), provider: "typesafe", requestedModel: request.model, resolvedModel: null,
            profileHash: hashConfiguration({ provider: "typesafe", model: request.model }), rubricVersion: request.rubricVersion,
            schemaVersion: request.schemaVersion, elapsedMs: 0, attempts: 0, usage: emptyUsage(), failureCode: null };
        const fail = (code: FailureCode): CallResult<JudgmentAnswers> => ({ status: "unavailable", code, meta: { ...meta, elapsedMs: Date.now() - started, failureCode: code } });
        if (call.signal?.aborted) return fail("cancelled");
        if (!this.options.apiKey) return fail("not_configured");
        // Jev charges input only. A nonzero output rate is a mismatched price
        // card, not permission to reserve zero against a potentially paid unit.
        if (this.options.prices && this.options.prices.outputPerMillion !== 0) return fail("unsupported");
        const preflight = typeSafePreflight(request);
        if (preflight) return fail(preflight);
        const body = JSON.stringify({ model: request.model, state: request.state, questions: request.questions });
        const http = await this.transport.postJson({ url: "https://api.typesafe.ai/v1/systemone", headers: { Authorization: `Bearer ${this.options.apiKey}` },
            body, timeoutMs: this.timeoutMs, estimatedUsd: reserveCost(Buffer.byteLength(body), 0, this.options.prices) }, call);
        meta.attempts = http.attempts;
        // A transient response does not include trustworthy billing. Preserve
        // each earlier attempt as unknown so run totals cannot look complete.
        for (let i = 1; i < http.attempts; i++) call.budget.usage.record(`${meta.callId}:attempt:${i}`, emptyUsage(), this.options.prices);
        if (http.status === "unavailable") {
            if (http.attempts) call.budget.usage.record(meta.callId, meta.usage, this.options.prices);
            return fail(http.code);
        }
        try {
            const parsed = parseTypeSafeAnswers(http.value, request);
            meta.resolvedModel = parsed.resolvedModel;
            meta.usage = { ...emptyUsage(), inputTokens: parsed.inputTokens, outputTokens: parsed.outputTokens };
            call.budget.usage.record(meta.callId, meta.usage, this.options.prices);
            const reservation = http.reservationIds[http.reservationIds.length - 1];
            if (reservation) call.budget.reconcile(reservation, estimateCost(meta.usage, this.options.prices));
            return { status: "ok", value: parsed.answers, meta: { ...meta, elapsedMs: Date.now() - started } };
        } catch {
            // Invalid batches are neither usable nor cacheable. Their unknown
            // billing retains the original reservation instead of becoming zero.
            call.budget.usage.record(meta.callId, meta.usage, this.options.prices);
            return fail("invalid_response");
        }
    }
}
