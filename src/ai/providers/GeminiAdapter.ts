import { randomUUID } from "node:crypto";
import type { CallContext, CallMeta, CallResult, FailureCode, StructuredReasoner, StructuredRequest } from "../contracts.js";
import { modelCapabilities, profileHash, validateModelProfile, type CapabilityCatalog } from "../modelProfiles.js";
import { NativeTransport } from "../transport.js";
import { emptyUsage, estimateCost, reserveCost, tokenCount, type TokenPrices } from "../usage.js";

export class GeminiAdapter implements StructuredReasoner {
    private readonly apiKey: string;
    private readonly transport: NativeTransport;
    private readonly timeoutMs: number;
    private readonly prices?: TokenPrices;
    private readonly capabilities?: CapabilityCatalog;
    constructor(options: { apiKey?: string; transport?: NativeTransport; timeoutMs?: number; prices?: TokenPrices; capabilities?: CapabilityCatalog } = {}) {
        this.apiKey = options.apiKey ?? "";
        this.transport = options.transport ?? new NativeTransport();
        this.timeoutMs = options.timeoutMs ?? 15000;
        this.prices = options.prices;
        this.capabilities = options.capabilities;
    }
    async generate<T>(request: StructuredRequest<T>, call: CallContext): Promise<CallResult<T>> {
        const started = Date.now();
        const meta: CallMeta = { callId: randomUUID(), provider: "gemini", requestedModel: request.profile.model,
            resolvedModel: null, profileHash: profileHash(request.profile), rubricVersion: request.rubricVersion,
            schemaVersion: request.schemaVersion, elapsedMs: 0, attempts: 0, usage: emptyUsage(), failureCode: null };
        const fail = (code: FailureCode): CallResult<T> => ({ status: "unavailable", code, meta: { ...meta, elapsedMs: Date.now() - started, failureCode: code } });
        if (call.signal?.aborted) return fail("cancelled");
        if (!this.apiKey) return fail("not_configured");
        let schema: Record<string, unknown>;
        try {
            validateModelProfile(request.profile, this.capabilities);
            if (request.profile.provider !== "gemini" || !modelCapabilities(request.profile, this.capabilities)?.structured || request.maxOutputTokens > request.profile.maxOutputTokens) return fail("unsupported");
            schema = geminiJsonSchema(request.jsonSchema);
        } catch { return fail("unsupported"); }
        const body = JSON.stringify({
            systemInstruction: { parts: [{ text: request.systemInstruction }] },
            contents: [{ role: "user", parts: [{ text: request.state }] }],
            generationConfig: { ...request.profile.options, responseMimeType: "application/json", responseJsonSchema: schema, candidateCount: 1, maxOutputTokens: request.maxOutputTokens },
        });
        if (Buffer.byteLength(body) > modelCapabilities(request.profile, this.capabilities)!.maxInputBytes) return fail("context_limit");
        const http = await this.transport.postJson({
            url: `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(request.profile.model)}:generateContent`,
            headers: { "x-goog-api-key": this.apiKey }, body, timeoutMs: this.timeoutMs,
            estimatedUsd: reserveCost(Buffer.byteLength(body), request.maxOutputTokens * 2, this.prices),
        }, call);
        meta.attempts = http.attempts;
        // A transient attempt may have consumed tokens before returning an
        // error. Preserve its unknown usage as a separate actual call rather
        // than reporting only the final response as the complete total.
        for (let attempt = 0; attempt < http.attempts - 1; attempt++) call.budget.usage.record(`${meta.callId}:attempt:${attempt}`, emptyUsage(), this.prices);
        if (http.status === "unavailable") {
            if (http.attempts) call.budget.usage.record(meta.callId, meta.usage, this.prices);
            return fail(http.code);
        }
        const response = object(http.value);
        if (!response) { call.budget.usage.record(meta.callId, meta.usage, this.prices); return fail("invalid_response"); }
        meta.resolvedModel = typeof response.modelVersion === "string" && response.modelVersion ? response.modelVersion : null;
        const usage = object(response.usageMetadata);
        meta.usage = { ...emptyUsage(), inputTokens: tokenCount(usage?.promptTokenCount), outputTokens: tokenCount(usage?.candidatesTokenCount),
            cachedReadTokens: tokenCount(usage?.cachedContentTokenCount), reasoningTokens: tokenCount(usage?.thoughtsTokenCount), reasoningIsOutputSubset: false };
        call.budget.usage.record(meta.callId, meta.usage, this.prices);
        // Earlier transient attempts may have unknown billing. Their reserved
        // bounds remain charged; only the final observed usage is reconciled.
        const reservationId = http.reservationIds[http.reservationIds.length - 1];
        if (reservationId) call.budget.reconcile(reservationId, estimateCost(meta.usage, this.prices));
        if (object(response.promptFeedback)?.blockReason) return fail("refusal");
        if (!Array.isArray(response.candidates) || response.candidates.length !== 1) return fail("invalid_response");
        const candidate = object(response.candidates[0]);
        if (!candidate) return fail("invalid_response");
        if (["SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY"].includes(String(candidate.finishReason))) return fail("refusal");
        if (candidate.finishReason === "MAX_TOKENS") return fail("incomplete");
        if (candidate.finishReason !== "STOP") return fail("invalid_response");
        const parts = object(candidate.content)?.parts;
        if (!Array.isArray(parts) || parts.length === 0) return fail("invalid_response");
        const text: string[] = [];
        for (const raw of parts) {
            const part = object(raw);
            if (!part || typeof part.text !== "string" || part.functionCall !== undefined) return fail("invalid_response");
            if (part.thought !== true) text.push(part.text);
        }
        try {
            const value = request.parse(JSON.parse(text.join("")));
            if (call.signal?.aborted) return fail("cancelled");
            if (Date.now() >= Math.min(call.deadlineMs, call.budget.deadlineMs, started + this.timeoutMs)) return fail("timeout");
            return { status: "ok", value, meta: { ...meta, elapsedMs: Date.now() - started } };
        } catch { return fail("invalid_response"); }
    }
}
function object(value: unknown): Record<string, unknown> | null {
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
/** Gemini documents no native string-length constraints. They remain enforced
 * by the unchanged local parser. Required fields, enum/type constraints and
 * additionalProperties are retained; unsupported semantic operators fail. */
export function geminiJsonSchema(schema: Record<string, unknown>): Record<string, unknown> {
    const allowed = new Set(["$id", "$defs", "$ref", "$anchor", "type", "format", "title", "description", "enum", "items", "prefixItems", "minItems", "maxItems", "minimum", "maximum", "anyOf", "properties", "additionalProperties", "required"]);
    const convert = (node: unknown): unknown => {
        if (typeof node === "boolean") return node;
        const value = object(node);
        if (!value) throw new Error("Unsupported schema");
        const out: Record<string, unknown> = {};
        for (const [key, child] of Object.entries(value)) {
            if (["$schema", "minLength", "maxLength"].includes(key)) continue;
            if (key === "const" && ["string", "number"].includes(typeof child)) { out.enum = [child]; continue; }
            if (!allowed.has(key)) throw new Error("Unsupported schema constraint");
            if (key === "properties" || key === "$defs") out[key] = Object.fromEntries(Object.entries(object(child) ?? {}).map(([name, property]) => [name, convert(property)]));
            else if (["items", "additionalProperties"].includes(key)) out[key] = convert(child);
            else if (["anyOf", "prefixItems"].includes(key) && Array.isArray(child)) out[key] = child.map(convert);
            else out[key] = child;
        }
        return out;
    };
    return convert(schema) as Record<string, unknown>;
}
