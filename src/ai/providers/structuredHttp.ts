import { randomUUID } from "node:crypto";
import type { CallContext, CallMeta, CallResult, FailureCode, ReasoningProviderId, StructuredRequest, Usage } from "../contracts.js";
import { modelCapabilities, profileHash, validateModelProfile, type CapabilityCatalog } from "../modelProfiles.js";
import { NativeTransport } from "../transport.js";
import { emptyUsage, estimateCost, reserveCost, type TokenPrices } from "../usage.js";

export interface StructuredHttpOptions { apiKey?: string; transport?: NativeTransport; timeoutMs?: number; prices?: TokenPrices; capabilities?: CapabilityCatalog }
export function object(value: unknown): Record<string, unknown> | null { return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null; }
export type ParsedNative = { text?: string; code?: FailureCode; usage: Usage; model: string | null };
export async function structuredHttp<T>(provider: ReasoningProviderId, request: StructuredRequest<T>, call: CallContext, options: StructuredHttpOptions,
    wire: () => { url: string; headers: Record<string, string>; body: unknown }, parseNative: (response: Record<string, unknown>) => ParsedNative): Promise<CallResult<T>> {
    const started = Date.now();
    const meta: CallMeta = { callId: randomUUID(), provider, requestedModel: request.profile.model, resolvedModel: null,
        profileHash: profileHash(request.profile), rubricVersion: request.rubricVersion, schemaVersion: request.schemaVersion,
        elapsedMs: 0, attempts: 0, usage: emptyUsage(), failureCode: null };
    const fail = (code: FailureCode): CallResult<T> => ({ status: "unavailable", code, meta: { ...meta, failureCode: code, elapsedMs: Date.now() - started } });
    if (call.signal?.aborted) return fail("cancelled");
    if (!options.apiKey) return fail("not_configured");
    let native: ReturnType<typeof wire>;
    try {
        validateModelProfile(request.profile, options.capabilities);
        if (request.profile.provider !== provider || !modelCapabilities(request.profile, options.capabilities)?.structured || request.maxOutputTokens > request.profile.maxOutputTokens) return fail("unsupported");
        native = wire();
    } catch { return fail("unsupported"); }
    const body = JSON.stringify(native.body);
    if (Buffer.byteLength(body) > modelCapabilities(request.profile, options.capabilities)!.maxInputBytes) return fail("context_limit");
    const timeoutMs = options.timeoutMs ?? 15000;
    const http = await (options.transport ?? new NativeTransport()).postJson({ ...native, body, timeoutMs,
        estimatedUsd: reserveCost(Buffer.byteLength(body), request.maxOutputTokens, options.prices) }, call);
    meta.attempts = http.attempts;
    for (let index = 0; index < http.attempts - 1; index++) call.budget.usage.record(`${meta.callId}:attempt:${index}`, emptyUsage(), options.prices);
    if (http.status === "unavailable") {
        if (http.attempts) call.budget.usage.record(meta.callId, meta.usage, options.prices);
        return fail(http.code);
    }
    const response = object(http.value);
    const parsed = response ? parseNative(response) : { usage: emptyUsage(), model: null, code: "invalid_response" as const };
    meta.usage = parsed.usage; meta.resolvedModel = parsed.model;
    call.budget.usage.record(meta.callId, meta.usage, options.prices);
    const reservationId = http.reservationIds[http.reservationIds.length - 1];
    if (reservationId) call.budget.reconcile(reservationId, estimateCost(meta.usage, options.prices));
    if (parsed.code) return fail(parsed.code);
    try {
        if (!parsed.text?.trim()) return fail("invalid_response");
        const value = request.parse(JSON.parse(parsed.text));
        if (call.signal?.aborted) return fail("cancelled");
        if (Date.now() >= Math.min(call.deadlineMs, call.budget.deadlineMs, started + timeoutMs)) return fail("timeout");
        return { status: "ok", value, meta: { ...meta, elapsedMs: Date.now() - started } };
    } catch { return fail("invalid_response"); }
}

/** Claude's native grammar cannot express these bounds. Preserve their meaning
 * in the description and always validate the original schema locally. */
export function anthropicJsonSchema(schema: Record<string, unknown>): Record<string, unknown> {
    const bounds = new Set(["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minLength", "maxLength", "minItems", "maxItems"]);
    const allowed = new Set(["type", "description", "title", "enum", "const", "properties", "additionalProperties", "required", "items", "anyOf", "$defs", "definitions", "$ref"]);
    const convert = (node: unknown): unknown => {
        if (typeof node === "boolean") return node;
        const value = object(node);
        if (!value) throw new Error("Unsupported schema");
        const out: Record<string, unknown> = {};
        const notes: string[] = [];
        for (const [key, child] of Object.entries(value)) {
            if (key === "$schema") continue;
            if (bounds.has(key)) { notes.push(`${key}: ${JSON.stringify(child)}`); continue; }
            if (!allowed.has(key)) throw new Error("Unsupported native schema constraint");
            if (["properties", "$defs", "definitions"].includes(key)) out[key] = Object.fromEntries(Object.entries(object(child) ?? {}).map(([name, item]) => [name, convert(item)]));
            else if (["items", "additionalProperties"].includes(key)) out[key] = convert(child);
            else if (key === "anyOf" && Array.isArray(child)) out[key] = child.map(convert);
            else out[key] = child;
        }
        if (notes.length) out.description = [out.description, `Required bounds (also checked locally): ${notes.join("; ")}.`].filter(Boolean).join(" ");
        return out;
    };
    return convert(schema) as Record<string, unknown>;
}
