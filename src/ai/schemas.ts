import { z } from "zod";

export const severitySchema = z.enum(["low", "medium", "high", "critical"]);
export const failureCodeSchema = z.enum(["not_configured", "unsupported", "authentication", "rate_limited",
    "timeout", "cancelled", "transport", "invalid_response", "refusal", "incomplete", "context_limit", "budget_exceeded"]);
const count = z.number().int().nonnegative().nullable();
export const usageSchema = z.strictObject({
    inputTokens: count, outputTokens: count, cachedReadTokens: count, cacheWriteTokens: count,
    reasoningTokens: count, reasoningIsOutputSubset: z.boolean(), cachedReadIsInputSubset: z.boolean(),
    cacheWriteIsInputSubset: z.boolean(),
});
export const callMetaSchema = z.strictObject({
    callId: z.string().min(1), provider: z.enum(["gemini", "anthropic", "openai", "typesafe"]),
    requestedModel: z.string().min(1), resolvedModel: z.string().min(1).nullable(),
    profileHash: z.string().min(1), rubricVersion: z.string().min(1), schemaVersion: z.string().min(1),
    elapsedMs: z.number().finite().nonnegative(), attempts: z.number().int().nonnegative(),
    usage: usageSchema, failureCode: failureCodeSchema.nullable(),
});
export function callResultSchema<T extends z.ZodType>(value: T) {
    return z.discriminatedUnion("status", [
        z.strictObject({ status: z.literal("ok"), value, meta: callMetaSchema }),
        z.strictObject({ status: z.literal("unavailable"), code: failureCodeSchema, meta: callMetaSchema }),
    ]);
}
export const reportVersionSchema = z.union([z.literal(1), z.literal(2)]);
export const promptInputSchema = z.strictObject({ prompt: z.string().min(1).max(100_000) });
export const skillInputSchema = z.strictObject({ skillContent: z.string().min(1).max(500_000) });
export const mcpPromptInputSchema = promptInputSchema.extend({ reportVersion: reportVersionSchema.optional() });
export const mcpSkillInputSchema = skillInputSchema.extend({ reportVersion: reportVersionSchema.optional() });
export function isSizeError(error: z.ZodError): boolean {
    return error.issues.some((issue) => issue.code === "too_big");
}
