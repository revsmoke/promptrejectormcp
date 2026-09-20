import { priceCardSchema, type PriceCard } from "./pricing.js";
import { z } from "zod";
import { hashConfiguration, validateModelProfile, loadCapabilityCatalog, capabilityCatalogSchema, modelCapabilities, type CapabilityCatalog } from "./modelProfiles.js";
import type { GenerativeRole, ReasoningProviderId } from "./contracts.js";
import type { PatternService } from "../services/PatternService.js";
import type { QualificationState } from "./qualification.js";
const identity = z.string().min(1).max(150).regex(/^[a-zA-Z0-9._-]+$/);
export const modelResolutionSchema = z.discriminatedUnion("kind", [
    z.strictObject({ kind: z.literal("pinned"), configuredModel: identity, resolvedModel: identity, method: z.string().min(1).max(1000) }),
    z.strictObject({ kind: z.literal("version_check"), configuredModel: identity, resolvedModel: identity, checkedAt: z.string().datetime(), expiresAt: z.string().datetime(), evidenceSha256: z.string().regex(/^[a-f0-9]{64}$/), method: z.string().min(1).max(1000) }),
]);
const positive = z.number().int().positive();
const profileSchema = z.strictObject({ provider: z.enum(["gemini", "anthropic", "openai"]), model: z.string().min(1).max(150).regex(/^[a-zA-Z0-9._-]+$/), maxOutputTokens: positive.max(131072), options: z.record(z.string(), z.unknown()).optional() });
const roleSchema = z.strictObject({ primary: z.string().min(1), fallback: z.string().min(1).optional() });
const mode = z.enum(["off", "shadow", "enforce"]);
const cascadeMode = z.enum(["off", "shadow", "enforce", "cascade"]);
export const limitsSchema = z.strictObject({
    reasoningTimeoutMs: positive.max(120000).default(15000), judgmentTimeoutMs: positive.max(30000).default(2000),
    analysisDeadlineMs: positive.max(120000).default(20000), maxConcurrentReasoning: positive.max(32).default(2),
    maxConcurrentJudgments: positive.max(64).default(4), maxQueue: z.number().int().nonnegative().max(1000).default(32),
    maxInferenceAttempts: z.strictObject({ prompt: positive.max(20).default(3), skill: positive.max(20).default(6), descriptor: positive.max(20).default(3), capability: positive.max(20).default(3) }).default({ prompt: 3, skill: 6, descriptor: 3, capability: 3 }),
    maxShadowAttempts: z.number().int().min(0).max(3).default(3),
});
export type AnalysisLimits = z.infer<typeof limitsSchema>;
export const aiConfigSchema = z.strictObject({
    schemaVersion: z.literal(1), profiles: z.record(z.string().min(1), profileSchema),
    roles: z.strictObject({ semantic: roleSchema, patternDraft: roleSchema, taster: roleSchema, monitor: roleSchema }),
    typesafe: z.strictObject({ model: z.string().min(1), descriptor: mode, prompt: cascadeMode, skill: cascadeMode, capability: mode, modelReference: mode }),
    limits: limitsSchema,
    qualificationPolicy: z.enum(["required", "optional"]).default("required"),
    mcpDefaultReportVersion: z.union([z.literal(1), z.literal(2)]).default(1),
    modelResolutions: z.record(z.string().min(1), modelResolutionSchema).optional(),
    capabilitiesFile: z.string().min(1).optional(), pricingFile: z.string().min(1).optional(), evaluationFile: z.string().min(1).optional(),
});
export type AIConfig = z.infer<typeof aiConfigSchema>;
export interface ConfigSnapshot { readonly config: AIConfig; readonly capabilities: CapabilityCatalog; readonly pricing?: PriceCard; readonly hash: string; readonly legacy: boolean; readonly evaluationOnly: boolean; readonly qualification?: QualificationState; readonly qualificationDirectory?: string; readonly evaluationPatternsSha256?: string }
export const keyNames: Readonly<Record<ReasoningProviderId | "typesafe", string>> = {
    gemini: "GEMINI_API_KEY", anthropic: "ANTHROPIC_API_KEY", openai: "OPENAI_API_KEY", typesafe: "TYPESAFE_API_KEY",
};
export function deepFreeze<T>(value: T): T {
    if (value && typeof value === "object") {
        for (const item of Object.values(value)) deepFreeze(item);
        Object.freeze(value);
    }
    return value;
}
export interface ConfigParseOptions { tasterEnabled?: boolean; capabilities?: CapabilityCatalog; pricing?: PriceCard; configDirectory?: string; patternService?: PatternService }
/** Internal structural validation shared only by serving config and the isolated evaluator. */
export function validateConfiguration(input: unknown, legacy = false, options: ConfigParseOptions = {}): ConfigSnapshot {
    const config = aiConfigSchema.parse(input);
    const pricing = options.pricing ? priceCardSchema.parse(options.pricing) : undefined;
    const capabilities = options.capabilities ? capabilityCatalogSchema.parse(options.capabilities) : loadCapabilityCatalog();
    if (new Set(capabilities.models.map((model) => `${model.provider}:${model.model}`)).size !== capabilities.models.length) throw new Error("Duplicate model capabilities");
    for (const role of Object.keys(config.roles) as GenerativeRole[]) {
        const setting = config.roles[role];
        if (setting.primary === setting.fallback) throw new Error(`Role ${role} cannot fall back to itself`);
        for (const name of [setting.primary, setting.fallback].filter((name): name is string => !!name)) {
            const profile = config.profiles[name];
            if (!profile) throw new Error(`Role ${role} references an unknown profile`);
            if (!(["taster", "monitor"].includes(role) && options.tasterEnabled === false)) {
                validateModelProfile(profile, capabilities);
                const cap = modelCapabilities(profile, capabilities)!;
                if (role === "taster" ? !cap.tools || !cap.statelessTools : !cap.structured) throw new Error(`Role ${role} requires supported capabilities`);
            }
        }
    }
    return deepFreeze({ config, capabilities, pricing, hash: hashConfiguration({ config, capabilities, pricing: pricing ?? null }), legacy, evaluationOnly: false });
}
