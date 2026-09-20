import { loadPriceCard, priceCardSchema, type PriceCard } from "./pricing.js";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { z } from "zod";
import { hashConfiguration, validateModelProfile, loadCapabilityCatalog, capabilityCatalogSchema, modelCapabilities, type CapabilityCatalog } from "./modelProfiles.js";
import type { GenerativeRole, ModelProfile, ReasoningProviderId } from "./contracts.js";

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
    capabilitiesFile: z.string().min(1).optional(), pricingFile: z.string().min(1).optional(), evaluationFile: z.string().min(1).optional(),
});
export type AIConfig = z.infer<typeof aiConfigSchema>;
export interface ConfigSnapshot { readonly config: AIConfig; readonly capabilities: CapabilityCatalog; readonly pricing?: PriceCard; readonly hash: string; readonly legacy: boolean }
export const keyNames: Readonly<Record<ReasoningProviderId | "typesafe", string>> = {
    gemini: "GEMINI_API_KEY", anthropic: "ANTHROPIC_API_KEY", openai: "OPENAI_API_KEY", typesafe: "TYPESAFE_API_KEY",
};
function deepFreeze<T>(value: T): T {
    if (value && typeof value === "object") {
        for (const item of Object.values(value)) deepFreeze(item);
        Object.freeze(value);
    }
    return value;
}
export function parseAIConfig(input: unknown, legacy = false, options: { tasterEnabled?: boolean; capabilities?: CapabilityCatalog; pricing?: PriceCard } = {}): ConfigSnapshot {
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
    // Enforced routes cannot accidentally start before the qualification gate
    // exists. Later rollout passes replace this with matching manifest validation.
    if (Object.entries(config.typesafe).some(([key, value]) => key !== "model" && ["enforce", "cascade"].includes(value))) throw new Error("Enforced TypeSafe routes require a matching qualification manifest");
    return deepFreeze({ config, capabilities, pricing, hash: hashConfiguration({ config, capabilities, pricing: pricing ?? null }), legacy });
}
export function loadAIConfig(env: NodeJS.ProcessEnv = process.env): ConfigSnapshot {
    if (env.AI_CONFIG_PATH) {
        // Config contents can contain untrusted strings. Do not echo them in a
        // startup error or include file bodies in logs.
        try {
            const input = JSON.parse(readFileSync(env.AI_CONFIG_PATH, "utf8"));
            const catalog = input.capabilitiesFile ? loadCapabilityCatalog(resolve(dirname(env.AI_CONFIG_PATH), input.capabilitiesFile)) : loadCapabilityCatalog();
            return parseAIConfig(input, false, { tasterEnabled: env.TASTE_TESTER_ENABLED === "true", capabilities: catalog, pricing: input.pricingFile ? loadPriceCard(resolve(dirname(env.AI_CONFIG_PATH), input.pricingFile)) : undefined });
        }
        catch { throw new Error("Invalid AI configuration; run ai-config-check for field diagnostics"); }
    }
    const tasterModel = env.TASTE_TESTER_MODEL || "claude-opus-4-7";
    return parseAIConfig({
        schemaVersion: 1,
        profiles: {
            "legacy-gemini": { provider: "gemini", model: "gemini-3-flash-preview", maxOutputTokens: 2048 },
            "legacy-anthropic": { provider: "anthropic", model: tasterModel, maxOutputTokens: 4096 },
        },
        roles: { semantic: { primary: "legacy-gemini" }, patternDraft: { primary: "legacy-gemini" }, taster: { primary: "legacy-anthropic" }, monitor: { primary: "legacy-anthropic" } },
        typesafe: { model: "jev-1.13.0", descriptor: "off", prompt: "off", skill: "off", capability: "off", modelReference: "off" },
        limits: {},
    }, true, { tasterEnabled: env.TASTE_TESTER_ENABLED === "true" });
}
export function roleProfiles(snapshot: ConfigSnapshot, role: GenerativeRole): ModelProfile[] {
    const setting = snapshot.config.roles[role];
    return [setting.primary, setting.fallback].filter((name): name is string => !!name).map((name) => snapshot.config.profiles[name]);
}
export function legacySemanticCompatible(snapshot: ConfigSnapshot): boolean {
    return roleProfiles(snapshot, "semantic").every((profile) => profile.provider === "gemini");
}
