import { readFileSync } from "node:fs";
import { z } from "zod";
import { createHash } from "node:crypto";
import type { ModelProfile } from "./contracts.js";

const capabilitySchema = z.strictObject({
    provider: z.enum(["anthropic", "openai", "gemini"]), model: z.string().min(1).max(150).regex(/^[a-zA-Z0-9._-]+$/),
    structured: z.boolean(), tools: z.boolean(), statelessTools: z.boolean(),
    maxInputBytes: z.number().int().positive().max(16_000_000), maxOutputTokens: z.number().int().positive().max(131072),
    allowedOptions: z.array(z.string()), reasoningEfforts: z.array(z.string()), thinkingLevels: z.array(z.string()),
    verifiedAt: z.string().regex(/^\d{4}-\d{2}-\d{2}$/), source: z.string().url(),
});
export const capabilityCatalogSchema = z.strictObject({ schemaVersion: z.literal(1), models: z.array(capabilitySchema).min(1).max(500) });
export type ModelCapabilities = z.infer<typeof capabilitySchema>;
export type CapabilityCatalog = z.infer<typeof capabilityCatalogSchema>;
export function loadCapabilityCatalog(path?: string): CapabilityCatalog {
    const catalog = capabilityCatalogSchema.parse(JSON.parse(readFileSync(path ?? new URL("../../config/model-capabilities.json", import.meta.url), "utf8")));
    const keys = catalog.models.map((model) => `${model.provider}:${model.model}`);
    if (new Set(keys).size !== keys.length) throw new Error("Duplicate model capability entries");
    return catalog;
}
export function modelCapabilities(profile: ModelProfile, catalog: CapabilityCatalog = loadCapabilityCatalog()): ModelCapabilities | null {
    return catalog.models.find((entry) => entry.provider === profile.provider && entry.model === profile.model) ?? null;
}
export function validateModelProfile(profile: ModelProfile, catalog?: CapabilityCatalog): void {
    const cap = modelCapabilities(profile, catalog);
    if (!cap) throw new Error(`Unsupported model profile: ${profile.provider}/${profile.model}; declare and probe capabilities first`);
    if (!Number.isSafeInteger(profile.maxOutputTokens) || profile.maxOutputTokens < 1 || profile.maxOutputTokens > cap.maxOutputTokens) throw new Error("Profile output limit exceeds model capability");
    const providerOptions = { gemini: ["temperature", "thinkingConfig"], anthropic: ["temperature", "thinking", "output_config"], openai: ["temperature", "top_p", "reasoning"] };
    for (const option of Object.keys(profile.options ?? {})) {
        if (!cap.allowedOptions.includes(option) || !providerOptions[profile.provider].includes(option)) throw new Error(`Unsupported model option: ${option}`);
    }
    const options = profile.options ?? {};
    if (options.temperature !== undefined && (typeof options.temperature !== "number" || !Number.isFinite(options.temperature) || options.temperature < 0 || options.temperature > 2)) throw new Error("Invalid temperature");
    if (options.top_p !== undefined && (typeof options.top_p !== "number" || !Number.isFinite(options.top_p) || options.top_p <= 0 || options.top_p > 1)) throw new Error("Invalid top_p");
    for (const [key, subkey, allowed] of [["reasoning", "effort", cap.reasoningEfforts], ["output_config", "effort", cap.reasoningEfforts], ["thinkingConfig", "thinkingLevel", cap.thinkingLevels]] as const) {
        if (options[key] !== undefined) {
            const value = options[key] as Record<string, unknown>;
            if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((name) => name !== subkey) || !allowed.includes(String(value[subkey]))) throw new Error(`Unsupported ${key} options`);
        }
    }
    if (options.thinking !== undefined) {
        const value = options.thinking as Record<string, unknown>;
        if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((key) => key !== "type") || value.type !== "adaptive" || options.temperature !== undefined) throw new Error("Unsupported thinking options");
    }
}
export function canonicalJson(value: unknown): string {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (value && typeof value === "object") {
        return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
}
export function hashConfiguration(value: unknown): string {
    return createHash("sha256").update(canonicalJson(value)).digest("hex");
}
export const profileHash = (profile: ModelProfile): string => hashConfiguration(profile);
