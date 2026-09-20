import { loadPriceCard } from "./pricing.js";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { hashConfiguration, loadCapabilityCatalog } from "./modelProfiles.js";
import type { GenerativeRole, ModelProfile } from "./contracts.js";
import { validateConfiguration, deepFreeze, type ConfigParseOptions, type ConfigSnapshot } from "./configValidation.js";
import { qualifyConfiguration } from "./qualification.js";
export { aiConfigSchema, limitsSchema, keyNames } from "./configValidation.js";
export type { AIConfig, AnalysisLimits, ConfigSnapshot, ConfigParseOptions } from "./configValidation.js";
export function parseAIConfig(input: unknown, legacy = false, options: ConfigParseOptions = {}): ConfigSnapshot {
    const snapshot = validateConfiguration(input, legacy, options);
    const qualification = qualifyConfiguration(snapshot, options.configDirectory, options.patternService);
    return deepFreeze({ ...snapshot, qualification, qualificationDirectory: options.configDirectory ? resolve(options.configDirectory) : undefined, hash: hashConfiguration({ config: snapshot.config, capabilities: snapshot.capabilities, pricing: snapshot.pricing ?? null, qualification }) });
}
export function loadAIConfig(env: NodeJS.ProcessEnv = process.env): ConfigSnapshot {
    if (env.AI_CONFIG_PATH) {
        // Config contents can contain untrusted strings. Do not echo them in a
        // startup error or include file bodies in logs.
        try {
            const input = JSON.parse(readFileSync(env.AI_CONFIG_PATH, "utf8"));
            const catalog = input.capabilitiesFile ? loadCapabilityCatalog(resolve(dirname(env.AI_CONFIG_PATH), input.capabilitiesFile)) : loadCapabilityCatalog();
            return parseAIConfig(input, false, { tasterEnabled: env.TASTE_TESTER_ENABLED === "true", capabilities: catalog, configDirectory: dirname(resolve(env.AI_CONFIG_PATH)), pricing: input.pricingFile ? loadPriceCard(resolve(dirname(env.AI_CONFIG_PATH), input.pricingFile)) : undefined });
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
