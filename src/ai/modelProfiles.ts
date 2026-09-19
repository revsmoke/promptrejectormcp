import { createHash } from "node:crypto";
import type { ModelProfile } from "./contracts.js";

export interface ModelCapabilities {
    structured: boolean;
    tools: boolean;
    maxInputBytes: number;
    maxOutputTokens: number;
    allowedOptions: readonly string[];
}
// Initial reference capabilities. Further native adapters and the external
// conformance catalog are introduced in Pass 2. IDs remain configuration strings.
const capabilities: Readonly<Record<string, ModelCapabilities>> = {
    "gemini:gemini-3-flash-preview": { structured: true, tools: true, maxInputBytes: 900_000, maxOutputTokens: 65536, allowedOptions: ["temperature", "thinkingConfig"] },
    "anthropic:claude-opus-4-7": { structured: true, tools: true, maxInputBytes: 900_000, maxOutputTokens: 65536, allowedOptions: [] },
    "anthropic:claude-sonnet-5": { structured: true, tools: true, maxInputBytes: 900_000, maxOutputTokens: 65536, allowedOptions: [] },
    "openai:gpt-6-astra": { structured: true, tools: true, maxInputBytes: 900_000, maxOutputTokens: 65536, allowedOptions: ["reasoning"] },
};
export function modelCapabilities(profile: ModelProfile): ModelCapabilities | null {
    return capabilities[`${profile.provider}:${profile.model}`] ?? null;
}
export function validateModelProfile(profile: ModelProfile): void {
    const cap = modelCapabilities(profile);
    if (!cap) throw new Error(`Unsupported model profile: ${profile.provider}/${profile.model}; run an explicit conformance probe first`);
    if (profile.maxOutputTokens > cap.maxOutputTokens) throw new Error("Profile output limit exceeds model capability");
    for (const option of Object.keys(profile.options ?? {})) {
        if (!cap.allowedOptions.includes(option)) throw new Error(`Unsupported model option: ${option}`);
    }
    const options = profile.options ?? {};
    if (options.temperature !== undefined && (typeof options.temperature !== "number" || !Number.isFinite(options.temperature) || options.temperature < 0 || options.temperature > 2)) throw new Error("Invalid temperature");
    if (options.reasoning !== undefined) {
        const reasoning = options.reasoning as Record<string, unknown>;
        if (!reasoning || typeof reasoning !== "object" || Array.isArray(reasoning) || Object.keys(reasoning).some((key) => key !== "effort") || !["low", "medium", "high", "xhigh", "max"].includes(String(reasoning.effort))) throw new Error("Unsupported reasoning options");
    }
    if (options.thinkingConfig !== undefined) {
        const thinking = options.thinkingConfig as Record<string, unknown>;
        if (!thinking || typeof thinking !== "object" || Array.isArray(thinking) || Object.keys(thinking).some((key) => key !== "thinkingLevel") || !["minimal", "low", "medium", "high"].includes(String(thinking.thinkingLevel))) throw new Error("Unsupported thinking options");
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
