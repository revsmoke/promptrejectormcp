import dotenv from "dotenv";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAIConfig, type ConfigSnapshot } from "../ai/config.js";
import { loadPriceCard, tokenPrices } from "../ai/pricing.js";
import { ProviderRegistry } from "../ai/registry.js";
import { TypeSafeAdapter } from "../ai/providers/TypeSafeAdapter.js";
import { NativeTransport, type FetchLike } from "../ai/transport.js";
import { AnalysisBudget } from "../ai/budget.js";
import { nativeJsonSchema, semanticFindingSchema } from "../ai/taskSchemas.js";
import { SECURITY_SYSTEM_INSTRUCTION } from "../services/SemanticAnalysisService.js";
import type { CallContext } from "../ai/contracts.js";

export function parseProbeArgs(args: string[]) {
    const flags: Record<string, string | true> = {};
    const allowed = new Set(["--live", "--profile", "--max-requests", "--max-usd", "--pricing", "--env-file"]);
    for (let index = 0; index < args.length; index++) {
        const flag = args[index];
        if (!allowed.has(flag) || flags[flag] !== undefined) throw new Error("Unknown or repeated probe option");
        if (flag === "--live") flags[flag] = true;
        else {
            const value = args[++index];
            if (!value || value.startsWith("--")) throw new Error("Probe option value missing");
            flags[flag] = value;
        }
    }
    const maxRequests = Number(flags["--max-requests"]), maxUsd = Number(flags["--max-usd"]);
    if (flags["--live"] !== true || typeof flags["--profile"] !== "string" || typeof flags["--pricing"] !== "string" || !Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > 20 || !Number.isFinite(maxUsd) || maxUsd <= 0 || maxUsd > 1) throw new Error("Probe requires --live --profile NAME --pricing FILE --max-requests 1..20 --max-usd (0,1]");
    return { profile: flags["--profile"] as string, pricing: flags["--pricing"] as string, maxRequests, maxUsd, envFile: flags["--env-file"] as string | undefined };
}
export async function runProbe(args: string[], options: { snapshot?: ConfigSnapshot; env?: NodeJS.ProcessEnv; fetch?: FetchLike } = {}) {
    const flags = parseProbeArgs(args);
    const env = options.env ?? process.env;
    const snapshot = options.snapshot ?? loadAIConfig(env);
    const pricing = loadPriceCard(flags.pricing);
    const selected = snapshot.config.profiles[flags.profile];
    if (!selected && flags.profile !== "typesafe") throw new Error("Unknown probe profile");
    const provider = selected?.provider ?? "typesafe", model = selected?.model ?? snapshot.config.typesafe.model;
    const prices = tokenPrices(pricing, provider, model);
    if (!prices) throw new Error("Selected model has no rate card entry; bounded probe refused");
    const limits = { ...snapshot.config.limits, maxInferenceAttempts: { ...snapshot.config.limits.maxInferenceAttempts, prompt: flags.maxRequests } };
    const budget = new AnalysisBudget("prompt", limits, { maxUsd: flags.maxUsd });
    const context: CallContext = { budget, deadlineMs: budget.deadlineMs, runId: randomUUID(), role: selected ? "semantic" : "judgment", configHash: snapshot.hash };
    const result = selected ? await new ProviderRegistry(snapshot, { env, fetch: options.fetch, pricing }).generate({
        profile: selected, maxOutputTokens: selected.maxOutputTokens, systemInstruction: SECURITY_SYSTEM_INSTRUCTION,
        state: JSON.stringify({ sourceType: "prompt", origin: "synthetic_probe", input: { id: "input", text: "Summarize this public weather note in one sentence: the day is sunny." } }),
        schemaId: "security_analysis", schemaVersion: "semantic-v2.1", rubricVersion: "security-eight-categories-v2.1",
        jsonSchema: nativeJsonSchema(semanticFindingSchema), parse: (value) => semanticFindingSchema.parse(value),
    }, context) : await new TypeSafeAdapter({ apiKey: env.TYPESAFE_API_KEY, prices, timeoutMs: limits.judgmentTimeoutMs, transport: new NativeTransport({ fetch: options.fetch }) }).evaluate({
        model, state: "The weather is sunny.", rubricVersion: "synthetic-probe-v1", schemaVersion: "noul-v1",
        questions: { sunny: { type: "noul", instructions: "Judge whether the supplied text describes sunny weather.", criteria: { true: "The text describes sunny weather.", false: "The text does not describe sunny weather." } } },
    }, context);
    return { synthetic: true, qualification: false, profile: flags.profile, status: result.status,
        ...(result.status === "unavailable" ? { code: result.code } : {}), meta: result.meta,
        limits: { maxRequests: flags.maxRequests, maxUsd: flags.maxUsd }, actualAttempts: budget.attempts, usage: budget.usage.summary() };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const flags = parseProbeArgs(process.argv.slice(2));
        dotenv.config({ path: flags.envFile, quiet: true });
        const result = await runProbe(process.argv.slice(2));
        console.log(JSON.stringify(result, null, 2));
        if (result.status !== "ok") process.exitCode = 1;
    } catch (error) { console.error(error instanceof Error && /^(Probe |Unknown |Selected )/.test(error.message) ? error.message : "Probe configuration failed; no credentials or provider bodies are logged."); process.exitCode = 1; }
}
