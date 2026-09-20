import dotenv from "dotenv";
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAIConfig, parseAIConfig, type ConfigSnapshot } from "../ai/config.js";
import { loadPriceCard, tokenPrices } from "../ai/pricing.js";
import { loadCorpus } from "../evaluation/Corpus.js";
import { summarizeObservations, repeatedAnswerChanges } from "../evaluation/Metrics.js";
import { evaluationServices, evaluateCase } from "../evaluation/Runner.js";
import { RunQuota } from "../evaluation/RunQuota.js";
export function parseEvaluationArgs(args: string[]) {
    const values: Record<string, string | true> = {};
    const switches = new Set(["--live", "--offline", "--acceptance"]);
    const named = new Set(["--dataset", "--profiles", "--scenarios", "--tasks", "--max-requests", "--max-usd", "--pricing", "--output", "--config", "--env-file", "--limit", "--repeats"]);
    for (let i = 0; i < args.length; i++) {
        const flag = args[i];
        if (values[flag] !== undefined || (!switches.has(flag) && !named.has(flag))) throw new Error("Unknown or repeated evaluation option");
        if (switches.has(flag)) values[flag] = true;
        else { const next = args[++i]; if (!next || next.startsWith("--")) throw new Error("Missing evaluation option value"); values[flag] = next; }
    }
    const live = values["--live"] === true;
    if (live && values["--offline"]) throw new Error("Choose offline or live evaluation");
    const dataset = values["--dataset"], profiles = typeof values["--profiles"] === "string" ? values["--profiles"].split(",") : undefined;
    if (typeof dataset !== "string") throw new Error("Evaluation requires a versioned dataset manifest");
    const maxRequests = Number(values["--max-requests"]), maxUsd = Number(values["--max-usd"]);
    if (live && (!profiles?.length || profiles.some((name) => !name) || typeof values["--pricing"] !== "string" || !Number.isSafeInteger(maxRequests) || maxRequests < 1 || !Number.isFinite(maxUsd) || maxUsd <= 0)) throw new Error("Live evaluation requires profiles, pricing, request limit and USD limit");
    const scenarios = String(values["--scenarios"] ?? "off").split(",");
    if (scenarios.some((mode) => mode !== "off" && mode !== "shadow")) throw new Error("Evaluation scenario is not implemented");
    const tasks = values["--tasks"] ? String(values["--tasks"]).split(",") : undefined;
    if (tasks?.some((task) => !["descriptor", "prompt", "skill", "capability", "modelReference", "taster"].includes(task))) throw new Error("Unknown evaluation task");
    const limit = values["--limit"] === undefined ? Infinity : Number(values["--limit"]), repeats = Number(values["--repeats"] ?? 1);
    if ((limit !== Infinity && (!Number.isSafeInteger(limit) || limit < 1)) || !Number.isSafeInteger(repeats) || repeats < 1 || repeats > 100) throw new Error("Invalid evaluation size");
    return { live, dataset, profiles, scenarios: scenarios as Array<"off" | "shadow">, tasks, maxRequests, maxUsd, limit, repeats,
        pricing: values["--pricing"] as string | undefined, config: values["--config"] as string | undefined, envFile: values["--env-file"] as string | undefined,
        output: typeof values["--output"] === "string" ? values["--output"] : `evaluations/ai/runs/${new Date().toISOString().replace(/[:.]/g, "-")}`,
        acceptance: values["--acceptance"] === true };
}
export async function runEvaluation(args: string[], options: { env?: NodeJS.ProcessEnv; snapshot?: ConfigSnapshot } = {}) {
    const flags = parseEvaluationArgs(args);
    const corpus = loadCorpus(flags.dataset, { acceptance: flags.acceptance });
    const cases = corpus.cases.filter((item) => !flags.tasks || flags.tasks.includes(item.task)).slice(0, flags.limit);
    if (!cases.length) throw new Error("No selected evaluation cases");
    if (existsSync(flags.output) && readdirSync(flags.output).length) throw new Error("Evaluation output directory must be empty");
    // Offline ignores ambient secrets and configuration. An explicit config
    // file may be inspected, but never enables provider access without --live.
    const env = flags.live ? options.env ?? process.env : {};
    const initial = options.snapshot ?? loadAIConfig({ ...env, ...(flags.config ? { AI_CONFIG_PATH: flags.config } : {}) });
    const pricing = flags.pricing ? loadPriceCard(flags.pricing) : initial.pricing;
    const profiles = flags.profiles ?? [initial.config.roles.semantic.primary];
    const quota = flags.live ? new RunQuota(flags.maxRequests, flags.maxUsd) : undefined;
    const records: Array<Awaited<ReturnType<typeof evaluateCase>> & { profile: string; scenario: string; repeat: number; configHash: string }> = [];
    const groups: Record<string, ReturnType<typeof summarizeObservations>> = {};
    const changes: Record<string, ReturnType<typeof repeatedAnswerChanges>> = {};
    const jobs: Array<{ profile: string; scenario: "off" | "shadow"; snapshot: ConfigSnapshot }> = [];
    // Preflight every route before any dispatch. A later invalid profile must
    // not cause a partly billed run whose configuration never validated.
    for (const profile of profiles) for (const scenario of flags.scenarios) {
        if (profile !== "typesafe" && !initial.config.profiles[profile]) throw new Error("Unknown selected profile");
        const config = structuredClone(initial.config);
        if (profile !== "typesafe") config.roles.semantic = { primary: profile };
        if (cases.some((item) => item.task === "taster") && profile !== "typesafe") config.roles.taster = { primary: profile };
        config.typesafe = { model: config.typesafe.model, descriptor: scenario, prompt: scenario, skill: scenario, capability: scenario, modelReference: scenario };
        const snapshot = parseAIConfig(config, false, { capabilities: initial.capabilities, pricing });
        if (flags.live) {
            if (scenario !== "off" && !tokenPrices(pricing, "typesafe", config.typesafe.model)) throw new Error("TypeSafe rate missing; live dispatch refused");
            if (cases.some((item) => ["prompt", "skill", "taster"].includes(item.task))) {
                if (profile === "typesafe") throw new Error("Full prompt/skill evaluation requires a reasoning profile");
                const selected = config.profiles[profile];
                if (!tokenPrices(pricing, selected.provider, selected.model)) throw new Error("Reasoning rate missing; live dispatch refused");
            }
            if (cases.some((item) => item.task === "taster")) for (const name of [config.roles.monitor.primary, config.roles.monitor.fallback].filter((name): name is string => !!name)) {
                const selected = config.profiles[name];
                if (!tokenPrices(pricing, selected.provider, selected.model)) throw new Error("Monitor rate missing; live dispatch refused");
            }
        }
        jobs.push({ profile, scenario, snapshot });
    }
    mkdirSync(flags.output, { recursive: true });
    let completed = true;
    const executionErrors: Array<{ id: string; profile: string; scenario: string; reason: string }> = [];
    outer: for (const { profile, scenario, snapshot } of jobs) for (let repeat = 0; repeat < flags.repeats; repeat++) {
        const services = evaluationServices(snapshot, { live: flags.live, env, quota });
        for (const item of cases) {
            if (quota?.exhausted) { completed = false; break outer; }
            try { records.push({ ...await evaluateCase(services, item), profile, scenario, repeat, configHash: snapshot.hash }); }
            catch { completed = false; executionErrors.push({ id: item.id, profile, scenario, reason: "case_execution_failed" }); break outer; }
            finally { quota?.finish(); }
        }
    }
    for (const key of new Set(records.map((row) => `${row.profile}:${row.scenario}:${row.task}`))) {
        const rows = records.filter((row) => `${row.profile}:${row.scenario}:${row.task}` === key);
        groups[key] = summarizeObservations(rows.map((row) => row.observation));
        changes[key] = repeatedAnswerChanges(Array.from({ length: flags.repeats }, (_, repeat) => rows.filter((row) => row.repeat === repeat).map((row) => row.observation)));
    }
    const summary = { schemaVersion: 1, evaluationOnly: true, qualification: false, live: flags.live, completed, dataset: { id: corpus.manifest.id, sha256: corpus.manifest.sha256, qualificationEligible: corpus.manifest.qualificationEligible },
        selectedCases: cases.length, completedCases: records.length, expectedCases: cases.length * profiles.length * flags.scenarios.length * flags.repeats,
        limits: flags.live ? { maxRequests: flags.maxRequests, maxUsd: flags.maxUsd } : null,
        budget: quota ? { attempts: quota.attempts, conservativeReservedUsd: quota.reservedUsd, unknownSpend: quota.unknownSpend } : null,
        groups, repeatedChanges: changes, exactReferenceExtraction: { cases: records.filter((row) => row.exactReferences !== null).length, correct: records.filter((row) => row.exactReferences === true).length },
        executionErrors, limitations: [...corpus.manifest.limitations, ...flags.live ? [] : ["Offline full scans explicitly lack live semantic and HF metadata coverage."], "A successful run is not an activation manifest. Review and unavailable remain abstentions."] };
    writeFileSync(resolve(flags.output, "records.jsonl"), records.map((item) => JSON.stringify(item)).join("\n") + "\n", { flag: "wx" });
    writeFileSync(resolve(flags.output, "summary.json"), JSON.stringify(summary, null, 2) + "\n", { flag: "wx" });
    return summary;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const flags = parseEvaluationArgs(process.argv.slice(2));
        if (flags.live) dotenv.config({ path: flags.envFile, quiet: true });
        const summary = await runEvaluation(process.argv.slice(2));
        console.log(JSON.stringify(summary, null, 2));
        if (!summary.completed) process.exitCode = 1;
    } catch { console.error("Evaluation failed validation or execution; provider bodies and credentials are not logged."); process.exitCode = 1; }
}
