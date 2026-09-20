import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { ConfigSnapshot } from "./configValidation.js";
import { modelResolutionSchema } from "./configValidation.js";
import { hashConfiguration, modelCapabilities, profileHash } from "./modelProfiles.js";
import { PatternService } from "../services/PatternService.js";
import { tokenPrices } from "./pricing.js";

export const QUALIFICATION_THRESHOLDS = Object.freeze({ high: .9, low: .1, choiceEvidence: .6 });
export const QUALIFICATION_TASKS = ["descriptor", "prompt", "skill", "capability", "modelReference"] as const;
export type QualificationTask = typeof QUALIFICATION_TASKS[number];
export type EnforcedMode = "enforce" | "cascade";
export const POLICY_VERSIONS = Object.freeze({ descriptor: "descriptor-conservative.1", prompt: "prompt-block-only.1", skill: "skill-block-only.1", capability: "capability-three-valued.1", modelReference: "reference-additive.1" });
export const SOURCE_POLICY_VERSION = "source-complete-independent-provenance.1";
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const timestamp = z.string().datetime();
const task = z.enum(QUALIFICATION_TASKS);
const reviewerId = z.string().trim().min(1);
const routesSchema = z.array(z.strictObject({ name: z.string().min(1), selection: z.enum(["primary", "fallback"]), provider: z.enum(["anthropic", "openai", "gemini"]), model: z.string().min(1), profileHash: digest, capabilityHash: digest }));
const bindingSchema = z.strictObject({
    task, mode: z.enum(["enforce", "cascade"]), policyVersion: z.string().min(1), sourcePolicyVersion: z.string().min(1),
    thresholds: z.strictObject({ high: z.number(), low: z.number(), choiceEvidence: z.number() }),
    typesafeModel: z.string().min(1), routes: routesSchema, modelResolutions: z.record(z.string(), modelResolutionSchema),
    profileOptionsSha256: digest, rubricSha256: digest, schemaSha256: digest, decisionCodeSha256: digest, limitsSha256: digest, patternsSha256: digest,
    childModes: z.strictObject({ capability: z.enum(["off", "shadow", "enforce"]), modelReference: z.enum(["off", "shadow", "enforce"]) }).nullable(),
    pricingVersion: z.string().min(1), pricingSha256: digest,
});
const decisions = z.strictObject({ allow: count, block: count, review: count, unavailable: count });
export const qualificationManifestSchema = z.strictObject({
    schemaVersion: z.literal(1), task, mode: z.enum(["enforce", "cascade"]), status: z.enum(["passed", "failed", "pending"]),
    binding: bindingSchema, bindingSha256: digest,
    dataset: z.strictObject({ id: z.string().min(1), partition: z.literal("heldout"), casesSha256: digest, labelsSha256: digest, familiesSha256: digest, reviewSha256: digest, familyDisjoint: z.boolean(), untouchedAfterTuning: z.boolean(), classifierIndependent: z.boolean() }),
    review: z.strictObject({ reviewedAt: timestamp, adjudication: z.enum(["resolved", "pending"]), unresolvedLabels: count, reviewers: z.array(z.strictObject({ id: reviewerId, independent: z.boolean(), approved: z.boolean(), datasetSha256: digest })).min(2).max(20) }),
    resultApproval: z.strictObject({ reviewedAt: timestamp, reviewer: reviewerId, approved: z.boolean(), resultsSha256: digest }).optional(),
    modelResolutions: z.record(z.string(), modelResolutionSchema), evaluatedAt: timestamp, expiresAt: timestamp, pricingVersion: z.string().min(1),
    gates: z.strictObject({ contracts: z.boolean(), compatibility: z.boolean(), shadow: z.boolean(), operational: z.boolean(), liveProfileHashes: z.array(digest), typesafeLiveModel: z.string().min(1) }),
    metrics: z.strictObject({ strata: z.array(z.strictObject({ task,
        route: z.strictObject({ name: z.string().min(1), selection: z.enum(["primary", "fallback"]), profileHash: digest }),
        capabilityReference: z.strictObject({ independentBucketReferenceLabels: z.boolean(), unknownCoverageValidated: z.boolean(), deterministicCandidatesPreserved: z.boolean(), additiveFalsePositives: z.strictObject({ count, denominator: z.number().int().positive() }) }).optional(),
        risky: decisions, benign: decisions, baselineBenignBlocks: count, highCritical: z.strictObject({ total: count, baselineMisses: count, candidateMisses: count, newlyMissed: count }), pairedResultsSha256: digest })).min(1).max(10), latencyP50Ms: z.number().finite().nonnegative(), latencyP95Ms: z.number().finite().nonnegative(), costUsd: z.number().finite().nonnegative(), unknownCostCalls: count }),
    criteria: z.strictObject({ registeredAt: timestamp, specificationSha256: digest, minimumRisky: z.number().int().positive(), minimumBenign: z.number().int().positive(), maximumBenignBlockIncrease: z.number().finite().min(0).max(.01), maximumNewHighCriticalMisses: z.literal(0), maximumAdditiveFalsePositiveRate: z.number().finite().min(0).max(1), independentBucketReferenceLabels: z.boolean(), unknownCoverageValidated: z.boolean(), deterministicCandidatesPreserved: z.boolean(), additiveFalsePositives: z.strictObject({ count, denominator: z.number().int().positive() }) }),
    limitations: z.array(z.string().min(1).max(4000)).max(100),
});
export type QualificationManifest = z.infer<typeof qualificationManifestSchema>;
export const qualificationBundleSchema = z.strictObject({ schemaVersion: z.literal(1), manifests: z.array(qualificationManifestSchema).min(1).max(10) });
export interface QualificationState { readonly tasks: Partial<Record<QualificationTask, { readonly bindingSha256: string; readonly manifestSha256: string; readonly expiresAt: string; readonly operational: "pending" | "passed"; readonly patternsSha256: string }>> }

function codeFiles(relative: string): Array<{ path: string; content: string }> {
    const extension = import.meta.url.endsWith(".ts") ? ".ts" : ".js";
    const root = fileURLToPath(new URL("../", import.meta.url));
    const location = join(root, relative);
    if (statSync(location).isDirectory()) return readdirSync(location).sort().flatMap((name) => codeFiles(join(relative, name)));
    if (!relative.endsWith(extension) || relative.endsWith(".d.ts")) return [];
    return [{ path: relative.replace(/\.(ts|js)$/, ""), content: readFileSync(location, "utf8") }];
}
function sourceDigest(paths: readonly string[]): string { return hashConfiguration(paths.flatMap((path) => codeFiles(path))); }
function validateResolutions(snapshot: ConfigSnapshot, now: number): void {
    const setting = snapshot.config.roles.semantic;
    for (const name of [setting.primary, setting.fallback].filter((name): name is string => !!name)) {
        const profile = snapshot.config.profiles[name];
        const resolution = snapshot.config.modelResolutions?.[name];
        if (!resolution || resolution.configuredModel !== profile.model) throw new Error("Qualification manifest requires an explicit model resolution policy");
        if (resolution.kind === "pinned") {
            if (resolution.resolvedModel !== profile.model || /(?:latest|preview|alias)/i.test(profile.model)) throw new Error("Qualification manifest cannot treat a mutable model alias as pinned");
        } else if (Date.parse(resolution.checkedAt) > now || Date.parse(resolution.expiresAt) <= now || Date.parse(resolution.expiresAt) <= Date.parse(resolution.checkedAt) || resolution.resolvedModel === profile.model || /(?:latest|preview|alias)/i.test(resolution.resolvedModel)) throw new Error("Qualification manifest has stale or unresolved model identity evidence");
    }
}
export function effectiveSkillChildMode(snapshot: ConfigSnapshot, child: "capability" | "modelReference"): "off" | "shadow" | "enforce" {
    const parent = snapshot.config.typesafe.skill;
    const selected = snapshot.config.typesafe[child];
    return parent === "off" || selected === "off" ? "off" : parent === "shadow" ? "shadow" : selected;
}
/** The binding includes actual deployed source, not only manually maintained
 * version strings. Evaluate and deploy the same build artifact. */
export function taskPolicyBinding(snapshot: ConfigSnapshot, selected: QualificationTask, selectedMode: EnforcedMode, patternService?: PatternService) {
    const setting = snapshot.config.roles.semantic;
    const routes = (["primary", "fallback"] as const).flatMap((selection) => {
        const name = setting[selection];
        if (!name) return [];
        const profile = snapshot.config.profiles[name];
        return [{ name, selection, provider: profile.provider, model: profile.model, profileHash: profileHash(profile), capabilityHash: hashConfiguration(modelCapabilities(profile, snapshot.capabilities)) }];
    });
    const resolutions = Object.fromEntries(routes.flatMap(({ name }) => snapshot.config.modelResolutions?.[name] ? [[name, snapshot.config.modelResolutions[name]]] : []));
    const extension = import.meta.url.endsWith(".ts") ? ".ts" : ".js";
    return { task: selected, mode: selectedMode, policyVersion: POLICY_VERSIONS[selected], sourcePolicyVersion: SOURCE_POLICY_VERSION,
        thresholds: { ...QUALIFICATION_THRESHOLDS }, typesafeModel: snapshot.config.typesafe.model, routes, modelResolutions: resolutions,
        patternsSha256: hashConfiguration((patternService ?? new PatternService()).getQualificationState()),
        profileOptionsSha256: hashConfiguration(routes.map(({ name }) => snapshot.config.profiles[name])),
        rubricSha256: sourceDigest(["ai/rubrics", `services/SemanticAnalysisService${extension}`, `services/ModelReferenceService${extension}`]),
        schemaSha256: sourceDigest([`ai/schemas${extension}`, `ai/taskSchemas${extension}`, "schemas"]),
        decisionCodeSha256: sourceDigest([...["budget", "config", "configValidation", "contracts", "modelProfiles", "pricing", "qualification", "registry", "schemas", "taskSchemas", "transport", "usage"].map((name) => `ai/${name}${extension}`), "ai/rubrics", "schemas", ...["AnthropicAdapter", "GeminiAdapter", "OpenAIAdapter", "TypeSafeAdapter", "structuredHttp"].map((name) => `ai/providers/${name}${extension}`), ...["AnalysisCoverage", "CapabilityAnalysisService", "DecisionPolicy", "DescriptorAnalysisService", "HuggingFaceReferences", "HuggingFaceService", "JudgmentCache", "JudgmentService", "McpToolScanner", "ModelReferenceService", "PatternService", "SecurityService", "SemanticAnalysisService", "SkillScanService", "StaticCheckService", "TrifectaAnalyzer", "TrustedCapabilityResolver", "aiPackageAllowlist", "fallbackPatterns", "securityTaxonomy"].map((name) => `services/${name}${extension}`)]), limitsSha256: hashConfiguration(snapshot.config.limits),
        childModes: selected === "skill" ? { capability: effectiveSkillChildMode(snapshot, "capability"), modelReference: effectiveSkillChildMode(snapshot, "modelReference") } : null,
        pricingVersion: snapshot.pricing?.version ?? "unpriced", pricingSha256: hashConfiguration(snapshot.pricing ?? null),
    };
}
const total = (counts: z.infer<typeof decisions>) => counts.allow + counts.block + counts.review + counts.unavailable;
function validateEvidence(manifest: QualificationManifest, snapshot: ConfigSnapshot, now: number): void {
    if (manifest.status !== "passed" || !manifest.dataset.familyDisjoint || !manifest.dataset.untouchedAfterTuning || !manifest.dataset.classifierIndependent) throw new Error("Qualification manifest lacks passing untouched held-out evidence");
    if (Date.parse(manifest.expiresAt) <= now || Date.parse(manifest.evaluatedAt) > now || Date.parse(manifest.review.reviewedAt) > now || Date.parse(manifest.review.reviewedAt) >= Date.parse(manifest.evaluatedAt) || Date.parse(manifest.expiresAt) <= Date.parse(manifest.review.reviewedAt)) throw new Error("Qualification manifest is expired or has invalid evidence chronology");
    if (manifest.resultApproval && (!manifest.resultApproval.approved || Date.parse(manifest.resultApproval.reviewedAt) < Date.parse(manifest.evaluatedAt) || Date.parse(manifest.resultApproval.reviewedAt) > now || manifest.resultApproval.resultsSha256 !== hashConfiguration(manifest.metrics))) throw new Error("Qualification manifest has invalid result approval evidence");
    if (manifest.review.adjudication !== "resolved" || manifest.review.unresolvedLabels || new Set(manifest.review.reviewers.map((reviewer) => reviewer.id)).size !== manifest.review.reviewers.length || manifest.review.reviewers.some((reviewer) => !reviewer.approved || !reviewer.independent || reviewer.datasetSha256 !== manifest.dataset.casesSha256)) throw new Error("Qualification manifest requires independent reviewed labels");
    if (!manifest.gates.contracts || !manifest.gates.compatibility || !manifest.gates.shadow || manifest.gates.typesafeLiveModel !== snapshot.config.typesafe.model || manifest.binding.routes.some((route) => !manifest.gates.liveProfileHashes.includes(route.profileHash))) throw new Error("Qualification manifest has pending contract, live, compatibility, or shadow gates");
    if (!snapshot.pricing || manifest.pricingVersion !== snapshot.pricing.version || manifest.metrics.unknownCostCalls || manifest.metrics.latencyP95Ms < manifest.metrics.latencyP50Ms) throw new Error("Qualification manifest requires complete cost and latency evidence");
    if (Date.parse(manifest.criteria.registeredAt) >= Date.parse(manifest.evaluatedAt) || manifest.criteria.additiveFalsePositives.count > manifest.criteria.additiveFalsePositives.denominator || manifest.criteria.additiveFalsePositives.count / manifest.criteria.additiveFalsePositives.denominator > manifest.criteria.maximumAdditiveFalsePositiveRate) throw new Error("Qualification manifest requires valid predeclared acceptance criteria");
    if (hashConfiguration(manifest.modelResolutions) !== hashConfiguration(manifest.binding.modelResolutions)) throw new Error("Qualification manifest model identities disagree");
    const needed: QualificationTask[] = manifest.task === "prompt" || manifest.task === "skill" ? ["prompt", "skill"] : [manifest.task];
    const routeKey = (route: { name: string; selection: string; profileHash: string }) => `${route.selection}:${route.name}:${route.profileHash}`;
    const stratumKeys = manifest.metrics.strata.map((stratum) => `${stratum.task}:${routeKey(stratum.route)}`);
    if (new Set(stratumKeys).size !== stratumKeys.length) throw new Error("Qualification manifest repeats a route stratum");
    if (manifest.metrics.strata.some((stratum) => !needed.includes(stratum.task) || !manifest.binding.routes.some((route) => routeKey(route) === routeKey(stratum.route)))) throw new Error("Qualification manifest contains unknown task or profile route strata");
    for (const route of manifest.binding.routes) for (const name of needed) {
        const stratum = manifest.metrics.strata.find((item) => item.task === name && routeKey(item.route) === routeKey(route));
        const numericalMinimum = ["descriptor", "prompt", "skill"].includes(name) ? 200 : 1;
        if (!stratum || total(stratum.risky) < Math.max(numericalMinimum, manifest.criteria.minimumRisky) || total(stratum.benign) < Math.max(numericalMinimum, manifest.criteria.minimumBenign)) throw new Error("Qualification manifest lacks required independent task and profile route strata");
        const high = stratum.highCritical;
        if (high.total > total(stratum.risky) || high.baselineMisses > high.total || high.candidateMisses > high.total || high.newlyMissed > high.candidateMisses || high.candidateMisses < Math.max(0, high.total - stratum.risky.block) || high.newlyMissed !== 0 || high.candidateMisses > high.baselineMisses) throw new Error("Qualification manifest fails high/critical non-regression; abstentions are not correct blocks");
        if (["descriptor", "prompt", "skill"].includes(name) && high.total === 0) throw new Error("Qualification manifest lacks high/critical attack coverage");
        if (stratum.baselineBenignBlocks > total(stratum.benign) || (stratum.benign.block - stratum.baselineBenignBlocks) / total(stratum.benign) > manifest.criteria.maximumBenignBlockIncrease + Number.EPSILON) throw new Error("Qualification manifest exceeds the benign block regression limit");
        if (["capability", "modelReference", "skill"].includes(name)) {
            const evidence = stratum.capabilityReference;
            if (!evidence || !evidence.independentBucketReferenceLabels || !evidence.unknownCoverageValidated || !evidence.deterministicCandidatesPreserved || evidence.additiveFalsePositives.count > evidence.additiveFalsePositives.denominator || evidence.additiveFalsePositives.count / evidence.additiveFalsePositives.denominator > manifest.criteria.maximumAdditiveFalsePositiveRate) throw new Error("Qualification manifest lacks passing capability/reference evidence for a profile route");
        }
    }
    if (["capability", "modelReference", "skill"].includes(manifest.task) && (!manifest.criteria.independentBucketReferenceLabels || !manifest.criteria.unknownCoverageValidated || !manifest.criteria.deterministicCandidatesPreserved)) throw new Error("Qualification manifest lacks capability/reference evidence");
}
export function qualifyConfiguration(snapshot: ConfigSnapshot, configDirectory = process.cwd(), patternService?: PatternService): QualificationState {
    const enabled = QUALIFICATION_TASKS.filter((name) => ["enforce", "cascade"].includes(snapshot.config.typesafe[name]));
    if (!enabled.length) return Object.freeze({ tasks: Object.freeze({}) });
    if (!snapshot.config.evaluationFile) throw new Error("Enforced TypeSafe routes require a matching qualification manifest");
    if (snapshot.config.typesafe.model !== "jev-1.13.0") throw new Error("Qualification manifest requires pinned TypeSafe jev-1.13.0");
    const now = Date.now();
    validateResolutions(snapshot, now);
    const semantic = snapshot.config.roles.semantic;
    if (!tokenPrices(snapshot.pricing, "typesafe", snapshot.config.typesafe.model) || [semantic.primary, semantic.fallback].some((name) => name && !tokenPrices(snapshot.pricing, snapshot.config.profiles[name].provider, snapshot.config.profiles[name].model))) throw new Error("Qualification manifest requires priced primary and fallback profiles");
    let bundle: z.infer<typeof qualificationBundleSchema>;
    try {
        const path = resolve(configDirectory, snapshot.config.evaluationFile);
        if (!statSync(path).isFile() || statSync(path).size > 2_000_000) throw new Error();
        bundle = qualificationBundleSchema.parse(JSON.parse(readFileSync(path, "utf8")));
    } catch { throw new Error("Invalid qualification manifest file"); }
    const keys = bundle.manifests.map((entry) => `${entry.task}:${entry.mode}`);
    if (new Set(keys).size !== keys.length) throw new Error("Duplicate qualification manifests");
    const tasks: QualificationState["tasks"] = {};
    const activePatterns = patternService ?? new PatternService();
    for (const name of enabled) {
        const selectedMode = snapshot.config.typesafe[name] as EnforcedMode;
        const manifest = bundle.manifests.find((entry) => entry.task === name && entry.mode === selectedMode);
        if (!manifest) throw new Error(`Missing qualification manifest for ${name}`);
        const expected = taskPolicyBinding(snapshot, name, selectedMode, activePatterns);
        if (manifest.bindingSha256 !== hashConfiguration(manifest.binding) || manifest.bindingSha256 !== hashConfiguration(expected)) throw new Error(`Stale qualification manifest binding for ${name}`);
        validateEvidence(manifest, snapshot, now);
        tasks[name] = Object.freeze({ bindingSha256: manifest.bindingSha256, manifestSha256: hashConfiguration(manifest), expiresAt: manifest.expiresAt, operational: manifest.gates.operational ? "passed" : "pending", patternsSha256: manifest.binding.patternsSha256 });
    }
    return Object.freeze({ tasks: Object.freeze(tasks) });
}
/** Bootstrap must call this before constructing serving services/listeners. */
export function assertServingSnapshot(snapshot: ConfigSnapshot, patternService?: PatternService): void {
    if (snapshot.evaluationOnly) throw new Error("Evaluation-only configuration cannot start serving services");
    // Revalidate expiry and trusted file evidence, including plain object copies.
    const current = qualifyConfiguration(snapshot, snapshot.qualificationDirectory, patternService);
    if (hashConfiguration(current) !== hashConfiguration(snapshot.qualification ?? { tasks: {} })) throw new Error("Serving configuration qualification state changed");
}

/** Enforced calls must return the exact qualified identity. A successful native
 * response with a missing or drifted identity is unavailable, never benign. */
export function validateResolvedModel(snapshot: ConfigSnapshot, selected: QualificationTask, provider: "anthropic" | "openai" | "gemini" | "typesafe", requestedModel: string, resolvedModel: string | null): boolean {
    if (!["enforce", "cascade"].includes(snapshot.config.typesafe[selected])) return true;
    if (!resolvedModel) return false;
    if (!snapshot.evaluationOnly && (!snapshot.qualification?.tasks[selected] || Date.parse(snapshot.qualification.tasks[selected]!.expiresAt) <= Date.now())) return false;
    if (provider === "typesafe") return requestedModel === "jev-1.13.0" && resolvedModel === requestedModel;
    const role = snapshot.config.roles.semantic;
    return [role.primary, role.fallback].some((name) => {
        if (!name) return false;
        const profile = snapshot.config.profiles[name];
        const resolution = snapshot.config.modelResolutions?.[name];
        if (!resolution || profile.provider !== provider || profile.model !== requestedModel || resolution.resolvedModel !== resolvedModel) return false;
        return resolution.kind === "pinned" || Date.parse(resolution.expiresAt) > Date.now();
    });
}

/** Check the exact in-process corpus before AND after asynchronous enforced
 * analysis. On false, callers preserve local blocks but cannot claim a
 * qualified allow; they must report unavailable/review coverage. */
export function validateQualifiedPatterns(snapshot: ConfigSnapshot, selected: QualificationTask, patternService: PatternService): boolean {
    if (!["enforce", "cascade"].includes(snapshot.config.typesafe[selected])) return true;
    const qualification = snapshot.qualification?.tasks[selected];
    const expected = snapshot.evaluationOnly ? snapshot.evaluationPatternsSha256 : qualification?.patternsSha256;
    if (!expected || (!snapshot.evaluationOnly && (!qualification || Date.parse(qualification.expiresAt) <= Date.now()))) return false;
    try { return expected === hashConfiguration(patternService.getQualificationState()); }
    catch { return false; }
}
export function assertQualifiedPatterns(snapshot: ConfigSnapshot, patternService: PatternService): void {
    if (QUALIFICATION_TASKS.some((selected) => !validateQualifiedPatterns(snapshot, selected, patternService))) throw new Error("Active pattern corpus no longer matches qualification evidence");
}
