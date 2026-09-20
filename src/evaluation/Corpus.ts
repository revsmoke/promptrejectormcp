import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { descriptorFields } from "../ai/rubrics/descriptor.js";
import { capabilityInputSchema } from "../services/CapabilityAnalysisService.js";
export const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");
export const evaluationCaseSchema = z.strictObject({
    id: z.string().min(1).max(200), task: z.enum(["descriptor", "prompt", "skill", "capability", "modelReference", "taster"]),
    partition: z.enum(["development", "calibration", "held-out"]), family: z.string().min(1), input: z.record(z.string(), z.unknown()), sourceSha256: z.string().regex(/^[a-f0-9]{64}$/),
    label: z.strictObject({ risk: z.boolean().nullable(), rationale: z.string().min(1), kind: z.string().min(1), target: z.string().min(1), severity: z.enum(["low", "medium", "high", "critical"]).nullable(), expected: z.unknown().optional() }),
    provenance: z.record(z.string(), z.unknown()), historical: z.record(z.string(), z.unknown()).optional(), duplicateOf: z.string().optional(),
});
export type EvaluationCase = z.infer<typeof evaluationCaseSchema>;
const inputSchemas = {
    prompt: z.strictObject({ prompt: z.string().min(1).max(100000) }),
    skill: z.strictObject({ skillContent: z.string().min(1).max(500000) }),
    descriptor: z.strictObject({ tool: z.record(z.string(), z.unknown()), priorHash: z.string().optional() }),
    capability: capabilityInputSchema,
    modelReference: z.strictObject({ text: z.string().max(500000) }),
    taster: z.strictObject({ prompt: z.string().min(1).max(100000), mode: z.enum(["fast", "thorough"]).optional(), context: z.string().max(100000).optional() }),
};
export function validateCaseInput(item: EvaluationCase): void {
    inputSchemas[item.task].parse(item.input);
    if (item.task === "descriptor") descriptorFields(item.input.tool as Record<string, unknown>);
}
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const partition = z.enum(["development", "calibration", "held-out"]);
const manifestSchema = z.object({ schemaVersion: z.literal(1), id: z.string().min(1), path: z.string().min(1), sha256: hash, count: z.number().int().positive(), qualificationEligible: z.boolean(), reviewFile: z.string().optional(), splitFile: z.string().optional(), splitSha256: hash.optional(), limitations: z.array(z.string()) });
const acceptanceReviewSchema = z.strictObject({ schemaVersion: z.literal(1), caseSha256: hash, splitSha256: hash, reviewedAt: z.string().datetime(), qualificationEligible: z.literal(true),
    familiesReviewed: z.literal(true), classifierIndependent: z.literal(true), adjudication: z.literal("resolved"), unresolvedCases: z.array(z.string()).length(0),
    reviewers: z.array(z.strictObject({ id: z.string().trim().min(1).max(200), approved: z.literal(true), independent: z.literal(true), caseSha256: hash, splitSha256: hash })).min(2).max(20) });
const splitSchema = z.strictObject({ schemaVersion: z.literal(1), families: z.record(z.string().min(1), partition), sources: z.record(z.string().regex(/^(descriptor|prompt|skill|capability|modelReference|taster):[a-f0-9]{64}$/), partition) });
/** Committed development evidence is always included in acceptance split
 * validation. A new manifest cannot quietly rename its partition or families. */
function knownPartitions() {
    const root = fileURLToPath(new URL("../../evaluations/ai/datasets/", import.meta.url));
    const families: Record<string, string> = {}, sources: Record<string, string> = {};
    for (const name of readdirSync(root, { withFileTypes: true }).filter((entry) => entry.isDirectory() && existsSync(resolve(root, entry.name, "manifest.json"))).map((entry) => entry.name)) {
        const manifest = manifestSchema.parse(JSON.parse(readFileSync(resolve(root, name, "manifest.json"), "utf8")));
        const data = readFileSync(resolve(root, name, manifest.path), "utf8");
        if (sha256(data) !== manifest.sha256) throw new Error("Known development evidence hash mismatch");
        for (const line of data.trim().split("\n")) {
            const item = evaluationCaseSchema.parse(JSON.parse(line));
            const value = ["exploratory-v1", "synthetic-stress-v1"].includes(name) ? "development" : item.partition;
            if (value === "held-out") continue;
            if (families[item.family] && families[item.family] !== value) throw new Error("Known family partition conflict");
            families[item.family] = value; sources[`${item.task}:${item.sourceSha256}`] = value;
        }
    }
    return { families, sources };
}
export function validateCases(inputs: unknown[], options: { acceptance?: boolean; knownFamilies?: Readonly<Record<string, string>> } = {}): EvaluationCase[] {
    const ids = new Set<string>(), sources = new Map<string, EvaluationCase>(), families = new Map<string, string>(Object.entries(options.knownFamilies ?? {}));
    return inputs.map((input) => {
        const item = evaluationCaseSchema.parse(input);
        if (ids.has(item.id)) throw new Error("Duplicate immutable case ID"); ids.add(item.id);
        if (sha256(JSON.stringify(item.input)) !== item.sourceSha256) throw new Error("Case source hash mismatch");
        const familyPartition = families.get(item.family);
        if (familyPartition && familyPartition !== item.partition) throw new Error("Paraphrase family leaks across partitions");
        families.set(item.family, item.partition);
        const sourceKey = `${item.task}:${item.sourceSha256}`;
        const duplicate = sources.get(sourceKey);
        if (duplicate && (options.acceptance || item.duplicateOf !== duplicate.id)) throw new Error("Duplicate input requires explicit development provenance");
        if (duplicate && duplicate.partition !== item.partition) throw new Error("Exact source leaks across partitions");
        if (!duplicate) sources.set(sourceKey, item);
        if (options.acceptance && (item.partition !== "held-out" || item.duplicateOf)) throw new Error("Acceptance requires untouched held-out cases");
        validateCaseInput(item);
        return item;
    });
}
export function loadCorpus(manifestPath: string, options: { acceptance?: boolean; knownFamilies?: Readonly<Record<string, string>> } = {}) {
    const manifest = manifestSchema.parse(JSON.parse(readFileSync(manifestPath, "utf8")));
    const data = readFileSync(resolve(dirname(manifestPath), manifest.path), "utf8");
    if (sha256(data) !== manifest.sha256) throw new Error("Dataset hash mismatch");
    const cases = validateCases(data.trim().split("\n").map((line) => JSON.parse(line)), options);
    if (cases.length !== manifest.count) throw new Error("Dataset count mismatch");
    if (options.acceptance) {
        if (!manifest.qualificationEligible || !manifest.reviewFile || !manifest.splitFile || !manifest.splitSha256) throw new Error("Dataset is not qualified for acceptance");
        const review = acceptanceReviewSchema.parse(JSON.parse(readFileSync(resolve(dirname(manifestPath), manifest.reviewFile), "utf8")));
        if (review.caseSha256 !== manifest.sha256 || review.splitSha256 !== manifest.splitSha256 || Date.parse(review.reviewedAt) > Date.now()) throw new Error("Acceptance labels or family review incomplete");
        const reviewers = review.reviewers;
        if (new Set(reviewers.map((entry) => entry.id)).size !== reviewers.length || reviewers.some((entry) => entry.caseSha256 !== manifest.sha256 || entry.splitSha256 !== manifest.splitSha256)) throw new Error("Acceptance needs two independent label reviews");
        const splitData = readFileSync(resolve(dirname(manifestPath), manifest.splitFile), "utf8");
        if (sha256(splitData) !== manifest.splitSha256) throw new Error("Reviewed family split hash mismatch");
        const split = splitSchema.parse(JSON.parse(splitData)), known = knownPartitions();
        for (const item of cases) {
            const source = `${item.task}:${item.sourceSha256}`;
            if (split.families[item.family] !== item.partition || split.sources[source] !== item.partition) throw new Error("Acceptance case missing from reviewed split");
            if (known.families[item.family] || known.sources[source]) throw new Error("Known development family or source cannot become held-out");
        }
        for (const [family, value] of Object.entries(split.families)) if (known.families[family] && known.families[family] !== value) throw new Error("Reviewed split contradicts known development families");
        for (const [source, value] of Object.entries(split.sources)) if (known.sources[source] && known.sources[source] !== value) throw new Error("Reviewed split contradicts known development sources");
        for (const task of new Set(cases.map((item) => item.task))) if (["descriptor", "prompt", "skill"].includes(task)) {
            for (const risk of [true, false]) if (cases.filter((item) => item.task === task && item.label.risk === risk).length < 200) throw new Error("Acceptance stratum is below 200 risky and 200 benign");
        }
    }
    return { manifest, cases };
}
