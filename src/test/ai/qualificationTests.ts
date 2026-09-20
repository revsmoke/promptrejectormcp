import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadAIConfig, parseAIConfig } from "../../ai/config.js";
import { createCandidateSnapshot } from "../../evaluation/candidateConfig.js";
import { assertServingSnapshot, effectiveSkillChildMode, taskPolicyBinding, qualificationManifestSchema, validateResolvedModel, type QualificationManifest } from "../../ai/qualification.js";
import { effectiveJudgmentMode } from "../../services/JudgmentService.js";
import { hashConfiguration } from "../../ai/modelProfiles.js";
const dir = mkdtempSync(join(tmpdir(), "qualification-fixture-"));
const hash = "a".repeat(64);
const now = Date.now();
const iso = (offset: number) => new Date(now + offset).toISOString();
const base = loadAIConfig({});
const pricing = { schemaVersion: 1 as const, version: "test-only", asOf: "2026-09-19", notes: ["Synthetic unit-test evidence only"], sources: ["https://example.test/pricing"], rates: { "typesafe:jev-1.13.0": { inputPerMillion: .042, outputPerMillion: 0 }, "gemini:gemini-3-flash-preview": { inputPerMillion: .5, outputPerMillion: 3 } } };
const configured = { ...base.config, evaluationFile: join(dir, "manifest.json"), modelResolutions: {
    "legacy-gemini": { kind: "version_check" as const, configuredModel: "gemini-3-flash-preview", resolvedModel: "fixture-gemini-immutable-1", checkedAt: iso(-60000), expiresAt: iso(3600000), evidenceSha256: hash, method: "Synthetic test fixture; not deployment evidence" },
}, typesafe: { ...base.config.typesafe, descriptor: "enforce" as const } };
const candidate = createCandidateSnapshot(configured, { pricing });
function manifest(task: "descriptor" | "prompt" | "skill" | "capability" | "modelReference" = "descriptor"): QualificationManifest {
    const mode = candidate.config.typesafe[task] === "cascade" ? "cascade" : "enforce";
    const binding = taskPolicyBinding(candidate, task, mode);
    const counts = { allow: 0, block: 200, review: 0, unavailable: 0 };
    return { schemaVersion: 1, task, mode, status: "passed", binding, bindingSha256: hashConfiguration(binding),
        dataset: { id: "synthetic-unit-test-only", partition: "heldout", casesSha256: hash, labelsSha256: hash, familiesSha256: hash, reviewSha256: hash, familyDisjoint: true, untouchedAfterTuning: true, classifierIndependent: true },
        review: { reviewedAt: iso(-30000), adjudication: "resolved", unresolvedLabels: 0, reviewers: ["fixture-reviewer-a", "fixture-reviewer-b"].map((id) => ({ id, independent: true, approved: true, datasetSha256: hash })) },
        modelResolutions: binding.modelResolutions, evaluatedAt: iso(-45000), expiresAt: iso(1800000), pricingVersion: pricing.version,
        gates: { contracts: true, compatibility: true, shadow: true, operational: true, liveProfileHashes: binding.routes.map((route) => route.profileHash), typesafeLiveModel: "jev-1.13.0" },
        metrics: { strata: [{ task, risky: counts, benign: { allow: 200, block: 0, review: 0, unavailable: 0 }, baselineBenignBlocks: 0, highCritical: { total: 100, baselineMisses: 0, candidateMisses: 0, newlyMissed: 0 }, pairedResultsSha256: hash }], latencyP50Ms: 100, latencyP95Ms: 250, costUsd: .01, unknownCostCalls: 0 },
        criteria: { registeredAt: iso(-120000), specificationSha256: hash, minimumRisky: 200, minimumBenign: 200, maximumBenignBlockIncrease: .01, maximumNewHighCriticalMisses: 0, maximumAdditiveFalsePositiveRate: .01, independentBucketReferenceLabels: true, unknownCoverageValidated: true, deterministicCandidatesPreserved: true, additiveFalsePositives: { count: 0, denominator: 200 } }, limitations: ["Synthetic unit-test fixture; not real qualification"],
    };
}
function save(value: unknown) { writeFileSync(configured.evaluationFile, JSON.stringify({ schemaVersion: 1, manifests: [value] })); }
try {
    assert.equal(candidate.evaluationOnly, true);
    assert.throws(() => assertServingSnapshot(candidate), /evaluation/i);
    assert.throws(() => parseAIConfig(configured, false, { pricing }), /manifest/i);
    const passing = manifest();
    qualificationManifestSchema.parse(passing);
    save(passing);
    const production = parseAIConfig(configured, false, { pricing });
    assert.equal(production.evaluationOnly, false);
    assert.doesNotThrow(() => assertServingSnapshot(production));
    assert.equal(production.qualification?.tasks.descriptor?.bindingSha256, passing.bindingSha256);
    assert.equal(validateResolvedModel(production, "descriptor", "gemini", "gemini-3-flash-preview", "fixture-gemini-immutable-1"), true);
    assert.equal(validateResolvedModel(production, "descriptor", "gemini", "gemini-3-flash-preview", "changed-model"), false);
    assert.equal(validateResolvedModel(production, "descriptor", "gemini", "gemini-3-flash-preview", null), false);
    assert.equal(validateResolvedModel(production, "descriptor", "typesafe", "jev-1.13.0", "jev-1.13.0"), true);
    assert.equal(validateResolvedModel(production, "descriptor", "typesafe", "jev-1.13.0", "jev-1.14.0"), false);
    assert.equal(validateResolvedModel(base, "prompt", "gemini", "gemini-3-flash-preview", null), true);
    assert.equal(validateResolvedModel({ ...production, qualification: { tasks: { descriptor: { ...production.qualification!.tasks.descriptor!, expiresAt: iso(-1) } } } }, "descriptor", "typesafe", "jev-1.13.0", "jev-1.13.0"), false);
    const relative = { ...configured, evaluationFile: "manifest.json" };
    const relativeSnapshot = parseAIConfig(relative, false, { pricing, configDirectory: dir });
    assert.doesNotThrow(() => assertServingSnapshot(relativeSnapshot));
    const reject = (change: (value: ReturnType<typeof manifest>) => void) => { const value = structuredClone(passing); change(value); save(value); assert.throws(() => parseAIConfig(configured, false, { pricing })); };
    reject((value) => { value.status = "failed"; });
    reject((value) => { value.expiresAt = iso(-1); });
    reject((value) => { value.binding.thresholds.high = .8; value.bindingSha256 = hashConfiguration(value.binding); });
    reject((value) => { value.binding.sourcePolicyVersion = "old"; value.bindingSha256 = hashConfiguration(value.binding); });
    reject((value) => { value.binding.rubricSha256 = "b".repeat(64); value.bindingSha256 = hashConfiguration(value.binding); });
    reject((value) => { value.metrics.strata[0].highCritical.newlyMissed = 1; });
    reject((value) => { value.metrics.strata[0].benign.block = 3; value.metrics.strata[0].benign.allow = 197; });
    reject((value) => { value.metrics.strata[0].risky = { allow: 0, block: 0, review: 200, unavailable: 0 }; });
    reject((value) => { value.review.reviewers[1].id = value.review.reviewers[0].id; });
    reject((value) => { value.dataset.familyDisjoint = false; });
    reject((value) => { value.gates.liveProfileHashes = []; });
    reject((value) => { value.metrics.strata[0].risky.block = 199; });
    reject((value) => { value.metrics.unknownCostCalls = 1; });
    reject((value) => { value.criteria.additiveFalsePositives.count = 3; });
    reject((value) => { value.criteria.registeredAt = iso(-1); });
    reject((value) => { value.metrics.strata[0].highCritical.total = 0; });
    save(passing);
    assert.throws(() => parseAIConfig({ ...configured, profiles: { ...configured.profiles, "legacy-gemini": { ...configured.profiles["legacy-gemini"], maxOutputTokens: 1024 } } }, false, { pricing }));
    assert.throws(() => parseAIConfig({ ...configured, roles: { ...configured.roles, semantic: { primary: "legacy-gemini", fallback: "legacy-anthropic" } } }, false, { pricing }));
    assert.throws(() => parseAIConfig({ ...configured, typesafe: { ...configured.typesafe, model: "jev-latest" } }, false, { pricing }));
    assert.throws(() => parseAIConfig({ ...configured, typesafe: { ...configured.typesafe, prompt: "cascade" } }, false, { pricing }), /manifest/i);
    assert.throws(() => parseAIConfig({ ...configured, modelResolutions: { "legacy-gemini": { kind: "pinned", configuredModel: "gemini-3-flash-preview", resolvedModel: "gemini-3-flash-preview", method: "not actually pinned" } } }, false, { pricing }));
    assert.throws(() => parseAIConfig({ ...configured, modelResolutions: { "legacy-gemini": { ...configured.modelResolutions["legacy-gemini"], expiresAt: iso(-1) } } }, false, { pricing }));
    assert.throws(() => parseAIConfig({ ...configured, evaluationOnly: true }, false, { pricing }));
    assert.equal(loadAIConfig({ AI_EVALUATION_ONLY: "true" }).evaluationOnly, false);
    for (const parent of ["off", "shadow", "enforce", "cascade"] as const) for (const child of ["off", "shadow", "enforce"] as const) {
        const snapshot = createCandidateSnapshot({ ...configured, typesafe: { ...configured.typesafe, skill: parent, capability: child, modelReference: child } }, { pricing });
        const expected = parent === "off" || child === "off" ? "off" : parent === "shadow" ? "shadow" : child;
        assert.equal(effectiveSkillChildMode(snapshot, "capability"), expected);
        assert.equal(effectiveSkillChildMode(snapshot, "modelReference"), expected);
        assert.equal(effectiveJudgmentMode(snapshot, "capability", "skill"), expected);
        assert.equal(effectiveJudgmentMode(snapshot, "modelReference", "skill"), expected);
    }
    const promptConfig = { ...configured, typesafe: { ...configured.typesafe, descriptor: "off" as const, prompt: "cascade" as const } };
    const promptCandidate = createCandidateSnapshot(promptConfig, { pricing });
    const promptManifest = structuredClone(passing);
    promptManifest.task = "prompt"; promptManifest.mode = "cascade";
    promptManifest.binding = taskPolicyBinding(promptCandidate, "prompt", "cascade");
    promptManifest.bindingSha256 = hashConfiguration(promptManifest.binding);
    promptManifest.metrics.strata[0].task = "prompt";
    save(promptManifest);
    assert.throws(() => parseAIConfig(promptConfig, false, { pricing }), /strata/i);
    promptManifest.metrics.strata.push({ ...structuredClone(promptManifest.metrics.strata[0]), task: "skill" });
    save(promptManifest);
    assert.doesNotThrow(() => parseAIConfig(promptConfig, false, { pricing }));
    promptManifest.metrics.strata[1].benign.allow = 199;
    save(promptManifest);
    assert.throws(() => parseAIConfig(promptConfig, false, { pricing }), /strata/i);
    console.log("PASS strict task qualification, frozen binding, private candidate scope, and complete skill child mode table");
} finally { rmSync(dir, { recursive: true, force: true }); }
