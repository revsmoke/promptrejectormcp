import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";
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
        review: { reviewedAt: iso(-90000), adjudication: "resolved", unresolvedLabels: 0, reviewers: ["fixture-reviewer-a", "fixture-reviewer-b"].map((id) => ({ id, independent: true, approved: true, datasetSha256: hash })) },
        modelResolutions: binding.modelResolutions, evaluatedAt: iso(-45000), expiresAt: iso(1800000), pricingVersion: pricing.version,
        gates: { contracts: true, compatibility: true, shadow: true, operational: true, liveProfileHashes: binding.routes.map((route) => route.profileHash), typesafeLiveModel: "jev-1.13.0" },
        metrics: { strata: [{ task, route: { name: binding.routes[0].name, selection: binding.routes[0].selection, profileHash: binding.routes[0].profileHash },
            capabilityReference: { independentBucketReferenceLabels: true, unknownCoverageValidated: true, deterministicCandidatesPreserved: true, additiveFalsePositives: { count: 0, denominator: 200 } }, risky: counts, benign: { allow: 200, block: 0, review: 0, unavailable: 0 }, baselineBenignBlocks: 0, highCritical: { total: 100, baselineMisses: 0, candidateMisses: 0, newlyMissed: 0 }, pairedResultsSha256: hash }], latencyP50Ms: 100, latencyP95Ms: 250, costUsd: .01, unknownCostCalls: 0 },
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
    const awaitingOperations = structuredClone(passing);
    awaitingOperations.gates.operational = false;
    save(awaitingOperations);
    assert.doesNotThrow(() => parseAIConfig(configured, false, { pricing }), "qualified staging must load before restart and rollback drills can run");
    assert.equal(parseAIConfig(configured, false, { pricing }).qualification?.tasks.descriptor?.operational, "pending");
    save(passing);
    const production = parseAIConfig(configured, false, { pricing });
    assert.equal(production.evaluationOnly, false);
    assert.equal(production.qualification?.tasks.descriptor?.operational, "passed");
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
    reject((value) => { value.review.reviewedAt = iso(-1); });
    reject((value) => { value.resultApproval = { reviewedAt: iso(-100000), reviewer: "result-reviewer", approved: true, resultsSha256: hashConfiguration(value.metrics) }; });
    reject((value) => { value.resultApproval = { reviewedAt: iso(-10000), reviewer: "result-reviewer", approved: true, resultsSha256: "b".repeat(64) }; });
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
    const resultApproved = structuredClone(passing);
    resultApproved.resultApproval = { reviewedAt: iso(-10000), reviewer: "result-reviewer", approved: true, resultsSha256: hashConfiguration(resultApproved.metrics) };
    save(resultApproved);
    assert.doesNotThrow(() => parseAIConfig(configured, false, { pricing }), "optional result approval is distinct from prior label approval");
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
    const withFallback = { ...configured, roles: { ...configured.roles, semantic: { primary: "legacy-gemini", fallback: "backup-gemini" } },
        profiles: { ...configured.profiles, "backup-gemini": { ...configured.profiles["legacy-gemini"], maxOutputTokens: 1024 } },
        modelResolutions: { ...configured.modelResolutions, "backup-gemini": configured.modelResolutions["legacy-gemini"] } };
    const fallbackManifest = structuredClone(passing);
    fallbackManifest.binding = taskPolicyBinding(createCandidateSnapshot(withFallback, { pricing }), "descriptor", "enforce");
    fallbackManifest.bindingSha256 = hashConfiguration(fallbackManifest.binding);
    fallbackManifest.modelResolutions = fallbackManifest.binding.modelResolutions;
    fallbackManifest.gates.liveProfileHashes = fallbackManifest.binding.routes.map((route) => route.profileHash);
    save(fallbackManifest);
    assert.throws(() => parseAIConfig(withFallback, false, { pricing }), /route|strata/i, "a probed fallback without its own quality evidence must not qualify");
    const fallbackRoute = fallbackManifest.binding.routes.find((route) => route.selection === "fallback")!;
    fallbackManifest.metrics.strata.push({ ...structuredClone(fallbackManifest.metrics.strata[0]), route: { name: fallbackRoute.name, selection: fallbackRoute.selection, profileHash: fallbackRoute.profileHash } });
    save(fallbackManifest);
    assert.doesNotThrow(() => parseAIConfig(withFallback, false, { pricing }), "every configured route has independent passing evidence");
    const failedFallback = structuredClone(fallbackManifest);
    failedFallback.metrics.strata[1].highCritical.newlyMissed = 1;
    failedFallback.metrics.strata[1].highCritical.candidateMisses = 1;
    save(failedFallback);
    assert.throws(() => parseAIConfig(withFallback, false, { pricing }), /non-regression/i, "primary quality cannot hide an unsafe fallback");
    const falsePositiveFallback = structuredClone(fallbackManifest);
    falsePositiveFallback.metrics.strata[1].benign.block = 3;
    falsePositiveFallback.metrics.strata[1].benign.allow = 197;
    save(falsePositiveFallback);
    assert.throws(() => parseAIConfig(withFallback, false, { pricing }), /benign block/i);
    const mismatchedFallback = structuredClone(fallbackManifest);
    mismatchedFallback.metrics.strata[1].route.profileHash = hash;
    save(mismatchedFallback);
    assert.throws(() => parseAIConfig(withFallback, false, { pricing }), /route strata/i);
    const capabilityConfig = { ...withFallback, typesafe: { ...withFallback.typesafe, descriptor: "off" as const, capability: "enforce" as const } };
    const capabilityManifest = structuredClone(fallbackManifest);
    capabilityManifest.task = "capability";
    capabilityManifest.binding = taskPolicyBinding(createCandidateSnapshot(capabilityConfig, { pricing }), "capability", "enforce");
    capabilityManifest.bindingSha256 = hashConfiguration(capabilityManifest.binding);
    capabilityManifest.metrics.strata.forEach((stratum) => { stratum.task = "capability"; });
    save(capabilityManifest);
    assert.doesNotThrow(() => parseAIConfig(capabilityConfig, false, { pricing }));
    capabilityManifest.metrics.strata[1].capabilityReference!.unknownCoverageValidated = false;
    save(capabilityManifest);
    assert.throws(() => parseAIConfig(capabilityConfig, false, { pricing }), /capability\/reference evidence/i);
    capabilityManifest.metrics.strata[1].capabilityReference!.unknownCoverageValidated = true;
    capabilityManifest.metrics.strata[1].capabilityReference!.additiveFalsePositives.count = 3;
    save(capabilityManifest);
    assert.throws(() => parseAIConfig(capabilityConfig, false, { pricing }), /capability\/reference evidence/i);
    const codeRoot = join(dir, "isolated-build");
    const runtimeRoot = fileURLToPath(new URL("../../", import.meta.url));
    for (const folder of ["ai", "services", "schemas"]) cpSync(join(runtimeRoot, folder), join(codeRoot, folder), { recursive: true });
    writeFileSync(join(codeRoot, "package.json"), JSON.stringify({ type: "module" }));
    symlinkSync(dirname(dirname(createRequire(import.meta.url).resolve("zod/package.json"))), join(codeRoot, "node_modules"));
    const isolatedQualification = await import(pathToFileURL(join(codeRoot, "ai/qualification.js")).href) as typeof import("../../ai/qualification.js");
    const before = isolatedQualification.taskPolicyBinding(candidate, "descriptor", "enforce");
    const validator = join(codeRoot, "schemas/DescriptorReportSchema.js");
    writeFileSync(validator, readFileSync(validator, "utf8") + "\n// Deliberate isolated qualification invalidation fixture.\n");
    const after = isolatedQualification.taskPolicyBinding(candidate, "descriptor", "enforce");
    assert.notEqual(before.schemaSha256, after.schemaSha256, "runtime report and evidence validator edits must invalidate schema evidence");
    assert.notEqual(before.decisionCodeSha256, after.decisionCodeSha256, "runtime validator edits must invalidate decision code evidence");
    const rubric = join(codeRoot, "ai/rubrics/descriptor.js");
    writeFileSync(rubric, readFileSync(rubric, "utf8") + "\n// Deliberate nested rubric invalidation fixture.\n");
    const changedRubric = isolatedQualification.taskPolicyBinding(candidate, "descriptor", "enforce");
    assert.notEqual(after.rubricSha256, changedRubric.rubricSha256, "nested rubric source must not be dropped from recursive directory hashing");
    console.log("PASS strict task qualification, frozen binding, private candidate scope, and complete skill child mode table");
} finally { rmSync(dir, { recursive: true, force: true }); }
