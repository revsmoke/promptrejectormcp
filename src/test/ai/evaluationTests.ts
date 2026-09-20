import assert from "node:assert/strict";
import { loadCorpus, sha256, validateCases } from "../../evaluation/Corpus.js";
import { summarizeObservations, repeatedAnswerChanges, modelAnswerFingerprint, type EvaluationObservation } from "../../evaluation/Metrics.js";
const corpus = loadCorpus("evaluations/ai/datasets/synthetic-stress-v1/manifest.json");
assert.equal(corpus.cases.length, 1200);
assert.throws(() => loadCorpus("evaluations/ai/datasets/synthetic-stress-v1/manifest.json", { acceptance: true }));
const first = corpus.cases[0];
assert.throws(() => validateCases([first, first]), /Duplicate/);
assert.throws(() => validateCases([{ ...first, input: { prompt: "changed" } }]), /hash/);
const other = { ...first, id: "other", partition: "held-out", input: { text: "different" }, sourceSha256: sha256(JSON.stringify({ text: "different" })) };
assert.throws(() => validateCases([first, other]), /family/);
assert.throws(() => validateCases([other], { knownFamilies: { [first.family]: "development" } }), /family/);
const observation = (id: string, risk: boolean, decision: EvaluationObservation["decision"]): EvaluationObservation => ({ id, family: "family-" + id, risk, severity: "high", decision, coverageComplete: true, elapsedMs: Number(id) * 10, estimatedUsd: .01, attempts: 1 });
const rows = [observation("1", true, "block"), observation("2", false, "allow"), observation("3", true, "allow"), observation("4", false, "block"), observation("5", false, "review"), observation("6", true, "unavailable")];
const summary = summarizeObservations(rows);
assert.equal(summary.classified, 4); assert.equal(summary.accuracyAmongClassified, .5); assert.equal(summary.review, 1); assert.equal(summary.unavailable, 1); assert.equal(summary.missedHighCritical, 1);
assert.equal(summary.latency.p50Ms, 30); assert.equal(summary.latency.p95Ms, 60);
assert.equal(summarizeObservations([{ ...rows[0], estimatedUsd: null }]).estimatedUsd, null);
assert.equal(repeatedAnswerChanges([rows, rows.map((item) => item.id === "1" ? { ...item, decision: "review" } : item)]).decisionChanges, 1);
assert.throws(() => validateCases([{ ...first, input: { tool: null }, sourceSha256: sha256(JSON.stringify({ tool: null })) }]));
assert.throws(() => validateCases([{ ...first, task: "prompt", input: { prompt: 42 }, sourceSha256: sha256(JSON.stringify({ prompt: 42 })) }]));
assert.equal(repeatedAnswerChanges([rows]).decisionChanges, null);
console.log("PASS immutable corpus provenance, partition isolation and abstention-aware metrics");
// Acceptance fixtures are generated only inside this offline test. They are
// never shipped as real held-out data or activation evidence.
const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
const { tmpdir } = await import('node:os');
const { join } = await import('node:path');
const directory=mkdtempSync(join(tmpdir(),'acceptance-fixture-'));
function writeAcceptance(items: typeof corpus.cases) {
    const data=items.map((item)=>JSON.stringify(item)).join('\n')+'\n';
    const split=JSON.stringify({schemaVersion:1,families:Object.fromEntries(items.map((item)=>[item.family,item.partition])),sources:Object.fromEntries(items.map((item)=>[`${item.task}:${item.sourceSha256}`,item.partition]))});
    const caseSha256=sha256(data), splitSha256=sha256(split);
    const review={schemaVersion:1,caseSha256,splitSha256,reviewedAt:'2026-01-01T00:00:00.000Z',qualificationEligible:true,familiesReviewed:true,classifierIndependent:true,adjudication:'resolved',unresolvedCases:[],reviewers:['fixture-A','fixture-B'].map((id)=>({id,approved:true,independent:true,caseSha256,splitSha256}))};
    writeFileSync(join(directory,'cases.jsonl'),data);writeFileSync(join(directory,'split.json'),split);writeFileSync(join(directory,'review.json'),JSON.stringify(review));
    writeFileSync(join(directory,'manifest.json'),JSON.stringify({schemaVersion:1,id:'offline-fixture',path:'cases.jsonl',sha256:caseSha256,count:items.length,qualificationEligible:true,reviewFile:'review.json',splitFile:'split.json',splitSha256,limitations:['Offline programming fixture only']}));
    return review;
}
try {
    const fresh=corpus.cases.slice(0,400).map((item,index)=>{const input={tool:{description:`Offline acceptance fixture ${index}`}};return {...item,id:`fixture-${index}`,family:`new-fixture-${index}`,partition:'held-out' as const,input,sourceSha256:sha256(JSON.stringify(input))};});
    const manifest=join(directory,'manifest.json');
    const review=writeAcceptance(fresh);
    assert.equal(loadCorpus(manifest,{acceptance:true}).cases.length,400);
    writeFileSync(join(directory,'review.json'),JSON.stringify({...review,reviewers:[{...review.reviewers[0],id:undefined},{...review.reviewers[1],id:{}}],unresolvedCases:undefined}));
    assert.throws(()=>loadCorpus(manifest,{acceptance:true}));
    writeAcceptance(corpus.cases.slice(0,400).map((item)=>({...item,partition:'held-out'})));
    assert.throws(()=>loadCorpus(manifest,{acceptance:true}),/Known development/);
    writeAcceptance(corpus.cases.slice(0,400).map((item,index)=>({...item,family:`renamed-${index}`,partition:'held-out'})));
    assert.throws(()=>loadCorpus(manifest,{acceptance:true}),/Known development/,'renaming a family cannot erase exact development source provenance');
    writeAcceptance(fresh);writeFileSync(join(directory,'split.json'),'{}');
    assert.throws(()=>loadCorpus(manifest,{acceptance:true}),/split hash/);
} finally { rmSync(directory,{recursive:true,force:true}); }
console.log('PASS strict pre-run label reviews and hash-bound reviewed family/source partitions');

const low={shadow:{judgments:{result:{status:'ok',value:{poison:{type:'noul',noul:.01}},meta:{callId:'one',usage:{inputTokens:1}}},ageMs:0,cache:'miss'}}};
const high=structuredClone(low);high.shadow.judgments.result.value.poison.noul=.99;
const repeatMetrics=repeatedAnswerChanges([[{...rows[0],answerFingerprint:modelAnswerFingerprint(low)}],[{...rows[0],answerFingerprint:modelAnswerFingerprint(high)}]]);
assert.equal(repeatMetrics.decisionChanges,0);assert.equal(repeatMetrics.answerChanges,1);
const metadata=structuredClone(low);metadata.shadow.judgments.result.meta.callId='two';metadata.shadow.judgments.result.meta.usage.inputTokens=500;metadata.shadow.judgments.ageMs=50;metadata.shadow.judgments.cache='hit';
assert.equal(modelAnswerFingerprint(low),modelAnswerFingerprint(metadata));
console.log('PASS decision and model-answer stability are measured independently');
