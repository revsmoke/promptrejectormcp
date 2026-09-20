import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadAIConfig } from '../../ai/config.js';
import { RunQuota } from '../../evaluation/RunQuota.js';
import { parseEvaluationArgs, runEvaluation } from '../../scripts/evaluateAi.js';
import { createCandidateSnapshot } from '../../evaluation/candidateConfig.js';
import { createServices } from '../../bootstrap.js';
const snapshot = loadAIConfig({});
assert.throws(() => createServices(createCandidateSnapshot(snapshot.config), { env: {} }), /Evaluation-only/);
const quota = new RunQuota(2, .1);
const budget = quota.context(snapshot, 'descriptor').budget;
assert.throws(() => quota.context(snapshot, 'prompt'), /sequential/);
assert.equal(budget.reserveAttempt().ok, false, 'missing price cannot dispatch');
const first = budget.reserveAttempt({ estimatedUsd: .01 });
assert.equal(first.ok, true);
if (first.ok) budget.reconcile(first.id, null);
budget.authorizeShadow({ requiredWorkComplete: true });
assert.equal(budget.reserveAttempt({ optional: true, estimatedUsd: .02 }).ok, true);
assert.equal(budget.reserveAttempt({ optional: true, estimatedUsd: .02 }).ok, false, 'shared run cap spans required and optional');
quota.finish();
assert.equal(quota.attempts, 2);
assert.equal(quota.reservedUsd, .03, 'unknown outcome retains conservative reservation');
assert.equal(quota.exhausted, true);
assert.throws(() => quota.context(snapshot, 'prompt'), /exhausted/);
const sharedQuota = new RunQuota(1, 1);
const sharedBudget = sharedQuota.context(snapshot, 'descriptor').budget;
const shared = sharedBudget.reserveSharedCall(snapshot.config.limits, { deadlineMs: Date.now()+1000, maxAttempts: 2, estimatedUsd: .01 });
assert.equal(shared.ok, true);
if (shared.ok) { assert.equal(shared.budget.reserveAttempt({ estimatedUsd: .01 }).ok, true); assert.equal(shared.budget.reserveAttempt({ estimatedUsd: .01 }).ok, false); shared.release(); }
sharedQuota.finish(); assert.equal(sharedQuota.attempts, 1);
const directory = mkdtempSync(join(tmpdir(), 'evaluation-cli-'));
const dataset = 'evaluations/ai/datasets/exploratory-v1/manifest.json';
assert.equal(parseEvaluationArgs(['--dataset',dataset]).live, false);
try {
  for (const flags of [['--live'], ['--live','--profiles','typesafe'], ['--live','--profiles','typesafe','--pricing','config/ai-pricing.example.json','--max-requests','1']]) assert.throws(() => parseEvaluationArgs(['--dataset',dataset,...flags]));
  let calls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { calls++; throw new Error('secret provider body'); };
  try {
    const output = join(directory,'offline');
    const summary = await runEvaluation(['--dataset',dataset,'--tasks','prompt','--limit','2','--output',output], { env: { GEMINI_API_KEY:'never-print-this' } });
    assert.equal(summary.live,false); assert.equal(summary.completed,true); assert.equal(summary.completedCases,2); assert.equal(calls,0);
    assert.ok(!JSON.stringify(summary).includes('never-print-this'));
    assert.equal(Object.values(summary.repeatedChanges)[0].decisionChanges,null,'single observations are not a stability result');
    await assert.rejects(runEvaluation(['--dataset',dataset,'--output',output]), /empty/);
    const live = ['--live','--dataset',dataset,'--tasks','prompt','--profiles','legacy-gemini,missing','--max-requests','1','--max-usd','1','--pricing','config/ai-pricing.example.json','--output',join(directory,'invalid')];
    await assert.rejects(runEvaluation(live,{ env:{ GEMINI_API_KEY:'fake' } }), /Unknown selected profile/);
    assert.equal(calls,0,'all selected profiles validate before first dispatch');
    const missingRates=join(directory,'rates.json'); writeFileSync(missingRates,JSON.stringify({schemaVersion:1,version:'empty',asOf:'2026-09-19',rates:{}}));
    await assert.rejects(runEvaluation(live.map((v,i,a)=>a[i-1]==='--profiles'?'legacy-gemini':a[i-1]==='--pricing'?missingRates:v),{env:{GEMINI_API_KEY:'fake'}}));
    assert.equal(calls,0);
    const writableArgs=['--live','--dataset',dataset,'--tasks','descriptor','--profiles','typesafe','--scenarios','shadow','--limit','1','--max-requests','1','--max-usd','1','--pricing','config/ai-pricing.example.json'];
    const locked=join(directory,'locked');mkdirSync(locked);chmodSync(locked,0o500);
    try { if (process.getuid?.() !== 0) await assert.rejects(runEvaluation([...writableArgs,'--output',locked],{env:{TYPESAFE_API_KEY:'fake'}})); }
    finally { chmodSync(locked,0o700); }
    assert.equal(calls,0,'unwritable output cannot spend');
    const concurrent=join(directory,'concurrent');
    let entered!:()=>void,release!:()=>void;
    const atFetch=new Promise<void>(resolve=>{entered=resolve;}), released=new Promise<void>(resolve=>{release=resolve;});
    globalThis.fetch=async()=>{calls++;assert.ok(existsSync(join(concurrent,'records.jsonl')));assert.ok(existsSync(join(concurrent,'summary.json')));entered();await released;return new Response('{}');};
    const firstRun=runEvaluation([...writableArgs,'--output',concurrent],{env:{TYPESAFE_API_KEY:'fake'}});
    await atFetch;
    await assert.rejects(runEvaluation([...writableArgs,'--output',concurrent],{env:{TYPESAFE_API_KEY:'fake'}}),/empty/);
    release();await firstRun;
    assert.equal(calls,1,'one run owns the artifact files before first dispatch');
  } finally { globalThis.fetch = originalFetch; }
} finally { rmSync(directory,{recursive:true,force:true}); }
console.log('PASS evaluation offline default, preflight, privacy, shared request and monetary caps');
