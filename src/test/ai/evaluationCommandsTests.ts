import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadAIConfig, parseAIConfig } from '../../ai/config.js';
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
assert.deepEqual(parseEvaluationArgs(['--dataset',dataset,'--scenarios','off,shadow,enforce,cascade']).scenarios,['off','shadow','enforce','cascade']);
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
    const candidate = await runEvaluation(['--dataset',dataset,'--tasks','prompt','--scenarios','enforce,cascade','--limit','1','--output',join(directory,'candidate')], { env: { GEMINI_API_KEY:'never-print-this' } });
    assert.equal(candidate.completed,true); assert.equal(candidate.completedCases,2); assert.equal(candidate.qualification,false);
    assert.equal(candidate.candidates.length,2); assert.ok(candidate.candidates.every((job)=>job.evaluationOnly && job.bindings.length === 1));
    assert.equal(calls,0,'private candidate evaluation remains offline by default');
    await assert.rejects(runEvaluation(['--dataset',dataset,'--tasks','descriptor','--scenarios','cascade','--output',join(directory,'invalid-cascade')]),/only prompt or skill/);
    await assert.rejects(runEvaluation(['--dataset',dataset,'--output',output]), /empty/);
    const live = ['--live','--dataset',dataset,'--tasks','prompt','--profiles','legacy-gemini,missing','--max-requests','1','--max-usd','1','--pricing','config/ai-pricing.example.json','--output',join(directory,'invalid')];
    await assert.rejects(runEvaluation(live,{ env:{ GEMINI_API_KEY:'fake' } }), /Unknown selected profile/);
    assert.equal(calls,0,'all selected profiles validate before first dispatch');
    const missingRates=join(directory,'rates.json'); writeFileSync(missingRates,JSON.stringify({schemaVersion:1,version:'empty',asOf:'2026-09-19',notes:[],sources:[],rates:{}}));
    await assert.rejects(runEvaluation(live.map((v,i,a)=>a[i-1]==='--profiles'?'legacy-gemini':a[i-1]==='--pricing'?missingRates:v),{env:{GEMINI_API_KEY:'fake'}}));
    assert.equal(calls,0);
    const onlyJev=join(directory,'jev-rates.json'); writeFileSync(onlyJev,JSON.stringify({schemaVersion:1,version:'jev-only',asOf:'2026-09-19',notes:[],sources:[],rates:{'typesafe:jev-1.13.0':{inputPerMillion:.042,outputPerMillion:0}}}));
    await assert.rejects(runEvaluation(['--live','--dataset',dataset,'--tasks','descriptor','--profiles','typesafe','--scenarios','enforce','--limit','1','--max-requests','3','--max-usd','1','--pricing',onlyJev,'--output',join(directory,'unpriced-reasoning')],{env:{TYPESAFE_API_KEY:'fake'}}),/Reasoning rate missing/);
    assert.equal(calls,0,'candidate descriptor contextual reasoning is priced before TypeSafe dispatch');
    const liveCandidate=['--live','--dataset',dataset,'--tasks','descriptor','--profiles','typesafe','--scenarios','enforce','--limit','1','--max-requests','1','--max-usd','1','--pricing','config/ai-pricing.example.json'];
    await assert.rejects(runEvaluation([...liveCandidate,'--output',join(directory,'missing-identity')],{env:{TYPESAFE_API_KEY:'fake'}}),/resolution|identity/i);
    assert.equal(calls,0,'known missing model identity cannot spend on earlier TypeSafe work');
    const laterScenario=liveCandidate.map((value,index,args)=>args[index-1]==='--scenarios'?'off,shadow,enforce':value);
    await assert.rejects(runEvaluation([...laterScenario,'--output',join(directory,'later-scenario')],{env:{TYPESAFE_API_KEY:'fake'}}),/resolution|identity/i);
    const mutableJev=parseAIConfig({...snapshot.config,typesafe:{...snapshot.config.typesafe,model:'jev-latest'}});
    await assert.rejects(runEvaluation([...liveCandidate,'--output',join(directory,'mutable-jev')],{snapshot:mutableJev,env:{TYPESAFE_API_KEY:'fake'}}),/pinned TypeSafe identity/);
    assert.equal(calls,0,'all scenario identities validate before earlier scenarios dispatch');
    const now=Date.now(), iso=(offset:number)=>new Date(now+offset).toISOString();
    const anthropicIdentity={kind:'pinned',configuredModel:'claude-opus-4-7',resolvedModel:'claude-opus-4-7',method:'synthetic evaluator test'};
    const geminiIdentity={kind:'version_check',configuredModel:'gemini-3-flash-preview',resolvedModel:'fixture-gemini-immutable',checkedAt:iso(-60000),expiresAt:iso(60000),evidenceSha256:'a'.repeat(64),method:'synthetic evaluator test'};
    const invalidIdentities=[undefined,{...geminiIdentity,expiresAt:iso(-1)},{...geminiIdentity,checkedAt:iso(30000)},{...geminiIdentity,configuredModel:'wrong-model'},{...anthropicIdentity,configuredModel:'gemini-3-flash-preview',resolvedModel:'gemini-3-flash-preview'}];
    for(const [index,identity] of invalidIdentities.entries()) {
      const configured=parseAIConfig({...snapshot.config,modelResolutions:{'legacy-anthropic':anthropicIdentity,...identity?{'legacy-gemini':identity}:{}}});
      const laterInvalid=liveCandidate.map((value,index,args)=>args[index-1]==='--profiles'?'legacy-anthropic,legacy-gemini':value);
      await assert.rejects(runEvaluation([...laterInvalid,'--output',join(directory,`invalid-identity-${index}`)],{snapshot:configured,env:{TYPESAFE_API_KEY:'fake'}}),/resolution|identity|pinned/i);
      assert.equal(calls,0,'a later invalid route prevents earlier valid route spending');
    }
    const validIdentity=parseAIConfig({...snapshot.config,modelResolutions:{'legacy-anthropic':anthropicIdentity}});
    globalThis.fetch=async(_url,init)=>{
      calls++;const body=JSON.parse(String(init?.body));
      return new Response(JSON.stringify({model:'jev-1.13.0',answers:Object.fromEntries(Object.entries(body.questions).map(([id,raw])=>{
        const question=raw as {type:string;criteria:Record<string,string>};
        return [id,question.type==='choice'?{type:'choice',choice:'none',confidence:1,probabilities:Object.fromEntries(Object.keys(question.criteria).map(id=>[id,id==='none'?1:0]))}:{type:'noul',noul:.01}];
      })),usage:{input_tokens:50,output_tokens:1}}));
    };
    const validArgs=liveCandidate.map((value,index,args)=>args[index-1]==='--profiles'?'legacy-anthropic':value);
    const liveSuccess=await runEvaluation([...validArgs,'--output',join(directory,'valid-identity')],{snapshot:validIdentity,env:{TYPESAFE_API_KEY:'fake'}});
    assert.equal(liveSuccess.completed,true);assert.equal(liveSuccess.budget?.attempts,1);assert.equal(calls,1);assert.equal(liveSuccess.qualification,false);
    calls=0;
    globalThis.fetch=async()=>{calls++;throw new Error('must not dispatch before reservation');};
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
