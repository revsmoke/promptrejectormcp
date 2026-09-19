import assert from 'node:assert/strict';
import {readFileSync,writeFileSync,readdirSync} from 'node:fs';
import {GeminiService} from '../../dist/services/GeminiService.js';
import {SecurityService} from '../../dist/services/SecurityService.js';
const dir=process.argv[2]||'experiments/typesafe/results/'+readdirSync('experiments/typesafe/results').sort().at(-1);
const read=name=>JSON.parse(readFileSync(dir+'/'+name,'utf8'));
const cases=read('cases.json'), followup=read('followup.json'), followupPlan=read('followup-plan.json');
const evidence=read('evidence-check.json'), evidencePlan=read('evidence-plan.json');
const rows=readFileSync(dir+'/results.jsonl','utf8').trim().split('\n').map(JSON.parse);
assert(read('metadata.json').completedAt);assert(followup.completed);assert(evidence.completed);
let validated=0;
const probability=v=>typeof v==='number'&&Number.isFinite(v)&&v>=0&&v<=1;
function validate(data,questions){
  assert.equal(data.model,'jev-1.13.0');
  assert.deepEqual(Object.keys(data.answers).sort(),Object.keys(questions).sort());
  for(const k of ['input_tokens','output_tokens'])assert(Number.isInteger(data.usage[k])&&data.usage[k]>=0);
  for(const [k,q] of Object.entries(questions)){
    const a=data.answers[k];assert.equal(a.type,q.type);
    if(q.type==='noul')assert(probability(a.noul));
    else{
      assert(Object.hasOwn(q.criteria,a.choice));assert(probability(a.confidence));
      assert.deepEqual(Object.keys(a.probabilities).sort(),Object.keys(q.criteria).sort());
      assert(Object.values(a.probabilities).every(probability));
      assert(Math.abs(Object.values(a.probabilities).reduce((n,v)=>n+v,0)-1)<.005);
    }
  }
  validated++;
}
for(const r of rows.filter(r=>r.data)){
  const c=cases.find(c=>c.id===r.id&&c.group===r.group);
  const questions=r.phase.startsWith('single-')?{[r.phase.slice(7)]:c.questions[r.phase.slice(7)]}:c.questions;
  validate(r.data,questions);
}
for(const r of followup.results)validate(r.data,followupPlan.cases.find(c=>c.id===r.id).variants[r.variant]);
for(const r of evidence.results)validate(r.data,evidencePlan.find(c=>c.id===r.id).questions);
assert.equal(validated,178);
const oldKey=process.env.GEMINI_API_KEY;
process.env.GEMINI_API_KEY='offline-placeholder';
const gemini=new GeminiService();
gemini.model={generateContent:async()=>({response:{text:()=> '{}'}})};
const malformed=await gemini.checkPrompt('ordinary input');
assert.equal(malformed.isInjection,false);assert.equal(malformed.severity,'low');assert.equal(malformed.error,undefined);
const security=new SecurityService();
security.geminiService={checkPrompt:async()=>({isInjection:false,confidence:0,severity:'medium',categories:[],explanation:'Offline probe',error:true})};
const outage=await security.runSecurityScan('ordinary input');
assert.equal(outage.safe,true);assert.equal(outage.geminiAvailable,false);
if(oldKey===undefined)delete process.env.GEMINI_API_KEY;else process.env.GEMINI_API_KEY=oldKey;
const result={verifiedAt:new Date().toISOString(),validatedTypeSafeResponses:validated,missingOrInvalidAnswers:0,
  offlineProbes:{emptyGeminiObject:{isInjection:malformed.isInjection,severity:malformed.severity,error:malformed.error??false},unavailableGemini:{safe:outage.safe,geminiAvailable:outage.geminiAvailable,severity:outage.overallSeverity}},
  note:'Offline probes reproduce current behavior; they are findings, not desired acceptance behavior. No provider calls are made by this verifier.'};
writeFileSync(dir+'/verification.json',JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify(result,null,2));
