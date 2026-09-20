import dotenv from 'dotenv';
import {mkdirSync,writeFileSync,appendFileSync,readFileSync,existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {prompts,capabilities,descriptors,extraction} from './cases.mjs';
import {promptQuestions,capabilityQuestions,fieldQuestions,extractionQuestions} from './questions.mjs';
import {PatternService} from '../../dist/services/PatternService.js';
import {StaticCheckService} from '../../dist/services/StaticCheckService.js';
import {TrifectaAnalyzer} from '../../dist/services/TrifectaAnalyzer.js';
import {McpToolScanner} from '../../dist/services/McpToolScanner.js';
import {HuggingFaceService} from '../../dist/services/HuggingFaceService.js';

const root=fileURLToPath(new URL('../../',import.meta.url));
process.chdir(root);
dotenv.config({path:root+'.env',quiet:true});
const live=process.argv.includes('--live');
const geminiEnabled=process.argv.includes('--gemini');
const model='jev-1.13.0';
const budgetUsd=0.10, pricePerMillion=0.042, maxAttempts=160;
let attempts=0, inputTokens=0, failures=0;
const stamp=new Date().toISOString().replaceAll(':','-');
const output=root+`experiments/typesafe/results/${stamp}`;
const hash=x=>createHash('sha256').update(typeof x==='string'?x:JSON.stringify(x)).digest('hex');
const patterns=new PatternService();
if(patterns.isFallbackActive()) throw new Error('Pattern baseline is in fallback mode; investigate before comparing.');
const statics=new StaticCheckService(patterns), trifecta=new TrifectaAnalyzer(), scanner=new McpToolScanner(patterns), hf=new HuggingFaceService();

function fieldsOf(node,path='',out=[]) {
  if(typeof node==='string') out.push({path:path||'(root)',text:node});
  else if(Array.isArray(node)) node.forEach((v,i)=>fieldsOf(v,`${path}[${i}]`,out));
  else if(node&&typeof node==='object') Object.entries(node).forEach(([k,v])=>fieldsOf(v,path?`${path}.${k}`:k,out));
  return out;
}
function candidatesOf(text) {
  // Deliberately broad lexical enumeration; the judgment supplies semantic filtering.
  const broad=[...text.matchAll(/\b([A-Za-z0-9_.][A-Za-z0-9_.-]*\/[A-Za-z0-9_.][A-Za-z0-9_.-]*)\b/g)].map(m=>m[1].replace(/[.]+$/,''));
  // Overlapping paths would otherwise hide the real owner/name after datasets/ or spaces/.
  const urls=[...text.matchAll(/https:\/\/huggingface\.co\/(?:datasets\/|spaces\/)?([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)/g)].map(m=>m[1].replace(/[.]+$/,''));
  return [...new Set([...broad,...urls])];
}

const cases=[
  ...prompts.map(c=>({group:'prompt',id:c.id,source:c.source,expected:c.expected,label:c.label,state:{text:c.text},questions:promptQuestions,baseline:statics.check(c.text)})),
  ...capabilities.map(c=>({group:'capability',id:c.id,expected:c.expected,state:{configuration:c.input},questions:capabilityQuestions,baseline:trifecta.analyze(c.input)})),
  ...descriptors.map(c=>{const fields=fieldsOf(c.tool);return {group:'descriptor',id:c.id,expected:c.expected,state:{tool:c.tool,fields},questions:fieldQuestions(fields),baseline:scanner.scan({tool:c.tool})};}),
  ...extraction.map(c=>{const candidates=candidatesOf(c.text);return {group:'extraction',id:c.id,expected:c.expected,state:{text:c.text,candidates},questions:extractionQuestions(candidates),baseline:hf.extractModelIds(c.text)};}),
];

function validateResponse(data,questions) {
  if(data?.model!==model || !data.answers || !data.usage || !Number.isInteger(data.usage.input_tokens) || data.usage.input_tokens<0 || !Number.isInteger(data.usage.output_tokens) || data.usage.output_tokens<0) throw new Error('Invalid response envelope/model/usage');
  if(Object.keys(data.answers).sort().join('|')!==Object.keys(questions).sort().join('|')) throw new Error('Question/answer coverage mismatch');
  const probability=v=>typeof v==='number'&&Number.isFinite(v)&&v>=0&&v<=1;
  for(const [id,q] of Object.entries(questions)) {
    const a=data.answers[id];
    if(a?.type!==q.type) throw new Error('Answer type mismatch');
    if(q.type==='noul') {if(!probability(a.noul)) throw new Error('Invalid Noul');}
    else if(q.type==='choice') {
      if(!Object.hasOwn(q.criteria,a.choice)||!probability(a.confidence)||!a.probabilities) throw new Error('Invalid Choice');
      if(Object.keys(a.probabilities).sort().join('|')!==Object.keys(q.criteria).sort().join('|')) throw new Error('Choice coverage mismatch');
      if(!Object.values(a.probabilities).every(probability)||Math.abs(Object.values(a.probabilities).reduce((x,y)=>x+y,0)-1)>0.005) throw new Error('Invalid Choice distribution');
    }
  }
}

// Offline contract checks: transport failures must never be fabricated as clean judgments.
function contractChecks() {
  const valid={model,usage:{input_tokens:1,output_tokens:1},answers:{a:{type:'noul',noul:0.1}}};
  const q={a:{type:'noul'}};
  validateResponse(valid,q);
  const invalid=[{}, {...valid,model:'other'}, {...valid,answers:{}}, {...valid,answers:{a:{type:'noul',noul:NaN}}}, {...valid,answers:{a:{type:'noul',noul:1.1}}}, {...valid,answers:{a:{type:'choice',choice:'clean'}}}];
  for(const v of invalid) {let rejected=false;try{validateResponse(v,q)}catch{rejected=true}if(!rejected)throw new Error('Malformed answer accepted');}
  const cq={a:{type:'choice',criteria:{none:'None',f0:'Field'}}};
  const cv={...valid,answers:{a:{type:'choice',choice:'f0',confidence:0.9,probabilities:{none:0.01,f0:0.99}}}};
  validateResponse(cv,cq);
  for(const a of [{...cv.answers.a,choice:'invented'}, {...cv.answers.a,probabilities:{f0:0.99}}, {...cv.answers.a,probabilities:{none:0.9,f0:0.9}}]) {
    let rejected=false;try{validateResponse({...cv,answers:{a}},cq)}catch{rejected=true}if(!rejected)throw new Error('Malformed choice accepted');
  }
  for(const c of cases.filter(c=>c.group==='extraction')) if(c.expected.some(v=>!c.state.candidates.includes(v))) throw new Error(`Candidate missing before inference: ${c.id}`);
  console.log('Contract checks passed; extraction candidate coverage complete on authored cases.');
}
contractChecks();
if(!live){console.log(`Dry run: ${cases.length} unique cases; use --live for TypeSafe, optionally --gemini for 16 paired baseline calls.`);process.exit(0);}
if(!process.env.TYPESAFE_API_KEY) throw new Error('TYPESAFE_API_KEY is missing');
mkdirSync(output,{recursive:true});
writeFileSync(output+'/cases.json',JSON.stringify(cases,null,2)+'\n');
const metadata={startedAt:new Date().toISOString(),model,budgetUsd,pricePerMillion,maxAttempts,concurrency:3,timeoutMs:20000,geminiEnabled,
  commit:execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),
  casesSha256:hash(cases),questionsSha256:hash(readFileSync(new URL('./questions.mjs',import.meta.url),'utf8')),
  patternsSha256:hash(readFileSync('patterns/manifest.json','utf8')),node:process.version,
  corpusNotes:'Existing Taste-Tester labels are used as input-risk labels, not enacted-behavior labels. New labels are authored hypotheses; no independent annotation or production distribution.'};
writeFileSync(output+'/metadata.json',JSON.stringify(metadata,null,2)+'\n');

async function call(request) {
  const start=performance.now();
  // Reserve a full 64k-token request per in-flight worker below the observed-spend cap.
  if(attempts>=maxAttempts || (inputTokens+3*64000)*pricePerMillion/1e6>budgetUsd) throw new Error('Experiment cap reached');
  for(let retry=0;retry<2;retry++) {
    if(attempts>=maxAttempts) throw new Error('Attempt cap reached');
    attempts++;
    const res=await fetch('https://api.typesafe.ai/v1/systemone',{method:'POST',headers:{Authorization:`Bearer ${process.env.TYPESAFE_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify(request),signal:AbortSignal.timeout(20000)});
    if([429,529].includes(res.status)&&retry===0){await res.arrayBuffer();await new Promise(r=>setTimeout(r,Math.min(5000,Math.max(1000,Number(res.headers.get('retry-after')||1)*1000))));continue;}
    if(!res.ok){await res.arrayBuffer();throw new Error(`TypeSafe HTTP ${res.status}`);}
    const data=await res.json();
    if(Number.isInteger(data?.usage?.input_tokens))inputTokens+=data.usage.input_tokens;
    validateResponse(data,request.questions);
    return {data,elapsedMs:Math.round(performance.now()-start)};
  }
  throw new Error('Retries exhausted');
}
const rows=[];
function save(row){rows.push(row);appendFileSync(output+'/results.jsonl',JSON.stringify(row)+'\n');}
async function evaluate(c,phase='primary',questions=c.questions) {
  if(Object.keys(questions).length===0) {save({group:c.group,id:c.id,phase,skipped:'no candidates',elapsedMs:0});return;}
  try {
    const result=await call({model,state:c.state,questions});
    save({group:c.group,id:c.id,phase,requestSha256:hash({model,state:c.state,questions}),...result});
  } catch(e) {
    failures++;
    save({group:c.group,id:c.id,phase,error:e.name==='TimeoutError'?'timeout':/^TypeSafe HTTP|^Invalid |mismatch|cap reached|exhausted/.test(e.message)?e.message:'transport_or_validation_failure'});
    if(failures>=3)throw new Error('Three service/contract failures; stopping experiment');
  }
}
async function parallel(items,fn,n=3){let i=0;await Promise.all(Array.from({length:n},async()=>{while(i<items.length){const item=items[i++];await fn(item);}}));}

// One smoke request before fan-out: do not repeat authentication or contract mistakes across the suite.
await evaluate(cases[0]);
if(failures)throw new Error('Smoke request failed; inspect sanitized results');
for(const group of ['prompt','capability','descriptor','extraction']) {
  const subset=cases.filter(c=>c.group===group&&c!==cases[0]);
  await parallel(subset,c=>evaluate(c));
  console.log(`${group}: completed ${subset.length+(group==='prompt'?1:0)} cases; input tokens so far ${inputTokens}`);
}
const repeats=['quote-override','attack-classifier','attack-chinese','attack-base64','denied','arbitrary-get','prerequisite','quoted-example'];
for(let i=1;i<=2;i++)await parallel(cases.filter(c=>repeats.includes(c.id)),c=>evaluate(c,`repeat-${i}`));
// Compare grouped questions with the same questions in separate requests.
for(const id of ['attack-euphemism','benign-negative','quote-override']) {
  const c=cases.find(c=>c.id===id);
  for(const [key,q] of Object.entries(c.questions))await evaluate(c,`single-${key}`,{[key]:q});
}

if(geminiEnabled) {
  if(!process.env.GEMINI_API_KEY)throw new Error('GEMINI_API_KEY missing for explicitly selected comparison');
  const {GeminiService}=await import('../../dist/services/GeminiService.js');
  const ids=['benign-1','benign-9','mal-read-ssh','mal-sql-drop','mal-memory-poison','mal-indirect-via-tool','quote-override','quote-sql','benign-role','benign-changing-request','attack-euphemism','attack-classifier','attack-german','attack-chinese','attack-base64','attack-manyshot'];
  await parallel(cases.filter(c=>c.group==='prompt'&&ids.includes(c.id)),async c=>{
    const svc=new GeminiService();
    let usage;
    const original=svc.model.generateContent.bind(svc.model);
    svc.model.generateContent=async(...args)=>{
      try{const r=await original(...args);usage=r.response.usageMetadata;return r;}
      catch{throw new Error('Gemini baseline API failure (details suppressed)');}
    };
    const start=performance.now();
    const result=await svc.checkPrompt(c.state.text);
    save({group:'gemini',id:c.id,phase:'baseline',elapsedMs:Math.round(performance.now()-start),result,usage});
  },2);
  console.log('Gemini paired baseline complete.');
}
metadata.completedAt=new Date().toISOString();metadata.attempts=attempts;metadata.inputTokens=inputTokens;metadata.estimatedUsd=inputTokens*pricePerMillion/1e6;metadata.failures=failures;
writeFileSync(output+'/metadata.json',JSON.stringify(metadata,null,2)+'\n');
console.log(JSON.stringify({output,attempts,inputTokens,estimatedUsd:metadata.estimatedUsd,failures}));
