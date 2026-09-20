import assert from 'node:assert/strict';
import { createApiApp } from '../../api/server.js';
import { createServices } from '../../bootstrap.js';
import { loadAIConfig, parseAIConfig } from '../../ai/config.js';
const base=loadAIConfig({});
const configured=parseAIConfig({...base.config,profiles:{...base.config.profiles,openai:{provider:'openai',model:'gpt-6-astra',maxOutputTokens:1024}},roles:{...base.config.roles,semantic:{primary:'openai',fallback:'legacy-gemini'}},typesafe:{...base.config.typesafe,descriptor:'shadow'}});
let inference=0;
const secret='synthetic-credential-never-in-health';
const services=createServices(configured,{env:{GEMINI_API_KEY:secret,TYPESAFE_API_KEY:secret},fetch:async()=>{inference++;throw new Error(secret);}});
const server=createApiApp(services).listen(0,'127.0.0.1');
await new Promise<void>(resolve=>server.on('listening',resolve));
try {
  const address=server.address();assert.ok(address&&typeof address==='object');
  const response=await fetch(`http://127.0.0.1:${address.port}/health`);
  const report=await response.json() as Record<string,any>;
  assert.equal(report.status,'ok');assert.equal(report.configHash,configured.hash);assert.equal(inference,0);
  assert.equal(report.roles.semantic.readiness,'degraded');
  assert.equal(report.roles.semantic.fallback.configured,true);
  assert.equal(report.roles.taster.readiness,'disabled');
  assert.equal(report.typesafe.readiness,'ready');assert.equal(report.typesafe.modes.descriptor,'shadow');
  assert.deepEqual(report.reports, {schemaVersion:2,restPrefix:'/v2'});
  assert.equal(report.mcpDefaultReportVersion,undefined);
  for(const marker of [secret,'_API_KEY','privateContinuation','MOCK_TOKEN_DO_NOT_USE'])assert.ok(!JSON.stringify(report).includes(marker));
  assert.equal(report.qualification.tasks.descriptor,undefined);
} finally {server.closeAllConnections();await new Promise<void>(resolve=>server.close(()=>resolve()));}
console.log('PASS health readiness, mode scope, sanitized metadata and zero inference');
