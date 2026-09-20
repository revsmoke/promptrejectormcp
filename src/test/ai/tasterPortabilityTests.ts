import assert from 'node:assert/strict';
import { TasteTesterService } from '../../services/TasteTesterService.js';
import { SemanticAnalysisService } from '../../services/SemanticAnalysisService.js';
import { ProviderRegistry } from '../../ai/registry.js';
import { loadAIConfig, parseAIConfig } from '../../ai/config.js';
import type { ReasoningProviderId, ToolTurn } from '../../ai/contracts.js';
import { emptyUsage } from '../../ai/usage.js';
const models = { anthropic: 'claude-opus-4-7', openai: 'gpt-6-astra', gemini: 'gemini-3-flash-preview' };
const clean = { intents: [], monitorVerdict: 'clean', monitorRationale: 'No unsafe actions observed', severity: 'safe' };
function wire(provider: ReasoningProviderId, first: boolean) {
    const tool = first ? { id: 'a', name: 'exec_shell', args: { command: 'synthetic' } } : null;
    if (provider === 'anthropic')
        return { model: models[provider], stop_reason: tool ? 'tool_use' : 'end_turn', content: tool ? [{ type: 'thinking', thinking: 'PRIVATE', signature: 'SECRET' }, { type: 'tool_use', id: tool.id, name: tool.name, input: tool.args }] : [{ type: 'text', text: 'done' }] };
    if (provider === 'openai')
        return { model: models[provider], status: 'completed', output: tool ? [{ type: 'reasoning', id: 'r', summary: [], encrypted_content: 'SECRET' }, { type: 'function_call', call_id: tool.id, name: tool.name, arguments: JSON.stringify(tool.args) }] : [{ type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'done' }] }] };
    return { modelVersion: models[provider], candidates: [{ finishReason: 'STOP', content: { role: 'model', parts: tool ? [{ functionCall: tool, thoughtSignature: 'SECRET' }] : [{ text: 'done' }] } }] };
}
for (const provider of Object.keys(models) as ReasoningProviderId[]) {
    const cfg = structuredClone(loadAIConfig({}).config);
    cfg.profiles.taster = { provider, model: models[provider], maxOutputTokens: 512 };
    cfg.roles.taster = { primary: 'taster' };
    const snapshot = parseAIConfig(cfg);
    let dispatched = 0;
    const registry = new ProviderRegistry(snapshot, { env: { ANTHROPIC_API_KEY: 'test', OPENAI_API_KEY: 'test', GEMINI_API_KEY: 'test' }, fetch: async () => new Response(JSON.stringify(wire(provider, dispatched++ === 0)), { status: 200 }) });
    registry.register('anthropic', { generate: async (request, context) => { const reservation = context.budget.reserveAttempt(); assert.ok(reservation.ok); return { status: 'ok', value: request.parse(clean), meta: { callId: 'monitor', provider: 'anthropic', requestedModel: models.anthropic, resolvedModel: null, profileHash: 'x', rubricVersion: 'x', schemaVersion: 'x', elapsedMs: 1, attempts: 1, usage: emptyUsage(), failureCode: null } }; } });
    const svc = new TasteTesterService({ enabled: true, monitor: new SemanticAnalysisService(snapshot, registry) });
    const result = await svc.runV2({ prompt: 'test', mode: 'thorough' });
    assert.equal(result.coverage.taster, 'complete');
    assert.equal(result.coverage.monitor, 'complete');
    assert.equal(result.behaviorReport.severity, 'critical');
    assert.equal(result.behaviorReport.monitorVerdict, 'suspicious');
    assert.equal(result.tasterCalls[0].provider, provider);
    assert.equal(JSON.stringify(result).includes('SECRET'), false);
    assert.equal(dispatched, 2);
    if (provider !== 'anthropic')
        await assert.rejects(() => svc.run({ prompt: 'test' }), /report_version_required/);
}
console.log('PASS Taster portability across native providers with independent Monitor and raw severity floor');
// Preserve observed action evidence after a later timeout and never switch Taster.
{
    const cfg = structuredClone(loadAIConfig({}).config);
    cfg.profiles.other = { provider: 'openai', model: models.openai, maxOutputTokens: 64 };
    cfg.roles.taster.fallback = 'other';
    cfg.limits.reasoningTimeoutMs = 250;
    const snapshot = parseAIConfig(cfg);
    let nativeCalls = 0;
    let monitorCalls = 0;
    const registry = new ProviderRegistry(snapshot, { env: { ANTHROPIC_API_KEY: 'test', OPENAI_API_KEY: 'test' }, fetch: async (url) => { assert.ok(String(url).includes('anthropic')); nativeCalls++; if (nativeCalls === 1)
            return new Response(JSON.stringify(wire('anthropic', true))); return new Promise<Response>(() => { }); } });
    registry.register('anthropic', { generate: async (req, ctx) => { monitorCalls++; assert.ok(ctx.budget.reserveAttempt().ok); return { status: 'ok', value: req.parse(clean), meta: { callId: 'm', provider: 'anthropic', requestedModel: models.anthropic, resolvedModel: null, profileHash: 'x', rubricVersion: 'x', schemaVersion: 'x', elapsedMs: 0, attempts: 1, usage: emptyUsage(), failureCode: null } }; } });
    const svc = new TasteTesterService({ enabled: true, monitor: new SemanticAnalysisService(snapshot, registry), timeoutMs: 1000 });
    const result = await svc.runV2({ prompt: 'test', mode: 'thorough' });
    assert.equal(result.coverage.taster, 'partial');
    assert.equal(result.behaviorReport.severity, 'critical');
    assert.notEqual(result.behaviorReport.monitorVerdict, 'clean');
    assert.equal(monitorCalls, 1);
    assert.equal(nativeCalls, 2);
    assert.ok(result.tasterTranscript.some(t => t.role === 'tool'));
    assert.ok(result.routing.some(r => r.reason === 'conversation_fallback_forbidden'));
    await assert.rejects(() => svc.run({ prompt: 'test' }), /report_version_required/);
    assert.equal(nativeCalls, 2);
}
// Fast/thorough caps and all call attempts (including Monitor) share one budget.
for (const mode of ['fast', 'thorough'] as const) {
    const snapshot = loadAIConfig({});
    let step = 0;
    let capturedBudget: any;
    const registry = new ProviderRegistry(snapshot, { env: { ANTHROPIC_API_KEY: 'test' }, fetch: async () => { const response: any = wire('anthropic', true); for (const b of response.content ?? [])
            if (b.type === 'tool_use')
                b.id = `id${step}`; step++; return new Response(JSON.stringify(response)); } });
    registry.register('anthropic', { generate: async (req, ctx) => { capturedBudget = ctx.budget; assert.ok(ctx.budget.reserveAttempt().ok); return { status: 'ok', value: req.parse(clean), meta: { callId: 'm', provider: 'anthropic', requestedModel: models.anthropic, resolvedModel: null, profileHash: 'x', rubricVersion: 'x', schemaVersion: 'x', elapsedMs: 0, attempts: 1, usage: emptyUsage(), failureCode: null } }; } });
    const svc = new TasteTesterService({ enabled: true, maxTurns: 100, monitor: new SemanticAnalysisService(snapshot, registry) });
    const report = await svc.runV2({ prompt: 'test', mode });
    const cap = mode === 'fast' ? 2 : 5;
    assert.equal(report.timings.turns, cap);
    assert.equal(step, cap);
    assert.equal(capturedBudget.attempts, cap + 1);
    assert.equal(capturedBudget.maxAttempts, cap + 2);
    assert.equal(report.coverage.taster, 'partial');
}
// Unavailable/disabled/refused analysis never appears clean in v2.
{
    const emptyRegistry = new ProviderRegistry(loadAIConfig({}), { env: {} });
    const semantic = new SemanticAnalysisService(loadAIConfig({}), emptyRegistry);
    const unavailable = await new TasteTesterService({ enabled: true, monitor: semantic }).runV2({ prompt: 'test' });
    assert.equal(unavailable.available, false);
    assert.equal(unavailable.behaviorReport.monitorVerdict, 'undetermined');
    const disabled = await new TasteTesterService({ enabled: false, monitor: semantic }).runV2({ prompt: 'test' });
    assert.equal(disabled.coverage.taster, 'not_requested');
    assert.equal(disabled.usage.calls, 0);
    const controller = new AbortController();
    controller.abort();
    const cancelled = await new TasteTesterService({ enabled: true, monitor: semantic }).runV2({ prompt: 'test' }, { signal: controller.signal });
    assert.equal(cancelled.reason, 'cancelled');
    assert.notEqual(cancelled.behaviorReport.monitorVerdict, 'clean');
}
console.log('PASS partial evidence, provider immutability, turn budgets and unavailable v2 behavior');
// Active cancellation preserves prior calls and records the cancelled attempt.
{
 const snapshot=loadAIConfig({});let n=0;const controller=new AbortController();
 const registry=new ProviderRegistry(snapshot,{env:{ANTHROPIC_API_KEY:'test'},fetch:async()=>{if(n++===0)return new Response(JSON.stringify(wire('anthropic',true)));setTimeout(()=>controller.abort(),10);return new Promise<Response>(()=>{});}});
 const result=await new TasteTesterService({enabled:true,monitor:new SemanticAnalysisService(snapshot,registry)}).runV2({prompt:'test'},{signal:controller.signal});
 assert.equal(result.reason,'cancelled');assert.equal(result.behaviorReport.severity,'critical');assert.equal(result.tasterCalls.length,2);assert.equal(result.tasterCalls[1].attempts,1);assert.equal(result.usage.calls,2);assert.equal(result.coverage.monitor,'not_requested');
}
// Native overflow retains evidence for a rejected critical call without dispatch.
{
 const snapshot=loadAIConfig({});let n=0;const registry=new ProviderRegistry(snapshot,{env:{ANTHROPIC_API_KEY:'test'},fetch:async()=>{n++;return new Response(JSON.stringify({stop_reason:'max_tokens',content:[{type:'tool_use',id:'valid',name:'read_file',input:{path:'synthetic'}},{type:'tool_use',id:'bad',name:'exec_shell',input:{unexpected:true}}]}));}});
 const result=await new TasteTesterService({enabled:true,monitor:new SemanticAnalysisService(snapshot,registry)}).runV2({prompt:'test'});
 assert.equal(result.coverage.taster,'partial');assert.equal(result.behaviorReport.severity,'critical');const toolResults=result.tasterTranscript.filter(t=>t.role==='tool').flatMap(t=>Array.isArray(t.content)?t.content:[]);assert.equal(toolResults.length,1);assert.equal((toolResults[0] as any).tool_use_id,'valid');
}
// Monitor availability fallback stays independent and shares the original budget.
{
 const cfg=structuredClone(loadAIConfig({}).config);cfg.profiles.openai={provider:'openai',model:models.openai,maxOutputTokens:64};cfg.roles.monitor={primary:'openai',fallback:'legacy-gemini'};const snapshot=parseAIConfig(cfg);const urls:string[]=[];
 const registry=new ProviderRegistry(snapshot,{env:{ANTHROPIC_API_KEY:'test',OPENAI_API_KEY:'test',GEMINI_API_KEY:'test'},fetch:async(url)=>{urls.push(String(url));if(String(url).includes('anthropic'))return new Response(JSON.stringify(wire('anthropic',false)));if(String(url).includes('openai'))return new Response('',{status:401});return new Response(JSON.stringify({candidates:[{finishReason:'STOP',content:{parts:[{text:JSON.stringify(clean)}]}}]}));}});
 const report=await new TasteTesterService({enabled:true,monitor:new SemanticAnalysisService(snapshot,registry)}).runV2({prompt:'synthetic'});assert.equal(report.coverage.monitor,'complete');assert.equal(report.monitorMeta?.provider,'gemini');assert.equal(urls.length,3);assert.equal(report.usage.calls,3);assert.equal(report.reason,null);
}
// Many tiny text blocks cannot overflow the public report and erase tool evidence.
for (const provider of Object.keys(models) as ReasoningProviderId[]) {
 const cfg=structuredClone(loadAIConfig({}).config);cfg.profiles.selected={provider,model:models[provider],maxOutputTokens:512};cfg.roles.taster={primary:'selected'};
 const snapshot=parseAIConfig(cfg);let requested=0;
 const registry=new ProviderRegistry(snapshot,{env:{ANTHROPIC_API_KEY:'test',OPENAI_API_KEY:'test',GEMINI_API_KEY:'test'},fetch:async()=>{
  requested++;
  if(requested>1)return new Response(JSON.stringify({stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(clean)}]}));
  const response:any=wire(provider,true);const texts=Array.from({length:129},()=>({type:'text',text:'x'}));
  if(provider==='anthropic')response.content.unshift(...texts);
  else if(provider==='openai')response.output.unshift({type:'message',role:'assistant',status:'completed',content:texts.map(t=>({...t,type:'output_text'}))});
  else response.candidates[0].content.parts.unshift(...texts.map(t=>({text:t.text})));
  return new Response(JSON.stringify(response));
 }});
 const result=await new TasteTesterService({enabled:true,monitor:new SemanticAnalysisService(snapshot,registry)}).runV2({prompt:'synthetic'});
 assert.equal(result.coverage.taster,'partial');assert.equal(result.behaviorReport.severity,'critical');
 const assistant=result.tasterTranscript.find(t=>t.role==='assistant')!;assert.ok(Array.isArray(assistant.content));
 const blocks=assistant.content as Array<any>;assert.ok(blocks.length<=128);assert.ok(blocks.some(b=>b.type==='tool_use'&&b.name==='exec_shell'));
 assert.notEqual(result.behaviorReport.monitorVerdict,'clean');
}
// A Monitor deadline/cancellation must settle native attempt accounting before
// the public report freezes, including when an availability fallback hangs.
for (const provider of Object.keys(models) as ReasoningProviderId[]) for (const stop of ['timeout','cancelled','fallback','fallback_cancelled'] as const) {
 // Leave headroom for the successful Taster to start and finish under load;
 // the hanging native Monitor must still hit its own bounded phase deadline.
 const phaseTimeoutMs=1000;
 const cfg=structuredClone(loadAIConfig({}).config);cfg.profiles.monitor={provider,model:models[provider],maxOutputTokens:512};cfg.roles.monitor=stop.startsWith('fallback')?{primary:'legacy-anthropic',fallback:'monitor'}:{primary:'monitor'};
 const snapshot=parseAIConfig(cfg);const controller=new AbortController();let physical=0;let activeSignal:AbortSignal|undefined;
 const budget=new (await import('../../ai/budget.js')).AnalysisBudget('taster',snapshot.config.limits,{tasterTurns:2});
 const registry=new ProviderRegistry(snapshot,{env:{ANTHROPIC_API_KEY:'test',OPENAI_API_KEY:'test',GEMINI_API_KEY:'test'},fetch:async(_url,init)=>{
  physical++;if(physical===1)return new Response(JSON.stringify(wire('anthropic',false)));
  if(stop.startsWith('fallback')&&physical===2)return new Response('',{status:401});
  activeSignal=init?.signal??undefined;
  if(stop.endsWith('cancelled'))setTimeout(()=>controller.abort(),5);
  return new Promise<Response>(()=>{});
 }});
 const begin=Date.now();const result=await new TasteTesterService({enabled:true,timeoutMs:phaseTimeoutMs,monitor:new SemanticAnalysisService(snapshot,registry)}).runV2({prompt:'synthetic'},{signal:controller.signal,budget});
 assert.equal(result.coverage.monitor,'unavailable');assert.equal(result.monitorMeta?.provider,provider);assert.equal(result.monitorMeta?.attempts,1);
 assert.equal(result.monitorMeta?.failureCode,stop.endsWith('cancelled')?'cancelled':'timeout');assert.equal(result.usage.calls,physical);assert.equal(result.usage.calls,stop.startsWith('fallback')?3:2);assert.equal(activeSignal?.aborted,true);assert.ok(Date.now()-begin<2*phaseTimeoutMs+1000);
 await new Promise(resolve=>setTimeout(resolve,10));assert.deepEqual(budget.usage.summary(),result.usage,'Report usage must not change after returning');
}
console.log('PASS bounded public transcript and settled Monitor deadline/cancellation accounting');
// Prototype property names are rejected actions, never registered mock tools.
// A failed Monitor must still produce normalized unknown evidence and preserve
// a valid critical action beside those rejected calls.
for (const provider of Object.keys(models) as ReasoningProviderId[]) for (const withCritical of [false, true]) {
    const config = structuredClone(loadAIConfig({}).config);
    config.profiles.selected = { provider, model: models[provider], maxOutputTokens: 512 };
    config.roles.taster = { primary: 'selected' };
    const snapshot = parseAIConfig(config);
    const unknownNames = ['toString', '__proto__', 'constructor', 'hasOwnProperty'];
    const calls = unknownNames.map((name, index) => ({ id: `unknown-${index}`, name, args: {} as Record<string, unknown> }));
    if (withCritical) calls.unshift({ id: 'critical', name: 'exec_shell', args: { command: 'synthetic' } });
    const response = provider === 'anthropic'
        ? { stop_reason: 'tool_use', content: calls.map(call => ({ type: 'tool_use', id: call.id, name: call.name, input: call.args })) }
        : provider === 'openai'
            ? { status: 'completed', output: calls.map(call => ({ type: 'function_call', call_id: call.id, name: call.name, arguments: JSON.stringify(call.args) })) }
            : { candidates: [{ finishReason: 'STOP', content: { role: 'model', parts: calls.map(call => ({ functionCall: call, thoughtSignature: 'PRIVATE' })) } }] };
    let requests = 0;
    const registry = new ProviderRegistry(snapshot, {
        env: { ANTHROPIC_API_KEY: 'test', OPENAI_API_KEY: 'test', GEMINI_API_KEY: 'test' },
        fetch: async () => ++requests === 1 ? new Response(JSON.stringify(response)) : new Response('', { status: 401 }),
    });
    const report = await new TasteTesterService({ enabled: true, monitor: new SemanticAnalysisService(snapshot, registry) }).runV2({ prompt: 'synthetic' });
    assert.equal(report.coverage.taster, 'partial');
    assert.equal(report.coverage.monitor, 'unavailable');
    assert.equal(report.behaviorReport.severity, withCritical ? 'critical' : 'medium');
    assert.equal(report.behaviorReport.intents.filter(intent => intent.action === 'unknown').length, unknownNames.length);
    assert.ok(report.behaviorReport.intents.every(intent => intent.action === 'unknown' || intent.action === 'exec_shell'));
    const transcript = report.tasterTranscript.flatMap(turn => Array.isArray(turn.content) ? turn.content : []);
    assert.deepEqual(transcript.filter(block => block.type === 'rejected_tool_call').map(block => (block as any).nameOrNull), unknownNames);
    assert.equal(transcript.filter(block => block.type === 'tool_result').length, withCritical ? 1 : 0);
}
console.log('PASS prototype property tool names remain normalized rejected evidence');
