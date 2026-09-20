import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { PromptRejectorMCPServer } from '../../mcp/mcpServer.js';
import { createServices } from '../../bootstrap.js';
import { loadAIConfig, parseAIConfig } from '../../ai/config.js';
const base = loadAIConfig({}).config;
const models = { anthropic: 'claude-sonnet-5', openai: 'gpt-6-astra', gemini: 'gemini-3-flash-preview' };
for (const provider of ['anthropic', 'openai', 'gemini'] as const) for (const changedRole of ['taster', 'monitor', 'fallback'] as const) {
    const config = structuredClone(base);
    config.profiles.selected = { provider, model: models[provider], maxOutputTokens: 512 };
    if (changedRole === 'fallback')
        config.roles.monitor.fallback = 'selected';
    else
        config.roles[changedRole] = { primary: 'selected' };
    const snapshot = parseAIConfig(config);
    let calls = 0;
    const services = createServices(snapshot, { env: { TASTE_TESTER_ENABLED: 'true', ANTHROPIC_API_KEY: 'test', OPENAI_API_KEY: 'test', GEMINI_API_KEY: 'test' }, fetch: async (url, init) => {
            calls++;
            const body = JSON.parse(String(init?.body));
            const monitor = !!body.output_config?.format || !!body.text?.format || !!body.generationConfig?.responseJsonSchema;
            const text = monitor ? JSON.stringify({ intents: [], monitorVerdict: 'clean', monitorRationale: 'No action observed', severity: 'safe' }) : 'Done';
            return new Response(JSON.stringify(String(url).includes('generativelanguage') ? { candidates: [{ finishReason: 'STOP', content: { role: 'model', parts: [{ text }] } }] } : String(url).includes('openai') ? { status: 'completed', output: [{ type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text }] }] } : { stop_reason: 'end_turn', content: [{ type: 'text', text }] }));
        } });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    const server = new PromptRejectorMCPServer(services);
    await server.connect(st);
    const client = new Client({ name: 'taster-conformance', version: '1' });
    await client.connect(ct);
    try {
        const tools = await client.listTools();
        assert.equal(tools.tools.length, 11);
        assert.equal(tools.tools.find(t => t.name === 'taste_test')?.inputSchema.properties?.reportVersion, undefined);
        const read = async (args: any) => { const result = await client.callTool({ name: 'taste_test', arguments: args }); return { error: result.isError, report: JSON.parse((result.content as any)[0].text) }; };
        const legacy = await read({ prompt: 'synthetic', reportVersion: 1 });
        assert.equal(legacy.report.error, 'invalid_input');
        assert.equal(calls, 0);
        for (const invalid of [{ prompt: 'x', reportVersion: 3 }, { prompt: 'x', unexpected: true }, { prompt: '', reportVersion: 2 }])
            assert.ok((await read(invalid)).error);
        assert.equal(calls, 0);
        const report = await read({ prompt: 'synthetic' });
        assert.equal(report.error, undefined);
        assert.equal(report.report.schemaVersion, 2);
        assert.equal(report.report.coverage.taster, 'complete');
        assert.equal(report.report.coverage.monitor, 'complete');
        assert.equal(report.report.behaviorReport.monitorVerdict, 'clean');
        assert.equal(calls, 2);
        assert.equal('safe' in report.report, false);
    }
    finally {
        await client.close();
        await st.close();
    }
}
console.log('PASS sole MCP Taster pipeline, validation and v1 preflight across all three providers and primary/Monitor/fallback switches');
// MCP cancellation reaches the active native request without a Monitor call.
{
 const snapshot=loadAIConfig({});let signalSeen:AbortSignal|undefined;let dispatchedResolve!:()=>void;const dispatched=new Promise<void>(resolve=>{dispatchedResolve=resolve;});
 const services=createServices(snapshot,{env:{TASTE_TESTER_ENABLED:'true',ANTHROPIC_API_KEY:'test'},fetch:async(_url,init)=>{signalSeen=init?.signal??undefined;dispatchedResolve();return new Promise<Response>(()=>{});}});
 const [ct,st]=InMemoryTransport.createLinkedPair();await new PromptRejectorMCPServer(services).connect(st);const client=new Client({name:'taster-cancel',version:'1'});await client.connect(ct);
 try{const controller=new AbortController();const request=client.callTool({name:'taste_test',arguments:{prompt:'synthetic',reportVersion:2}},undefined,{signal:controller.signal});await dispatched;controller.abort();await assert.rejects(request);await new Promise(resolve=>setTimeout(resolve,10));assert.equal(signalSeen?.aborted,true);}finally{await client.close();await st.close();}
}
