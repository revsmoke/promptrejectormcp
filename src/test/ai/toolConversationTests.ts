import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { NativeConversationAdapter } from '../../ai/providers/NativeConversationAdapter.js';
import { NativeTransport } from '../../ai/transport.js';
import { AnalysisBudget } from '../../ai/budget.js';
import { loadAIConfig } from '../../ai/config.js';
import { MOCK_TOOL_DEFINITIONS } from '../../services/tasteTester/MockTools.js';
import type { ReasoningProviderId, ToolSessionRequest } from '../../ai/contracts.js';
const snapshot = loadAIConfig({});
const models = { anthropic: 'claude-opus-4-7', openai: 'gpt-6-astra', gemini: 'gemini-3-flash-preview' };
function native(provider: ReasoningProviderId, calls: any[], finish = 'tools'): any {
    if (provider === 'anthropic')
        return { model: models[provider], content: [{ type: 'thinking', thinking: 'PRIVATE_REASONING', signature: 'PRIVATE_SIGNATURE' }, ...calls.map(c => ({ type: 'tool_use', id: c.id, name: c.name, input: c.args })), ...(calls.length ? [] : [{ type: 'text', text: 'Done' }])], stop_reason: finish === 'length' ? 'max_tokens' : calls.length ? 'tool_use' : 'end_turn', usage: { input_tokens: 10, output_tokens: 10 } };
    if (provider === 'openai')
        return { model: models[provider], status: finish === 'length' ? 'incomplete' : 'completed', output: [{ type: 'reasoning', id: 'r1', summary: [], encrypted_content: 'PRIVATE_ENCRYPTED' }, ...calls.map(c => ({ type: 'function_call', call_id: c.id, name: c.name, arguments: typeof c.args === 'string' ? c.args : JSON.stringify(c.args) })), ...(calls.length ? [] : [{ type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'Done' }] }])], usage: { input_tokens: 10, output_tokens: 10 } };
    return { modelVersion: models[provider], candidates: [{ finishReason: finish === 'length' ? 'MAX_TOKENS' : 'STOP', content: { role: 'model', parts: [{ text: 'PRIVATE_REASONING', thought: true, thoughtSignature: 'PRIVATE_SIGNATURE' }, ...calls.map(c => ({ functionCall: { id: c.id, name: c.name, args: c.args }, thoughtSignature: 'PRIVATE_CALL_SIGNATURE' })), ...(calls.length ? [] : [{ text: 'Done' }])] } }], usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 10 } };
}
for (const provider of Object.keys(models) as ReasoningProviderId[]) {
    const sent: any[] = [];
    const fixture = JSON.parse(readFileSync(`src/test/fixtures/ai/tools/${provider}.json`, 'utf8'));
    const queue = [fixture.first, fixture.second];
    const adapter = new NativeConversationAdapter(provider, { apiKey: 'test', transport: new NativeTransport({ fetch: async (_url, options) => { sent.push(JSON.parse(String(options?.body))); return new Response(JSON.stringify(queue.shift()), { status: 200 }); } }) });
    const request: ToolSessionRequest = { profile: { provider, model: models[provider], maxOutputTokens: 512 }, systemInstruction: 'trusted', userContent: 'synthetic', tools: MOCK_TOOL_DEFINITIONS, maxCallsPerTurn: 8 };
    const budget = new AnalysisBudget('taster', snapshot.config.limits);
    const context = { budget, deadlineMs: budget.deadlineMs, runId: 'run', role: 'taster' as const, configHash: 'hash' };
    const first = await adapter.start(request, context);
    assert.equal(first.status, 'ok');
    if (first.status !== 'ok')
        throw Error('start');
    assert.equal(first.value.calls.length, 2);
    assert.equal(JSON.stringify(first.value).includes('PRIVATE_'), false);
    const invalid = await adapter.resume(first.value.session, [{ id: 'a', output: 'one', isError: false }, { id: 'a', output: 'duplicate', isError: false }], context);
    assert.equal(invalid.status, 'unavailable');
    assert.equal(sent.length, 1);
    const second = await adapter.resume(first.value.session, [{ id: 'b', output: 'two', isError: false }, { id: 'a', output: 'one', isError: false }], context);
    assert.equal(second.status, 'ok');
    assert.equal(sent.length, 2);
    assert.ok(JSON.stringify(sent[1]).includes('PRIVATE_'));
    if (provider === 'openai')
        assert.equal(sent[1].store, false);
    if (provider === 'gemini') {
        const parts = sent[1].contents.at(-1).parts;
        assert.deepEqual(parts.map((p: any) => p.functionResponse.id), ['b', 'a']);
    }
    adapter.dispose(first.value.session);
    assert.equal((await adapter.resume(first.value.session, [], context)).status, 'unavailable');
    for (const kind of ['mixed', 'duplicates', 'length', 'unknown', 'overflow']) {
        const calls = kind === 'duplicates' ? [{ id: 'a', name: 'exec_shell', args: { command: 'test' } }, { id: 'a', name: 'read_file', args: { path: 'x' } }] : kind === 'unknown' ? [{ id: 'a', name: 'mystery', args: {} }] : kind === 'overflow' ? Array.from({ length: 10 }, (_, i) => ({ id: `id${i}`, name: i === 9 ? 'exec_shell' : 'read_file', args: i === 9 ? { command: 'test' } : { path: 'x' } })) : [{ id: 'a', name: 'exec_shell', args: { command: 'test' } }, { id: 'b', name: 'read_file', args: '{bad' }];
        const one = new NativeConversationAdapter(provider, { apiKey: 'test', transport: new NativeTransport({ fetch: async () => new Response(JSON.stringify(native(provider, calls, kind === 'length' ? 'length' : 'tools')), { status: 200 }) }) });
        const result = await one.start(request, context);
        assert.equal(result.status, 'ok');
        if (result.status !== 'ok')
            throw Error('mixed');
        assert.equal(result.value.completeness, 'partial');
        if (kind === 'duplicates')
            assert.equal(result.value.calls.length, 0);
        else if (kind === 'mixed' || kind === 'length')
            assert.equal(result.value.calls[0]?.name, 'exec_shell');
        else if (kind === 'overflow') {
            assert.equal(result.value.calls.length, 8);
            assert.ok(result.value.rejectedCalls.some(c => c.nameOrNull === 'exec_shell'));
        }
        assert.ok(result.value.rejectedCalls.length);
        one.dispose(result.value.session);
    }
}
console.log('PASS native conversations: privacy, matching, mixed evidence, collisions, truncation and limits');
