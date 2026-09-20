import { randomUUID } from 'node:crypto';
import type { CallContext, CallMeta, CallResult, FailureCode, ReasoningProviderId, ToolConversationProvider, ToolResult, ToolSessionHandle, ToolSessionRequest, ToolTurn, Usage } from '../contracts.js';
import { modelCapabilities, profileHash, validateModelProfile } from '../modelProfiles.js';
import { NativeTransport } from '../transport.js';
import { emptyUsage, estimateCost, reserveCost, tokenCount } from '../usage.js';
import { object, type StructuredHttpOptions } from './structuredHttp.js';
type RawCall = {
    id: unknown;
    name: unknown;
    arguments: unknown;
    json?: boolean;
    nativeId?: string;
};
type Session = {
    request: ToolSessionRequest;
    budget: CallContext['budget'];
    runId: string;
    configHash: string;
    expires: number;
    history: unknown[];
    pending: ToolTurn['calls'];
    nativeIds: Map<string, string | undefined>;
    busy: boolean;
    terminal: boolean;
    turn: number;
    seenIds: Set<string>;
    expiry?: ReturnType<typeof setTimeout>;
};
/** Native continuation remains in this adapter-owned map, never in a transcript.
 * No provider callback can execute tools. The service supplies synthetic results. */
export class NativeConversationAdapter implements ToolConversationProvider {
    private readonly sessions = new Map<ToolSessionHandle, Session>();
    constructor(private readonly provider: ReasoningProviderId, private readonly options: StructuredHttpOptions = {}) { }
    async start(request: ToolSessionRequest, call: CallContext): Promise<CallResult<ToolTurn>> {
        this.prune();
        if (this.sessions.size >= 64)
            return this.failure(request, 'budget_exceeded');
        const handle = randomUUID() as ToolSessionHandle;
        const copy = { ...request, profile: JSON.parse(JSON.stringify(request.profile)), tools: request.tools.map(t => ({ ...t, inputSchema: JSON.parse(JSON.stringify(t.inputSchema)) })) };
        const s: Session = { request: copy, budget: call.budget, runId: call.runId, configHash: call.configHash, expires: Math.min(call.deadlineMs, call.budget.deadlineMs, Date.now() + 60000), history: [], pending: [], nativeIds: new Map(), busy: false, terminal: false, turn: 0, seenIds: new Set() };
        s.history = this.provider === 'anthropic' ? [{ role: 'user', content: request.userContent }] : this.provider === 'openai' ? [{ role: 'user', content: [{ type: 'input_text', text: request.userContent }] }] : [{ role: 'user', parts: [{ text: request.userContent }] }];
        s.expiry = setTimeout(() => this.dispose(handle), Math.max(0, s.expires - Date.now()));
        s.expiry.unref();
        this.sessions.set(handle, s);
        const result = await this.send(handle, s, call);
        if (result.status !== 'ok')
            this.dispose(handle);
        return result;
    }
    async resume(handle: ToolSessionHandle, results: ToolResult[], call: CallContext): Promise<CallResult<ToolTurn>> {
        const s = this.sessions.get(handle);
        if (!s)
            return this.failure(undefined, 'invalid_response');
        if (s.busy || s.terminal || call.role !== 'taster' || s.budget !== call.budget || s.runId !== call.runId || s.configHash !== call.configHash || Date.now() >= s.expires)
            return this.failure(s.request, 'invalid_response');
        if (!Array.isArray(results) || !s.pending.length || results.length !== s.pending.length || new Set(results.map(r => r?.id)).size !== results.length || results.some(r => !r || typeof r.output !== 'string' || r.output.length > 100000 || typeof r.isError !== 'boolean' || !s.pending.some(p => p.id === r.id)))
            return this.failure(s.request, 'invalid_response');
        const submitted = results.map(r => ({ ...r }));
        if (this.provider === 'anthropic')
            s.history.push({ role: 'user', content: submitted.map(r => ({ type: 'tool_result', tool_use_id: r.id, content: r.output, is_error: r.isError })) });
        else if (this.provider === 'openai')
            s.history.push(...submitted.map(r => ({ type: 'function_call_output', call_id: r.id, output: r.output })));
        else
            s.history.push({ role: 'user', parts: submitted.map(r => ({ functionResponse: { ...(s.nativeIds.get(r.id) ? { id: s.nativeIds.get(r.id) } : {}), name: s.pending.find(p => p.id === r.id)!.name, response: r.isError ? { error: r.output } : { output: r.output } } })) });
        s.pending = [];
        return this.send(handle, s, call);
    }
    dispose(handle: ToolSessionHandle): void { const s = this.sessions.get(handle); if (s?.expiry)
        clearTimeout(s.expiry); this.sessions.delete(handle); }
    private prune(): void { for (const [id, s] of this.sessions)
        if (Date.now() >= s.expires && !s.busy)
            this.dispose(id); }
    private failure(request: ToolSessionRequest | undefined, code: FailureCode): CallResult<ToolTurn> { return { status: 'unavailable', code, meta: { callId: randomUUID(), provider: this.provider, requestedModel: request?.profile.model ?? 'unknown', resolvedModel: null, profileHash: request ? profileHash(request.profile) : 'unknown', rubricVersion: 'taster-v2', schemaVersion: 'tool-turn-v2', elapsedMs: 0, attempts: 0, usage: emptyUsage(), failureCode: code } }; }
    private async send(handle: ToolSessionHandle, s: Session, call: CallContext): Promise<CallResult<ToolTurn>> {
        const started = Date.now();
        const request = s.request;
        const initial = this.failure(request, 'invalid_response');
        const meta: CallMeta = { ...initial.meta, callId: call.callId ?? initial.meta.callId, failureCode: null };
        const fail = (code: FailureCode): CallResult<ToolTurn> => { s.terminal = true; return { status: 'unavailable', code, meta: { ...meta, elapsedMs: Date.now() - started, failureCode: code } }; };
        if (call.role !== 'taster') return fail('unsupported');
        if (call.signal?.aborted)
            return fail('cancelled');
        if (!this.options.apiKey)
            return fail('not_configured');
        try {
            validateModelProfile(request.profile, this.options.capabilities);
            const c = modelCapabilities(request.profile, this.options.capabilities);
            if (request.profile.provider !== this.provider || !c?.tools || !c.statelessTools || !Number.isInteger(request.maxCallsPerTurn) || request.maxCallsPerTurn < 1 || request.maxCallsPerTurn > 8 || !request.tools.length || request.tools.length > 8 || new Set(request.tools.map(t => t.name)).size !== request.tools.length)
                return fail('unsupported');
            for (const t of request.tools)
                validateToolSchema(t.inputSchema);
        }
        catch {
            return fail('unsupported');
        }
        const tools = request.tools;
        let url: string;
        let headers: Record<string, string>;
        let body: unknown;
        if (this.provider === 'anthropic') {
            url = 'https://api.anthropic.com/v1/messages';
            headers = { 'x-api-key': this.options.apiKey, 'anthropic-version': '2023-06-01' };
            body = { model: request.profile.model, system: request.systemInstruction, messages: s.history, max_tokens: request.profile.maxOutputTokens, ...request.profile.options, tools: tools.map(t => ({ name: t.name, description: t.description, input_schema: t.inputSchema })) };
        }
        else if (this.provider === 'openai') {
            url = 'https://api.openai.com/v1/responses';
            headers = { Authorization: `Bearer ${this.options.apiKey}` };
            body = { model: request.profile.model, instructions: request.systemInstruction, input: s.history, store: false, include: ['reasoning.encrypted_content'], max_output_tokens: request.profile.maxOutputTokens, ...request.profile.options, tools: tools.map(t => ({ type: 'function', name: t.name, description: t.description, parameters: t.inputSchema, strict: true })) };
        }
        else {
            url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(request.profile.model)}:generateContent`;
            headers = { 'x-goog-api-key': this.options.apiKey };
            body = { systemInstruction: { parts: [{ text: request.systemInstruction }] }, contents: s.history, generationConfig: { ...request.profile.options, candidateCount: 1, maxOutputTokens: request.profile.maxOutputTokens }, tools: [{ functionDeclarations: tools.map(t => ({ name: t.name, description: t.description, parametersJsonSchema: t.inputSchema })) }] };
        }
        const encoded = JSON.stringify(body);
        if (Buffer.byteLength(encoded) > modelCapabilities(request.profile, this.options.capabilities)!.maxInputBytes)
            return fail('context_limit');
        s.busy = true;
        try {
            const timeoutMs = Math.min(this.options.timeoutMs ?? 15000, 30000);
            const http = await (this.options.transport ?? new NativeTransport()).postJson({ url, headers, body: encoded, timeoutMs, estimatedUsd: reserveCost(Buffer.byteLength(encoded), request.profile.maxOutputTokens * (this.provider === 'gemini' ? 2 : 1), this.options.prices) }, { ...call, deadlineMs: Math.min(call.deadlineMs, s.expires) });
            meta.attempts = http.attempts;
            for (let i = 0; i < http.attempts - 1; i++)
                call.budget.usage.record(`${meta.callId}:attempt:${i}`, emptyUsage(), this.options.prices);
            if (http.status === 'unavailable') {
                if (http.attempts)
                    call.budget.usage.record(meta.callId, meta.usage, this.options.prices);
                return fail(http.code);
            }
            const response = object(http.value);
            if (!response) {
                call.budget.usage.record(meta.callId, meta.usage, this.options.prices);
                return fail('invalid_response');
            }
            const parsed = this.parse(response, s);
            meta.usage = parsed.usage;
            meta.resolvedModel = parsed.model;
            call.budget.usage.record(meta.callId, meta.usage, this.options.prices);
            const reservation = http.reservationIds[http.reservationIds.length - 1];
            if (reservation)
                call.budget.reconcile(reservation, estimateCost(meta.usage, this.options.prices));
            if (parsed.code)
                return fail(parsed.code);
            if (call.signal?.aborted)
                return fail('cancelled');
            if (Date.now() >= Math.min(call.deadlineMs, call.budget.deadlineMs, s.expires, started + timeoutMs))
                return fail('timeout');
            const normalized = normalizeCalls(parsed.calls, request, s.seenIds);
            const partial = parsed.partial || normalized.rejectedCalls.length > 0;
            for (const c of parsed.calls)
                if (typeof c.id === 'string')
                    s.seenIds.add(c.id);
            s.turn++;
            const turn: ToolTurn = { session: handle, text: parsed.text, calls: normalized.calls, rejectedCalls: normalized.rejectedCalls, completeness: partial ? 'partial' : 'complete', finish: parsed.finish };
            s.nativeIds = normalized.nativeIds;
            s.pending = turn.calls;
            s.terminal = partial || turn.finish !== 'tool_calls';
            if (this.provider === 'openai')
                s.history.push(...parsed.privateContent!);
            else
                s.history.push(parsed.privateContent);
            return { status: 'ok', value: turn, meta: { ...meta, elapsedMs: Date.now() - started } };
        }
        catch {
            return fail('invalid_response');
        }
        finally {
            s.busy = false;
        }
    }
    private parse(r: Record<string, unknown>, s: Session): Parsed {
        const out: Parsed = { calls: [], text: [], finish: 'error', partial: false, usage: emptyUsage(), model: null };
        const malformed = () => ({ ...out, code: 'invalid_response' as const });
        let blocks: unknown[];
        if (this.provider === 'anthropic') {
            const u = object(r.usage);
            out.usage = { ...emptyUsage(), inputTokens: tokenCount(u?.input_tokens), outputTokens: tokenCount(u?.output_tokens), cachedReadTokens: tokenCount(u?.cache_read_input_tokens), cacheWriteTokens: tokenCount(u?.cache_creation_input_tokens), cachedReadIsInputSubset: false, cacheWriteIsInputSubset: false };
            out.model = typeof r.model === 'string' ? r.model : null;
            if (!Array.isArray(r.content))
                return malformed();
            blocks = r.content;
            out.privateContent = { role: 'assistant', content: blocks };
            out.finish = r.stop_reason === 'tool_use' ? 'tool_calls' : r.stop_reason === 'end_turn' ? 'stop' : r.stop_reason === 'max_tokens' ? 'length' : r.stop_reason === 'refusal' ? 'refusal' : 'error';
            for (const raw of blocks) {
                const b = object(raw);
                if (b?.type === 'tool_use')
                    out.calls.push({ id: b.id, name: b.name, arguments: b.input });
                else if (b?.type === 'text' && typeof b.text === 'string')
                    out.text.push(b.text);
                else if (b?.type === 'refusal')
                    out.finish = 'refusal';
                else if (!b || !['thinking', 'redacted_thinking'].includes(String(b.type)))
                    out.partial = true;
            }
        }
        else if (this.provider === 'openai') {
            const u = object(r.usage);
            out.usage = { ...emptyUsage(), inputTokens: tokenCount(u?.input_tokens), outputTokens: tokenCount(u?.output_tokens), cachedReadTokens: tokenCount(object(u?.input_tokens_details)?.cached_tokens), cacheWriteTokens: tokenCount(object(u?.input_tokens_details)?.cache_write_tokens), reasoningTokens: tokenCount(object(u?.output_tokens_details)?.reasoning_tokens) };
            out.model = typeof r.model === 'string' ? r.model : null;
            if (!Array.isArray(r.output))
                return malformed();
            blocks = r.output;
            out.privateContent = blocks;
            out.finish = r.status === 'completed' && !r.error ? 'stop' : r.status === 'incomplete' ? 'length' : 'error';
            for (const raw of blocks) {
                const b = object(raw);
                if (b?.type === 'function_call')
                    out.calls.push({ id: b.call_id, name: b.name, arguments: b.arguments, json: true });
                else if (b?.type === 'reasoning') {
                    if (typeof b.encrypted_content !== 'string' || !b.encrypted_content)
                        out.partial = true;
                }
                else if (b?.type === 'message' && b.role === 'assistant' && Array.isArray(b.content)) {
                    if (b.status !== 'completed')
                        out.partial = true;
                    for (const rawPart of b.content) {
                        const p = object(rawPart);
                        if (p?.type === 'refusal')
                            out.finish = 'refusal';
                        else if (p?.type === 'output_text' && typeof p.text === 'string')
                            out.text.push(p.text);
                        else
                            out.partial = true;
                    }
                }
                else
                    out.partial = true;
            }
            if (out.calls.length && out.finish === 'stop')
                out.finish = 'tool_calls';
        }
        else {
            const u = object(r.usageMetadata);
            out.usage = { ...emptyUsage(), inputTokens: tokenCount(u?.promptTokenCount), outputTokens: tokenCount(u?.candidatesTokenCount), cachedReadTokens: tokenCount(u?.cachedContentTokenCount), reasoningTokens: tokenCount(u?.thoughtsTokenCount), reasoningIsOutputSubset: false };
            out.model = typeof r.modelVersion === 'string' ? r.modelVersion : null;
            if (object(r.promptFeedback)?.blockReason)
                return { ...out, code: 'refusal' };
            if (!Array.isArray(r.candidates) || r.candidates.length !== 1)
                return malformed();
            const candidate = object(r.candidates[0]);
            const content = object(candidate?.content);
            if (!Array.isArray(content?.parts))
                return malformed();
            blocks = content.parts;
            out.privateContent = content;
            out.finish = candidate?.finishReason === 'STOP' ? 'stop' : candidate?.finishReason === 'MAX_TOKENS' ? 'length' : ['SAFETY', 'RECITATION', 'BLOCKLIST', 'PROHIBITED_CONTENT', 'SPII', 'IMAGE_SAFETY'].includes(String(candidate?.finishReason)) ? 'refusal' : 'error';
            for (const [i, raw] of blocks.entries()) {
                const b = object(raw);
                const f = object(b?.functionCall);
                if (f)
                    out.calls.push({ id: f.id === undefined ? `g${s.turn}_${i}` : f.id, nativeId: typeof f.id === 'string' ? f.id : undefined, name: f.name, arguments: f.args });
                else if (typeof b?.text === 'string') {
                    if (b.thought !== true)
                        out.text.push(b.text);
                }
                else
                    out.partial = true;
            }
            if (out.calls.length && out.finish === 'stop')
                out.finish = 'tool_calls';
        }
        if (out.finish === 'length' || out.finish === 'error' || out.finish === 'refusal')
            out.partial = true;
        if (!out.calls.length && (out.finish === 'error' || out.finish === 'refusal' || out.finish === 'length'))
            return { ...out, code: out.finish === 'refusal' ? 'refusal' : out.finish === 'length' ? 'incomplete' : 'invalid_response' };
        if (!out.calls.length && !out.text.length)
            return malformed();
        return out;
    }
}
type Parsed = {
    calls: RawCall[];
    text: string[];
    finish: ToolTurn['finish'];
    partial: boolean;
    usage: Usage;
    model: string | null;
    privateContent?: any;
    code?: FailureCode;
};
function normalizeCalls(raw: RawCall[], request: ToolSessionRequest, seenIds: Set<string>): {
    calls: ToolTurn['calls'];
    rejectedCalls: ToolTurn['rejectedCalls'];
    nativeIds: Map<string, string | undefined>;
} {
    const calls: ToolTurn['calls'] = [];
    const rejectedCalls: ToolTurn['rejectedCalls'] = [];
    const nativeIds = new Map<string, string | undefined>();
    const counts = new Map<string, number>();
    for (const c of raw)
        if (typeof c.id === 'string')
            counts.set(c.id, (counts.get(c.id) ?? 0) + 1);
    for (const [index, c] of raw.entries()) {
        const id = typeof c.id === 'string' && c.id.length > 0 && c.id.length <= 200 ? c.id : null;
        const name = typeof c.name === 'string' ? c.name.slice(0, 200) : null;
        const def = request.tools.find(t => t.name === name);
        let reason = '';
        let args: Record<string, unknown> | undefined;
        if (!id)
            reason = 'invalid_id';
        else if (counts.get(id) !== 1 || seenIds.has(id))
            reason = 'duplicate_id';
        else if (!def)
            reason = 'unknown_tool';
        else if (index >= request.maxCallsPerTurn)
            reason = 'call_limit';
        else
            try {
                args = def.parse(c.json ? JSON.parse(String(c.arguments)) : c.arguments);
            }
            catch {
                reason = 'invalid_arguments';
            }
        if (reason) {
            const excerpt = (typeof c.arguments === 'string' ? c.arguments : JSON.stringify(c.arguments) ?? '').slice(0, 2000);
            if (rejectedCalls.length < 40 || (!!def && !rejectedCalls.some(r => r.nameOrNull === name)))
                rejectedCalls.push({ idOrNull: id, nameOrNull: name, reason, argumentExcerpt: excerpt });
        }
        else {
            calls.push({ id: id!, name: name!, arguments: args! });
            nativeIds.set(id!, c.nativeId);
        }
    }
    return { calls, rejectedCalls, nativeIds };
}
/** The eight mock tools use a small common grammar. Unsupported constraints
 * fail preflight instead of being silently removed by a provider mapping. */
function validateToolSchema(value: Record<string, unknown>): void {
    const allowed = new Set(['type', 'description', 'enum', 'properties', 'required', 'additionalProperties']);
    if (Object.keys(value).some(k => !allowed.has(k)) || !['object', 'string', 'number', 'boolean'].includes(String(value.type)))
        throw Error('Unsupported tool schema');
    if (value.type === 'object') {
        const properties = object(value.properties);
        if (!properties || value.additionalProperties !== false || !Array.isArray(value.required) || Object.keys(properties).some(k => !(value.required as unknown[]).includes(k)))
            throw Error('Tool schemas must be closed with required properties');
        for (const child of Object.values(properties)) {
            const schema = object(child);
            if (!schema)
                throw Error('Invalid property');
            validateToolSchema(schema);
        }
    }
}
