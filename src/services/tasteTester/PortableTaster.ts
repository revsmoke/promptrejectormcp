import { randomUUID } from 'node:crypto';
import { AnalysisBudget } from '../../ai/budget.js';
import { roleProfiles } from '../../ai/config.js';
import type { CallContext, CallMeta, ToolConversationProvider, ToolResult, ToolSessionHandle } from '../../ai/contracts.js';
import { emptyUsage } from '../../ai/usage.js';
import { tokenPrices } from '../../ai/pricing.js';
import { profileHash } from '../../ai/modelProfiles.js';
import { monitorReportSchema, nativeJsonSchema } from '../../ai/taskSchemas.js';
import { withDeadline } from '../../ai/transport.js';
import { tasterInputSchema, tasterReportSchema, type TasterReport } from '../../schemas/TasterReportSchema.js';
import type { TasteTesterInput } from '../TasteTesterService.js';
import type { SemanticAnalysisService } from '../SemanticAnalysisService.js';
import { MOCK_TOOL_DEFINITIONS, routeMockTool } from './MockTools.js';
import { MONITOR_SYSTEM_PROMPT, TASTER_SYSTEM_PROMPT } from './Prompts.js';
import { actionIntents, maxSeverity, observedActions, publicAssistant, severityFloor, type ObservedAction, type PublicTurn } from './Transcript.js';
export class PortableTaster {
    constructor(private readonly semantic: SemanticAnalysisService, private readonly settings: {
        enabled: boolean;
        maxTurns: number;
        maxTokens: number;
        timeoutMs: number;
        conversation?: ToolConversationProvider;
    }) { }
    get supportsV1(): boolean { return [...roleProfiles(this.semantic.snapshot, 'taster'), ...roleProfiles(this.semantic.snapshot, 'monitor')].every(p => p.provider === 'anthropic'); }
    async run(input: TasteTesterInput, options: {
        signal?: AbortSignal;
        maxUsd?: number;
        budget?: AnalysisBudget;
    } = {}): Promise<TasterReport> {
        tasterInputSchema.parse(input);
        const start = Date.now();
        const runId = randomUUID();
        const snapshot = this.semantic.snapshot;
        const cap = Math.min(this.settings.maxTurns, input.mode === 'thorough' ? 5 : 2);
        const phaseMs = Math.min(this.settings.timeoutMs, 30000);
        const budget = options.budget ?? new AnalysisBudget('taster', snapshot.config.limits, { tasterTurns: cap, maxUsd: options.maxUsd });
        const deadline = Math.min(budget.deadlineMs, start + 60000);
        const context: CallContext = { budget, deadlineMs: deadline, runId, role: 'taster', configHash: snapshot.hash, signal: options.signal, routing: [] };
        const profile = { ...roleProfiles(snapshot, 'taster')[0], maxOutputTokens: Math.min(roleProfiles(snapshot, 'taster')[0].maxOutputTokens, this.settings.maxTokens) };
        const transcript: PublicTurn[] = [];
        const actions: ObservedAction[] = [];
        const calls: CallMeta[] = [];
        let monitorMeta: CallMeta | null = null;
        let reason: string | null = null;
        let coverage: TasterReport['coverage'] = { taster: 'not_requested', monitor: 'not_requested' };
        let turns = 0;
        let complete = false;
        let tasterMs = 0;
        let monitorMs = 0;
        let behavior: TasterReport['behaviorReport'] = { intents: [], monitorVerdict: 'undetermined', monitorRationale: 'Taster has not completed.', severity: 'safe' };
        const finish = () => tasterReportSchema.parse({ schemaVersion: 2, task: 'taster', runId, available: coverage.taster !== 'not_requested' && coverage.taster !== 'unavailable', reason, behaviorReport: behavior, coverage, tasterTranscript: transcript, tasterCalls: calls, monitorMeta, routing: context.routing, configHash: snapshot.hash, policyVersion: 'taster-v2.1', timings: { tasterMs, monitorMs, totalMs: Date.now() - start, turns, truncated: !complete && turns > 0 }, usage: budget.usage.summary() });
        if (!this.settings.enabled) {
            reason = 'TASTE_TESTER_ENABLED=false';
            return finish();
        }
        const conversation = this.settings.conversation ?? this.semantic.registry.conversation(profile);
        let session: ToolSessionHandle | undefined;
        const userContent = input.context ? `[Context]\n${input.context}\n\n[Prompt]\n${input.prompt}` : input.prompt;
        transcript.push({ role: 'user', content: userContent });
        const tasterDeadline = Math.min(deadline, start + phaseMs);
        context.routing!.push({ role: 'taster', provider: profile.provider, model: profile.model, profileHash: profileHash(profile), status: 'attempted', reason: 'primary_no_conversation_fallback' });
        const fallback = roleProfiles(snapshot, 'taster')[1];
        if (fallback)
            context.routing!.push({ role: 'taster', provider: fallback.provider, model: fallback.model, profileHash: profileHash(fallback), status: 'skipped', reason: 'conversation_fallback_forbidden' });
        let nextResults: ToolResult[] = [];
        let totalCalls = 0;
        let pendingMeta: CallMeta | null = null;
        let pendingStarted = 0;
        try {
            for (let i = 0; i < cap; i++) {
                pendingStarted = Date.now();
                pendingMeta = { callId: randomUUID(), provider: profile.provider, requestedModel: profile.model, resolvedModel: null,
                    profileHash: profileHash(profile), rubricVersion: 'taster-v2', schemaVersion: 'tool-turn-v2', elapsedMs: 0,
                    attempts: 0, usage: emptyUsage(), failureCode: null };
                const operationMeta = pendingMeta;
                const operation = { ...context, callId: operationMeta.callId, onAttempt: () => { operationMeta.attempts++; } };
                const result = await withDeadline(signal => session ? conversation.resume(session, nextResults, { ...operation, signal, deadlineMs: tasterDeadline }) : conversation.start({ profile, systemInstruction: TASTER_SYSTEM_PROMPT, userContent, tools: MOCK_TOOL_DEFINITIONS, maxCallsPerTurn: Math.min(8, 40 - totalCalls) }, { ...operation, signal, deadlineMs: tasterDeadline }), tasterDeadline, options.signal);
                pendingMeta = null;
                calls.push(result.meta);
                if (result.status !== 'ok') {
                    reason = result.code;
                    coverage.taster = turns ? 'partial' : 'unavailable';
                    break;
                }
                session = result.value.session;
                turns++;
                const turn = result.value;
                const publicTurn = publicAssistant(turn);
                transcript.push(publicTurn.turn);
                actions.push(...observedActions(turn));
                let partial = turn.completeness === 'partial' || publicTurn.partial;
                nextResults = [];
                // Both native and injected adapters are checked at the execution boundary.
                const ids = turn.calls.map(c => c.id);
                for (const c of turn.calls) {
                    if (nextResults.length >= 8 || totalCalls >= 40 || ids.filter(id => id === c.id).length !== 1) {
                        partial = true;
                        continue;
                    }
                    const def = MOCK_TOOL_DEFINITIONS.find(t => t.name === c.name);
                    try {
                        if (!def)
                            throw Error('unknown');
                        const parsed = def.parse(c.arguments);
                        nextResults.push({ id: c.id, output: routeMockTool(c.name, parsed), isError: false });
                        totalCalls++;
                    }
                    catch {
                        partial = true;
                    }
                }
                if (nextResults.length)
                    transcript.push({ role: 'tool', content: nextResults.map(r => ({ type: 'tool_result', tool_use_id: r.id, content: r.output, is_error: r.isError })) });
                if (partial || ['refusal', 'length', 'error'].includes(turn.finish)) {
                    reason = turn.finish === 'length' ? 'incomplete' : 'partial_tool_turn';
                    coverage.taster = 'partial';
                    break;
                }
                if (turn.finish === 'stop') {
                    complete = true;
                    reason = null;
                    coverage.taster = 'complete';
                    break;
                }
                if (!nextResults.length) {
                    reason = 'invalid_response';
                    coverage.taster = 'partial';
                    break;
                }
                coverage.taster = 'partial';
                reason = 'turn_limit';
            }
        }
        catch {
            reason = options.signal?.aborted ? 'cancelled' : Date.now() >= tasterDeadline ? 'timeout' : 'invalid_response';
            coverage.taster = turns ? 'partial' : 'unavailable';
            if (pendingMeta) {
                const failureCode = options.signal?.aborted ? 'cancelled' : Date.now() >= tasterDeadline ? 'timeout' : 'invalid_response';
                const failed = { ...pendingMeta, elapsedMs: Date.now() - pendingStarted, failureCode } as CallMeta;
                calls.push(failed);
                if (failed.attempts) {
                    const prices = tokenPrices(snapshot.pricing, profile.provider, profile.model);
                    for (let i = 0; i < failed.attempts - 1; i++) budget.usage.record(`${failed.callId}:attempt:${i}`, emptyUsage(), prices);
                    budget.usage.record(failed.callId, emptyUsage(), prices);
                }
            }
        }
        finally {
            if (session)
                conversation.dispose(session);
            tasterMs = Date.now() - start;
        }
        behavior = { intents: actionIntents(actions), monitorVerdict: 'undetermined', monitorRationale: reason ? `Taster incomplete: ${reason}.` : 'Monitor unavailable.', severity: severityFloor(actions) };
        if (turns && !options.signal?.aborted && Date.now() < deadline) {
            const monitorStart = Date.now();
            const monitorDeadline = Math.min(deadline, monitorStart + phaseMs);
            try {
                const result = await withDeadline(signal => this.semantic.generate('monitor', { systemInstruction: MONITOR_SYSTEM_PROMPT + ' Return the supplied schema, using null for an unavailable rationale.', state: JSON.stringify({ transcript }), schemaId: 'behavior_report', schemaVersion: 'monitor-v2', rubricVersion: 'monitor-v2', jsonSchema: nativeJsonSchema(monitorReportSchema), parse: value => monitorReportSchema.parse(value) }, { ...context, role: 'monitor', signal, deadlineMs: monitorDeadline }, { maxOutputTokens: this.settings.maxTokens }), monitorDeadline, options.signal);
                monitorMeta = result.meta;
                if (result.status === 'ok') {
                    coverage.monitor = 'complete';
                    behavior = { ...result.value, severity: maxSeverity(result.value.severity, severityFloor(actions)) };
                    for (const intent of behavior.intents)
                        behavior.severity = maxSeverity(behavior.severity, intent.severity);
                    if (behavior.severity !== 'safe' && behavior.monitorVerdict === 'clean')
                        behavior.monitorVerdict = 'suspicious';
                    if (!complete && behavior.monitorVerdict === 'clean')
                        behavior.monitorVerdict = 'undetermined';
                }
                else {
                    coverage.monitor = 'unavailable';
                    reason ??= `monitor_${result.code}`;
                }
            }
            catch {
                coverage.monitor = 'unavailable';
                reason ??= options.signal?.aborted ? 'cancelled' : 'monitor_timeout';
            }
            monitorMs = Date.now() - monitorStart;
        }
        return finish();
    }
}
