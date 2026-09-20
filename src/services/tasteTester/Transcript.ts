import type { ToolTurn } from '../../ai/contracts.js';
import { TOOL_DEFAULTS } from './MockTools.js';
import type { Severity, TasterAction } from '../TasteTesterService.js';
export type TranscriptBlock = {
    type: 'text';
    text: string;
} | {
    type: 'tool_use';
    id: string;
    name: string;
    input: Record<string, unknown>;
} | {
    type: 'rejected_tool_call';
    idOrNull: string | null;
    nameOrNull: string | null;
    reason: string;
    argumentExcerpt: string;
} | {
    type: 'tool_result';
    tool_use_id: string;
    content: string;
    is_error: boolean;
};
export interface PublicTurn {
    role: 'user' | 'assistant' | 'tool';
    content: string | TranscriptBlock[];
}
export interface ObservedAction {
    name: string;
    input?: Record<string, unknown>;
}
const rank: Record<Severity, number> = { safe: 0, medium: 1, high: 2, critical: 3 };
export const maxSeverity = (a: Severity, b: Severity): Severity => rank[a] >= rank[b] ? a : b;
export function observedActions(turn: ToolTurn): ObservedAction[] { return [...turn.calls.map(c => ({ name: c.name, input: c.arguments })), ...turn.rejectedCalls.filter(c => c.nameOrNull).map(c => ({ name: c.nameOrNull! }))]; }
export function actionIntents(actions: ObservedAction[]) { return actions.slice(0, 40).map(action => { const defaults = TOOL_DEFAULTS[action.name] ?? { severity: 'medium' as Severity, atlas: [] }; const a = action.input ?? {}; return { action: (TOOL_DEFAULTS[action.name] ? action.name : 'unknown') as TasterAction, target: String(a.url ?? a.path ?? a.command ?? a.to ?? a.account ?? a.sql ?? a.key ?? '').slice(0, 4000), severity: defaults.severity, atlasTechniques: defaults.atlas, rationale: 'Derived from observed tool call evidence.' }; }); }
export function severityFloor(actions: ObservedAction[]): Severity { return actions.reduce<Severity>((max, a) => maxSeverity(max, TOOL_DEFAULTS[a.name]?.severity ?? 'medium'), 'safe'); }
/** Native normalization permits at most eight valid calls and 48 rejected-call
 * records. Reserve room for every one before fitting public text to the schema.
 * Dropped text marks coverage partial; action evidence is never displaced by it. */
export function publicAssistant(turn: ToolTurn): { turn: PublicTurn; partial: boolean } {
    const evidence: TranscriptBlock[] = [
        ...turn.calls.map(c => ({ type: 'tool_use' as const, id: c.id, name: c.name, input: c.arguments })),
        ...turn.rejectedCalls.map(c => ({ type: 'rejected_tool_call' as const, ...c })),
    ];
    const textSlots = Math.max(0, 128 - evidence.length);
    const blocks: TranscriptBlock[] = [];
    let length = 0;
    let partial = false;
    for (const text of turn.text) {
        const allowed = blocks.length < textSlots ? Math.min(20000, 100000 - length) : 0;
        if (text.length > allowed) partial = true;
        const clipped = text.slice(0, allowed);
        length += clipped.length;
        if (clipped) blocks.push({ type: 'text', text: clipped });
    }
    blocks.push(...evidence);
    return { turn: { role: 'assistant', content: blocks }, partial };
}
