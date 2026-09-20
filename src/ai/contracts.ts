import type { AnalysisBudget } from "./budget.js";

export type ReasoningProviderId = "anthropic" | "openai" | "gemini";
export type ProviderId = ReasoningProviderId | "typesafe";
export type GenerativeRole = "semantic" | "patternDraft" | "taster" | "monitor";
export type Role = GenerativeRole | "judgment";
export type AnalysisTask = "prompt" | "skill" | "descriptor" | "capability" | "taster";
export type FailureCode = "not_configured" | "unsupported" | "authentication" | "rate_limited" |
    "timeout" | "cancelled" | "transport" | "invalid_response" | "refusal" | "incomplete" |
    "context_limit" | "budget_exceeded";
export type Severity = "low" | "medium" | "high" | "critical";
export interface Usage {
    inputTokens: number | null;
    outputTokens: number | null;
    cachedReadTokens: number | null;
    cacheWriteTokens: number | null;
    reasoningTokens: number | null;
    /** Whether reasoning tokens are already included in outputTokens. */
    reasoningIsOutputSubset: boolean;
    /** Whether cached reads and writes are included in inputTokens. */
    cachedReadIsInputSubset: boolean;
    cacheWriteIsInputSubset: boolean;
}
export interface CallMeta {
    callId: string;
    provider: ProviderId;
    requestedModel: string;
    resolvedModel: string | null;
    profileHash: string;
    rubricVersion: string;
    schemaVersion: string;
    elapsedMs: number;
    attempts: number;
    usage: Usage;
    failureCode: FailureCode | null;
}
export type CallResult<T> = { status: "ok"; value: T; meta: CallMeta } |
    { status: "unavailable"; code: FailureCode; meta: CallMeta };
export interface ModelProfile {
    readonly provider: ReasoningProviderId;
    readonly model: string;
    readonly maxOutputTokens: number;
    readonly options?: Readonly<Record<string, unknown>>;
}
export interface CallContext {
    /** Internal operation identity/progress; never populated from scan input. */
    readonly callId?: string;
    readonly onAttempt?: () => void;
    readonly signal?: AbortSignal;
    readonly deadlineMs: number;
    readonly runId: string;
    readonly role: Role;
    readonly configHash: string;
    readonly budget: AnalysisBudget;
    readonly optional?: boolean;
    readonly routing?: RoutingEntry[];
}
export interface RoutingEntry { role: Role; provider: ProviderId; model: string; profileHash: string; status: "attempted" | "skipped"; reason: string }
export interface StructuredRequest<T> {
    profile: ModelProfile;
    systemInstruction: string;
    state: string;
    schemaId: string;
    schemaVersion: string;
    rubricVersion: string;
    jsonSchema: Record<string, unknown>;
    parse(value: unknown): T;
    maxOutputTokens: number;
}
export interface StructuredReasoner {
    generate<T>(request: StructuredRequest<T>, call: CallContext): Promise<CallResult<T>>;
}
export type JudgmentInstructions = string | Record<string, unknown>;
export type JudgmentQuestion = { type: "noul"; instructions: JudgmentInstructions; criteria: { true: string; false: string } } |
    { type: "choice"; instructions: JudgmentInstructions; criteria: Record<string, string> };
export interface JudgmentRequest {
    model: string;
    state: string;
    questions: Record<string, JudgmentQuestion>;
    rubricVersion: string;
    schemaVersion: string;
}
export type JudgmentAnswer = { type: "noul"; noul: number } |
    { type: "choice"; choice: string; probabilities: Record<string, number>; confidence: number };
export type JudgmentAnswers = Record<string, JudgmentAnswer>;
export interface JudgmentProvider {
    evaluate(request: JudgmentRequest, call: CallContext): Promise<CallResult<JudgmentAnswers>>;
}
declare const sessionBrand: unique symbol;
export type ToolSessionHandle = string & { readonly [sessionBrand]: true };
export interface ToolDefinition {
    name: string;
    description: string;
    inputSchema: Record<string, unknown>;
    parse(value: unknown): Record<string, unknown>;
}
export interface ToolSessionRequest {
    profile: ModelProfile;
    systemInstruction: string;
    userContent: string;
    tools: readonly ToolDefinition[];
    maxCallsPerTurn: number;
}
export interface ToolTurn {
    session: ToolSessionHandle;
    text: string[];
    calls: Array<{ id: string; name: string; arguments: Record<string, unknown> }>;
    rejectedCalls: Array<{ idOrNull: string | null; nameOrNull: string | null; reason: string; argumentExcerpt: string }>;
    completeness: "complete" | "partial";
    finish: "stop" | "tool_calls" | "refusal" | "length" | "error";
}
export interface ToolResult { id: string; output: string; isError: boolean }
export interface ToolConversationProvider {
    start(request: ToolSessionRequest, call: CallContext): Promise<CallResult<ToolTurn>>;
    resume(session: ToolSessionHandle, results: ToolResult[], call: CallContext): Promise<CallResult<ToolTurn>>;
    dispose(session: ToolSessionHandle): void;
}
