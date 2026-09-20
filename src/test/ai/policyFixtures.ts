import { randomUUID } from "node:crypto";
import { loadAIConfig } from "../../ai/config.js";
import { createCandidateSnapshot } from "../../evaluation/candidateConfig.js";
import { PatternService } from "../../services/PatternService.js";
import { ProviderRegistry } from "../../ai/registry.js";
import { SemanticAnalysisService } from "../../services/SemanticAnalysisService.js";
import { JudgmentService } from "../../services/JudgmentService.js";
import { emptyUsage } from "../../ai/usage.js";
import { profileHash } from "../../ai/modelProfiles.js";
import type { FailureCode, JudgmentAnswers } from "../../ai/contracts.js";
import { benignFinding } from "./fixtures.js";
export function policyFixture(options: { modes?: Record<string, string>; answers?: JudgmentAnswers; result?: unknown; resultFor?: (state: any) => unknown; reasonAttempts?: number; failure?: FailureCode; resolvedModel?: string; onReason?: (state: any) => void; onJudgment?: () => void } = {}) {
    const patterns = new PatternService();
    const base = loadAIConfig({});
    const model = "claude-opus-4-7";
    const snapshot = createCandidateSnapshot({ ...base.config, roles: { ...base.config.roles, semantic: { primary: "legacy-anthropic" } },
        modelResolutions: { "legacy-anthropic": { kind: "pinned", method: "synthetic fixture", configuredModel: model, resolvedModel: model } },
        typesafe: { ...base.config.typesafe, ...options.modes } }, { patternService: patterns });
    const registry = new ProviderRegistry(snapshot, { env: {} });
    const calls = { reason: 0, judgment: 0, totalAttempts: 0 };
    registry.register("anthropic", { async generate(request, context) {
        calls.reason++;
        options.onReason?.(JSON.parse(request.state));
        let reservation = context.budget.reserveAttempt();
        for (let i = 1; reservation.ok && i < (options.reasonAttempts ?? 1); i++) reservation = context.budget.reserveAttempt();
        calls.totalAttempts = context.budget.attempts;
        const code = !reservation.ok ? reservation.code : options.failure;
        const meta = { callId: randomUUID(), provider: "anthropic" as const, requestedModel: model, resolvedModel: options.resolvedModel ?? model, profileHash: profileHash(request.profile), rubricVersion: request.rubricVersion, schemaVersion: request.schemaVersion, elapsedMs: 0, attempts: reservation.ok ? 1 : 0, usage: emptyUsage(), failureCode: code ?? null };
        if (code) return { status: "unavailable", code, meta };
        try { return { status: "ok", value: request.parse(options.resultFor?.(JSON.parse(request.state)) ?? options.result ?? benignFinding), meta }; }
        catch { return { status: "unavailable", code: "invalid_response", meta: { ...meta, failureCode: "invalid_response" } }; }
    } });
    const semantic = new SemanticAnalysisService(snapshot, registry);
    const judgments = new JudgmentService(snapshot, { apiKey: "fixture", fetch: async (_url, init) => {
        calls.judgment++; options.onJudgment?.();
        const request = JSON.parse(String(init?.body));
        const answers = Object.fromEntries(Object.entries(request.questions).map(([id, question]: [string, any]) => [id, options.answers?.[id] ?? (question.type === "choice" ? { type: "choice", choice: "none", confidence: 1, probabilities: Object.fromEntries(Object.keys(question.criteria).map((key) => [key, key === "none" ? 1 : 0])) } : { type: "noul", noul: .01 })]));
        return new Response(JSON.stringify({ model: "jev-1.13.0", answers, usage: { input_tokens: 5, output_tokens: 5 } }));
    } });
    return { patterns, snapshot, semantic, judgments, calls };
}
export const unknownCapability = { completeDeclaredScope: false, restrictionEvidenceIds: [], privateDataRead: { state: "unknown", evidenceIds: [] }, untrustedContentFetch: { state: "unknown", evidenceIds: [] }, externalEgress: { state: "unknown", evidenceIds: [] }, explanation: "Scope is unspecified." };
