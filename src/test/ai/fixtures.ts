import { randomUUID } from "node:crypto";
import { loadAIConfig, type ConfigSnapshot } from "../../ai/config.js";
import { ProviderRegistry } from "../../ai/registry.js";
import { profileHash } from "../../ai/modelProfiles.js";
import { emptyUsage } from "../../ai/usage.js";
import { SemanticAnalysisService } from "../../services/SemanticAnalysisService.js";
import type { SemanticFinding } from "../../ai/taskSchemas.js";
import type { FailureCode } from "../../ai/contracts.js";

export const benignFinding: SemanticFinding = { verdict: "benign", severity: "low", categories: [], explanation: "A harmless analysis request.", evidenceIds: [], isInjection: false, selfReportedConfidence: 0.9 };
export function fixtureSemantic(options: { snapshot?: ConfigSnapshot; finding?: SemanticFinding; unavailable?: FailureCode; called?: () => void } = {}) {
    const snapshot = options.snapshot ?? loadAIConfig({});
    const registry = new ProviderRegistry(snapshot, { env: {} });
    for (const provider of ["gemini", "openai", "anthropic"] as const) registry.register(provider, {
        async generate(request, call) {
            options.called?.();
            const meta = { callId: randomUUID(), provider, requestedModel: request.profile.model, resolvedModel: null,
                profileHash: profileHash(request.profile), rubricVersion: request.rubricVersion, schemaVersion: request.schemaVersion,
                elapsedMs: 0, attempts: 1, usage: emptyUsage(), failureCode: options.unavailable ?? null };
            if (options.unavailable) return { status: "unavailable", code: options.unavailable, meta };
            const value = request.parse(options.finding ?? benignFinding);
            call.budget.usage.record(meta.callId, meta.usage);
            return { status: "ok", value, meta };
        },
    });
    return new SemanticAnalysisService(snapshot, registry);
}
