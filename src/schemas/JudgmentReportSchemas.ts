import { z } from "zod";
import { callResultSchema } from "../ai/schemas.js";
import type { CoverageEntry } from "../services/AnalysisCoverage.js";
import type { JudgmentObservation } from "../services/JudgmentService.js";
import type { RoutingEntry } from "../ai/contracts.js";
import { hashConfiguration } from "../ai/modelProfiles.js";

const unit = z.number().finite().min(0).max(1);
export const judgmentAnswerSchema = z.discriminatedUnion("type", [
    z.strictObject({ type: z.literal("noul"), noul: unit }),
    z.strictObject({ type: z.literal("choice"), choice: z.string(), probabilities: z.record(z.string(), unit), confidence: unit }),
]);
export const judgmentObservationSchema = z.strictObject({
    mode: z.enum(["off", "shadow", "enforce", "cascade"]), cache: z.enum(["disabled", "miss", "hit", "shared"]),
    ageMs: z.number().finite().nonnegative(), sourceHash: z.string(),
    completion: z.enum(["completed", "waiter_timed_out", "waiter_cancelled", "not_requested"]),
    coverage: z.enum(["complete", "partial", "unavailable", "not_requested"]),
    result: callResultSchema(z.record(z.string(), judgmentAnswerSchema)).nullable(),
});
export const descriptorEvidenceSchema = z.strictObject({ id: z.string(), path: z.string(), pointer: z.string(), text: z.string() });
export const routingSchema = z.array(z.strictObject({ role: z.enum(["semantic", "patternDraft", "taster", "monitor", "judgment"]), provider: z.enum(["gemini", "anthropic", "openai", "typesafe"]), model: z.string(), profileHash: z.string(), status: z.enum(["attempted", "skipped"]), reason: z.string() }));
export function judgmentRouting(observation: JudgmentObservation, model: string): RoutingEntry {
    const result = observation.result;
    const cached = observation.cache === "hit" || observation.cache === "shared";
    return { role: "judgment", provider: "typesafe", model, profileHash: result?.meta.profileHash ?? hashConfiguration({ provider: "typesafe", model }),
        status: !cached && (result?.meta.attempts ?? 0) > 0 ? "attempted" : "skipped",
        reason: cached ? `cache_${observation.cache}` : result?.status === "unavailable" ? result.code : observation.mode === "off" ? "mode_off" : "shadow_observation" };
}
export function judgmentCoverage(check: string, observation: JudgmentObservation, characters: number, fields: number): CoverageEntry {
    const result = observation.result;
    return { check, required: observation.mode === "enforce" || observation.mode === "cascade", status: observation.coverage,
        reason: result?.status === "unavailable" ? result.code : null,
        inspectedCharacters: result?.status === "ok" ? characters : 0, inspectedFields: result?.status === "ok" ? fields : 0,
        scope: "full_input", provider: result ? "typesafe" : null, model: result ? result.meta.resolvedModel ?? result.meta.requestedModel : null,
        rubricVersion: result?.meta.rubricVersion ?? null };
}
