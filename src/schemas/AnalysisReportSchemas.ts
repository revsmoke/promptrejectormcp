import { z } from "zod";
import { callResultSchema, severitySchema, usageSchema } from "../ai/schemas.js";
import { semanticFindingSchema } from "../ai/taskSchemas.js";

export const coverageSchema = z.strictObject({
    check: z.string().min(1), required: z.boolean(), status: z.enum(["complete", "partial", "unavailable", "not_requested"]),
    reason: z.string().nullable(), inspectedCharacters: z.number().int().nonnegative(), inspectedFields: z.number().int().nonnegative(),
    scope: z.enum(["local", "full_input", "declared", "external"]), provider: z.enum(["gemini", "anthropic", "openai", "typesafe"]).nullable(),
    model: z.string().nullable(), rubricVersion: z.string().nullable(),
});
const staticSchema = z.strictObject({
    hasXSS: z.boolean(), hasSQLi: z.boolean(), hasShellInjection: z.boolean(), hasObfuscation: z.boolean(), hasPolicyPuppetry: z.boolean(),
    hasMarkdownExfil: z.boolean(), hasPromptInjection: z.boolean(), hasManyShot: z.boolean(), severity: severitySchema,
    categories: z.array(z.string()), findings: z.array(z.string()), atlasTechniques: z.array(z.string()),
    strippedChars: z.array(z.strictObject({ index: z.number().int().nonnegative(), codePoint: z.string(), class: z.enum(["tag", "zero-width", "bidi"]) })).optional(),
});
const base = {
    schemaVersion: z.literal(2), decision: z.enum(["allow", "block", "review", "unavailable"]), safe: z.boolean(),
    overallSeverity: severitySchema, categories: z.array(z.string()), findings: z.array(z.string()), atlasTechniques: z.array(z.string()),
    timestamp: z.string(), coverage: z.array(coverageSchema), semantic: callResultSchema(semanticFindingSchema),
    judgments: z.null(), analysisMode: z.enum(["off", "shadow", "enforce", "cascade"]), policyVersion: z.string(), configHash: z.string(),
    routing: z.array(z.strictObject({ role: z.enum(["semantic", "patternDraft", "taster", "monitor", "judgment"]), provider: z.enum(["gemini", "anthropic", "openai", "typesafe"]), model: z.string(), profileHash: z.string(), status: z.enum(["attempted", "skipped"]), reason: z.string() })),
    timings: z.strictObject({ totalMs: z.number().finite().nonnegative() }),
    usage: z.strictObject({ calls: z.number().int().nonnegative(), usage: usageSchema, estimatedUsd: z.number().finite().nonnegative().nullable(), pricingVersions: z.array(z.string()) }),
    static: staticSchema,
};
export const promptAnalysisReportSchema = z.strictObject({ ...base, task: z.literal("prompt") }).refine((report) => report.safe === (report.decision === "allow"), "safe must exactly match allow");
const skillSpecific = z.strictObject({ hasHiddenInstructions: z.boolean(), hasDangerousToolUsage: z.boolean(), hasSensitiveFileAccess: z.boolean(), hasObfuscation: z.boolean(), hasSocialEngineering: z.boolean(), hasNetworkExfiltration: z.boolean(), findings: z.array(z.string()), severity: severitySchema, categories: z.array(z.string()) });
const bucket = z.strictObject({ present: z.boolean(), evidence: z.array(z.strictObject({ source: z.enum(["capability", "tool", "skill-content"]), match: z.string(), pattern: z.string() })) });
const trifecta = z.strictObject({ privateDataRead: bucket, untrustedContentFetch: bucket, externalEgress: bucket, trifectaPresent: z.boolean(), severity: z.enum(["safe", "medium", "critical"]), recommendation: z.string() });
const hfFlag = z.strictObject({ class: z.enum(["unsafe_serialization", "code_execution_risk", "scanner_warning", "gated", "no_safetensors", "lookup_failed"]), note: z.string(), rawField: z.string().optional() });
const hfReport = z.strictObject({ modelId: z.string(), fetchedAt: z.string(), flags: z.array(hfFlag), severity: z.enum(["safe", "low", "medium", "high", "critical"]) });
export const skillAnalysisReportSchema = z.strictObject({ ...base, task: z.literal("skill"), skillSpecific, trifectaResult: trifecta, hasLethalTrifecta: z.boolean(), huggingFaceSecurityFlags: z.array(hfFlag), huggingFaceReports: z.array(hfReport) }).refine((report) => report.safe === (report.decision === "allow"), "safe must exactly match allow");
export type PromptAnalysisReport = z.infer<typeof promptAnalysisReportSchema>;
export type SkillAnalysisReport = z.infer<typeof skillAnalysisReportSchema>;
