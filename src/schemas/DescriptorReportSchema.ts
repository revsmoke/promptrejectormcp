import { z } from "zod";
import { callResultSchema, severitySchema, usageSchema } from "../ai/schemas.js";
import { sourcedSemanticReportSchema } from "../ai/taskSchemas.js";
import { coverageSchema } from "./AnalysisReportSchemas.js";
import { descriptorEvidenceSchema, judgmentObservationSchema, routingSchema } from "./JudgmentReportSchemas.js";
const localSchema = z.strictObject({ hash: z.string(), drift: z.boolean(), severity: z.enum(["safe", "low", "medium", "high", "critical"]), inspectedFields: z.array(z.string()),
    findings: z.array(z.strictObject({ field: z.string(), category: z.string(), severity: severitySchema, patternId: z.string().optional(), excerpt: z.string(), note: z.string().optional() })) });
export const descriptorReportSchema = z.strictObject({
    schemaVersion: z.literal(2), task: z.literal("descriptor"), decision: z.enum(["allow", "block", "review", "unavailable"]), safe: z.boolean(),
    overallSeverity: severitySchema, categories: z.array(z.string()), findings: z.array(z.string()), local: localSchema,
    timestamp: z.string(), coverage: z.array(coverageSchema), judgments: judgmentObservationSchema.nullable(),
    semantic: callResultSchema(sourcedSemanticReportSchema).nullable().optional(), evidence: descriptorEvidenceSchema.nullable().optional(),
    shadow: z.strictObject({ judgments: judgmentObservationSchema, evidence: descriptorEvidenceSchema.nullable() }).nullable(),
    analysisMode: z.enum(["off", "shadow", "enforce", "cascade"]), policyVersion: z.string(), configHash: z.string(),
    routing: routingSchema,
    timings: z.strictObject({ totalMs: z.number().finite().nonnegative() }),
    usage: z.strictObject({ calls: z.number().int().nonnegative(), usage: usageSchema, estimatedUsd: z.number().finite().nonnegative().nullable(), pricingVersions: z.array(z.string()) }),
}).refine((report) => report.safe === (report.decision === "allow"), "safe must exactly match allow");
export type DescriptorReport = z.infer<typeof descriptorReportSchema>;
