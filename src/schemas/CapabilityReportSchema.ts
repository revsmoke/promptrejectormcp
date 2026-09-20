import { z } from "zod";
import { callResultSchema, severitySchema, usageSchema } from "../ai/schemas.js";
import { capabilityAssessmentSchema } from "../ai/taskSchemas.js";
import { capabilityStatesSchema, coverageSchema, trifecta } from "./AnalysisReportSchemas.js";
import { judgmentObservationSchema, routingSchema } from "./JudgmentReportSchemas.js";
export const capabilityReportSchema = z.strictObject({ schemaVersion: z.literal(2), task: z.literal("capability"), safe: z.boolean(), decision: z.enum(["allow", "block", "review", "unavailable"]),
    overallSeverity: severitySchema, categories: z.array(z.string()), findings: z.array(z.string()), local: trifecta, buckets: capabilityStatesSchema,
    judgments: judgmentObservationSchema.nullable(), shadow: z.strictObject({ judgments: judgmentObservationSchema, buckets: capabilityStatesSchema }).nullable(),
    semantic: callResultSchema(capabilityAssessmentSchema(["skillContent", ...Array.from({ length: 512 }, (_, i) => `tools:${i}`), ...Array.from({ length: 512 }, (_, i) => `capabilities:${i}`)])).nullable().optional(),
    coverage: z.array(coverageSchema), timestamp: z.string(), analysisMode: z.enum(["off", "shadow", "enforce", "cascade"]), policyVersion: z.string(), configHash: z.string(), routing: routingSchema,
    timings: z.strictObject({ totalMs: z.number().finite().nonnegative() }),
    usage: z.strictObject({ calls: z.number().int().nonnegative(), usage: usageSchema, estimatedUsd: z.number().finite().nonnegative().nullable(), pricingVersions: z.array(z.string()) }),
}).refine((report) => report.safe === (report.decision === "allow"), "safe must exactly match allow");
