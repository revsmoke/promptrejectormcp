import { z } from 'zod';
import { callMetaSchema, usageSchema, reportVersionSchema } from '../ai/schemas.js';
import { monitorReportSchema } from '../ai/taskSchemas.js';
const block = z.discriminatedUnion('type', [
    z.strictObject({ type: z.literal('text'), text: z.string().max(20000) }),
    z.strictObject({ type: z.literal('tool_use'), id: z.string().max(200), name: z.string().max(200), input: z.record(z.string(), z.unknown()) }),
    z.strictObject({ type: z.literal('rejected_tool_call'), idOrNull: z.string().max(200).nullable(), nameOrNull: z.string().max(200).nullable(), reason: z.string(), argumentExcerpt: z.string().max(2000) }),
    z.strictObject({ type: z.literal('tool_result'), tool_use_id: z.string().max(200), content: z.string().max(100000), is_error: z.boolean() }),
]);
export const tasterInputSchema = z.strictObject({ prompt: z.string().min(1).max(100000), context: z.string().max(100000).optional(), mode: z.enum(['fast', 'thorough']).optional(), reportVersion: reportVersionSchema.optional() });
export const tasterReportSchema = z.strictObject({
    schemaVersion: z.literal(2), task: z.literal('taster'), runId: z.string(), available: z.boolean(), reason: z.string().nullable(),
    behaviorReport: monitorReportSchema.extend({ monitorVerdict: z.enum(['clean', 'suspicious', 'malicious', 'undetermined']) }),
    coverage: z.strictObject({ taster: z.enum(['complete', 'partial', 'unavailable', 'not_requested']), monitor: z.enum(['complete', 'unavailable', 'not_requested']) }),
    tasterTranscript: z.array(z.strictObject({ role: z.enum(['user', 'assistant', 'tool']), content: z.union([z.string().max(200050), z.array(block).max(128)]) })).max(11),
    tasterCalls: z.array(callMetaSchema).max(5), monitorMeta: callMetaSchema.nullable(),
    routing: z.array(z.strictObject({ role: z.enum(['taster', 'monitor']), provider: z.enum(['gemini', 'anthropic', 'openai']), model: z.string(), profileHash: z.string(), status: z.enum(['attempted', 'skipped']), reason: z.string() })),
    configHash: z.string(), policyVersion: z.literal('taster-v2.1'),
    timings: z.strictObject({ tasterMs: z.number().nonnegative(), monitorMs: z.number().nonnegative(), totalMs: z.number().nonnegative(), turns: z.number().int().min(0).max(5), truncated: z.boolean() }),
    usage: z.strictObject({ calls: z.number().int().nonnegative(), usage: usageSchema, estimatedUsd: z.number().nonnegative().nullable(), pricingVersions: z.array(z.string()) }),
}).refine(r => r.behaviorReport.monitorVerdict !== 'clean' || (r.coverage.taster === 'complete' && r.coverage.monitor === 'complete'), 'Only complete analysis can be clean');
export type TasterReport = z.infer<typeof tasterReportSchema>;
