import { z } from "zod";
import type { Services } from "../bootstrap.js";
import { reportVersionSchema, isSizeError } from "../ai/schemas.js";
import { DescriptorLimitError, descriptorFields } from "../ai/rubrics/descriptor.js";
import { capabilityInputSchema } from "../services/CapabilityAnalysisService.js";
const descriptorInput = z.strictObject({ tool: z.record(z.string(), z.unknown()), priorHash: z.string().max(128).optional(), reportVersion: reportVersionSchema.optional() });
const capabilityInput = z.strictObject({ tools: z.array(z.string()).optional(), capabilities: z.array(z.string()).optional(), skillContent: z.string().optional(), reportVersion: reportVersionSchema.optional() });
export async function handleMcpJudgment(services: Services, name: "scan_mcp_tool" | "check_lethal_trifecta", args: unknown, signal?: AbortSignal) {
    try {
        let report: unknown;
        if (name === "scan_mcp_tool") {
            const input = descriptorInput.parse(args);
            descriptorFields(input.tool);
            report = await services.descriptorAnalysis.analyze(input, { signal });
        } else {
            const { reportVersion, ...input } = capabilityInput.parse(args);
            if (!Object.keys(input).length) throw new z.ZodError([{ code: "custom", path: [], message: "Missing source" }]);
            const source = capabilityInputSchema.parse(input);
            report = await services.capabilityAnalysis.analyze(source, { signal });
        }
        return { content: [{ type: "text" as const, text: JSON.stringify(report) }] };
    } catch (error) {
        const code = error instanceof DescriptorLimitError ? error.limit === "json" ? "invalid_input" : "input_too_large"
            : error instanceof z.ZodError ? isSizeError(error) ? "input_too_large" : "invalid_input" : "analysis_unavailable";
        return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ error: code }) }] };
    }
}
