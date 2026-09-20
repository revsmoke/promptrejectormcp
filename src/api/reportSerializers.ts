import type { Services } from "../bootstrap.js";
import { mcpPromptInputSchema, mcpSkillInputSchema, isSizeError } from "../ai/schemas.js";

export async function scanPromptReport(services: Pick<Services, "securityService">, prompt: string, signal?: AbortSignal) {
    return services.securityService.runSecurityScanV2(prompt, { signal });
}
export async function scanSkillReport(services: Pick<Services, "skillScanService">, content: string, signal?: AbortSignal) {
    return services.skillScanService.scanSkillV2(content, { signal });
}
export async function handleMcpScan(services: Services, name: "check_prompt" | "scan_skill", args: unknown, signal?: AbortSignal) {
    const parsed = name === "check_prompt" ? mcpPromptInputSchema.safeParse(args) : mcpSkillInputSchema.safeParse(args);
    if (!parsed.success) return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ error: isSizeError(parsed.error) ? "input_too_large" : "invalid_input" }) }] };
    try {
        const input = parsed.data;
        const report = "prompt" in input ? await scanPromptReport(services, input.prompt, signal)
            : await scanSkillReport(services, input.skillContent, signal);
        return { content: [{ type: "text" as const, text: JSON.stringify(report) }] };
    } catch {
        return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ error: "internal_error" }) }] };
    }
}
