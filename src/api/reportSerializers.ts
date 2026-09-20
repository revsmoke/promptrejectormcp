import type { Services } from "../bootstrap.js";
import { mcpPromptInputSchema, mcpSkillInputSchema, isSizeError } from "../ai/schemas.js";
import { ReportVersionRequiredError } from "../services/SecurityService.js";

export async function scanPromptReport(services: Pick<Services, "securityService">, prompt: string, version: 1 | 2, signal?: AbortSignal) {
    if (version === 1 && !services.securityService.supportsV1) throw new ReportVersionRequiredError();
    return version === 1 ? services.securityService.runSecurityScan(prompt, { signal }) : services.securityService.runSecurityScanV2(prompt, { signal });
}
export async function scanSkillReport(services: Pick<Services, "skillScanService">, content: string, version: 1 | 2, signal?: AbortSignal) {
    if (version === 1 && !services.skillScanService.supportsV1) throw new ReportVersionRequiredError();
    return version === 1 ? services.skillScanService.scanSkill(content, { signal }) : services.skillScanService.scanSkillV2(content, { signal });
}
export async function handleMcpScan(services: Services, name: "check_prompt" | "scan_skill", args: unknown, signal?: AbortSignal) {
    const parsed = name === "check_prompt" ? mcpPromptInputSchema.safeParse(args) : mcpSkillInputSchema.safeParse(args);
    if (!parsed.success) return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ error: isSizeError(parsed.error) ? "input_too_large" : "invalid_input" }) }] };
    try {
        const input = parsed.data;
        const report = "prompt" in input ? await scanPromptReport(services, input.prompt, input.reportVersion ?? services.snapshot.config.mcpDefaultReportVersion, signal)
            : await scanSkillReport(services, input.skillContent, input.reportVersion ?? services.snapshot.config.mcpDefaultReportVersion, signal);
        return { content: [{ type: "text" as const, text: JSON.stringify(report) }] };
    } catch (error) {
        const code = error instanceof ReportVersionRequiredError ? error.code : "internal_error";
        return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ error: code, ...(code === "report_version_required" ? { reportVersion: 2 } : {}) }) }] };
    }
}
