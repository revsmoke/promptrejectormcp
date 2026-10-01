import { z } from "zod";
import type { Services } from "../bootstrap.js";
import { promptInputSchema, skillInputSchema, isSizeError } from "../ai/schemas.js";
import { descriptorFields, DescriptorLimitError } from "../ai/rubrics/descriptor.js";
import { capabilityInputSchema } from "../services/CapabilityAnalysisService.js";
import { tasterInputSchema } from "../schemas/TasterReportSchema.js";
import { serviceHealth } from "../api/health.js";
import { PromptRejectorError } from "./errors.js";

export const operationSchemas = {
    "check-prompt": promptInputSchema,
    "scan-skill": skillInputSchema,
    "scan-mcp-tool": z.strictObject({ tool: z.record(z.string(), z.unknown()), priorHash: z.string().max(128).optional() }),
    "check-lethal-trifecta": capabilityInputSchema.refine(input => Object.keys(input).length > 0),
    "taste-test": tasterInputSchema.omit({ reportVersion: true }),
    "list-patterns": z.strictObject({ category: z.string().optional(), scope: z.enum(["general", "skill"]).optional(), enabled: z.boolean().optional() }),
    "update-vuln-feeds": z.strictObject({ lookbackDays: z.number().int().min(1).max(365).optional() }),
    "verify-pattern-integrity": z.strictObject({}),
    "query-cve": z.strictObject({ keyword: z.string().optional(), ecosystem: z.string().optional(), atlasTechnique: z.string().optional(), severity: z.enum(["low", "medium", "high", "critical"]).optional(), inKev: z.boolean().optional(), limit: z.number().int().min(1).max(200).optional() }),
    "deploy-canary": z.strictObject({ context: z.string().max(1000).optional(), ttlSeconds: z.number().int().min(1).max(2592000).optional() }),
    "verify-canary": z.strictObject({ content: z.string().min(1).max(500000), watchHandle: z.string().regex(/^[a-f0-9]{12}$/i).optional() }),
    health: z.strictObject({}),
} as const;

export type Command = keyof typeof operationSchemas;
export type CommandInput<C extends Command> = z.infer<(typeof operationSchemas)[C]>;
export const commandNames = Object.freeze(Object.keys(operationSchemas) as Command[]);

export function normalizeCommand(name: string): Command {
    const command = name.replace(/_/g, "-");
    if (!Object.prototype.hasOwnProperty.call(operationSchemas, command)) throw new PromptRejectorError("unknown_command");
    return command as Command;
}

/** Validate every boundary before invoking services, including JavaScript callers. */
export function validateInput<C extends Command>(command: C, input: unknown): CommandInput<C> {
    try {
        const parsed = operationSchemas[command].parse(input);
        if (command === "scan-mcp-tool") descriptorFields((parsed as CommandInput<"scan-mcp-tool">).tool);
        return parsed as CommandInput<C>;
    } catch (error) {
        if (error instanceof DescriptorLimitError) throw new PromptRejectorError(error.limit === "json" ? "invalid_input" : "input_too_large");
        throw new PromptRejectorError(error instanceof z.ZodError && isSizeError(error) ? "input_too_large" : "invalid_input");
    }
}

export function operationHandlers(services: Services) {
    return {
        "check-prompt": (input: CommandInput<"check-prompt">, signal?: AbortSignal) => services.securityService.runSecurityScanV2(input.prompt, { signal }),
        "scan-skill": (input: CommandInput<"scan-skill">, signal?: AbortSignal) => services.skillScanService.scanSkillV2(input.skillContent, { signal }),
        "scan-mcp-tool": (input: CommandInput<"scan-mcp-tool">, signal?: AbortSignal) => services.descriptorAnalysis.analyze(input, { signal }),
        "check-lethal-trifecta": (input: CommandInput<"check-lethal-trifecta">, signal?: AbortSignal) => services.capabilityAnalysis.analyze(input, { signal }),
        "taste-test": (input: CommandInput<"taste-test">, signal?: AbortSignal) => services.tasteTesterService.runV2(input, { signal }),
        "list-patterns": (input: CommandInput<"list-patterns">) => { const patterns = services.patternService.list(input); return { count: patterns.length, patterns }; },
        "update-vuln-feeds": (input: CommandInput<"update-vuln-feeds">) => services.vulnFeedService.updateFeeds(input.lookbackDays),
        "verify-pattern-integrity": (_input: CommandInput<"verify-pattern-integrity">) => services.patternService.verify(),
        "query-cve": (input: CommandInput<"query-cve">) => services.unifiedCveCache.query(input),
        "deploy-canary": (input: CommandInput<"deploy-canary">) => services.canaryService.issueToken(input),
        "verify-canary": (input: CommandInput<"verify-canary">) => services.canaryService.checkEcho(input.content, input.watchHandle),
        health: (_input: CommandInput<"health">) => serviceHealth(services),
    };
}
export type CommandResult<C extends Command> = Awaited<ReturnType<ReturnType<typeof operationHandlers>[C]>>;

/** Unknown/missing scan decisions fail closed. Non-scan successes mean only that operation completed. */
export function resultExitCode(command: Command, result: unknown): 0 | 1 | 3 {
    const report = result as Record<string, any> | null;
    if (!report || typeof report !== "object") return 3;
    if (["check-prompt", "scan-skill", "scan-mcp-tool", "check-lethal-trifecta"].includes(command)) {
        if (report.decision === "block" || report.decision === "review") return 1;
        return report.decision === "allow" && report.safe === true ? 0 : 3;
    }
    if (command === "taste-test") {
        if (!report.available || report.coverage?.taster !== "complete" || report.coverage?.monitor !== "complete") return 3;
        return report.behaviorReport?.monitorVerdict === "clean" ? 0 : ["suspicious", "malicious"].includes(report.behaviorReport?.monitorVerdict) ? 1 : 3;
    }
    if (command === "verify-pattern-integrity") return report.valid === true ? 0 : 1;
    if (command === "verify-canary") return report.echoDetected === false ? 0 : report.echoDetected === true ? 1 : 3;
    if (command === "update-vuln-feeds") return Array.isArray(report.errors) && report.errors.length === 0 ? 0 : 3;
    if (command === "health") return report.typesafe?.readiness === "degraded" || Object.values(report.roles ?? {}).some((role: any) => role.readiness === "degraded") ? 3 : 0;
    return 0;
}
