import { GeminiService, GeminiCheckResult } from "./GeminiService.js";
import { StaticCheckService } from "./StaticCheckService.js";
import type { PatternService, ActivePattern } from "./PatternService.js";

export interface SkillScanResult {
    safe: boolean;
    geminiConfidence: number; // Confidence score from LLM analysis only
    overallSeverity: "low" | "medium" | "high" | "critical";
    categories: string[];
    skillSpecific: SkillSpecificFindings;
    gemini: GeminiCheckResult;
    static: {
        hasXSS: boolean;
        hasSQLi: boolean;
        hasShellInjection: boolean;
        severity: "low" | "medium" | "high" | "critical";
        categories: string[];
        findings: string[];
    };
    timestamp: string;
}

export interface SkillSpecificFindings {
    hasHiddenInstructions: boolean;
    hasDangerousToolUsage: boolean;
    hasSensitiveFileAccess: boolean;
    hasObfuscation: boolean;
    hasSocialEngineering: boolean;
    hasNetworkExfiltration: boolean;
    findings: string[];
    severity: "low" | "medium" | "high" | "critical";
    categories: string[];
}

const SEVERITIES: readonly ("low" | "medium" | "high" | "critical")[] = ["low", "medium", "high", "critical"];

function severityIdx(s: string): number {
    return SEVERITIES.indexOf(s as any);
}

export class SkillScanService {
    private geminiService: GeminiService;
    private staticCheckService: StaticCheckService;
    private patternService: PatternService | null;

    constructor(patternService?: PatternService) {
        this.patternService = patternService ?? null;
        this.geminiService = new GeminiService();
        this.staticCheckService = new StaticCheckService(patternService);
    }

    async scanSkill(skillContent: string): Promise<SkillScanResult> {
        const [geminiResult, staticResult, skillSpecificResult] = await Promise.all([
            this.geminiService.checkPrompt(skillContent),
            Promise.resolve(this.staticCheckService.check(skillContent)),
            Promise.resolve(this.runSkillSpecificChecks(skillContent))
        ]);

        // Aggregate severity
        const geminiSevIdx = SEVERITIES.indexOf(geminiResult.severity);
        const staticSevIdx = SEVERITIES.indexOf(staticResult.severity);
        const skillSevIdx = SEVERITIES.indexOf(skillSpecificResult.severity);
        const overallSeverity = SEVERITIES[Math.max(geminiSevIdx, staticSevIdx, skillSevIdx)];

        // Aggregate categories
        const categories = Array.from(new Set([
            ...geminiResult.categories,
            ...staticResult.categories,
            ...skillSpecificResult.categories
        ]));

        // Decide "safe" status
        const isDangerous =
            overallSeverity === "critical" ||
            overallSeverity === "high" ||
            (geminiResult.isInjection && geminiResult.confidence > 0.6) ||
            skillSpecificResult.hasDangerousToolUsage ||
            skillSpecificResult.hasNetworkExfiltration;

        const safe = !isDangerous;

        return {
            safe,
            geminiConfidence: geminiResult.confidence,
            overallSeverity,
            categories,
            skillSpecific: skillSpecificResult,
            gemini: geminiResult,
            static: staticResult,
            timestamp: new Date().toISOString()
        };
    }

    private runSkillSpecificChecks(content: string): SkillSpecificFindings {
        if (this.patternService) {
            return this.runSkillChecksWithPatternService(content);
        }
        return this.runSkillChecksWithHardcoded(content);
    }

    private runSkillChecksWithPatternService(content: string): SkillSpecificFindings {
        const findings: string[] = [];
        const categories: string[] = [];
        let severity: "low" | "medium" | "high" | "critical" = "low";

        const patterns = this.patternService!.getActivePatterns("skill");

        // Group patterns by flagGroup
        const groups = new Map<string, ActivePattern[]>();
        for (const p of patterns) {
            const group = groups.get(p.entry.flagGroup) || [];
            group.push(p);
            groups.set(p.entry.flagGroup, group);
        }

        const flags: Record<string, boolean> = {
            hasHiddenInstructions: false,
            hasDangerousToolUsage: false,
            hasSensitiveFileAccess: false,
            hasObfuscation: false,
            hasSocialEngineering: false,
            hasNetworkExfiltration: false,
        };

        for (const [flagGroup, groupPatterns] of groups) {
            for (const { entry, regex } of groupPatterns) {
                let triggered = false;

                if (entry.detection.mode === "threshold") {
                    const matches = content.match(regex);
                    if (matches) {
                        const countThreshold = entry.detection.countThreshold;
                        const singleMatchLength = entry.detection.singleMatchLength;

                        const exceedsCount = countThreshold !== undefined && matches.length > countThreshold;
                        const exceedsLength = singleMatchLength !== undefined && matches.some(m => m.length >= singleMatchLength);

                        triggered = exceedsCount || exceedsLength;
                    }
                } else {
                    triggered = regex.test(content);
                }

                if (triggered) {
                    // Build finding message based on flag group
                    if (flagGroup === "hasHiddenInstructions") {
                        findings.push("Hidden instructions detected in HTML comments");
                    } else if (flagGroup === "hasDangerousToolUsage") {
                        findings.push(`Dangerous tool usage detected: ${entry.pattern}`);
                    } else if (flagGroup === "hasSensitiveFileAccess") {
                        findings.push(`Sensitive file access detected: ${entry.pattern}`);
                    } else if (flagGroup === "hasObfuscation") {
                        findings.push("Obfuscation detected: potential encoded content");
                    } else if (flagGroup === "hasSocialEngineering") {
                        findings.push("Social engineering indicators detected");
                    } else if (flagGroup === "hasNetworkExfiltration") {
                        findings.push(`Potential data exfiltration detected: ${entry.pattern}`);
                    }

                    if (!categories.includes(entry.category)) {
                        categories.push(entry.category);
                    }

                    if (severityIdx(entry.severity) > severityIdx(severity)) {
                        severity = entry.severity;
                    }

                    if (flagGroup in flags) {
                        flags[flagGroup] = true;
                    }

                    break; // first match per flag group
                }
            }
        }

        return {
            hasHiddenInstructions: flags.hasHiddenInstructions,
            hasDangerousToolUsage: flags.hasDangerousToolUsage,
            hasSensitiveFileAccess: flags.hasSensitiveFileAccess,
            hasObfuscation: flags.hasObfuscation,
            hasSocialEngineering: flags.hasSocialEngineering,
            hasNetworkExfiltration: flags.hasNetworkExfiltration,
            findings,
            severity,
            categories: Array.from(new Set(categories)),
        };
    }

    private runSkillChecksWithHardcoded(content: string): SkillSpecificFindings {
        const findings: string[] = [];
        const categories: string[] = [];
        let severity: "low" | "medium" | "high" | "critical" = "low";

        // 1. Hidden instructions
        const hiddenInstructionPatterns = [
            /<!--[\s\S]*?(ignore|override|bypass|secret|hidden)[\s\S]*?-->/gi,
            /<!--[\s\S]*?(curl|wget|bash|exec|eval)[\s\S]*?-->/gi,
        ];

        const hasHiddenInstructions = hiddenInstructionPatterns.some(pattern => {
            if (pattern.test(content)) {
                findings.push(`Hidden instructions detected in HTML comments`);
                categories.push("obfuscation");
                if (severity === "low") severity = "medium";
                return true;
            }
            return false;
        });

        // 2. Dangerous tool usage
        const dangerousToolPatterns = [
            /bash.*?(curl|wget)\s+.*?https?:\/\/(?!(?:localhost|127\.0\.0\.1|github\.com|npmjs\.com))/gi,
            /bash.*?(rm\s+-rf|dd\s+if=|mkfs|format)/gi,
            /bash.*?(sudo|su\s+|chmod\s+777|chown)/gi,
            /bash.*?(kill\s+-9|killall|pkill)/gi,
            /(?:^|\s|```)(bash|sh|zsh)?\s*(curl|wget)\s+.*?https?:\/\/(?!(?:localhost|127\.0\.0\.1|github\.com|npmjs\.com))/gim,
            /(?:^|\s|```)(bash|sh|zsh)?\s*(rm\s+-rf|dd\s+if=|mkfs|format)/gim,
            /(?:^|\s|```)(bash|sh|zsh)?\s*(sudo|su\s+|chmod\s+777|chown)/gim,
            /(?:^|\s|```)(bash|sh|zsh)?\s*(kill\s+-9|killall|pkill)/gim,
        ];

        const hasDangerousToolUsage = dangerousToolPatterns.some(pattern => {
            if (pattern.test(content)) {
                findings.push(`Dangerous tool usage detected: ${pattern.source}`);
                categories.push("shell_injection");
                severity = "critical";
                return true;
            }
            return false;
        });

        // 3. Sensitive file access
        const sensitiveFilePatterns = [
            /\/etc\/(passwd|shadow|sudoers)/gi,
            /~?\/.ssh\/(id_rsa|id_ed25519|authorized_keys)/gi,
            /~?\/.aws\/(credentials|config)/gi,
            /(?:^|\/|\\|~\/|\.\/|['"`\s])\.env(?:\.local|\.production|\.development)?(?:$|\s|['"`]|\/)/gim,
            /\.git\/config/gi,
        ];

        const hasSensitiveFileAccess = sensitiveFilePatterns.some(pattern => {
            if (pattern.test(content)) {
                findings.push(`Sensitive file access detected: ${pattern.source}`);
                categories.push("data_exfiltration");
                if (severity !== "critical") severity = "high";
                return true;
            }
            return false;
        });

        // 4. Obfuscation
        const obfuscationPatterns = [
            /[A-Za-z0-9+/]{40,}={0,2}/g,
            /\\x[0-9a-fA-F]{2}/g,
            /\\u[0-9a-fA-F]{4}/g,
            /[\u200B-\u200D\uFEFF]/g,
        ];

        const hasObfuscation = obfuscationPatterns.some(pattern => {
            const matches = content.match(pattern);
            const hasMultipleMatches = matches && matches.length > 5;
            const hasSingleLargeBlob = matches && matches.some(m => m.length >= 200);

            if (hasMultipleMatches || hasSingleLargeBlob) {
                findings.push(`Obfuscation detected: potential encoded content`);
                categories.push("obfuscation");
                if (severity === "low") severity = "medium";
                return true;
            }
            return false;
        });

        // 5. Social engineering
        const socialEngineeringPatterns = [
            /\b(official|urgent|critical|immediate|security update|required|mandatory)\b/gi,
            /\b(from Anthropic|from Claude|from OpenAI|authorized by|approved by)\b/gi,
            /\b(trust me|don't worry|safe to|guaranteed|certified)\b/gi,
        ];

        const hasSocialEngineering = socialEngineeringPatterns.some(pattern => {
            const matches = content.match(pattern);
            if (matches && matches.length > 2) {
                findings.push(`Social engineering indicators detected`);
                categories.push("social_engineering");
                if (severity === "low") severity = "medium";
                return true;
            }
            return false;
        });

        // 6. Network exfiltration
        const exfiltrationPatterns = [
            /https?:\/\/(?!(?:localhost|127\.0\.0\.1|github\.com|npmjs\.com|api\.github\.com))[\w.-]+.*?[\?&](data|key|token|secret|password)=/gi,
            /(curl|wget).*?(-d|--data|--data-binary).*?(key|token|secret|password|env)/gi,
            /nslookup.*?\$\(/gi,
        ];

        const hasNetworkExfiltration = exfiltrationPatterns.some(pattern => {
            if (pattern.test(content)) {
                findings.push(`Potential data exfiltration detected: ${pattern.source}`);
                categories.push("data_exfiltration");
                severity = "critical";
                return true;
            }
            return false;
        });

        return {
            hasHiddenInstructions,
            hasDangerousToolUsage,
            hasSensitiveFileAccess,
            hasObfuscation,
            hasSocialEngineering,
            hasNetworkExfiltration,
            findings,
            severity,
            categories: Array.from(new Set(categories))
        };
    }
}
