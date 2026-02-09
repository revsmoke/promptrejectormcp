import type { PatternService, ActivePattern } from "./PatternService.js";

export interface StaticCheckResult {
    hasXSS: boolean;
    hasSQLi: boolean;
    hasShellInjection: boolean;
    severity: "low" | "medium" | "high" | "critical";
    categories: ("xss" | "sqli" | "shell_injection" | "directory_traversal")[];
    findings: string[];
}

// Returns fresh RegExp instances to avoid lastIndex pollution from global regexes
function getHardcodedXSS(): RegExp[] {
    return [
        new RegExp(/<script\b[^>]*>([\s\S]*?)<\/script>/.source, "gim"),
        new RegExp(/on\w+\s*=\s*"[^"]*"/.source, "gim"),
        new RegExp(/on\w+\s*=\s*'[^']*'/.source, "gim"),
        new RegExp(/javascript:/.source, "gim"),
        new RegExp(/src\s*=\s*"data:/.source, "gim"),
    ];
}

function getHardcodedSQLi(): RegExp[] {
    return [
        new RegExp(/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\s+(FROM|INTO|TABLE|DISTINCT)\b/.source, "gim"),
        new RegExp(/['";]--/.source, "g"),
        new RegExp(/['";]\s+OR\s+['"]?1['"]?\s*=\s*['"]?1['"]?/.source, "gim"),
        new RegExp(/@@VERSION/.source, "gim"),
        new RegExp(/INFORMATION_SCHEMA/.source, "gim"),
    ];
}

function getHardcodedShell(): RegExp[] {
    return [
        new RegExp(/(\betc\/passwd\b)/.source, "gim"),
        new RegExp(/\.\.\//.source, "g"),
        new RegExp(/(2>&1|&>|>\/dev\/null)/.source, "g"),
    ];
}

const SEVERITIES: readonly ("low" | "medium" | "high" | "critical")[] = ["low", "medium", "high", "critical"];

function severityIdx(s: string): number {
    return SEVERITIES.indexOf(s as any);
}

export class StaticCheckService {
    private patternService: PatternService | null;

    constructor(patternService?: PatternService) {
        this.patternService = patternService ?? null;
    }

    check(input: string): StaticCheckResult {
        if (this.patternService) {
            return this.checkWithPatternService(input);
        }
        return this.checkWithHardcoded(input);
    }

    private checkWithPatternService(input: string): StaticCheckResult {
        const findings: string[] = [];
        const categories: ("xss" | "sqli" | "shell_injection" | "directory_traversal")[] = [];
        let severity: "low" | "medium" | "high" | "critical" = "low";

        const patterns = this.patternService!.getActivePatterns("general");

        // Group patterns by flagGroup
        const groups = new Map<string, ActivePattern[]>();
        for (const p of patterns) {
            const group = groups.get(p.entry.flagGroup) || [];
            group.push(p);
            groups.set(p.entry.flagGroup, group);
        }

        // Evaluate each flag group — stop at first match per group (preserves .some() semantics)
        const flags: Record<string, boolean> = {
            hasXSS: false,
            hasSQLi: false,
            hasShellInjection: false,
        };

        for (const [flagGroup, groupPatterns] of groups) {
            for (const { entry, regex } of groupPatterns) {
                const match = regex.test(input);
                if (match) {
                    findings.push(`Potential ${entry.category} detected: ${entry.pattern}`);

                    const cat = entry.category as typeof categories[number];
                    if (!categories.includes(cat)) {
                        categories.push(cat);
                    }

                    if (severityIdx(entry.severity) > severityIdx(severity)) {
                        severity = entry.severity;
                    }

                    if (flagGroup in flags) {
                        flags[flagGroup] = true;
                    }

                    break; // first match per flag group, then move on
                }
            }
        }

        return {
            hasXSS: flags.hasXSS,
            hasSQLi: flags.hasSQLi,
            hasShellInjection: flags.hasShellInjection,
            severity,
            categories,
            findings,
        };
    }

    private checkWithHardcoded(input: string): StaticCheckResult {
        const findings: string[] = [];
        const categories: ("xss" | "sqli" | "shell_injection" | "directory_traversal")[] = [];
        let severity: "low" | "medium" | "high" | "critical" = "low";

        const hasXSS = getHardcodedXSS().some(pattern => {
            const match = pattern.test(input);
            if (match) {
                findings.push(`Potential XSS detected: ${pattern.source}`);
                if (!categories.includes("xss")) categories.push("xss");
                severity = "high";
            }
            return match;
        });

        const hasSQLi = getHardcodedSQLi().some(pattern => {
            const match = pattern.test(input);
            if (match) {
                findings.push(`Potential SQLi detected: ${pattern.source}`);
                if (!categories.includes("sqli")) categories.push("sqli");
                severity = "critical";
            }
            return match;
        });

        const hasShellInjection = getHardcodedShell().some(pattern => {
            const match = pattern.test(input);
            if (match) {
                findings.push(`Potential Shell Injection/Traversal detected: ${pattern.source}`);
                if (pattern.source.includes("\\.\\.\\/")) {
                    if (!categories.includes("directory_traversal")) categories.push("directory_traversal");
                } else {
                    if (!categories.includes("shell_injection")) categories.push("shell_injection");
                }
                if (severity !== "critical") severity = "high";
            }
            return match;
        });

        return { hasXSS, hasSQLi, hasShellInjection, severity, categories, findings };
    }
}
