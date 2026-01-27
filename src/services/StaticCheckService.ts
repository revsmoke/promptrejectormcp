import validator from "validator";

export interface StaticCheckResult {
    hasXSS: boolean;
    hasSQLi: boolean;
    hasShellInjection: boolean;
    severity: "low" | "medium" | "high" | "critical";
    categories: ("xss" | "sqli" | "shell_injection" | "directory_traversal")[];
    findings: string[];
}

export class StaticCheckService {
    check(input: string): StaticCheckResult {
        const findings: string[] = [];
        const categories: ("xss" | "sqli" | "shell_injection" | "directory_traversal")[] = [];
        let severity: "low" | "medium" | "high" | "critical" = "low";

        // 1. Check for XSS
        const xssPatterns = [
            /<script\b[^>]*>([\s\S]*?)<\/script>/gim,
            /on\w+\s*=\s*"[^"]*"/gim,
            /on\w+\s*=\s*'[^']*'/gim,
            /javascript:/gim,
            /src\s*=\s*"data:/gim
        ];

        const hasXSS = xssPatterns.some(pattern => {
            const match = pattern.test(input);
            if (match) {
                findings.push(`Potential XSS detected: ${pattern.source}`);
                if (!categories.includes("xss")) categories.push("xss");
                severity = "high";
            }
            return match;
        });

        // 2. Check for SQL Injection
        // Stricter patterns to avoid natural language false positives
        const sqliPatterns = [
            /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\s+(FROM|INTO|TABLE|DISTINCT)\b/gim,
            /['";]--/g,
            /['";]\s+OR\s+['"]?1['"]?\s*=\s*['"]?1['"]?/gim,
            /@@VERSION/gim,
            /INFORMATION_SCHEMA/gim
        ];

        const hasSQLi = sqliPatterns.some(pattern => {
            const match = pattern.test(input);
            if (match) {
                findings.push(`Potential SQLi detected: ${pattern.source}`);
                if (!categories.includes("sqli")) categories.push("sqli");
                severity = "critical";
            }
            return match;
        });

        // 3. Check for Shell Injection & Traversal
        const shellPatterns = [
            /(\betc\/passwd\b)/gim,
            /[&|;`$]/g,
            /\.\.\//g, // Directory traversal
            /(2>&1|&>|>\/dev\/null)/g, // Specific redirection
        ];

        const hasShellInjection = shellPatterns.some(pattern => {
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

        return {
            hasXSS,
            hasSQLi,
            hasShellInjection,
            severity,
            categories,
            findings
        };
    }
}
