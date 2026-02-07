import { GeminiService, GeminiCheckResult } from "./GeminiService.js";
import { StaticCheckService } from "./StaticCheckService.js";

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

/**
 * Service for scanning Claude Code SKILL.md files for security vulnerabilities.
 *
 * This service performs comprehensive security analysis by combining:
 * - LLM-based semantic analysis (via GeminiService)
 * - Static pattern matching (via StaticCheckService)
 * - Skill-specific threat detection (dangerous tools, file access, exfiltration)
 *
 * @example
 * const scanner = new SkillScanService();
 * const result = await scanner.scanSkill(skillContent);
 * if (!result.safe) {
 *   console.error(`Security threat detected: ${result.overallSeverity}`);
 * }
 */
export class SkillScanService {
    private geminiService: GeminiService;
    private staticCheckService: StaticCheckService;

    /**
     * Initializes the skill scanning service with default dependencies.
     */
    constructor() {
        this.geminiService = new GeminiService();
        this.staticCheckService = new StaticCheckService();
    }

    /**
     * Scan a SKILL.md file content for security vulnerabilities
     * @param skillContent The raw markdown content of the SKILL.md file
     * @returns Comprehensive security scan result
     */
    async scanSkill(skillContent: string): Promise<SkillScanResult> {
        // Analyze the FULL skill content to catch prompt injection anywhere in the file,
        // not just in structured ## Instructions blocks
        // Run parallel scans
        const [geminiResult, staticResult, skillSpecificResult] = await Promise.all([
            this.geminiService.checkPrompt(skillContent),
            Promise.resolve(this.staticCheckService.check(skillContent)),
            Promise.resolve(this.runSkillSpecificChecks(skillContent))
        ]);

        // Aggregate severity
        const severities: ("low" | "medium" | "high" | "critical")[] = ["low", "medium", "high", "critical"];
        const geminiSevIdx = severities.indexOf(geminiResult.severity);
        const staticSevIdx = severities.indexOf(staticResult.severity);
        const skillSevIdx = severities.indexOf(skillSpecificResult.severity);
        const overallSeverity = severities[Math.max(geminiSevIdx, staticSevIdx, skillSevIdx)];

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

    /**
     * Performs skill-specific security checks on SKILL.md content.
     *
     * Checks for six categories of threats:
     * 1. Hidden instructions in HTML comments
     * 2. Dangerous tool usage (curl, wget, rm -rf, sudo)
     * 3. Sensitive file access (.ssh/, .aws/, .env, /etc/passwd)
     * 4. Obfuscation techniques (Base64, hex, unicode, zero-width chars)
     * 5. Social engineering indicators (urgency, fake authority)
     * 6. Network exfiltration attempts (data in URL params, POST with secrets)
     *
     * @param content - The raw SKILL.md content to analyze
     * @returns Detailed findings with severity and categories
     * @private
     */
    private runSkillSpecificChecks(content: string): SkillSpecificFindings {
        const findings: string[] = [];
        const categories: string[] = [];
        let severity: "low" | "medium" | "high" | "critical" = "low";

        // 1. Check for hidden instructions in HTML comments
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

        // 2. Check for dangerous tool usage patterns
        const dangerousToolPatterns = [
            // Bash tool with network access
            /bash.*?(curl|wget)\s+.*?https?:\/\/(?!(?:localhost|127\.0\.0\.1|github\.com|npmjs\.com))/gi,
            // File system manipulation
            /bash.*?(rm\s+-rf|dd\s+if=|mkfs|format)/gi,
            // Privilege escalation
            /bash.*?(sudo|su\s+|chmod\s+777|chown)/gi,
            // Process manipulation
            /bash.*?(kill\s+-9|killall|pkill)/gi,

            // Standalone dangerous commands (with or without shell prefix)
            // Network access commands in code blocks
            /(?:^|\s|```)(bash|sh|zsh)?\s*(curl|wget)\s+.*?https?:\/\/(?!(?:localhost|127\.0\.0\.1|github\.com|npmjs\.com))/gim,
            // Destructive file system commands
            /(?:^|\s|```)(bash|sh|zsh)?\s*(rm\s+-rf|dd\s+if=|mkfs|format)/gim,
            // Privilege escalation commands
            /(?:^|\s|```)(bash|sh|zsh)?\s*(sudo|su\s+|chmod\s+777|chown)/gim,
            // Process manipulation commands
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

        // 3. Check for sensitive file access
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

        // 4. Check for obfuscation techniques
        const obfuscationPatterns = [
            // Base64 encoded content that looks like commands
            /[A-Za-z0-9+/]{40,}={0,2}/g,
            // Hex encoding
            /\\x[0-9a-fA-F]{2}/g,
            // Unicode obfuscation
            /\\u[0-9a-fA-F]{4}/g,
            // Zero-width characters
            /[\u200B-\u200D\uFEFF]/g,
        ];

        const hasObfuscation = obfuscationPatterns.some(pattern => {
            const matches = content.match(pattern);
            // Flag if many matches OR a single large encoded blob (200+ chars)
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

        // 5. Check for social engineering indicators
        const socialEngineeringPatterns = [
            /\b(official|urgent|critical|immediate|security update|required|mandatory)\b/gi,
            /\b(from Anthropic|from Claude|from OpenAI|authorized by|approved by)\b/gi,
            /\b(trust me|don't worry|safe to|guaranteed|certified)\b/gi,
        ];

        const hasSocialEngineering = socialEngineeringPatterns.some(pattern => {
            const matches = content.match(pattern);
            if (matches && matches.length > 2) { // Multiple social engineering indicators
                findings.push(`Social engineering indicators detected`);
                categories.push("social_engineering");
                if (severity === "low") severity = "medium";
                return true;
            }
            return false;
        });

        // 6. Check for network exfiltration attempts
        const exfiltrationPatterns = [
            // HTTP requests to non-standard domains with data parameters
            /https?:\/\/(?!(?:localhost|127\.0\.0\.1|github\.com|npmjs\.com|api\.github\.com))[\w.-]+.*?[\?&](data|key|token|secret|password)=/gi,
            // Curl/wget with POST data
            /(curl|wget).*?(-d|--data|--data-binary).*?(key|token|secret|password|env)/gi,
            // DNS exfiltration
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
