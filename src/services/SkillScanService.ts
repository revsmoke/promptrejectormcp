import { GeminiService, GeminiCheckResult } from "./GeminiService.js";
import { StaticCheckService } from "./StaticCheckService.js";
import type { PatternService, ActivePattern } from "./PatternService.js";
import { TrifectaAnalyzer, type TrifectaResult } from "./TrifectaAnalyzer.js";
import { HuggingFaceService, type HuggingFaceModelFlag, type HuggingFaceModelReport } from "./HuggingFaceService.js";

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
        atlasTechniques?: string[];
    };
    // Pass 5: Lethal-trifecta capability analysis (Willison).
    hasLethalTrifecta: boolean;
    trifectaResult: TrifectaResult;
    /** Pass 7: Aggregated MITRE ATLAS technique IDs across all sub-checks. */
    atlasTechniques: string[];
    /** Pass 8: Flat list of HF security findings across all detected model IDs. */
    huggingFaceSecurityFlags: HuggingFaceModelFlag[];
    /** Pass 8: Per-model reports for richer downstream consumers. */
    huggingFaceReports: HuggingFaceModelReport[];
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

/**
 * Pass 7: map Gemini's category vocabulary to MITRE ATLAS technique IDs.
 * Mirrors SPEC §7. Categories that pre-date ATLAS or aren't AI-specific
 * (xss, sqli, shell, social_engineering, multilingual) are intentionally
 * absent — we'd rather report no tag than a misleading one.
 */
export function mapGeminiCategoriesToAtlas(categories: string[]): string[] {
    const map: Record<string, string> = {
        unicode_smuggling: "AML.T0051",
        policy_puppetry: "AML.T0054",
        markdown_exfil: "AML.T0024",
        prompt_injection: "AML.T0051",
        obfuscation: "AML.T0051",
    };
    const out = new Set<string>();
    for (const c of categories) {
        const id = map[c];
        if (id) out.add(id);
    }
    return Array.from(out);
}

/**
 * Multi-layer scanner for SKILL.md content.
 *
 * Aggregates results from four sub-services into a single
 * {@link SkillScanResult}:
 * - {@link GeminiService} — semantic LLM classification
 * - {@link StaticCheckService} — regex/pattern detection (general + skill-scoped)
 * - {@link TrifectaAnalyzer} — Willison's lethal-trifecta capability analysis
 * - {@link HuggingFaceService} — security signals for any HF model IDs referenced
 *
 * Round-2 semantic fix: a 3-of-3 lethal trifecta now forces
 * `overallSeverity = "critical"` and `isDangerous = true`. Previously the
 * trifecta result was reported on `hasLethalTrifecta` but did not bubble up
 * into the safe/unsafe decision. 2-of-3 contributes `medium` severity but
 * does not add the synthetic `lethal_trifecta` category or force unsafe.
 *
 * v1.1 result-type additions: `hasLethalTrifecta`, `trifectaResult`,
 * `huggingFaceSecurityFlags`, `huggingFaceReports`, `atlasTechniques[]`.
 *
 * HF integration: extracts model IDs from skill content via
 * {@link HuggingFaceService.extractModelIds}, then fans out to
 * `checkModel()` in parallel (`Promise.allSettled`) and rolls severity
 * into the final result.
 *
 * Also exports {@link mapGeminiCategoriesToAtlas} as a top-level helper
 * shared with {@link SecurityService}.
 *
 * Environment variables: none consumed directly (delegates to sub-services).
 */
export class SkillScanService {
    private geminiService: GeminiService;
    private staticCheckService: StaticCheckService;
    private patternService: PatternService | null;
    private trifectaAnalyzer: TrifectaAnalyzer;
    private huggingFaceService: HuggingFaceService;

    constructor(patternService?: PatternService, huggingFaceService?: HuggingFaceService) {
        this.patternService = patternService ?? null;
        this.geminiService = new GeminiService();
        this.staticCheckService = new StaticCheckService(patternService);
        this.trifectaAnalyzer = new TrifectaAnalyzer();
        // Pass 8: HF security signals. Default keeps existing call sites working;
        // mcpServer passes a shared instance so the in-memory cache is reused
        // across scans.
        this.huggingFaceService = huggingFaceService ?? new HuggingFaceService();
    }

    async scanSkill(skillContent: string): Promise<SkillScanResult> {
        // Pass 8: extract HF model ids first (sync, cheap) so we can fan out
        // network requests in parallel with the LLM + static checks.
        const modelIds = this.huggingFaceService.extractModelIds(skillContent);
        const hfCheckPromise = modelIds.length === 0
            ? Promise.resolve([] as HuggingFaceModelReport[])
            : Promise.allSettled(modelIds.map((id) => this.huggingFaceService.checkModel(id)))
                  .then((settled) =>
                      settled
                          .filter((s): s is PromiseFulfilledResult<HuggingFaceModelReport> => s.status === "fulfilled")
                          .map((s) => s.value),
                  );

        const [geminiResult, staticResult, skillSpecificResult, hfReports] = await Promise.all([
            this.geminiService.checkPrompt(skillContent),
            Promise.resolve(this.staticCheckService.check(skillContent)),
            Promise.resolve(this.runSkillSpecificChecks(skillContent)),
            hfCheckPromise,
        ]);

        // Pass 5: lethal-trifecta capability classification (sync, cheap).
        const trifectaResult = this.trifectaAnalyzer.analyze({ skillContent });

        // Pass 8: flatten HF flags + compute their severity contribution.
        const huggingFaceSecurityFlags: HuggingFaceModelFlag[] = [];
        for (const r of hfReports) huggingFaceSecurityFlags.push(...r.flags);
        // Map HF severity ladder (safe/low/medium/high/critical) onto the
        // 4-level skill scan ladder. "safe" → "low" (we don't have a safer level).
        const HF_TO_SKILL_SEV: Record<HuggingFaceModelReport["severity"], "low" | "medium" | "high" | "critical"> = {
            safe: "low",
            low: "low",
            medium: "medium",
            high: "high",
            critical: "critical",
        };
        let hfSeverity: "low" | "medium" | "high" | "critical" = "low";
        for (const r of hfReports) {
            const mapped = HF_TO_SKILL_SEV[r.severity];
            if (SEVERITIES.indexOf(mapped) > SEVERITIES.indexOf(hfSeverity)) {
                hfSeverity = mapped;
            }
        }

        // Aggregate severity
        // why: TrifectaAnalyzer reports its own severity ladder ("safe" | "medium" | "critical").
        // SPEC §2 + §7 list lethal_trifecta as a composite critical-severity category, so the
        // final rollup must fold the trifecta result in — otherwise a 3-of-3 skill (read+fetch+egress)
        // can slip through as `safe: true` when no other sub-check fires high/critical.
        const TRIFECTA_TO_SKILL_SEV: Record<TrifectaResult["severity"], "low" | "medium" | "high" | "critical"> = {
            safe: "low",
            medium: "medium",
            critical: "critical",
        };
        const trifectaSeverityMapped = TRIFECTA_TO_SKILL_SEV[trifectaResult.severity];
        const geminiSevIdx = SEVERITIES.indexOf(geminiResult.severity);
        const staticSevIdx = SEVERITIES.indexOf(staticResult.severity);
        const skillSevIdx = SEVERITIES.indexOf(skillSpecificResult.severity);
        const hfSevIdx = SEVERITIES.indexOf(hfSeverity);
        const trifectaSevIdx = SEVERITIES.indexOf(trifectaSeverityMapped);
        const overallSeverity = SEVERITIES[Math.max(geminiSevIdx, staticSevIdx, skillSevIdx, hfSevIdx, trifectaSevIdx)];

        // Aggregate categories. When trifectaPresent we add a synthetic
        // `lethal_trifecta` category so downstream consumers can see *why* the
        // composite severity bumped to critical without re-running the analyzer.
        const categories = Array.from(new Set([
            ...geminiResult.categories,
            ...staticResult.categories,
            ...skillSpecificResult.categories,
            ...(trifectaResult.trifectaPresent ? ["lethal_trifecta"] : []),
        ]));

        // Decide "safe" status. trifectaPresent OR'd in so all-three-buckets
        // forces dangerous even when each sub-check on its own stayed low/medium.
        const isDangerous =
            overallSeverity === "critical" ||
            overallSeverity === "high" ||
            (geminiResult.isInjection && geminiResult.confidence > 0.6) ||
            skillSpecificResult.hasDangerousToolUsage ||
            skillSpecificResult.hasNetworkExfiltration ||
            trifectaResult.trifectaPresent;

        const safe = !isDangerous;

        // Pass 7: aggregate ATLAS techniques across static + Gemini (skill-specific
        // checks don't carry pattern entries today; future ATLAS hooks can fold in here).
        // SPEC §7 maps `lethal_trifecta → AML.T0024 + AML.T0051` (composite). Add both
        // when the trifecta is present; Set dedup handles overlap with other sub-checks.
        const atlasTechniques = Array.from(new Set([
            ...(staticResult.atlasTechniques || []),
            ...mapGeminiCategoriesToAtlas(geminiResult.categories || []),
            ...(trifectaResult.trifectaPresent ? ["AML.T0024", "AML.T0051"] : []),
        ]));

        return {
            safe,
            geminiConfidence: geminiResult.confidence,
            overallSeverity,
            categories,
            skillSpecific: skillSpecificResult,
            gemini: geminiResult,
            static: staticResult,
            hasLethalTrifecta: trifectaResult.trifectaPresent,
            trifectaResult,
            atlasTechniques,
            huggingFaceSecurityFlags,
            huggingFaceReports: hfReports,
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
