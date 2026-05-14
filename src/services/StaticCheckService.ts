import type { PatternService, ActivePattern } from "./PatternService.js";

export type StaticCheckCategory =
    | "xss"
    | "sqli"
    | "shell_injection"
    | "directory_traversal"
    | "unicode_smuggling"
    | "policy_puppetry"
    | "markdown_exfil"
    | "prompt_injection";

export interface StrippedChar {
    index: number;
    codePoint: string;
    class: "tag" | "zero-width" | "bidi";
}

export interface StaticCheckResult {
    hasXSS: boolean;
    hasSQLi: boolean;
    hasShellInjection: boolean;
    hasObfuscation: boolean;
    hasPolicyPuppetry: boolean;
    hasMarkdownExfil: boolean;
    hasPromptInjection: boolean;
    severity: "low" | "medium" | "high" | "critical";
    categories: StaticCheckCategory[];
    findings: string[];
    // Populated when Unicode smuggling characters are stripped/detected.
    // Allows callers to surface evidence to operators without re-scanning input.
    strippedChars?: StrippedChar[];
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

// why: classify a code-point against the three Unicode-smuggling families we care about.
// Returns null when the code point is not a smuggling concern (the hot path for normal text).
function classifySmugglingCodePoint(cp: number): "tag" | "zero-width" | "bidi" | null {
    // Unicode Tag block — essentially no legitimate use in user prompts.
    if (cp >= 0xE0000 && cp <= 0xE007F) return "tag";
    // Zero-width: U+200B..U+200F plus the BOM U+FEFF. (U+200D ZWJ is legitimate inside emoji
    // sequences — we still strip/count it; the per-pattern countThreshold suppresses false
    // positives at the *detection* layer, not here at the *extraction* layer.)
    if ((cp >= 0x200B && cp <= 0x200F) || cp === 0xFEFF) return "zero-width";
    // Bidirectional overrides — rare in legitimate text; Trojan Source-style spoofing.
    if ((cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069)) return "bidi";
    return null;
}

/**
 * Remove invisible Unicode-smuggling characters from `text` and return both the cleaned
 * string and an audit record of every stripped character.
 *
 * why: detection alone is not enough — when downstream callers want to forward the
 * sanitized prompt onward (e.g. to an LLM that should not see invisible instructions),
 * they need a stripped copy plus the evidence trail. The Tag block lives above U+FFFF
 * so we iterate by code point, but report indices in original UTF-16 units so they
 * match the input string directly.
 */
export function stripUnicodeSmuggling(text: string): {
    cleaned: string;
    strippedChars: StrippedChar[];
} {
    const strippedChars: StrippedChar[] = [];
    let cleaned = "";
    let utf16Index = 0;

    // Iterating with for..of yields code points, advancing past surrogate pairs as a unit.
    for (const ch of text) {
        const cp = ch.codePointAt(0)!;
        const klass = classifySmugglingCodePoint(cp);
        if (klass !== null) {
            strippedChars.push({
                index: utf16Index,
                codePoint: "U+" + cp.toString(16).toUpperCase().padStart(4, "0"),
                class: klass,
            });
        } else {
            cleaned += ch;
        }
        // Advance by UTF-16 units: 2 for surrogate-paired (astral) code points, else 1.
        utf16Index += ch.length;
    }

    return { cleaned, strippedChars };
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
        const categories: StaticCheckCategory[] = [];
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
            hasObfuscation: false,
            hasPolicyPuppetry: false,
            hasMarkdownExfil: false,
            hasPromptInjection: false,
        };

        for (const [flagGroup, groupPatterns] of groups) {
            for (const { entry, regex } of groupPatterns) {
                // why: threshold-mode patterns (e.g. zero-width countThreshold:3) require
                // counting matches; a bare .test() would mis-flag a single legitimate ZWJ
                // inside an emoji sequence. matchAll gives us exact counts cheaply.
                let matched = false;
                if (entry.detection.mode === "threshold" && entry.detection.countThreshold) {
                    // Ensure global flag so matchAll works; patterns in our files declare 'g'
                    // already, but be defensive.
                    const globalRegex = regex.flags.includes("g")
                        ? regex
                        : new RegExp(regex.source, regex.flags + "g");
                    const count = [...input.matchAll(globalRegex)].length;
                    matched = count >= entry.detection.countThreshold;
                } else {
                    matched = regex.test(input);
                }

                if (matched) {
                    findings.push(`Potential ${entry.category} detected: ${entry.pattern}`);

                    const cat = entry.category as StaticCheckCategory;
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

        // why: Unicode-smuggling patterns above tell us *that* invisible chars exist; the
        // strip-and-flag helper additionally tells us *which ones and where*. We attach
        // the evidence whenever any smuggling char is present so operators can audit
        // what was sent, even if the regex layer also caught it.
        const { strippedChars } = stripUnicodeSmuggling(input);
        if (strippedChars.length > 0) {
            findings.push(
                `Unicode smuggling chars stripped: ${strippedChars.length} ` +
                `(tag=${strippedChars.filter(s => s.class === "tag").length}, ` +
                `zero-width=${strippedChars.filter(s => s.class === "zero-width").length}, ` +
                `bidi=${strippedChars.filter(s => s.class === "bidi").length})`
            );
        }

        return {
            hasXSS: flags.hasXSS,
            hasSQLi: flags.hasSQLi,
            hasShellInjection: flags.hasShellInjection,
            hasObfuscation: flags.hasObfuscation,
            hasPolicyPuppetry: flags.hasPolicyPuppetry,
            hasMarkdownExfil: flags.hasMarkdownExfil,
            hasPromptInjection: flags.hasPromptInjection,
            severity,
            categories,
            findings,
            strippedChars: strippedChars.length > 0 ? strippedChars : undefined,
        };
    }

    private checkWithHardcoded(input: string): StaticCheckResult {
        const findings: string[] = [];
        const categories: StaticCheckCategory[] = [];
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

        return {
            hasXSS,
            hasSQLi,
            hasShellInjection,
            hasObfuscation: false,
            hasPolicyPuppetry: false,
            hasMarkdownExfil: false,
            hasPromptInjection: false,
            severity,
            categories,
            findings,
        };
    }
}
