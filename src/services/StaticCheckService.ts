import type { PatternService, ActivePattern } from "./PatternService.js";

export type StaticCheckCategory =
    | "xss"
    | "sqli"
    | "shell_injection"
    | "directory_traversal"
    | "unicode_smuggling"
    | "policy_puppetry"
    | "markdown_exfil"
    | "prompt_injection"
    | "many_shot"
    | "obfuscation";

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
    hasManyShot: boolean;
    severity: "low" | "medium" | "high" | "critical";
    categories: StaticCheckCategory[];
    findings: string[];
    // Populated when Unicode smuggling characters are stripped/detected.
    // Allows callers to surface evidence to operators without re-scanning input.
    strippedChars?: StrippedChar[];
    /**
     * Pass 7: MITRE ATLAS technique IDs attached to matched patterns (deduped).
     * Empty when no matched pattern declared `atlasTechnique`. Web vulns
     * (xss/sqli/shell) pre-date ATLAS and stay unset by design.
     */
    atlasTechniques: string[];
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

/**
 * Evaluate a single ActivePattern against `text`, honoring simple vs threshold detection.
 *
 * why: factored out of StaticCheckService so any service that loads patterns
 * (e.g. McpToolScanner) can run identical detection semantics without duplicating
 * the threshold/count logic. Returns both whether the pattern matched and the
 * raw match count — callers that care only about boolean detection can ignore
 * the count.
 */
export function evaluatePattern(text: string, pattern: ActivePattern): { matched: boolean; matchCount: number } {
    const { entry, regex } = pattern;
    if (entry.detection.mode === "threshold" && entry.detection.countThreshold) {
        const globalRegex = regex.flags.includes("g")
            ? regex
            : new RegExp(regex.source, regex.flags + "g");
        // why: ActivePattern.regex is cached at load-time and reused across every
        // evaluatePattern() call. If a prior call (or any external code) left
        // lastIndex non-zero on a global regex, matchAll() would start mid-string
        // and silently skip earlier matches. Reset before iterating to guarantee
        // deterministic detection regardless of call order.
        globalRegex.lastIndex = 0;
        const count = [...text.matchAll(globalRegex)].length;
        return { matched: count >= entry.detection.countThreshold, matchCount: count };
    }
    // why: .test() on a g-/y-flagged regex advances lastIndex, so the next call on
    // the same cached instance starts searching from that offset and can miss a
    // match that is *before* the previous hit. Reset to 0 to make repeated calls
    // on the shared instance deterministic. No-op on non-sticky/non-global regexes.
    regex.lastIndex = 0;
    const matched = regex.test(text);
    return { matched, matchCount: matched ? 1 : 0 };
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

/**
 * Regex/pattern-based static detection layer.
 *
 * Loads detection patterns from {@link PatternService} when injected;
 * otherwise falls back to a hardcoded pattern set (see `fallbackPatterns.ts`)
 * so the service is still functional if the pattern library fails integrity
 * verification.
 *
 * Detection modes (per {@link ActivePattern}):
 * - `simple` — any regex match counts as a finding.
 * - `threshold` — requires `countThreshold` matches or `singleMatchLength`
 *   chars; used for low-false-positive detectors like zero-width chars.
 *
 * Round-2 correctness fixes baked in:
 * - **`lastIndex = 0` reset** before every `regex.test()` / `regex.matchAll()`
 *   call, so `g`-flagged patterns don't carry state across invocations.
 *   Live exposure was strongest in {@link McpToolScanner}, which iterates
 *   one cached pattern array across every string field of a tool descriptor.
 * - **Flag-group loop continues scanning after first match** within a
 *   group, taking max severity rather than breaking on first hit. Sneaky
 *   Bits payloads now correctly surface `critical` severity instead of
 *   being capped at `high`.
 *
 * Also exports a top-level {@link evaluatePattern} helper used by
 * {@link McpToolScanner} so threshold semantics stay consistent across
 * services. {@link stripUnicodeSmuggling} is exported for callers that
 * want a cleaned string + audit trail of the stripped code points.
 *
 * Environment variables: none.
 */
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
        const atlasTechniques: string[] = [];
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
            hasManyShot: false,
        };

        // why: previously this loop `break`ed on the first match per flagGroup, which
        // under-reported severity when a later pattern in the same group had a higher
        // severity ceiling (e.g. Sneaky Bits paired ZWNJ/ZWJ first hits `unicode-zero-width`
        // at "high" and skips `obfuscation-sneaky-bits` at "critical"). We now scan every
        // pattern in the group, aggregate all matched-pattern findings/categories/ATLAS
        // tags, and let max-severity emerge from the per-pattern compare further down.
        // The boolean flag still latches once per group (truth never un-sets).
        for (const [flagGroup, groupPatterns] of groups) {
            for (const ap of groupPatterns) {
                const { entry } = ap;
                // why: threshold-mode patterns (e.g. zero-width countThreshold:3) require
                // counting matches; a bare .test() would mis-flag a single legitimate ZWJ
                // inside an emoji sequence. Delegated to evaluatePattern() so the
                // McpToolScanner can apply identical semantics.
                const { matched } = evaluatePattern(input, ap);

                if (!matched) continue;

                findings.push(`Potential ${entry.category} detected: ${entry.pattern}`);

                const cat = entry.category as StaticCheckCategory;
                if (!categories.includes(cat)) {
                    categories.push(cat);
                }

                // Pass 7: surface MITRE ATLAS technique tag if the pattern has one.
                // Deduped so a category with multiple matching patterns reports once.
                if (entry.atlasTechnique && !atlasTechniques.includes(entry.atlasTechnique)) {
                    atlasTechniques.push(entry.atlasTechnique);
                }

                if (severityIdx(entry.severity) > severityIdx(severity)) {
                    severity = entry.severity;
                }

                if (flagGroup in flags) {
                    flags[flagGroup] = true;
                }
                // No `break` — continue scanning so higher-severity siblings in the
                // same flagGroup still register their finding/category/ATLAS tag.
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
            hasManyShot: flags.hasManyShot,
            severity,
            categories,
            findings,
            strippedChars: strippedChars.length > 0 ? strippedChars : undefined,
            atlasTechniques,
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
            hasManyShot: false,
            severity,
            categories,
            findings,
            // Hardcoded path covers pre-ATLAS web vulns only — no ATLAS mapping.
            atlasTechniques: [],
        };
    }
}
