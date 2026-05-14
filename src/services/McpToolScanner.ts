import { createHash } from "crypto";
import { PatternService, type ActivePattern } from "./PatternService.js";
import { stripUnicodeSmuggling, evaluatePattern } from "./StaticCheckService.js";

export type McpSeverity = "safe" | "low" | "medium" | "high" | "critical";

export interface McpFinding {
    field: string;
    category: string;
    severity: "low" | "medium" | "high" | "critical";
    patternId?: string;
    excerpt: string;
    note?: string;
}

export interface McpToolScanInput {
    tool: object;
    priorHash?: string;
}

export interface McpToolScanResult {
    hash: string;
    drift: boolean;
    findings: McpFinding[];
    severity: McpSeverity;
    inspectedFields: string[];
}

// Severity ordering shared with StaticCheckService; null entry for "safe" baseline.
const SEVERITY_RANK: Record<string, number> = {
    safe: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
};

// Categories whose patterns are relevant to tool descriptor scanning.
// Tool-poisoning patterns are the primary signal; prompt-injection and
// policy-puppetry are reused because a poisoned descriptor will commonly
// embed the same imperative-override patterns we already catch in prompts.
const SCAN_CATEGORIES = new Set<string>([
    "mcp_tool_poisoning",
    "prompt_injection",
    "policy_puppetry",
]);

// Maximum number of UTF-16 units we keep in a finding excerpt. Keeps output
// readable in logs and prevents an attacker from blowing up report size via
// a giant description.
const EXCERPT_MAX = 200;

function excerpt(text: string): string {
    return text.length <= EXCERPT_MAX ? text : text.slice(0, EXCERPT_MAX) + "…";
}

/**
 * Stable JSON stringify with sorted keys at every object level.
 *
 * why: the descriptor hash is the drift signal; without sorted keys, two
 * semantically identical descriptors with different key insertion order would
 * produce different hashes and emit false drift. We don't need full RFC 8785
 * — sorted-keys JSON is enough for the tool-descriptor shape MCP defines.
 */
function canonicalStringify(value: unknown): string {
    if (value === null || typeof value !== "object") {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return "[" + value.map((v) => canonicalStringify(v)).join(",") + "]";
    }
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts = keys.map((k) => JSON.stringify(k) + ":" + canonicalStringify(obj[k]));
    return "{" + parts.join(",") + "}";
}

function rankSeverity(s: McpSeverity): number {
    return SEVERITY_RANK[s] ?? 0;
}

function maxSeverity(a: McpSeverity, b: McpSeverity): McpSeverity {
    return rankSeverity(a) >= rankSeverity(b) ? a : b;
}

export class McpToolScanner {
    private patternService: PatternService | null;

    constructor(patternService?: PatternService) {
        this.patternService = patternService ?? null;
    }

    scan(input: McpToolScanInput): McpToolScanResult {
        const canonical = canonicalStringify(input.tool);
        const hash = createHash("sha256").update(canonical).digest("hex");
        const drift = !!input.priorHash && input.priorHash !== hash;

        const findings: McpFinding[] = [];
        const inspectedFields = new Set<string>();

        // Pull the patterns we care about once. If no PatternService is wired
        // (e.g. early bootstrap), we still emit hash/drift but skip pattern checks.
        const patterns: ActivePattern[] = this.patternService
            ? this.patternService
                  .getActivePatterns("general")
                  .filter((p) => SCAN_CATEGORIES.has(p.entry.category))
            : [];

        this.walkStrings(input.tool, "", (path, text) => {
            inspectedFields.add(path);

            // 1) Unicode smuggling — every invisible-instruction smuggling vector
            // is critical inside tool metadata because the descriptor is treated
            // as trusted by the model.
            const { strippedChars } = stripUnicodeSmuggling(text);
            if (strippedChars.length > 0) {
                findings.push({
                    field: path,
                    category: "unicode_smuggling",
                    severity: "critical",
                    excerpt: excerpt(text),
                    note: `Stripped ${strippedChars.length} smuggling char(s): ` +
                        `tag=${strippedChars.filter((s) => s.class === "tag").length}, ` +
                        `zero-width=${strippedChars.filter((s) => s.class === "zero-width").length}, ` +
                        `bidi=${strippedChars.filter((s) => s.class === "bidi").length}`,
                });
            }

            // 2) Pattern matching against tool-poisoning + reused prompt-injection patterns.
            // We do NOT short-circuit per flagGroup here — for a tool descriptor we want
            // every signal, not just the first per group, so operators can see the full
            // attack surface.
            for (const ap of patterns) {
                const { matched } = evaluatePattern(text, ap);
                if (matched) {
                    findings.push({
                        field: path,
                        category: ap.entry.category,
                        severity: ap.entry.severity,
                        patternId: ap.entry.id,
                        excerpt: excerpt(text),
                    });
                }
            }
        });

        let severity: McpSeverity = "safe";
        for (const f of findings) {
            severity = maxSeverity(severity, f.severity);
        }

        return {
            hash,
            drift,
            findings,
            severity,
            inspectedFields: Array.from(inspectedFields).sort(),
        };
    }

    /**
     * Recursively walk an object and invoke `visit` for every string value,
     * passing the dot-path of where the string lives.
     *
     * why: tool descriptors are arbitrarily nested (especially inside
     * `inputSchema.properties.*.description`), and a tool-poisoning payload
     * can hide in any string field. We don't filter by field name — every
     * string is suspect, including `examples` arrays and nested schema
     * `title`/`description` fields. Indices are included in paths so two
     * findings on different array elements are distinguishable.
     */
    private walkStrings(node: unknown, path: string, visit: (path: string, text: string) => void): void {
        if (typeof node === "string") {
            // Skip empty strings — nothing to lint, no useful path.
            if (node.length > 0) {
                visit(path || "(root)", node);
            }
            return;
        }
        if (node === null || typeof node !== "object") {
            return;
        }
        if (Array.isArray(node)) {
            for (let i = 0; i < node.length; i++) {
                const childPath = path ? `${path}[${i}]` : `[${i}]`;
                this.walkStrings(node[i], childPath, visit);
            }
            return;
        }
        const obj = node as Record<string, unknown>;
        for (const key of Object.keys(obj)) {
            const childPath = path ? `${path}.${key}` : key;
            this.walkStrings(obj[key], childPath, visit);
        }
    }
}
