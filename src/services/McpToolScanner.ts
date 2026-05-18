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

/**
 * Lints MCP tool descriptors for tool-poisoning attacks and emits a canonical
 * SHA-256 hash for drift detection across versions.
 *
 * The scanner recursively walks every string-valued field in a tool descriptor
 * (top-level `description`, nested `inputSchema.properties.*.description`,
 * `examples[]`, schema `title`/`description`, etc.) and evaluates each one
 * against patterns in three categories: `mcp_tool_poisoning`,
 * `prompt_injection`, and `policy_puppetry`. Prompt-injection and
 * policy-puppetry patterns are reused here because poisoned descriptors
 * commonly embed the same imperative-override payloads we already catch in
 * end-user prompts.
 *
 * Two signals are produced per scan:
 * 1. **Findings** — pattern matches plus a separate `unicode_smuggling`
 *    finding for any tag/zero-width/bidi characters stripped by
 *    `stripUnicodeSmuggling`. Pattern evaluation uses the same threshold-aware
 *    logic as `StaticCheckService` via the exported `evaluatePattern` helper.
 * 2. **Canonical hash** — `canonicalStringify` produces a sorted-key
 *    deterministic JSON representation; the SHA-256 of that is the descriptor
 *    identity. When a `priorHash` is supplied and doesn't match, `drift: true`
 *    is set in the result independent of finding severity.
 *
 * `inspectedFields` lists the dot-path of every string field the scanner read
 * (e.g. `inputSchema.properties.q.description`, `examples[0]`) — useful for
 * audit trails and for proving coverage in tests.
 *
 * Severity is rolled up as the max across all findings; `safe` when none fire.
 * No env vars; PatternService is injected via the constructor. When no
 * PatternService is wired (early bootstrap), the scanner still emits
 * hash/drift but skips pattern checks.
 */
export class McpToolScanner {
    private patternService: PatternService | null;

    constructor(patternService?: PatternService) {
        this.patternService = patternService ?? null;
    }

    /**
     * Scan a single MCP tool descriptor.
     *
     * @param input.tool       The tool descriptor object as received from an
     *                         MCP server (typically `{ name, description,
     *                         inputSchema }` plus any extension fields).
     * @param input.priorHash  Optional known-good hash. If supplied and not
     *                         equal to the freshly-computed hash, the result's
     *                         `drift` flag is set.
     * @returns Canonical hash, drift flag, ordered list of findings, rolled-up
     *          severity, and the sorted list of every string field path the
     *          scanner inspected.
     */
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
