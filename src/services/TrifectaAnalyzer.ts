/**
 * TrifectaAnalyzer — Willison's Lethal Trifecta capability classifier.
 *
 * Background:
 *   Simon Willison (Jun 2025) observed an AI agent is guaranteed to be
 *   exfil-exploitable when it simultaneously has all three of:
 *     1. private-data read   (access to sensitive local data / user secrets)
 *     2. untrusted-content fetch (ability to ingest attacker-controlled text)
 *     3. external egress     (any outbound channel through which a secret can leak)
 *   Removing ANY one of the three breaks the chain.
 *
 * This analyzer does NOT do regex pattern detection (PatternService handles that).
 * It classifies declared capabilities/tools/skill content into the three buckets
 * and flags critical when all three co-locate.
 */

// One bucket of the trifecta. `evidence` enumerates the specific rules that matched.
export interface TrifectaBucket {
    present: boolean;
    evidence: Array<{ source: "capability" | "tool" | "skill-content"; match: string; pattern: string }>;
}

// Pass 0 compatibility alias — older callers still reference TrifectaSignal.
export type TrifectaSignal = TrifectaBucket;

export interface TrifectaInput {
    capabilities?: string[];
    tools?: string[];
    skillContent?: string;
}

export interface TrifectaResult {
    privateDataRead: TrifectaBucket;
    untrustedContentFetch: TrifectaBucket;
    externalEgress: TrifectaBucket;
    trifectaPresent: boolean;
    severity: "safe" | "medium" | "critical";
    recommendation: string;
}

// Rule shape — either a regex (for skill content & free-text names) or a string
// list match (case-insensitive substring) for capability/tool name slugs.
type ClassifierRule =
    | { kind: "regex"; pattern: RegExp; label: string }
    | { kind: "name"; needles: string[]; label: string };

// Bucket 1 — private data read indicators.
// Tight matches against well-known sensitive paths, capability slug substrings,
// and English phrases that explicitly call out reading user secrets.
const PRIVATE_DATA_READ_RULES: ClassifierRule[] = [
    // Sensitive on-disk paths / files (regex on free text + names).
    { kind: "regex", pattern: /\.ssh\b/i, label: "path:.ssh" },
    { kind: "regex", pattern: /\.aws\b/i, label: "path:.aws" },
    { kind: "regex", pattern: /\.kube\b/i, label: "path:.kube" },
    { kind: "regex", pattern: /\.env\b/i, label: "path:.env" },
    { kind: "regex", pattern: /credentials/i, label: "keyword:credentials" },
    { kind: "regex", pattern: /secrets/i, label: "keyword:secrets" },
    { kind: "regex", pattern: /keychain/i, label: "keyword:keychain" },
    { kind: "regex", pattern: /cookies\.sqlite/i, label: "path:cookies.sqlite" },
    { kind: "regex", pattern: /~\/Library\/(Keychains|Cookies|Mail)/i, label: "path:~/Library/(Keychains|Cookies|Mail)" },
    { kind: "regex", pattern: /\/etc\/passwd/, label: "path:/etc/passwd" },
    { kind: "regex", pattern: /\/etc\/shadow/, label: "path:/etc/shadow" },
    // Capability/tool name substrings (case-insensitive).
    {
        kind: "name",
        needles: [
            "read_file",
            "fs_read",
            "read_secrets",
            "read_env",
            "get_credentials",
            "keychain_read",
            "load_credentials",
            "read_user_data",
            "gmail_read",
            "drive_read",
            "mail_read",
            "calendar_read",
        ],
        label: "tool-name:private-data-reader",
    },
    // Natural-language description of reading user secrets.
    {
        kind: "regex",
        pattern: /\bread(ing)?\s+(my|user|local|private)\s+(files?|secrets?|credentials?|tokens?|keys?)\b/i,
        label: "phrase:read user/private files/secrets",
    },
];

// Bucket 2 — untrusted-content fetch indicators (the LLM ingests web content
// the attacker controls).
const UNTRUSTED_FETCH_RULES: ClassifierRule[] = [
    {
        kind: "name",
        needles: [
            "fetch",
            "fetch_url",
            "http_get",
            "http_request",
            "browser_navigate",
            "web_search",
            "scrape",
            "curl",
            "wget",
            "read_url",
            "load_url",
            "openai_browse",
            "webfetch",
        ],
        label: "tool-name:fetcher",
    },
    // "fetch/GET/curl/wget/scrape/crawl/browse ... https://..." within ~80 chars.
    {
        kind: "regex",
        pattern: /\b(fetch|GET|curl|wget|scrape|crawl|browse)\b[\s\S]{0,80}\bhttps?:/i,
        label: "phrase:fetch-verb-near-url",
    },
];

// Bucket 3 — external egress indicators (any outbound channel).
const EXTERNAL_EGRESS_RULES: ClassifierRule[] = [
    {
        kind: "name",
        needles: [
            "send_email",
            "post_message",
            "http_post",
            "slack_post",
            "webhook",
            "upload",
            "share",
            "publish",
            "tweet",
            "sms_send",
            "outgoing",
            "push_to",
            "notify",
            "fire_webhook",
            "send_to",
        ],
        label: "tool-name:egress",
    },
    // Explicit outbound HTTP verbs.
    {
        kind: "regex",
        pattern: /\b(POST|PUT|PATCH|DELETE)\s+https?:/i,
        label: "phrase:write-http-verb",
    },
    // English "send to / send via / sending email/message/webhook/http".
    // Allows one optional article ("an"/"a"/"the") between the verb and the channel,
    // so "send an email" / "sending a message" classify as egress.
    {
        kind: "regex",
        pattern: /\bsend(s|ing)?\s+(?:an?\s+|the\s+)?(to|via|email|message|webhook|http)\b/i,
        label: "phrase:send-to-channel",
    },
    // Per Willison: markdown image rendering counts — the renderer fetches the
    // URL and the query string is exfil-able via referer/path.
    {
        kind: "regex",
        pattern: /!\[[^\]]*\]\(https?:\/\//,
        label: "markdown-image-egress",
    },
];

const MAX_EVIDENCE_PER_BUCKET = 10;

/**
 * Classify capability strings (tools[] or capabilities[]) against the bucket's
 * `name` rules. Substring match, case-insensitive.
 */
function classifyNames(
    names: string[],
    rules: ClassifierRule[],
    source: "capability" | "tool",
    bucket: TrifectaBucket,
): void {
    for (const name of names) {
        const lc = name.toLowerCase();
        for (const rule of rules) {
            if (bucket.evidence.length >= MAX_EVIDENCE_PER_BUCKET) return;
            if (rule.kind === "name") {
                for (const needle of rule.needles) {
                    if (lc.includes(needle.toLowerCase())) {
                        bucket.evidence.push({ source, match: name, pattern: `${rule.label}:${needle}` });
                        bucket.present = true;
                        break;
                    }
                }
            } else {
                // Allow regex rules to fire against tool/capability names too —
                // e.g. a capability literally named "read_~/.ssh/id_rsa".
                if (rule.pattern.test(name)) {
                    bucket.evidence.push({ source, match: name, pattern: rule.label });
                    bucket.present = true;
                }
            }
        }
    }
}

/**
 * Apply all regex rules to free-text skill content.
 */
function classifyContent(content: string, rules: ClassifierRule[], bucket: TrifectaBucket): void {
    for (const rule of rules) {
        if (bucket.evidence.length >= MAX_EVIDENCE_PER_BUCKET) return;
        if (rule.kind === "regex") {
            const m = content.match(rule.pattern);
            if (m) {
                bucket.evidence.push({ source: "skill-content", match: m[0].slice(0, 120), pattern: rule.label });
                bucket.present = true;
            }
        } else {
            // "name"-kind rules also apply to skill-content: scan content for any
            // of the substrings (useful when a SKILL.md mentions tool names inline).
            for (const needle of rule.needles) {
                if (bucket.evidence.length >= MAX_EVIDENCE_PER_BUCKET) return;
                const re = new RegExp(`\\b${needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
                if (re.test(content)) {
                    bucket.evidence.push({ source: "skill-content", match: needle, pattern: `${rule.label}:${needle}` });
                    bucket.present = true;
                }
            }
        }
    }
}

/**
 * Special case: untrusted-fetch can also be inferred from a code-style import
 * of an HTTP client + a URL elsewhere in the content. Cheap to compute, keeps
 * FPs down (both signals required).
 */
function classifyImportPlusUrl(content: string, bucket: TrifectaBucket): void {
    if (bucket.evidence.length >= MAX_EVIDENCE_PER_BUCKET) return;
    const importMatch = content.match(/\b(requests|axios|node-fetch|undici|got)\b/i)
        ?? content.match(/\bfetch\s*\(/);
    if (!importMatch) return;
    if (!/https?:\/\//i.test(content)) return;
    bucket.evidence.push({
        source: "skill-content",
        match: importMatch[0].slice(0, 60),
        pattern: "http-client-import+url",
    });
    bucket.present = true;
}

export class TrifectaAnalyzer {
    /**
     * Classify the supplied capabilities/tools/skillContent into the three
     * trifecta buckets and roll up severity.
     *
     * `capabilities` and `tools` are treated identically (both are slug lists)
     * — the only difference is the `source` label on the evidence entry, which
     * helps callers understand where a signal originated.
     */
    analyze(input: TrifectaInput): TrifectaResult {
        const capabilities = input.capabilities ?? [];
        const tools = input.tools ?? [];
        const content = input.skillContent ?? "";

        // Fresh buckets per call.
        const privateDataRead: TrifectaBucket = { present: false, evidence: [] };
        const untrustedContentFetch: TrifectaBucket = { present: false, evidence: [] };
        const externalEgress: TrifectaBucket = { present: false, evidence: [] };

        // Classify capability slugs.
        classifyNames(capabilities, PRIVATE_DATA_READ_RULES, "capability", privateDataRead);
        classifyNames(capabilities, UNTRUSTED_FETCH_RULES, "capability", untrustedContentFetch);
        classifyNames(capabilities, EXTERNAL_EGRESS_RULES, "capability", externalEgress);

        // Classify tool slugs.
        classifyNames(tools, PRIVATE_DATA_READ_RULES, "tool", privateDataRead);
        classifyNames(tools, UNTRUSTED_FETCH_RULES, "tool", untrustedContentFetch);
        classifyNames(tools, EXTERNAL_EGRESS_RULES, "tool", externalEgress);

        // Classify skill content.
        if (content.length > 0) {
            classifyContent(content, PRIVATE_DATA_READ_RULES, privateDataRead);
            classifyContent(content, UNTRUSTED_FETCH_RULES, untrustedContentFetch);
            classifyContent(content, EXTERNAL_EGRESS_RULES, externalEgress);
            classifyImportPlusUrl(content, untrustedContentFetch);
        }

        // Roll up severity.
        const presentCount =
            (privateDataRead.present ? 1 : 0) +
            (untrustedContentFetch.present ? 1 : 0) +
            (externalEgress.present ? 1 : 0);
        const trifectaPresent = presentCount === 3;

        let severity: TrifectaResult["severity"];
        let recommendation: string;
        if (trifectaPresent) {
            severity = "critical";
            recommendation =
                "Lethal trifecta present — disable any one of: private-data read, untrusted-content fetch, external egress.";
        } else if (presentCount === 2) {
            severity = "medium";
            const labels: string[] = [];
            if (privateDataRead.present) labels.push("privateDataRead");
            if (untrustedContentFetch.present) labels.push("untrustedContentFetch");
            if (externalEgress.present) labels.push("externalEgress");
            recommendation = `2 of 3 trifecta capabilities present (${labels.join(" + ")}) — adding the third would enable exfil; avoid.`;
        } else {
            severity = "safe";
            recommendation = "Lethal trifecta not present.";
        }

        return {
            privateDataRead,
            untrustedContentFetch,
            externalEgress,
            trifectaPresent,
            severity,
            recommendation,
        };
    }
}
