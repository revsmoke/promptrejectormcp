# PLAN.md — Prompt Rejector v1.1.0 Execution Plan

**Status:** Ready to execute
**Authoring date:** 2026-05-13
**Methodology:** Vertical-slice / walking-skeleton development (see `/vertical-slice-dev` skill)
**Companions:** [SPEC.md](SPEC.md), [RESEARCH_THREATS.md](RESEARCH_THREATS.md), [RESEARCH_FEEDS.md](RESEARCH_FEEDS.md)

---

## How to read this plan

Each pass leaves the system **fully runnable and testable** before the next pass starts. No horizontal layer-building — Pass 0 wires every new subsystem end-to-end with stubs; every subsequent pass adds one user-visible capability across all relevant layers simultaneously.

Status legend: `⬜ pending` · `🟡 in progress` · `✅ done` · `⚠️ blocked`

Each pass has:
- **Goal** — the single user-visible capability shipped
- **Touch list** — files created or modified
- **Verify** — concrete check that the slice works end-to-end
- **Status** — current state

---

## Pass 0 — Walking skeleton  ✅

**Goal:** Every new subsystem callable end-to-end; every new MCP tool reachable; existing capability preserved.

**Touch list (create):**
- `RESEARCH_THREATS.md`, `RESEARCH_FEEDS.md` — copy from `~/.claude/plans/please-launch-a-research-snug-backus-agent-*.md` (✅ already done in plan-mode exit)
- `SPEC.md`, `PLAN.md` — this document and its companion (✅ already done)
- `src/services/AtlasService.ts` — stub returning hardcoded `AML.T0051` entry
- `src/services/OsvFeedService.ts` — stub returning `[]`
- `src/services/GhsaGraphQLService.ts` — stub returning `[]`
- `src/services/KevFeedService.ts` — stub returning `{count: 0, entries: []}`
- `src/services/HuggingFaceService.ts` — stub returning `{flags: []}`
- `src/services/TrifectaAnalyzer.ts` — stub returning `{trifectaPresent: false}`
- `src/services/CanaryService.ts` — stub returning hardcoded token
- `src/services/McpToolScanner.ts` — stub returning `{hash: "stub", findings: []}`
- `src/services/TasteTesterService.ts` — stub returning `{behaviorReport: {monitorVerdict: "clean", intents: []}}`
- `patterns/unicode-smuggling.json`, `policy-puppetry.json`, `markdown-exfil.json`, `mcp-tool-poisoning.json`, `many-shot.json`, `llm-threats.json` — each with one trivial example pattern (`enabled: false`)
- `src/test/v11SkeletonTests.ts` — one test per new service confirming stub returns

**Touch list (modify):**
- `src/mcp/mcpServer.ts` — register 6 new tools (`scan_mcp_tool`, `check_lethal_trifecta`, `query_cve`, `deploy_canary`, `verify_canary`, `taste_test`); each handler delegates to its stub service
- `src/index.ts` — instantiate new services and pass into mcpServer
- `patterns/manifest.json` — regenerate (root hash + HMAC)
- `package.json` — bump to `1.1.0-pre.0`; add `@anthropic-ai/sdk` dependency (used in Pass 11)
- `src/test/index.ts` (or test runner script) — include `v11SkeletonTests`

**Verify:**
1. `npm run build` — TypeScript compiles
2. `npm test` — all existing tests green + new skeleton tests green
3. `node dist/index.js` — server starts in default mode
4. Manual MCP probe: each of the 11 tools (5 existing + 6 new) returns a response without throwing
5. `verify_pattern_integrity` returns `valid: true` after manifest regen

---

## Pass 1 — Unicode smuggling detector  ✅

**Goal:** `check_prompt` catches invisible-instruction payloads.

**Touch list:**
- `patterns/unicode-smuggling.json` — enable detector patterns for:
  - U+E0000–U+E007F (Unicode Tag block)
  - U+200B–U+200F, U+FEFF (zero-width)
  - U+202A–U+202E, U+2066–U+2069 (bidi controls)
- Use `detection.mode: "threshold"` with `countThreshold: 3` to suppress false positives on isolated zero-width chars
- `src/services/GeminiService.ts` — system prompt adds Unicode-smuggling guidance
- `src/services/StaticCheckService.ts` — strip-and-flag helper exposing the stripped chars in finding evidence
- `patterns/manifest.json` — regen
- `src/test/unicodeSmugglingTests.ts` — tag-smuggled "DROP TABLE", invisible-prefix attack, mixed bidi payload

**Verify:** `check_prompt` on tag-smuggled "DROP TABLE\u{e0044}\u{e0052}\u{e004f}\u{e0050}…" returns `severity: critical, categories: ["unicode_smuggling"]`; benign Unicode emoji prompt returns `safe`.

---

## Pass 2 — Policy-puppetry structural detector  ✅

**Goal:** `check_prompt` catches HiddenLayer-style policy-wrapper jailbreaks.

**Touch list:**
- `patterns/policy-puppetry.json` — enable detectors for XML/JSON/INI/YAML in user content containing `policy|system|instruction|developer_message|role` tokens
- `src/services/GeminiService.ts` — add policy-puppetry hint
- `src/test/policyPuppetryTests.ts` — 5 corpus samples (INI, XML, JSON, YAML, mixed)

**Verify:** HiddenLayer fake-INI policy payload → `critical, category: policy_puppetry`. Benign config-file question (`"How do I parse an INI file in Python?"`) returns `safe`.

---

## Pass 3 — Markdown-exfil + indirect-injection seed corpus  ✅

**Goal:** `check_prompt` catches data-exfil vectors and known indirect-injection IOCs.

**Touch list:**
- `patterns/markdown-exfil.json` — patterns for `![text](http…?param={data})`, `javascript:` URIs, base64 query-string smuggling
- `patterns/prompt-injection.json` — supplement with Unit42 IOCs and a curated subset of Garak `promptinject` probes (Apache 2.0; track provenance in `source` field)
- `src/test/markdownExfilTests.ts`
- `scripts/import-garak-probes.ts` — one-shot script that pulls a pinned Garak commit, extracts probe strings, and emits PatternEntry candidates to `patterns/staging/`

**Verify:** Markdown image with query-param data URL flagged `critical`. Benign markdown image `![logo](https://example.com/logo.png)` returns `safe`. Garak subset detection rate ≥ 70% (recorded as baseline in CHANGELOG).

---

## Pass 4 — `scan_mcp_tool` — tool-poisoning scanner  ✅

**Goal:** New `scan_mcp_tool` MCP tool fully functional.

**Touch list:**
- `src/services/McpToolScanner.ts` — implement:
  - SHA-256 of canonicalized descriptor (`JSON.stringify` with sorted keys)
  - Imperative lint (`/ignore previous|you must|the user actually wants/i`)
  - Hidden-instruction lint (Unicode-tag + zero-width inside description/schema)
  - Drift detection vs `priorHash`
- `patterns/mcp-tool-poisoning.json` — enable patterns
- `src/mcp/mcpServer.ts` — flesh out handler
- `src/test/mcpToolScannerTests.ts` — poisoned + benign descriptors

**Verify:** OWASP MCP poisoning sample → flagged with at least one finding; benign tool (`{name: "list_files", description: "Lists files in a directory"}`) → `safe`; drift detected when `priorHash` mismatches.

---

## Pass 5 — `check_lethal_trifecta` — capability analyzer  ✅

**Goal:** New `check_lethal_trifecta` MCP tool fully functional; `scan_skill` also reports trifecta status.

**Touch list:**
- `src/services/TrifectaAnalyzer.ts` — implement:
  - Capability classifier maps tool names / capability strings / skill-content phrases to `{privateRead, untrustedFetch, egress}` buckets
  - Returns critical when all three present, medium when 2-of-3, safe otherwise
- `src/services/SkillScanService.ts` — call `TrifectaAnalyzer` from `scanSkill`; add `hasLethalTrifecta` to `SkillScanResult`
- `src/mcp/mcpServer.ts` — handler
- `src/test/trifectaTests.ts` — 3-of-3 / each 2-of-3 / each 1-of-3 / none

**Verify:** Skill with `read ~/.ssh/*` + `curl` + markdown-image render → `critical`; remove any one capability → drops to `medium`; remove two → `safe`.

---

## Pass 6 — Feed expansion: OSV.dev + GHSA GraphQL  ✅

**Goal:** `update_vuln_feeds` pulls AI-relevant CVEs from two new sources.

**Touch list:**
- `src/services/OsvFeedService.ts` — implement `/v1/querybatch`; AI-package allowlist (langchain, transformers, litellm, mlflow, ollama, llama-index, autogen, crewai, langgraph, vllm, sglang, anthropic-sdk-python, openai-python, transformers-js, openai, anthropic)
- `src/services/GhsaGraphQLService.ts` — implement `securityVulnerabilities` GraphQL query with ecosystem filter
- `src/services/VulnFeedService.ts` — orchestrate NVD + GHSA-GraphQL + OSV in parallel; aggregate counts in `update_vuln_feeds` response
- Keep existing GHSA REST as fallback when token absent
- `src/test/vulnFeedTests.ts` — extend with OSV + GHSA-GraphQL fixtures

**Verify:** `update_vuln_feeds({lookbackDays: 30})` returns `{nvd: N1, ghsaRest: N2, ghsaGraphql: N3, osv: N4}` with `N3 + N4 > 0`. At least one staged candidate has `source: "osv"` or `source: "ghsa-graphql"`.

---

## Pass 7 — MITRE ATLAS taxonomy + CISA KEV escalator  ✅

**Goal:** Findings carry ATLAS technique IDs; KEV-listed CVEs get severity bumped.

**Touch list:**
- `src/services/AtlasService.ts` — fetch `stix-atlas.json` from `https://github.com/mitre-atlas/atlas-navigator-data`; cache in `patterns/feed-cache/atlas-stix.json` with 7-day TTL; expose `lookup(techniqueId)` → details
- `src/services/KevFeedService.ts` — fetch CISA KEV catalog JSON daily; cache; expose `isInKev(cveId): boolean`
- `src/services/VulnFeedService.ts` — apply KEV escalator (`severity` += 1 level if in KEV); attach `inKev: true`
- All new pattern files — populate `atlasTechnique` field per SPEC §7 mapping
- `src/types/PatternEntry.ts` — add optional `atlasTechnique` field
- `src/services/PatternService.ts` — round-trip `atlasTechnique` through load/save
- `src/services/SkillScanService.ts` + `GeminiService.ts` — propagate ATLAS tags into `findings[]`
- `src/test/atlasTests.ts`, `src/test/kevTests.ts`

**Verify:** Existing prompt-injection pattern returns `atlasTechnique: "AML.T0051"` in findings. LiteLLM CVE-2026-42208 (known KEV-listed) staged with `inKev: true, severity: critical`. **Pass 7 also confirms the actual ATLAS IDs for Feb 2026 additions** (per SPEC §13 open question 4).

---

## Pass 8 — Hugging Face Hub security signals  ✅

**Goal:** `scan_skill` flags references to insecure models/datasets.

**Touch list:**
- `src/services/HuggingFaceService.ts` — `securityStatus` query; scan-result aggregation
- `src/services/SkillScanService.ts` — detect `huggingface.co/<owner>/<repo>` and `transformers.from_pretrained("<id>")` references in skill content; route through `HuggingFaceService`
- `src/test/huggingFaceTests.ts` — known-flagged model fixture + clean model

**Verify:** Skill referencing a model HF has flagged for unsafe serialization → `scan_skill` reports `huggingFaceSecurityFlags: [{model: "...", flag: "..."}]`; benign reference → empty array.

---

## Pass 9 — `query_cve` unified lookup  ✅

**Goal:** New `query_cve` MCP tool merges all feed sources.

**Touch list:**
- `src/services/UnifiedCveCache.ts` — merge NVD + OSV + GHSA + KEV + ATLAS records keyed by `cveId`; deduplicate; flag `sources[]`
- `src/services/VulnFeedService.ts` — populate cache during `updateFeeds`
- `src/mcp/mcpServer.ts` — `query_cve` handler with filters per SPEC §4.2
- `src/test/queryCveTests.ts`

**Verify:** `query_cve({keyword: "prompt injection"})` returns ≥ 3 unified records. `query_cve({inKev: true, ecosystem: "PyPI"})` returns the KEV-AI subset.

---

## Pass 10 — `deploy_canary` + `verify_canary`  ✅

**Goal:** Memory/RAG poisoning detection via canary tokens.

**Touch list:**
- `src/services/CanaryService.ts` — `issueToken({context?, ttlSeconds?})` + `checkEcho(content)`; UUID-formatted tokens; state persisted in `patterns/canary-state.json` (HMAC-signed via `CANARY_HMAC_SECRET` or fallback)
- `src/mcp/mcpServer.ts` — `deploy_canary`, `verify_canary` handlers
- `src/services/PatternService.ts` — also verify `canary-state.json` HMAC in `verify_pattern_integrity` rollup (optional integration)
- `src/test/canaryTests.ts` — issue / echo / TTL expiry / tamper detection

**Verify:** Issue token → embed in mock RAG context → call `verify_canary` on echoing response → `echoDetected: true, severity: critical`. Expired tokens → `echoDetected: false`.

---

## Pass 11 — `taste_test` — dual-agent sandbox (split 11a / 11b)  ✅

### Pass 11a — Architecture + Monitor + happy-path single-turn  ✅

**Goal:** `taste_test` callable end-to-end in fast mode; correct verdict on one known-malicious and one benign sample.

**Touch list:**
- `src/services/TasteTesterService.ts` — implement:
  - Anthropic SDK client construction; gate on `TASTE_TESTER_ENABLED`
  - Taster invocation with single mock tool (`fetch_url` only for 11a)
  - Monitor invocation with zod-validated structured output schema
  - Hard caps (`MAX_TURNS`, `MAX_TOKENS`, `TIMEOUT_MS`)
- `src/mcp/mcpServer.ts` — `taste_test` handler
- `src/test/tasteTesterTests.ts` — fixture-based (mock Anthropic responses); one malicious + one benign

### Pass 11b — Full mock tool surface + scoring + multi-turn  ✅

**Goal:** Thorough mode catches multi-turn Crescendo-style attacks.

**Touch list:**
- `src/services/TasteTesterService.ts` — add mock tools: `read_file`, `exec_shell`, `send_email`, `transfer_funds`, `navigate_browser`, `write_memory`, `query_database`
- Multi-turn loop with `MAX_TASTER_TURNS`
- Monitor scoring rubric calibrated against a 20-sample labeled corpus stored in `src/test/fixtures/taste-tester-corpus.json`
- ATLAS technique inference in Monitor output

**Verify (combined 11a + 11b):**
- Known indirect-injection payload from RESEARCH_THREATS §1 → `monitorVerdict: malicious, intents[0]: {action: "fetch_url", target: "<attacker host>", severity: "critical", atlasTechniques: ["AML.T0051"]}`
- Benign prompt (`"What is the capital of France?"`) → `monitorVerdict: clean, intents: []`
- With `TASTE_TESTER_ENABLED=false`, tool returns `{available: false}`
- Hard caps respected — cost-runaway test forces 100 turns, observes truncation at `MAX_TASTER_TURNS`

---

## Pass 12 — Many-shot heuristic + obfuscation expansion  ✅

**Goal:** `check_prompt` flags context-saturation and Crescendo signatures.

**Touch list:**
- `patterns/many-shot.json` — heuristic for ≥ N alternating Q/A pairs followed by an instruction-tail divergence
- Extend existing obfuscation patterns: Sneaky Bits two-char encoder, additional homoglyph homographs (Cyrillic confusables), Base32/Base85, hex chunks
- `src/services/StaticCheckService.ts` — many-shot scoring (token-window heuristic)
- `src/test/manyShotTests.ts`

**Verify:** 50-pair synthetic Q/A + divergent instruction tail → `category: many_shot, severity: high`. Normal 5-turn conversation history → `safe`.

---

## Pass 13 — Hardening, docs, ship  ✅

**Goal:** v1.1.0 release candidate.

**Touch list:**
- Update `README.md`:
  - New tool list section
  - New feed sources section
  - New env vars table (including `TASTE_TESTER_ENABLED`)
  - "Defense in depth, not silver bullet" disclaimer per SPEC §1
- `CHANGELOG.md` — `[1.1.0] - 2026-XX-XX` entry covering every pass; include Garak adversarial regression baseline number
- `SKILLS_SECURITY.md` — extend with lethal-trifecta + HF security signals + ATLAS taxonomy
- `patterns/manifest.json` — final regen + HMAC re-sign
- `package.json` — bump to `1.1.0` (remove `-pre.0` suffix)
- `scripts/smoke-v1.1.ts` — end-to-end MCP-client smoke test exercising all 11 tools
- Resolve all `[unverified]` markers per SPEC §13:
  - Confirm or correct CVE-2026-2796 in NVD
  - Confirm MemoryGraft arXiv ID
  - Confirm `AML.T0070` / `AML.T0071` against live ATLAS bundle
- Run full regression: `npm test`, `npm run build`, smoke test, server boot in all three modes

**Verify (per SPEC §11 matrix, full):** every row passes; document each verification result inline in this PLAN.md under the matching pass.

---

## Cross-cutting concerns

### Testing strategy
- Unit tests per service in `src/test/*.ts` (the project's existing pattern)
- All new tests added to `npm test` runner sequence in `package.json`
- Fixture-based for SDK-dependent tests (no live Anthropic calls in CI)
- Garak adversarial regression as a separate `npm run test:adversarial` script (not in default `npm test` due to runtime)

### Commit hygiene
- One commit per pass, conventional commit prefix (`feat:`, `chore:`, `docs:`, `test:`)
- Each commit leaves `npm test` green and the server runnable
- Pattern manifest regenerated **in the same commit** that adds/modifies a pattern file
- No commit lands with `[unverified]` SPEC items unresolved at Pass 13

### Risk register
Carried from SPEC §13. Resolved items struck through here as work progresses.

| # | Risk | Pass | Resolution |
|---|---|---|---|
| 1 | CVE-2026-2796 unverified | 13 | **2026-05-18:** verified against NVD — CVE exists but maps to Firefox WebAssembly JIT bug, NOT ClaudeBleed; kept `[unverified]` in §2, claim now flagged as advisory in SPEC §13.1 |
| 2 | MemoryGraft arXiv ID unverified | 13 | **2026-05-18:** verified against arXiv — paper/title/authors/date all confirmed; resolved |
| 3 | OWASP LLM 2026 still draft | 13 | **2026-05-18:** verified against genai.owasp.org — 2026 edition not published; 2025 remains operative; resolved (using 2025 by design) |
| 4 | ATLAS Feb 2026 IDs unconfirmed | 7 | **2026-05-18:** could not be verified (atlas.mitre.org 404, STIX bundle truncated); kept `[unverified]` with fallback table in `AtlasService`; Cluster-E follow-up if canonical ID differs |
| 5 | Taster MAX_TURNS=5 uncalibrated | 11b | **Resolved with adverse finding** (see SPEC §13.1 row 5); real-API calibration `2026-05-14` `scripts/calibrate-taste-tester.ts` 10/20 agreement; complementary-not-replacement positioning documented |
| 6 | Mock tool router I/O leak | 11a/b | **Resolved** — mock tools verified as pure functions returning canned strings during Pass 11a/11b review |
| 7 | Monitor itself prompt-injectable | 11a | **Resolved** — Monitor responses parsed through zod-validated `BehaviorReport` schema with neutral-stub fallback on non-conforming output |
| 8 | Garak detection rate baseline unknown | 3 | **Deferred to v1.2** — curated Garak probes shipped in `patterns/prompt-injection.json` with provenance, full adversarial regression run not yet recorded; tracked as known limitation in CHANGELOG |

### Workflow hooks (per session-start reminder)
- Run `project-kickoff-template` at start of each execution session.
- Run `project-notebooklm-plan-sync` after this PLAN.md or SPEC.md changes.
- Run `project-update-history` before each session ends.
- Use `vertical-slice-dev` skill at the start of execution to enforce walking-skeleton discipline across all passes.

### When to commit
After each pass passes its **Verify** step:
1. `npm test` green
2. `npm run build` clean
3. `verify_pattern_integrity` green (if patterns touched)
4. Commit with passing CI signal locally
5. Update this PLAN.md: mark pass `✅ done` and note any resolutions to the risk register

---

## Execution log

This section is updated as passes complete. Each entry: pass number, completion date, brief note, link to commit.

| Pass | Completed | Commit | Note |
|---|---|---|---|
| 0 | 2026-05-13 | `24e7dbb` | Walking skeleton — 6 new MCP tools reachable, 9 new service stubs wired |
| 1 | 2026-05-13 | `3d8b366` | Unicode smuggling — Tag block + zero-width + bidi controls with threshold gating |
| 2 | 2026-05-13 | `5066946` | Policy-puppetry — XML/INI/JSON/YAML fake-policy wrapper detection |
| 3 | 2026-05-13 | `457793d` | Markdown-exfil patterns + curated indirect-injection IOC seed corpus |
| 4 | 2026-05-13 | `cd70003` | `scan_mcp_tool` — canonical-hash + imperative/Unicode lint + drift detection |
| 5 | 2026-05-13 | `8f92168` | `check_lethal_trifecta` — capability classifier (private/fetch/egress) |
| 6 | 2026-05-13 | `f8df98b` | OSV.dev `/v1/querybatch` + GHSA GraphQL with AI-package allowlist |
| 7 | 2026-05-13 | `e9297da` | MITRE ATLAS STIX bundle + CISA KEV severity escalator + `atlasTechnique` field |
| 8 | 2026-05-13 | `3c8fc09` | Hugging Face `securityStatus` integration in `scan_skill` |
| 9 | 2026-05-13 | `9cc9d15` | `query_cve` — unified read across NVD/OSV/GHSA/KEV/ATLAS |
| 10 | 2026-05-13 | `e784938` | `deploy_canary` / `verify_canary` — UUID + HMAC-state + TTL pruning |
| 11a | 2026-05-13 | `dc8e251` | Taste-Tester architecture, Monitor zod schema, fast-mode single-turn |
| 11b | 2026-05-13 | `ec04cac` | Full mock-tool surface + multi-turn loop + 20-sample labeled corpus (20/20) |
| 12 | 2026-05-13 | `fe7d64d` | Many-shot heuristic + Sneaky-Bits/Cyrillic/Base32/hex obfuscation expansion |
| 13 | 2026-05-14 | `31868ea` | Hardening, docs, ship — README/CHANGELOG/SKILLS_SECURITY/SPEC §13.1, smoke script `scripts/smoke-v1.1.ts`, manifest regen + HMAC re-sign, `1.1.0-pre.0`→`1.1.0` bump, enumerated-Q FP fix; v1.1.0 tag |
