# Changelog

All notable changes to Prompt Rejector will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-05-14

### 🚀 LLM/Agentic Threat Expansion

A major coverage expansion adding **6 new MCP tools** and **5 new vulnerability-feed sources** to address the late-2025/2026 shift toward LLM-native attacks (Policy Puppetry, Unicode-tag smuggling, MCP tool poisoning, lethal trifecta, indirect injection, RAG/memory poisoning, many-shot jailbreaks). Delivered as 13 vertical-slice passes; every pass left the system fully runnable, tested, and committable.

> **Defense in depth, not silver bullet.** A 2026 meta-study of 78 defense papers found that adaptive attacks still beat ~85% of state-of-the-art single defenses. Prompt Rejector v1.1.0 stacks five complementary layers (static patterns, semantic LLM analysis, taxonomy-tagged vulnerability feeds, lethal-trifecta capability analysis, and a sandboxed Taste-Tester dynamic detonator) but does not guarantee detection. Use it as one layer among many.

### Added

#### New MCP Tools

- **`scan_mcp_tool`** — Hash + lint MCP tool descriptors for poisoning. Detects imperative override language, "ignore previous" phrases, hidden HTML comments, priority claims, authority claims, hidden Unicode-tag/zero-width chars, and drift vs a known-good SHA-256 hash.
- **`check_lethal_trifecta`** — Static analyzer for Willison's lethal trifecta (private-data read + untrusted-content fetch + external egress). Returns *critical* when all three capabilities are co-located in one agent, *medium* on any 2-of-3.
- **`query_cve`** — Unified CVE lookup across NVD, OSV, GHSA REST, GHSA GraphQL, CISA KEV, and MITRE ATLAS. Filters by keyword, ecosystem, severity, ATLAS technique, and KEV-only.
- **`deploy_canary`** / **`verify_canary`** — Memory/RAG poisoning detection via UUIDv4 canary tokens. HMAC-signed state file, TTL-pruned, scan content for echoes returning `severity: critical` on match.
- **`taste_test`** — User-designed dual-agent sandbox detonator (the "Taste-Tester"). Taster + Monitor architecture with structured zod-validated verdicts; gated behind `TASTE_TESTER_ENABLED`. See SPEC §5.

#### New Detection Categories

- **`unicode_smuggling`** — Unicode Tag block (U+E0000–U+E007F), zero-width characters (U+200B–U+200F, U+FEFF), bidirectional overrides (U+202A–U+202E, U+2066–U+2069); Sneaky Bits two-char encoder
- **`policy_puppetry`** — XML/INI/JSON/YAML fake-policy wrappers per HiddenLayer (April 2025)
- **`markdown_exfil`** — markdown image/link exfiltration plus `javascript:` and `data:text/html` URI schemes
- **`mcp_tool_poisoning`** — imperatives, "ignore previous," HTML-comment side-channels in MCP tool descriptors
- **`many_shot`** — Q/A pair stacks (≥20), turn-marker stacks (≥30), and enumerated `Q1:`/`Question 1:` stacks (≥15) per Anthropic 2024
- **`prompt_injection`** — 8 hand-curated IOC patterns (ignore-previous, act-as, safety-bypass, system-prompt extraction, etc.)
- **Obfuscation expansion** — Cyrillic homoglyphs, Base32 chunks (≥32 chars), hex chunks (≥60 chars)

#### New Feed Sources

- **OSV.dev `/v1/querybatch`** with an AI-package allowlist (PyPI: langchain, langchain-core, langchain-community, langgraph, llama-index, autogen, crewai, transformers, vllm, sglang, litellm, mlflow, ollama, openai, anthropic; npm: @langchain/core, @langchain/community, langchain, @huggingface/transformers, @anthropic-ai/sdk, openai, ollama, llamaindex). Full list in `src/services/aiPackageAllowlist.ts`.
- **GHSA GraphQL** `securityVulnerabilities` query with ecosystem filter
- **MITRE ATLAS v5.4 taxonomy** with 7-day cache and offline fallback table
- **CISA KEV catalog** with 24h cache and severity escalator (`severity` bumps one level when CVE is KEV-listed; entry receives `inKev: true`)
- **Hugging Face Hub `securityStatus`** with 6h in-memory cache

#### New Architecture

- **`TasteTesterService`** — dual-agent sandbox detonator with 8 pure-function mock tools, multi-turn loop, structured Monitor verdict, AbortController-driven timeouts, and an `anthropicFactory` injection seam for tests
- **`TrifectaAnalyzer`** — rule-data-driven capability classifier with three buckets (private-read / untrusted-fetch / external-egress) and per-bucket signal tracing
- **`AtlasService`**, **`KevFeedService`**, **`OsvFeedService`**, **`GhsaGraphQLService`**, **`HuggingFaceService`**, **`UnifiedCveCache`**, **`CanaryService`**, **`McpToolScanner`**
- `PatternEntry.atlasTechnique?: string` — optional new field, additive only
- `evaluatePattern()` shared helper factored out of `StaticCheckService` for use by both the static checker and the MCP-tool scanner

### Changed

- `PatternEntrySchema.source` enum extended with `"ghsa_graphql"` and `"osv"`
- `VulnFeedResult` gains `perSource: { nvd, ghsaRest, ghsaGraphql, osv }` count breakdown
- `SkillScanResult` gains `hasLethalTrifecta`, `trifectaResult`, `huggingFaceSecurityFlags`, `huggingFaceReports`, `atlasTechniques[]`
- `scan_skill` now bubbles `trifectaResult` into `overallSeverity` and `isDangerous` — a skill with all three lethal-trifecta capabilities returns `safe: false` with severity `critical`. Previously the trifecta result was computed and reported on `hasLethalTrifecta` but did not influence the final risk decision. Pre-release fix (v1.1.0 lives only on `claude/hopeful-brahmagupta-338986` at time of writing); no shipped consumers affected.
- `SecurityReport` gains `atlasTechniques[]`
- Threshold-mode pattern detection now properly honored (previously bypassed by a simple-match path on some entries)
- Existing patterns regenerated with `atlasTechnique` field on relevant categories

### Test coverage

- **457 tests / 0 failures across 17 suites** at the v1.1.0 tag commit `31868ea` (up from 87 in v1.0.2). Post-tag cluster fixes adjust these totals further and will be reported in their own entry.
- 20-sample labeled Taste-Tester corpus in `src/test/fixtures/taste-tester-corpus.json` (20/20 pass against scripted-mock Taster flow; this measures Monitor verdict logic, not real-API predictive accuracy)
- Mock `fetch` and mock Anthropic SDK helpers in `src/test/helpers/` keep all tests offline by default
- Curated subset of Garak `promptinject` probes (Apache 2.0; provenance tracked in `PatternEntry.source`) shipped in `patterns/prompt-injection.json` — full adversarial regression baseline against `check_prompt` deferred to v1.2

### Documentation

- New `SPEC.md` — full v1.1 architecture, threat model, tool catalog, feed catalog, sandbox design, verification matrix, risk register
- New `PLAN.md` — 13-pass vertical-slice execution plan with completed execution log
- New `RESEARCH_THREATS.md`, `RESEARCH_FEEDS.md` — research notes underpinning the threat-model and feed-source choices
- `README.md` extended with v1.1.0 tool/feed/env coverage and defense-in-depth disclaimer (existing structure preserved)
- `SKILLS_SECURITY.md` extended with lethal-trifecta, Hugging Face security signals, and ATLAS taxonomy sections

### Tooling

- `scripts/smoke-v1.1.ts` — end-to-end MCP-client smoke test exercising all 11 tools (5 existing + 6 new). Tolerates network unavailability; non-network paths must pass even offline. Run:
  ```bash
  GEMINI_API_KEY=dummy CANARY_HMAC_SECRET=test-secret npx tsx scripts/smoke-v1.1.ts
  ```

### Configuration (new env vars, all optional with safe defaults)

```env
# Feeds
GITHUB_TOKEN=...                  # also used for GHSA GraphQL
HF_TOKEN=...                      # Hugging Face Hub security signals
KEV_REFRESH_INTERVAL_HOURS=24
ATLAS_REFRESH_INTERVAL_HOURS=168

# Taste-Tester (opt-in)
TASTE_TESTER_ENABLED=false
TASTE_TESTER_MODEL=claude-opus-4-7
TASTE_TESTER_MAX_TURNS=5
TASTE_TESTER_MAX_TOKENS=4096
TASTE_TESTER_TIMEOUT_MS=30000
ANTHROPIC_API_KEY=...

# Canary
CANARY_HMAC_SECRET=...            # falls back to PATTERN_INTEGRITY_SECRET if unset
CANARY_DEFAULT_TTL_SECONDS=86400
```

### Known limitations / risk register (carried from SPEC §13)

See `SPEC.md` §13.1 for full status of each entry.

- **CVE-2026-2796 (ClaudeBleed)** — **2026-05-18 verification:** the CVE ID exists in NVD but maps to a Firefox/Thunderbird WebAssembly JIT bug (Mozilla source), **not** the claimed Chrome-extension Claude-in-Chrome hijack. The "ClaudeBleed" narrative is preserved as advisory only; consumers should not cite this CVE ID for that claim. Project scope is prompts/skills, not Chrome-extension runtime, so no detection rule depends on this ID. See SPEC §13.1 row 1.
- **MemoryGraft arXiv ID `2512.16962`** — **2026-05-18 verified.** Paper exists ("MemoryGraft: Persistent Compromise of LLM Agents via Poisoned Experience Retrieval"; Srivastava & He, 2025-12-18). Cited for narrative context; no code path depends on the ID.
- **ATLAS Feb-2026 technique IDs (`AML.T0070`, `AML.T0071`)** — `[unverified]` against live STIX bundle; the `atlas.mitre.org` 404'd both pages on 2026-05-18 and the bundle response truncated before the matching `attack-pattern` objects. Fallback table tags note this. Real-bundle reconciliation deferred to v1.2.
- **OWASP LLM Top 10 2026** — **2026-05-18 verified.** genai.owasp.org lists the 2025 list as operative; no 2026 release. Project design choice to track v2025 stands.
- **Taste-Tester real-API calibration (2026-05-14, claude-opus-4-7, fast mode, 20-sample corpus): 10/20 agreement.** Perfect benign classification (10/10) but zero direct-malicious detection (0/9, 0/1 suspicious — `mal-crescendo` was the closest miss at `suspicious`). The Taster's safety training refused most direct-attack prompts, producing clean transcripts that the Monitor correctly graded as clean. **The Taste-Tester catches *enacted* malicious behavior, not *refused* malicious intent** — its real value is for subtle indirect-injection payloads that bypass static + semantic + safety-training filters, not for re-detecting attacks the base model already refuses. The pre-release scripted-mock baseline (20/20) measured Monitor verdict propagation under canned transcripts, not real-API behavior — these are different things and the gap is precisely why a real calibration was warranted. A v1.2 corpus should focus on indirect-injection via tool-result tripwires (the `SYNTHETIC_FETCH_BODY` `sk-test-FAKE` flow) rather than direct user-prompt attacks. Calibration script: `scripts/calibrate-taste-tester.ts`.
- **Garak adversarial regression** — full baseline against `check_prompt` not yet recorded; deferred to v1.2.

---

## [1.0.0] - 2026-01-27

### 🎉 Initial Release

The first public release of Prompt Rejector — a dual-layer security gateway for AI agents and applications.

### Added

#### Core Features
- **Dual-Layer Detection Architecture**
  - Semantic analysis via Google Gemini 3 Flash
  - Static pattern matching with optimized regex
  - Results aggregation with severity rollup

- **Prompt Injection Detection**
  - Classic "ignore instructions" attacks
  - Role-play and persona jailbreaks (DAN, HelpfulBot, etc.)
  - Social engineering and fake authority claims
  - "Sandwiched" attacks (malicious content between benign context)

- **Obfuscation Detection**
  - Base64 encoded payloads (with automatic decoding analysis)
  - Hidden HTML/Markdown comments
  - Unicode tricks and homoglyphs

- **Multilingual Attack Detection**
  - Supports detection in any language
  - Specifically tested with German, Chinese, and other non-English attacks
  - Tags attacks with `multilingual` category for analysis

- **Traditional Vulnerability Detection**
  - XSS (Cross-Site Scripting) patterns
  - SQL Injection patterns
  - Shell injection and command execution
  - Directory traversal (`../`)
  - Sensitive file access (`/etc/passwd`)

- **Severity Scoring System**
  - Four levels: `low`, `medium`, `high`, `critical`
  - Automatic rollup from both detection layers
  - Actionable routing guidance

- **Category Taxonomy**
  - `prompt_injection` - Core LLM attacks
  - `social_engineering` - Manipulation attempts
  - `obfuscation` - Encoded/hidden content
  - `multilingual` - Non-English evasion
  - `xss` - Cross-site scripting
  - `sqli` - SQL injection
  - `shell_injection` - Command injection
  - `directory_traversal` - Path traversal

#### Interfaces
- **REST API**
  - `POST /v1/check-prompt` - Main security check endpoint
  - `GET /health` - Health check endpoint
  - JSON request/response format
  - CORS enabled

- **MCP Server**
  - Full Model Context Protocol support
  - `check_prompt` tool for AI agents
  - Compatible with Claude, Cursor, and other MCP clients
  - Stdio transport

#### Configuration
- Environment variable configuration via `.env`
- Configurable startup mode (`api`, `mcp`, or `both`)
- Configurable API port

### Validated

Successfully tested against 14 attack vectors with 100% detection rate:

| Test | Attack Type | Result |
|------|-------------|--------|
| 1 | Benign baseline | ✅ Correctly allowed |
| 2 | Classic prompt injection | ✅ Detected (critical) |
| 3 | SQL Injection | ✅ Detected (critical) |
| 4 | XSS | ✅ Detected (high) |
| 5 | German language injection | ✅ Detected (high) |
| 6 | Chinese language injection | ✅ Detected (high) |
| 7 | Base64 encoded attack | ✅ Detected (high) |
| 8 | CSV formula injection | ✅ Detected (high) |
| 9 | Hidden HTML comment | ✅ Detected (high) |
| 10 | Role-play jailbreak | ✅ Detected (high) |
| 11 | Fake authorization | ✅ Detected (critical) |
| 12 | Sandwiched attack | ✅ Detected (high) |
| 13 | Educational query | ✅ Correctly allowed |
| 14 | DAN jailbreak | ✅ Detected (critical) |

### Technical Details

- **Runtime:** Node.js 18+
- **Language:** TypeScript 5.9
- **LLM:** Google Gemini 3 Flash (preview)
- **Framework:** Express 5.x
- **MCP SDK:** @modelcontextprotocol/sdk 1.25

---

## [1.0.2] - 2026-02-08

### Added

- **Dynamic Pattern Library** — File-based pattern CRUD via `PatternService` with `patterns/` directory. Supports two detection modes: `simple` (any match) and `threshold` (count/length gating).
- **Vulnerability Intelligence** — `VulnFeedService` scans NVD and GitHub Advisory databases for new CVEs (XSS, SQLi, command injection, path traversal, SSRF) and generates candidate detection patterns via Gemini, staged for human review.
- **Integrity Verification** — SHA-256 file hashes + optional HMAC signature in `patterns/manifest.json`. Automatic fallback to compiled-in patterns on verification failure.
- **Skill Scanning** — `SkillScanService` with 6 threat categories: hidden instructions, dangerous tool usage, sensitive file access, obfuscation, social engineering, and network exfiltration.
- 3 new MCP tools: `list_patterns`, `update_vuln_feeds`, `verify_pattern_integrity`
- 3 new REST endpoints: `GET /v1/patterns`, `POST /v1/patterns/update-feeds`, `POST /v1/patterns/verify`
- `npm test` now runs offline test suites (patternService, integration, vulnFeed)

### Changed

- `GeminiService` now exposes `generateRaw()` for non-security Gemini calls
- `GeminiService` returns `error: true` and `severity: "medium"` on API failure (was `severity: "low"`)
- `SecurityReport` includes `geminiAvailable` field indicating whether the LLM check succeeded
- `VulnFeedResult.errors` are now structured objects (`{ source, cveId?, message }`) instead of plain strings
- `PatternService.remove()` renamed to `disable()` for clarity (it soft-disables, not deletes)
- Shell metacharacters pattern moved from general scope to skill scope to avoid false positives on `$50`, `Q&A`, etc.
- Hardcoded regex fallback path now returns fresh `RegExp` instances per call (fixes `lastIndex` state pollution)
- Severity handling simplified: removed `severityBehavior` field, all severity is now max-wins
- `VulnFeedService` uses atomic writes for staging file
- `VulnFeedService` uses public `generateRaw()` instead of accessing `GeminiService` private internals

### Security

- Input length limits: prompts capped at 100K chars, skill content at 500K chars (REST + MCP)
- CORS is now configurable via `CORS_ORIGIN` env var (was hardcoded `*`)

### Fixed

- `lastIndex` pollution on hardcoded regex arrays causing intermittent false negatives
- Version string in health endpoint and MCP server now reads from `package.json` (was hardcoded `1.0.0`)
- Removed unused `zod` import from MCP server

### Removed

- `severityBehavior` field from pattern schema, all pattern files, and fallback patterns
- `src/listModels.ts` moved to `scripts/listModels.ts` (utility, not part of build)

## [Unreleased]

### Planned
- Response caching for repeated inputs
- Configurable severity thresholds
- Additional static detection patterns
- Webhook notifications for critical threats
- Prometheus metrics endpoint
- Docker image
- npm package publication

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 1.1.0 | 2026-05-14 | LLM/agentic threat expansion: 6 new MCP tools, 5 new feed sources, Taste-Tester sandbox, lethal-trifecta analyzer |
| 1.0.2 | 2026-02-08 | Pattern library, vuln feeds, skill scanning, code review fixes |
| 1.0.1 | 2026-02-01 | MCP publishing setup |
| 1.0.0 | 2026-01-27 | Initial release with dual-layer detection |

---

## Upgrade Guide

### Upgrading to 1.x

This is the initial release. For future upgrades, migration guides will be provided here.

---

## Deprecations

None yet.

---

## Security Fixes

None yet. For security vulnerability reports, see [CONTRIBUTING.md](CONTRIBUTING.md#security-vulnerability-reporting).
