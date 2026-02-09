# Changelog

All notable changes to Prompt Rejector will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
