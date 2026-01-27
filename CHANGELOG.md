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
