# Contributing to Prompt Rejector

First off, thank you for considering contributing to Prompt Rejector! 🛡️

This project aims to make AI agents safer by providing a robust defense against prompt injection and other attacks. Every contribution helps protect developers and their users.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Submitting Pull Requests](#submitting-pull-requests)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Guidelines](#coding-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Security Vulnerability Reporting](#security-vulnerability-reporting)

---

## Code of Conduct

This project adheres to a simple code of conduct: **be respectful, be constructive, and be helpful**. We're all here to make AI safer.

---

## How Can I Contribute?

### Reporting Bugs

Found a bug? We'd love to hear about it!

**Before submitting:**
1. Search existing issues to avoid duplicates
2. Try to reproduce with the latest version

**When submitting, include:**
- Clear, descriptive title
- Steps to reproduce
- Expected vs. actual behavior
- Your environment (Node.js version, OS, etc.)
- Relevant logs or error messages

**Example bug report:**
```markdown
### Bug: False positive on legitimate SQL query discussion

**Environment:** Node.js 20.x, macOS 14.0

**Steps to reproduce:**
1. Send prompt: "Can you explain how SELECT * FROM users works?"
2. Check result

**Expected:** safe: true (educational query)
**Actual:** safe: false, categories: ["sqli"]

**Notes:** The static checker seems to trigger on any SQL keywords.
```

### Suggesting Features

Have an idea to improve Prompt Rejector? Open a feature request!

**Great feature requests include:**
- Clear description of the problem it solves
- Proposed solution (if you have one)
- Use cases and examples
- Consideration of potential drawbacks

**Areas we're especially interested in:**
- New attack vector detection
- Performance optimizations
- Additional language/framework integrations
- Better developer experience

### Submitting Pull Requests

Ready to contribute code? Awesome! Here's the process:

1. **Fork the repository** and create your branch from `main`
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

2. **Make your changes** following our [coding guidelines](#coding-guidelines)

3. **Test your changes** thoroughly (see [testing guidelines](#testing-guidelines))

4. **Commit with clear messages**
   ```bash
   git commit -m "feat: add detection for Unicode homoglyph attacks"
   # or
   git commit -m "fix: reduce false positives on educational SQL queries"
   ```

5. **Push and open a PR**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Fill out the PR template** with:
   - What the PR does
   - Why it's needed
   - How to test it
   - Any breaking changes

---

## Development Setup

```bash
# 1. Clone your fork
git clone https://github.com/YOUR_USERNAME/promptrejectormcp.git
cd promptrejectormcp

# 2. Install dependencies
npm install

# 3. Set up environment
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY

# 4. Build
npm run build

# 5. Run in development mode
npm run dev
```

### Prerequisites

- Node.js 18.x or higher
- npm 9.x or higher
- A Google AI API key (free at https://aistudio.google.com/apikey)

---

## Project Structure

```
promptrejectormcp/
├── src/
│   ├── index.ts                       # Entry point — picks mode, redirects stdout under MCP
│   ├── api/
│   │   └── server.ts                  # REST API (Express)
│   ├── mcp/
│   │   └── mcpServer.ts               # MCP server (11 tools)
│   ├── schemas/
│   │   └── PatternSchemas.ts          # Zod schemas for the pattern library
│   ├── services/
│   │   ├── SecurityService.ts         # Main aggregator (check_prompt)
│   │   ├── SkillScanService.ts        # scan_skill aggregator
│   │   ├── GeminiService.ts           # LLM-based semantic detection
│   │   ├── StaticCheckService.ts      # Regex pattern detection
│   │   ├── PatternService.ts          # File-based pattern library + integrity
│   │   ├── VulnFeedService.ts         # NVD + GHSA scanning → staged patterns
│   │   ├── KevFeedService.ts          # CISA KEV catalog ingest (v1.1)
│   │   ├── OsvFeedService.ts          # OSV/deps.dev feed ingest (v1.1)
│   │   ├── GhsaGraphQLService.ts      # GitHub Advisory GraphQL client (v1.1)
│   │   ├── UnifiedCveCache.ts         # Cross-feed CVE de-duplication (v1.1)
│   │   ├── AtlasService.ts            # MITRE ATLAS taxonomy lookup (v1.1)
│   │   ├── TrifectaAnalyzer.ts        # Lethal-Trifecta detector (v1.1)
│   │   ├── HuggingFaceService.ts      # HF Hub security-flag lookup (v1.1)
│   │   ├── McpToolScanner.ts          # MCP-tool-manifest scanner (v1.1)
│   │   ├── CanaryService.ts           # Canary-token issue/verify (v1.1)
│   │   ├── TasteTesterService.ts      # Dual-agent sandbox detonator (v1.1)
│   │   ├── fallbackPatterns.ts        # Hardcoded emergency patterns
│   │   └── aiPackageAllowlist.ts      # Trusted-package allowlist for HF/PyPI checks
│   └── test/                          # Standalone test scripts (run via npx tsx)
├── patterns/                          # JSON pattern library + manifest
├── dist/                              # Compiled output
└── docs/                              # Additional documentation
```

### Key Files

| File | Purpose |
|------|---------|
| `SecurityService.ts` | Orchestrates Gemini + static layers for `check_prompt` |
| `SkillScanService.ts` | Aggregates Gemini + static + skill-specific + trifecta + HF for `scan_skill` |
| `GeminiService.ts` | Semantic analysis via Gemini API |
| `StaticCheckService.ts` | Fast regex-based pattern matching |
| `TrifectaAnalyzer.ts` | Detects co-location of private-read / untrusted-fetch / external-egress |
| `HuggingFaceService.ts` | Looks up model security flags via the HF Hub API |
| `AtlasService.ts` | Maps findings to MITRE ATLAS technique IDs |
| `TasteTesterService.ts` | Dual-agent (Anthropic) dynamic detonator for suspicious prompts |
| `server.ts` | REST API endpoints |
| `mcpServer.ts` | MCP protocol implementation |

---

## Coding Guidelines

### TypeScript Style

- Use TypeScript strict mode
- Prefer `interface` over `type` for object shapes
- Use explicit return types on public functions
- Document complex logic with comments

```typescript
// Good
interface SecurityResult {
  safe: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

async function checkPrompt(input: string): Promise<SecurityResult> {
  // Implementation
}

// Avoid
const checkPrompt = async (input) => {
  // No types, arrow function for top-level
}
```

### Naming Conventions

- **Files:** camelCase for modules (`myService.ts`), PascalCase for classes
- **Variables:** camelCase (`userInput`, `isInjection`)
- **Constants:** UPPER_SNAKE_CASE (`MAX_RETRIES`, `DEFAULT_PORT`)
- **Interfaces:** PascalCase, descriptive (`SecurityCheckResult`, `GeminiResponse`)

### Error Handling

- Always catch and handle errors gracefully
- Log errors to stderr (not stdout, to preserve MCP compatibility)
- Provide meaningful error messages

```typescript
try {
  const result = await geminiService.checkPrompt(input);
  return result;
} catch (error) {
  console.error('Gemini check failed:', error);
  // Return safe default, let static checks handle it
  return {
    isInjection: false,
    confidence: 0,
    explanation: 'Gemini check failed, relying on static analysis'
  };
}
```

---

## Testing Guidelines

### Types of Tests

1. **Unit Tests** - Test individual services in isolation
2. **Integration Tests** - Test the full API flow
3. **Attack Vector Tests** - Verify detection of known attacks

### Test Suites

Tests are standalone scripts in `src/test/` — there is no test runner. The `npm test` chain (see `package.json`) runs every offline suite sequentially. Suites that hit a real API (Gemini, Anthropic, Hugging Face) are excluded from `npm test` and must be invoked explicitly with the relevant API key set.

| Suite | Covers | Online? |
|-------|--------|---------|
| `patternServiceTests.ts` | Pattern CRUD, integrity manifest, HMAC | offline |
| `integrationTests.ts` | End-to-end regression on the refactored services | offline |
| `vulnFeedTests.ts` / `vulnFeed2Tests.ts` | NVD + GHSA ingest with mocked HTTP | offline |
| `v11SkeletonTests.ts` | v1.1 service wiring smoke test | offline |
| `unicodeSmugglingTests.ts` | Zero-width / tag-char / homoglyph payloads | offline |
| `policyPuppetryTests.ts` | XML/JSON role-puppetry jailbreaks | offline |
| `markdownExfilTests.ts` | Image/link-based exfil patterns | offline |
| `mcpToolScannerTests.ts` | MCP-tool-manifest scanner | offline |
| `trifectaTests.ts` | Lethal-Trifecta analyzer | offline |
| `atlasKevTests.ts` | ATLAS + KEV feed ingest and lookup | offline |
| `huggingFaceTests.ts` | HF Hub security-flag parser | offline |
| `queryCveTests.ts` | Unified CVE cache + `query_cve` MCP tool | offline |
| `canaryTests.ts` | Canary-token issue/verify lifecycle | offline |
| `tasteTesterTests.ts` | Taste-Tester unit tests with stubs | offline |
| `tasteTesterCorpusTests.ts` | Real-API Taste-Tester calibration corpus | requires `ANTHROPIC_API_KEY` |
| `manyShotObfuscationTests.ts` | Many-shot jailbreak corpus | offline |
| `advancedTests.ts` | 7 attack-vector scenarios | requires `GEMINI_API_KEY` |
| `skillScanTests.ts` | 7 SKILL.md scan scenarios | requires `GEMINI_API_KEY` |

When adding new detection logic, prefer extending one of these suites. New behavior should at minimum be exercised by an offline suite so it lands in `npm test`.

### Writing Tests

```typescript
// Example test structure
describe('StaticCheckService', () => {
  describe('SQL Injection Detection', () => {
    it('should detect classic OR 1=1 attack', () => {
      const result = staticChecker.check("' OR '1'='1");
      expect(result.hasSQLi).toBe(true);
      expect(result.categories).toContain('sqli');
    });

    it('should NOT flag educational SQL discussion', () => {
      const result = staticChecker.check("How does SELECT work in SQL?");
      expect(result.hasSQLi).toBe(false);
    });
  });
});
```

### Running Tests

```bash
# Run all offline suites (recommended before opening a PR)
npm test

# Run a single suite directly (use npx tsx, not ts-node — ESM compat)
npx tsx src/test/trifectaTests.ts

# Run the online suites — set the relevant key first
GEMINI_API_KEY=... npx tsx src/test/advancedTests.ts
ANTHROPIC_API_KEY=... npx tsx src/test/tasteTesterCorpusTests.ts
```

There is no coverage tool wired up yet.

---

## Pull Request Checklist

Before submitting your PR, ensure:

- [ ] Code builds without errors (`npm run build`)
- [ ] All existing tests pass
- [ ] New features have corresponding tests
- [ ] No new TypeScript warnings
- [ ] Documentation is updated if needed
- [ ] Commit messages follow conventional format
- [ ] PR description explains the change

---

## Security Vulnerability Reporting

**⚠️ Do NOT open a public issue for security vulnerabilities!**

If you discover a security vulnerability in Prompt Rejector itself (not the attacks it's designed to detect), please report it responsibly:

1. **Email:** [your-security-email@example.com]
2. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We'll respond within 48 hours and work with you on a fix before any public disclosure.

---

## Recognition

Contributors will be recognized in:
- The project README
- Release notes when their changes ship
- Our eternal gratitude 🙏

---

## Questions?

- Open a [Discussion](https://github.com/revsmoke/promptrejectormcp/discussions) for general questions
- Check existing issues and discussions first
- Be patient - maintainers are volunteers!

---

## Release & Publishing

This project uses Release Drafter + Git tags to automate releases. CI then publishes to npm and the MCP Registry.

### How release notes are drafted
- When PRs are opened/updated/merged on `main`, the Release Drafter workflow updates a single draft release.
- PR labels determine sections and the next version:
  - `breaking`, `semver:major` → next release = major (X.0.0)
  - `feature`, `enhancement`, `semver:minor` → minor (Y increase)
  - `fix`, `bug`, `security`, `docs`, `chore`, `refactor`, `dependencies` → patch (Z increase)
- Exclude a PR from notes with `skip-changelog`.

### Cutting a release (two options)
1) Using GitHub UI (recommended)
- Go to Releases → open the draft → review → Publish.
- Publishing creates tag `vX.Y.Z`. Our CI workflow then:
  - builds and validates `server.json` against the MCP schema,
  - publishes the package to npm,
  - authenticates via GitHub OIDC and publishes to the MCP Registry.

2) From the CLI
```bash
# Make sure package.json and server.json versions are bumped
npm run build
# Create and push the tag (replaces Publish in UI)
git tag vX.Y.Z -m "Release X.Y.Z"
git push origin vX.Y.Z
```

### CI prerequisites (already configured here)
- GitHub Secret `NPM_TOKEN`: npm granular token with Read/Write and "Bypass 2FA requirement" enabled.
- Workflow permissions include `id-token: write` for OIDC to the MCP Registry.

### Deprecating or yanking versions
- Deprecate a bad version with a message:
```bash
npm deprecate prompt-rejector@1.0.0 "Deprecated; please upgrade to 1.0.1"
```

---

Thank you for helping make AI agents safer! 🛡️
