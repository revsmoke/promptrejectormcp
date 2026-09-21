# Repository Discovery and Onboarding Implementation Plan

> **For agentic workers:** Use `subagent-driven-development` if subagents are available and tasks are independent; otherwise use `executing-plans`. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the repository easier to discover, try, report vulnerabilities to, and contribute to.

**Architecture:** Improve the existing README and contribution workflow without changing application behavior. Use GitHub private vulnerability reporting instead of inventing a security email. Publish bounded contributor issues and update repository discovery metadata.

**Tech Stack:** Markdown, GitHub issue-form YAML, GitHub CLI/API, existing Node.js build and offline tests.

Scope: repository preparation only. No ads, external outreach, directory submissions, new release, model calls, or changes to the installed service.

## Chunk 1: Documentation and contribution entry points

Files: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `AGENTS.md`, `.github/ISSUE_TEMPLATE/installation.yml`, `.github/ISSUE_TEMPLATE/test-case.yml`, `.github/ISSUE_TEMPLATE/config.yml`, `.github/pull_request_template.md`.

- [x] Review the plan independently for scope and missing dependencies.
- [x] Add prominent README links to the Jev evidence, installation, open contributor opportunities and security reporting. Show one recorded nested-descriptor example, with its source and limitations.
- [x] Add a discoverable no-key historical replay path using `npm ci`, `npm run build`, and `node dist/test/ai/historicalReplayTests.js`; label it as saved evidence, not live inference. Preserve the tested source/plugin live setup, key requirements, MCP/HTTPS distinction and retired `/v1` behavior. Explain that npm publication does not provide an `npx prompt-rejector` executable.
- [x] Remove machine-specific onboarding prose from the public README; link the existing local runbook where useful.
- [x] Refresh CONTRIBUTING concisely: offline-first development, current Node recommendation, live-provider prerequisites via README, code map via AGENTS, synthetic/redacted test cases and current offline suite. Preserve the `Release & publishing` section and anchor; avoid unrelated release edits.
- [x] Add SECURITY.md pointing to `https://github.com/revsmoke/promptrejectormcp/security/advisories/new`. Distinguish private vulnerability reports from ordinary installation/docs issues; direct security-sensitive detection bypasses privately too. Ask for version, configuration, minimal reproduction and impact without credentials. Include no invented email, bounty, or guaranteed response SLA.
- [x] Add compact installation and test-case issue forms, with a private-report warning, environment/reproduction fields, and no request for secrets. Add an issue chooser security contact link and a concise PR template. Keep blank issues available for other scoped proposals.
- [x] Add a compact SECURITY/CONTRIBUTING resource pointer to AGENTS.md if needed; preserve CLAUDE.md's existing import.
- [x] Review implementation for spec compliance, then correctness and clarity. Fix actionable findings.

## Chunk 2: Validate and publish

Remote resources: `revsmoke/promptrejectormcp` private reporting, description/topics/homepage, labels, and three new contributor issues. Local application source and release versions stay unchanged.

- [x] From the clean worktree, run `npm ci`, `npm run build`, historical replay and `npm run test:offline`. Verify relative links and GitHub form structure; run `git diff --check`.
- [x] Enable GitHub private vulnerability reporting with `gh api --method PUT repos/revsmoke/promptrejectormcp/private-vulnerability-reporting`; verify GET returns `enabled: true` and the reporting entry point is available. Do not submit a fake vulnerability report.
- [x] Review the staged diff, commit using the commit skill, integrate into `main`, and push. Preserve unrelated untracked user files.
- [x] Update GitHub description to accurately mention TypeSafe Jev, MCP/HTTPS screening and configurable reasoning. Add relevant discovery topics while preserving existing ones. Use the public Jev article as homepage until a separate project page exists.
- [x] Publish three contributor issues after checking for duplicates: (1) independently verify a supported plugin installation, (2) contribute reviewed quoted-vs-operative instruction examples, (3) add a currently missing descriptor source-evidence regression case. Give each a bounded scope, exact resource links, acceptance criteria and appropriate labels. Do not publish the replay-discoverability issue because this implementation completes it.
- [x] Verify published README, issue chooser/forms, private reporting, metadata, and issue URLs. Confirm main contains the commit and record the results below.

## Completion record

Documentation, forms and contributor briefs passed independent scope and quality reviews. A fresh Node 24.13.0 dependency installation, build and historical replay passed; all 58 offline suites passed with zero network violations. YAML and local links/anchors passed validation. Private reporting is enabled and the public Advisories page displays its reporting link.


Published on `main` in `884582b`:

- GitHub description names TypeSafe AI Jev; added `typesafe-ai`, `jev`, `codex`, `mcp-security`, and `tool-poisoning`, preserving prior topics. The homepage links the public Jev article.
- Contributor issues: [Linux Claude Code plugin verification #8](https://github.com/revsmoke/promptrejectormcp/issues/8), [six paired instruction examples #9](https://github.com/revsmoke/promptrejectormcp/issues/9), and [escaped descriptor evidence paths #10](https://github.com/revsmoke/promptrejectormcp/issues/10). Their published bodies and labels match the reviewed briefs.
- Published README, CONTRIBUTING, SECURITY, issue forms/chooser configuration and PR template match the local files. The public Security policy renders correctly and GitHub recognizes the chooser's private reporting contact. The browser requires sign-in to display the issue forms; their YAML structure and published definitions were checked without submitting a test issue.
- [Offline CI](https://github.com/revsmoke/promptrejectormcp/actions/runs/35638513093) passed on Node 18.20.8, 22, 24 and 26. [Plugin packaging CI](https://github.com/revsmoke/promptrejectormcp/actions/runs/35638513018) passed.
- No ads, promotional outreach, directory submissions, release/tag changes, live inference or installed-service changes were performed.
