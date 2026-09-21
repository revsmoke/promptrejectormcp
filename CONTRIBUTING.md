# Contributing to Prompt Rejector

Choose a [good first issue](https://github.com/revsmoke/promptrejectormcp/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22) or a [help wanted task](https://github.com/revsmoke/promptrejectormcp/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22help%20wanted%22). Installation feedback, clear documentation and well-labeled synthetic test cases are useful contributions alongside code. Comment on a task before starting so others can coordinate with you.

## Report a problem

- [Installation or documentation problem](https://github.com/revsmoke/promptrejectormcp/issues/new?template=installation.yml): include the version, environment and minimal steps.
- [Synthetic test case or false positive](https://github.com/revsmoke/promptrejectormcp/issues/new?template=test-case.yml): explain the expected result and the actual result, if tested.
- Other suggestions: search [existing issues](https://github.com/revsmoke/promptrejectormcp/issues) first, then explain the problem and intended outcome in a new issue.
- Vulnerabilities and **security-sensitive detection bypasses**: use the private reporting route in [SECURITY.md](SECURITY.md), including when the problem concerns an attack the scanner is intended to detect.

Use synthetic or redacted examples. Never publish keys, `.env` contents, private prompts or customer data. Be respectful and constructive when discussing results.

## Development setup

Use **Node.js 24 with npm**, Git, and OpenSSL (for temporary HTTPS test certificates). Clone your fork or the repository:

```sh
git clone https://github.com/revsmoke/promptrejectormcp.git
cd promptrejectormcp
npm ci
npm run build
npm run test:offline
```

Offline development needs **no `.env`, provider keys or running server**. `npm ci` downloads dependencies; the offline test runner then builds, isolates each suite, removes credential access and guards network calls. Only designated transport tests may use loopback. `npm test` is an incomplete legacy chain; use `npm run test:offline` before a code PR.

For the smaller saved-results check after building:

```sh
node dist/test/ai/historicalReplayTests.js
```

This replays historical evidence without model inference. Live scans require the [README's provider setup](README.md#3-add-your-keys), send inputs to configured providers and may incur charges. Keep live tests synthetic and explicitly bounded; follow [model operations](docs/operations/ai-models.md) and [evaluation guidance](evaluations/ai/README.md).

## Find the relevant code and tests

[AGENTS.md](AGENTS.md) is the compact code and documentation map. Provider contracts live in `src/ai/contracts.ts`; final decisions and incomplete-analysis handling live in `src/services/DecisionPolicy.ts` and `src/services/AnalysisCoverage.ts`. Preserve known findings when a provider fails: unavailable required analysis must never become an allow decision. Keep MCP stdout reserved for protocol messages.

Tests are standalone scripts under `src/test/`, registered in `src/scripts/runOfflineTests.ts`. Extend the relevant suite for a behavior change; register new offline suites there. Use synthetic native-response fixtures for provider contracts. Decision tests should cover failures and incomplete coverage as well as successful analysis. [Evaluation evidence](evaluations/ai/README.md) distinguishes development fixtures, historical replay and live runs. Development fixtures and historical replay are not independent held-out qualification; live runs need the documented corpus, review and qualification evidence to support that claim.

## Submit a pull request

Fork the repository, branch from `main`, and keep the change focused. In the [PR template](.github/pull_request_template.md), link the issue, explain the resulting behavior and list validation actually performed. Update affected documentation. For code changes, run `npm run test:offline`; for documentation-only changes, check commands and links. Plugin changes also need the checks below. Report sensitive findings privately before opening a public PR.

## Plugin packaging

Use Node 24 for `npm run plugin:build`, then `npm run test:plugins`. The offline app suite (`npm run test:offline`) also covers remote MCP authentication. Maintain the shared skill in `plugins/prompt-rejector/skills/prompt-rejector/`; generated ZIP/MCPB files are build artifacts and must not be committed. Bump package, portable, Codex, Claude and Desktop manifest versions together when releasing an update. See [plugin architecture](docs/plugin-architecture.md), [package guide](docs/plugins.md), and [schema provenance](packaging/schemas/README.md). Never include private environment files, certificates, canary state or feed caches in a package.

## Release & Publishing

This project uses Release Drafter and `v*` Git tags for GitHub releases and npm publishing. **MCP Registry publication is not part of either release path.** No Registry schema validation, publisher download, login, or publication runs automatically.

### How release notes are drafted
- When PRs are opened/updated/merged on `main`, the Release Drafter workflow updates a single draft release.
- PR labels determine sections and the next version:
  - `breaking`, `semver:major` → next release = major (X.0.0)
  - `feature`, `enhancement`, `semver:minor` → minor (Y increase)
  - `fix`, `bug`, `security`, `docs`, `chore`, `refactor`, `dependencies` → patch (Z increase)
- Exclude a PR from notes with `skip-changelog`.

### Cutting a release (two options)

Before releasing, commit the intended versions in `package.json`, `package-lock.json`, `server.json` and the plugin manifests. Choose the corresponding `vX.Y.Z` tag; the workflow does not bump the npm package version or move existing tags.

1) Using GitHub UI (recommended)
- Go to Releases → open the draft → review the version and target commit → Publish.
- Select a new tag `vX.Y.Z` at the intended commit, or the matching existing tag.
- A pushed `v*` tag runs **Publish npm package** (`.github/workflows/publish-mcp.yml`): install, build, synchronize the top-level and package versions in the runner's `server.json` from the tag, audit package contents, then run `npm publish --access public`.
- GitHub release creation and Release Drafter have no dependency on this npm job or any MCP Registry service. Selecting an existing tag does not push it again.

2) From the CLI
```bash
# Commit the intended package, lockfile, server and plugin versions first.
npm run build
git tag vX.Y.Z -m "Release X.Y.Z"
git push origin vX.Y.Z
```

A tag push starts npm publishing; it does not by itself publish the draft GitHub Release. Open the draft and publish it using that tag, or use `gh release create vX.Y.Z --verify-tag --generate-notes` after reviewing the release contents.

### npm publishing and GitHub-only releases

- npm publishing stays enabled by default. Supply the GitHub Actions secret `NPM_TOKEN` with permission to publish `prompt-rejector`; it is passed as `NODE_AUTH_TOKEN`. Missing or invalid npm credentials fail npm publishing, rather than report a false success.
- For a GitHub-only release, set the repository **Actions variable** `PUBLISH_NPM` to `false` **before pushing the tag** (Settings → Secrets and variables → Actions → Variables). The npm job is skipped. Delete the variable or set it to `true` to restore publishing for future tags. This setting persists until changed; it does not automatically republish skipped tags.
- The npm workflow needs only `contents: read`. It requests no MCP Registry OIDC permission, credentials or endpoint.
- Registry listing, if ever wanted, is a separate explicitly initiated operation and cannot block a repository or npm release.
- Retrying an old failed run uses that run's original workflow revision. Future release tags must include this workflow correction; do not move an already published tag to pick it up.

Reference: GitHub's [npm publishing guide](https://docs.github.com/en/actions/tutorials/publish-packages/publish-nodejs-packages) and [release management guide](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository).

### Deprecating or yanking versions
- Deprecate a bad version with a message:
```bash
npm deprecate prompt-rejector@1.0.0 "Deprecated; please upgrade to 1.0.1"
```
