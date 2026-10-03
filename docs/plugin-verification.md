# Plugin verification

Verified on 2026-09-20 with Node 24.13.0, Codex CLI 0.155.1 and Claude Code 2.1.274 on macOS.
Additionally verified on 2026-09-22 with Node 24.13.0 and Claude Code 2.1.x on Linux (fresh client installation).

| Gate | Observed result |
| --- | --- |
| TypeScript build and type check | Passed |
| Existing and new offline suites | 58 passed; zero network-policy violations |
| Package/install suite | Seven scenarios passed (eight Node test entries including the parent suite) |
| Codex plugin-creator validator | Passed |
| Skill-creator validator | Passed |
| Claude plugin and marketplace strict validators | Passed |
| Portable plugin/MCP and Desktop schemas | Passed using versioned official schemas during the build |
| Official MCPB CLI | Authored manifest validated with `@anthropic-ai/mcpb@2.1.2`; ZIP entry point additionally exercised from an extracted bundle |
| Codex installation | Marketplace registered; plugin installed successfully; its actual cached launcher connected and listed all 11 tools |
| Claude Code installation (macOS & Linux) | Installed in an isolated client configuration on macOS and fresh Linux client; inventory showed one skill and one MCP server; actual cached launcher connected and listed all 11 tools |
| Live bundled app | Real TypeSafe descriptor call: block, complete judgment, active model `jev-1.13.0` |
| Live HTTPS MCP | Real SDK client, trusted local TLS, production JWKS fetch/verification, expected unauthenticated 401, real TypeSafe block |
| Existing HTTPS API after restart | Health ready; benign prompt allowed with complete TypeSafe and Gemini coverage on port 3001 |
| Mapbox | Port 3000 still returned HTTP 200 |
| Dependency audit | Zero reported vulnerabilities after compatible lockfile patch updates |

Package cases cover an unconfigured copied plugin, configuration without secret persistence, missing-credential refusal, archive exclusions, a relocated runtime without source settings, canary persistence across process restarts, remote connection generation, and Desktop manifest substitution. Some checks are grouped within the seven scenarios. Remote authentication tests cover issuer/audience/signature verification, expired/missing-expiry tokens, denied subjects/scopes/origins, rejection of query-string tokens, JSON/body limits, protocol initialization and actual tool calls. The remote service does not expose the REST endpoints.

The sanitized [live evidence](../evaluations/ai/runs/2026-09-20-plugins/live.json) records the bundle runtime hash, real calls, configuration identity and observed timings. Those timings are two observations, not a latency benchmark or quality evaluation. The separate [API report](../evaluations/ai/runs/2026-09-20-plugins/api-benign.json) records the successful post-restart scan. Provider keys, JWTs, signing keys and TLS private keys are not saved.
