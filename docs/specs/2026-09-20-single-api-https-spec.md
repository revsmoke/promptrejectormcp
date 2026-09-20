# Single current API and HTTPS specification

This correction supersedes the public version-compatibility requirements in the [original TypeSafe specification](2026-09-19-typesafe-model-routing-spec.md). Bryan requested a working TypeSafe integration through both MCP and the existing REST workflow, retirement of version 1, and HTTPS on a free port while Mapbox continues running.

## Required behavior

1. Serve exactly one public analysis pipeline. REST uses `/v2`; MCP keeps all 11 existing tool names and always returns the current structured reports. No public request selects legacy scanning behavior.
2. Retire every `/v1/*` path with HTTP 410, `api_version_retired` and the corresponding `/v2` path. Reject before body parsing, scanning or feed updates. Move pattern operations to `/v2` as well.
3. Remove `mcpDefaultReportVersion` from trusted configuration and version selectors from MCP discovery. Reject explicit MCP version 1 before inference. Accept redundant version 2 from existing callers.
4. Preserve request fields, report decision/coverage semantics, strict validation, deterministic findings, TypeSafe source binding, bounded calls and required reasoning on the clean path. Retiring a transport version must not change the underlying task policies.
5. Make `npm start` and `npm run start:api` launch the active HTTPS API. Make `npm run start:mcp` launch only stdio MCP. Both anchor the installation directory, load an explicit credential file when provided and default to `config/ai.active.json` unless an explicit configuration is selected.
6. Default the API to loopback port 3001 and HTTPS. Validate port range, load certificate/key files, require TLS 1.2 or newer, and surface binding/TLS failures as failed startup. Never silently downgrade HTTPS. Allow explicit plaintext HTTP only for an operator-configured reverse proxy deployment.
7. Keep Mapbox on port 3000 and preserve Apache's existing configuration. Run the API as a user LaunchAgent using the existing trusted localhost certificate. Keep keys and credential values out of Git, command arguments and logs.
8. Keep role-based Claude/OpenAI/Gemini selection and independent TypeSafe task modes. Both transports must report the same configuration hash when launched from the same file. Existing processes require restart after changes.

## Acceptance evidence

- Offline coverage for all current routes, rejected retired versions, unchanged TypeSafe policy, launcher configuration precedence, arbitrary working directories and quiet MCP output.
- HTTPS integration tests with actual certificate validation, plus failed startup for missing TLS files, occupied ports and invalid port values.
- Full offline suites on the declared runtime matrix, with no unexpected network access.
- Normal-trust HTTPS health and real prompt analyses: a clean prompt completes contextual reasoning; a conclusive TypeSafe block skips larger reasoning.
- A real stdio MCP descriptor scan adds a TypeSafe block with validated source evidence and the same configuration hash as HTTPS.
- Persistent API service status, a live port check preserving Mapbox, and explicit documentation for using/restarting both connections.
- Independent specification and quality review, secret scan, committed changes and pushed branch.

These operational checks establish that the requested integration runs. They do not claim a held-out detection benchmark or live access to unused model accounts. The [implementation checklist](../superpowers/plans/2026-09-20-single-api-https.md) and [run record](../../evaluations/ai/runs/2026-09-20-single-api/README.md) track completion.
