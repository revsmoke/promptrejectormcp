# Single API and HTTPS rollout checklist

Governing [specification](../../specs/2026-09-20-single-api-https-spec.md). This checklist supersedes the original plan's public v1/v2 compatibility and MCP version selection. Preserve TypeSafe policies and configurable reasoning models throughout.

- [x] Check the actual running service and identify the port conflict: Mapbox owns port 3000; preserve it and select 3001.
- [x] Route REST and MCP through the current pipeline only; retire `/v1/*` before parsing or inference and move pattern routes to `/v2`.
- [x] Remove the trusted MCP version default and advertised version selectors; reject explicit version 1 before inference.
- [x] Share launcher setup for credentials, installation directory and active configuration. Keep API and MCP processes independently startable.
- [x] Implement HTTPS by default, explicit certificate/key configuration, loopback binding and awaited startup failure handling.
- [x] Cover real TLS trust and startup failures in the offline launcher suite. Preserve existing policy/transport regressions.
- [x] Install and start the current-user HTTPS LaunchAgent using the existing trusted certificate, without changing Mapbox or Apache.
- [x] Verify real HTTPS benign/attack scans and a real stdio MCP poisoned-descriptor scan with the same active config hash.
- [x] Complete independent SPEC and quality reviews of the code. Both reviewers independently rebuilt and passed ten focused suites.
- [x] Update README, configuration guidance, model operations, rollout instructions, changelog and deployment runbook.
- [x] Complete the full four-runtime offline matrix: 57/57 suites on Node 18.20.8, 22.23.2, 24.13.0 and 26.9.0, with zero unexpected network violations.
- [x] Recheck persistent HTTPS health, retired/invalid requests and both occupied ports; scan all 265 tracked/new files for saved or inherited credential values (none found).
- [ ] Review the final diff, commit and push the coordinated change; record remote CI result.

For later model switches: copy the active configuration, select the semantic/drafting/Taster/Monitor profiles independently, check configuration and account access, restart both API and MCP processes, and compare configuration hashes and actual attribution. Existing native adapters normalize provider methods and responses; adding a supported model requires catalog/profile configuration, while adding a new provider requires an adapter and contract tests. See [model operations](../../operations/ai-models.md).
