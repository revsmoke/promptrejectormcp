# Single API, HTTPS and MCP live verification

Date: 2026-09-20. This deployment completes the existing REST workflow alongside the active stdio MCP installation. The only public API is `/v2`, with HTTPS on `localhost:3001`. Mapbox remains on port 3000.

The persistent API is a current-user LaunchAgent using the existing trusted localhost certificate. HTTPS requests succeeded with normal certificate verification; no insecure TLS override was used. A separate SDK stdio client launched the installed MCP entry from `/tmp`, discovered all 11 tools without advertised version selectors, and performed a real descriptor scan.

All four saved reports use config hash `9fb705c74bbc77df8d1fe6c1c446fdf41ffe19277f22ee5cdbb64ee5329e99d6`. Jev is pinned to `jev-1.13.0`; contextual reasoning uses `gemini-3-flash-preview`.

| Check | Result | Physical inference calls | Artifact |
| --- | --- | --- | --- |
| Trusted HTTPS health | Current `/v2` reports; active TypeSafe locally ready | 0 | [health.json](health.json) |
| HTTPS benign weather prompt | `allow`, with complete TypeSafe and contextual reasoning | 2 | [https_benign.json](https_benign.json) |
| HTTPS synthetic credential-exfiltration prompt | `block`; TypeSafe cascade skipped larger reasoning | 1 | [https_attack.json](https_attack.json) |
| MCP nested poisoned tool description | `block`; local severity was safe, validated TypeSafe evidence added the block | 1 | [mcp_descriptor.json](mcp_descriptor.json) |

These checks used four physical inference requests, with no provider failures. Reported estimated costs remain estimates; the benign scan's combined actual estimate is unknown because the provider did not supply all billing fields. No general latency, cost-reduction percentage or held-out detection accuracy is inferred from three live examples.

The active profile explicitly uses optional formal qualification. This record proves live operation and preserved response semantics; it does not claim a held-out qualification pass. The previous [activation record](../2026-09-19-active-mcp/README.md) retains broader task-specific checks and earlier corrective failures.

See [local operations](../../../../docs/operations/local-server.md), the [rollout checklist](../../../../docs/superpowers/plans/2026-09-20-single-api-https.md) and [implementation ledger](../../../../docs/implementation/typesafe-progress.md) for deployment and final regression status.

Final non-inferencing checks and the four-runtime 57-suite matrix are summarized in [verification-summary.json](verification-summary.json). [health-after.json](health-after.json) records the persistent service after those tests. Retired prompt, skill and feed-update routes returned 410; malformed/current invalid inputs returned 400; `/v2/patterns` returned 200. The separate Mapbox service returned 200 on port 3000.
