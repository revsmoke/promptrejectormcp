# Plugin architecture research and decisions

Researched 2026-09-20 against current first-party documentation, with installed Codex and Claude CLIs checked locally. Platform capabilities can change; follow the linked current documentation when installing in a different client version.

## Evidence

- [OpenAI plugin architecture](https://developers.openai.com/plugins/concepts/plugins): plugins combine skills and MCP; capability availability depends on execution surface.
- [OpenAI packaging](https://developers.openai.com/plugins/build/plugins): new portable packages use root `plugin.json` and typed `mcp.json`; `.codex-plugin/plugin.json` remains a compatibility fallback. Current root OpenAI extensions replace, rather than merge with, the compatibility overlay. Local/repository marketplaces differ from public directory submission.
- [Claude plugin reference](https://code.claude.com/docs/en/plugins-reference): `.claude-plugin/plugin.json`, `skills/`, `.mcp.json`, plugin-root substitution and cached installation rules. Claude `userConfig` is not portable to OpenAI.
- [Claude marketplaces](https://code.claude.com/docs/en/plugin-marketplaces): source paths, Git distribution, version-aware updates and validation.
- [Anthropic MCPB specification](https://github.com/anthropics/mcpb/blob/main/MANIFEST.md): Desktop Node extensions bundle dependencies and use host substitution/configuration fields. We target manifest 0.3, validated with the official MCPB CLI and a pinned schema snapshot.
- [Claude local MCP](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop) and [remote connectors](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp): desktop local execution and cloud-to-server requests are distinct.
- [OpenAI Claude-plugin conversion](https://developers.openai.com/plugins/guides/submit-claude-plugin): reusable behavior should be provider-neutral skills; local MCP and `.mcpb` are not accepted as public remote submissions.
- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels): private stdio/HTTP servers can connect outbound to supported OpenAI clients, with separate tunnel permissions and account association; public publication still needs a public HTTPS endpoint.
- [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization): resource metadata, token audience binding, scopes, and distinct OAuth authorization/resource-server roles.

## Decisions

1. **One app, one skill, small format adapters.** Keep the existing services, provider routing and policy decisions. A shared source plugin includes portable, Codex and Claude manifests. Its legacy MCP declarations differ only in the host's plugin-root variable.
2. **Source distribution plus complete bundles.** Source marketplaces carry the setup/use skill and a launcher that reuses an explicitly configured installation. Generated local ZIP/MCPB artifacts include compiled code, verified patterns, active config and lockfile-installed production dependencies. Do not commit generated copies of the app or vendored node_modules.
3. **No hidden installation hooks.** Installing a source plugin does not silently clone arbitrary code or run npm inside a client cache. The setup skill performs the authorized source installation. Complete bundles run without downloading dependencies.
4. **Durable configuration and state.** Paths-only settings live outside caches. Bundled runtime state is materialized under a content hash; a version update cannot overwrite the old canary/feed state. Key material and local state never enter archives.
5. **Web support uses a real transport.** OpenAI's private tunnel can use existing stdio. A separate authenticated Streamable HTTP app serves web connectors without exposing unauthenticated REST routes. OAuth accounts, hosting and publication remain operator/platform responsibilities.
6. **Provider switching stays intact.** The plugin uses `ai.active.json` or an explicit custom config and the same adapters as the app. Host choice (Claude/Codex) does not force reasoning-provider choice. TypeSafe remains active by default.
7. **No automatic prompt hook.** Review is explicit or skill-selected within the user's request; automatic interception would add latency/cost and would be incompatible across ordinary web and local execution environments. Tools include accurate read/write/open-world annotations.
8. **Do not imply absolute safety.** Structured outputs and deterministic policy enforcement improve reliability; probabilistic model judgments still require coverage/error reporting and real-client verification.

## Rollout checklist

- [x] Research current OpenAI, Claude Code, MCPB, web connector and MCP authorization formats.
- [x] Create shared skill, installation/use references and three client manifests.
- [x] Add paths-only setup, direct stdio launch and real MCP doctor.
- [x] Add full local ZIP, Desktop extension and standalone skill builds.
- [x] Add authenticated remote MCP and a generator for a real remote endpoint package.
- [x] Verify validators, isolated source/bundle installs, credential exclusions and active TypeSafe calls.
- [x] Run offline regression and package tests; verify existing HTTPS service and Mapbox port separation.
- [x] Commit/push source and documentation; verify CI package artifacts.
- [ ] Operator-specific: configure a tunnel or public HTTPS/OAuth deployment and complete cloud-client connection tests.
- [ ] Optional publication: submit to platform directories and complete their approval requirements.
