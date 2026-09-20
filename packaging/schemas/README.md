# Validation schema snapshots

Retrieved 2026-09-20 for deterministic, offline package validation:

- `agent-plugins-1.0.0.schema.json`: https://agent-plugins.org/schemas/1.0.0/plugin.schema.json
- `agent-plugins-mcp-1.0.0.schema.json`: https://agent-plugins.org/schemas/1.0.0/mcp.schema.json
- `mcpb-manifest-v0.3.schema.json`: exported by `@anthropic-ai/mcpb@2.1.2`, https://github.com/anthropics/mcpb. The upstream license notice is included in `LICENSE.mcpb`. Its official CLI was also used to validate the authored Desktop manifest.

These are schemas, not downloaded executable code. Update deliberately when changing the supported format version, rerun client validators, and test a real extracted package. The MCPB CLI's optional interactive scaffold/editor dependency tree is not needed to build ZIP bundles and is not installed or shipped by this project.
