# Prompt Rejector plugin

Screen prompts, skill files, MCP tool descriptions, and agent capabilities using the Prompt Rejector app. TypeSafe is active by default; reasoning-provider selection is independent of whether you use Codex or Claude.

Start with the included [skill](skills/prompt-rejector/SKILL.md) for setup and use. The [installation guide](skills/prompt-rejector/references/setup.md) explains how to clone/build/configure the source installation, start MCP or the separate HTTPS API, and verify a real TypeSafe result. [Usage](skills/prompt-rejector/references/usage.md) describes tool selection and report interpretation; [web clients](skills/prompt-rejector/references/web.md) covers tunnel/hosted connections.

Source marketplace packages need a configured source installation. Built local ZIP and Desktop MCPB packages contain the app, active model configuration, verified patterns and production dependencies. Bundled code runs from a writable, content-keyed directory outside the client plugin cache. Provider keys are supplied privately and are never included in this package.

Full platform instructions, packaging commands, update/removal steps, data handling, and remote hosting requirements: [repository plugin guide](https://github.com/revsmoke/promptrejectormcp/blob/codex/typesafe-model-routing/docs/plugins.md).

Installing the plugin starts only MCP over stdio. It does not start an API listener or change another application's port. Real scans send input to configured model providers and may incur charges. The skill applies to requested security reviews; it does not install automatic hooks or require screening every conversation.
