# Install and verify

## Reuse before cloning

Look for already available Prompt Rejector tools or an existing checkout supplied by the user. Check its README and configuration; do not replace local changes or start a duplicate listener. MCP uses stdio and needs no HTTP port or TLS certificate. The separate application API uses `https://localhost:3001/v2/check-prompt` by default.

If a packaged runtime is present, the plugin launcher handles it; a build is unnecessary. Claude Desktop's extension asks for keys in its settings. A source marketplace installation contains this skill and launcher, and needs the following checkout setup once.

## Fresh source installation

Use Node 24 LTS, npm and Git. Choose an unused destination. These shell examples are for macOS/Linux; on Windows use equivalent PowerShell file operations. Run on a machine with a filesystem and terminal, not in an ordinary web chat.

```sh
git clone --branch codex/typesafe-model-routing https://github.com/revsmoke/promptrejectormcp.git
cd promptrejectormcp
npm ci
npm run build
```

This branch contains the implemented upgrade. Do not substitute a published npm version without verifying that it contains this configuration and the plugin launchers.

Create `.env` from `.env.example` only if no `.env` exists. Set file permissions to owner-only where supported. Have the user enter the real values privately in an editor; never ask for keys in chat or print an existing environment file:

```dotenv
TYPESAFE_API_KEY=your-typesafe-key
GEMINI_API_KEY=your-gemini-key
AI_CONFIG_PATH=config/ai.active.json
```

The default reasoning provider is Gemini. TypeSafe stays active when reasoning providers change. To use Anthropic or OpenAI, configure the corresponding key and role profiles as described in the repository's `docs/operations/ai-models.md`. Relative capability/pricing paths resolve from the configuration file's directory; copy those companion files when moving a configuration. Do not guess provider model availability.

```sh
npm run ai:config
npm run plugin:setup
npm run plugin:doctor
```

`plugin:setup` checks the real configuration and required credential presence, then saves only absolute paths in `~/.config/prompt-rejector/plugin.json`. It can use an existing private file:

```sh
npm run plugin:setup -- --installation /absolute/path/promptrejectormcp --env-file /absolute/path/private.env --config /absolute/path/promptrejectormcp/config/ai.active.json
```

`plugin:doctor` initializes the packaged launcher, lists the tools, and verifies patterns. For an authorized real TypeSafe call with a synthetic attack descriptor:

```sh
npm run plugin:doctor -- --live
```

Expected: 11 tools, valid patterns, then `liveTypeSafe: passed` and `decision: block`. Credential presence alone does not verify account access.

## Install the plugin

From the checkout, choose the client in use:

```sh
# Codex CLI and desktop: register this local repository marketplace, then install.
codex plugin marketplace add "$PWD"
codex plugin add prompt-rejector@prompt-rejector

# Claude Code: register the same checkout in Claude's marketplace format.
claude plugin marketplace add "$PWD"
claude plugin install prompt-rejector@prompt-rejector --scope user
```

Start a new client session. If an older manually configured MCP entry exists, use one connection to avoid duplicate tool lists; do not delete unrelated client configuration. The installed namespace may contain both plugin and server names.

For **Claude Desktop chat**, use the generated `.mcpb` extension and install the skill separately. From the checkout run `npm run plugin:build`; outputs appear in `artifacts/plugins/`. Open the `.mcpb` in Claude Desktop, configure keys in the extension settings, and upload `prompt-rejector-skill.zip` using its skill settings. See the repository `docs/plugins.md` for each surface and updates.

## Optional HTTPS application API

Reuse a valid trusted localhost certificate or follow the repository README's mkcert instructions. Set `TLS_CERT_FILE`, `TLS_KEY_FILE`, and `PORT=3001` in the private `.env`. Use another free port if occupied; preserve unrelated services.

```sh
npm start
```

Verify `/health` with normal certificate verification, then perform a requested real POST to `/v2/check-prompt`. Do not use `curl -k`, turn off TLS validation, or claim REST is an MCP connection. `/v1` is retired.

## Troubleshooting

- Missing setup: build the source installation and rerun `plugin:setup`; an installed plugin cache may not contain the whole repository.
- Node unavailable in a graphical client: ensure Node is in its PATH or use an absolute Node path in a manually configured MCP entry. Claude Desktop extensions supply a Node runtime.
- Missing credentials/provider error: correct the private environment or extension settings; leave TypeSafe active. Check account/model access separately.
- Invalid pattern integrity: stop and diagnose; fallback patterns do not establish full coverage.
- Tools absent after installing/updating: start a fresh client session and inspect client MCP/plugin status. Avoid starting the stdio launcher through npm, whose banners corrupt JSON-RPC.
- Upgrade: rebuild the checkout, refresh the marketplace/plugin, reconnect, then run the doctor. Bundled builds use a content-keyed writable runtime; preserve old canary/feed state until deliberately migrated.
