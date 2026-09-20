# Plugins and agent skill

Prompt Rejector ships one shared skill, a portable local plugin with Codex and Claude Code manifests, a bundled Claude Desktop extension, and an OAuth-protected remote MCP transport for web connectors. All use the same application and active TypeSafe configuration. Installing a plugin does not change the existing HTTPS REST API at `https://localhost:3001/v2/check-prompt`.

## Choose your client

| Client/surface | Install/use | Where the app runs |
| --- | --- | --- |
| Codex CLI or desktop | Local/repository marketplace plugin | Your machine, MCP over stdio |
| Claude Code CLI or its local desktop coding environment | Same repository, Claude marketplace manifest | The coding environment, MCP over stdio |
| Claude Desktop chat | `.mcpb` extension plus skill ZIP | Your machine; bundled JavaScript dependencies, host-provided Node |
| ChatGPT desktop Work / local Codex environment | Local plugin where that environment supports local plugins | Its execution environment; ordinary Chat uses a connector |
| ChatGPT web / ordinary Chat | Skill plus Secure MCP Tunnel or hosted MCP connection | Your machine through the tunnel, or your server |
| Claude web / cloud sessions | Skill plus hosted remote MCP connector; plugin availability follows account/workspace settings | Your server or cloud execution environment; no access to your laptop's localhost |

A skill adds instructions. An MCP connection adds callable tools. A package can contain both, but it cannot install Node, supply API keys, provision hosting, or grant platform permissions automatically. Cloud sessions with terminal access can follow the setup skill inside their own environment; ordinary web chat cannot install software on your computer.

## Quick installation: Codex and Claude Code

First complete the [README installation](../README.md#installation). The source checkout needs `npm ci`, `npm run build`, a private `.env`, and active AI configuration. Then:

```sh
npm run plugin:setup
npm run plugin:doctor
```

Setup saves **paths only** in `~/.config/prompt-rejector/plugin.json`, with owner-only permissions where supported. It does not copy your keys. To reuse an environment file elsewhere:

```sh
npm run plugin:setup -- --env-file /absolute/path/private.env
```

From the checkout, install in the client you use:

```sh
# Codex
codex plugin marketplace add "$PWD"
codex plugin add prompt-rejector@prompt-rejector

# Claude Code
claude plugin marketplace add "$PWD"
claude plugin install prompt-rejector@prompt-rejector --scope user
```

For installation directly from Git, use `main`:

```sh
codex plugin marketplace add revsmoke/promptrejectormcp --ref main
claude plugin marketplace add https://github.com/revsmoke/promptrejectormcp.git#main
```

Then run the corresponding install command above. A Git marketplace downloads the plugin and skill, **not a ready-built source checkout**. Invoke the included `prompt-rejector` skill to clone/build/configure a separate installation once. The generated local ZIP described below includes the built app and production dependencies.

Start a new client session after installation. Ask: “Use Prompt Rejector to inspect this prompt.” The skill is `prompt-rejector`; Claude Code namespaces it under `prompt-rejector:prompt-rejector`. Tool names are client-prefixed versions of the 11 MCP names.

If an older manual MCP connection already works, choose one connection so the agent does not see duplicate tools. Installing this plugin does not silently remove your existing connection. MCP launches Node directly; do not use an npm command as the MCP transport command.

## Build the complete packages

Use Node 24 with the repository's locked dependencies:

```sh
npm ci
npm run clean
npm run plugin:build
```

Output in `artifacts/plugins/`:

| File | Contents |
| --- | --- |
| `prompt-rejector-1.1.0-local.zip` | Portable manifest, Codex compatibility manifest, Claude Code manifest, shared skill, launchers, built app, active model configuration, verified patterns, production dependencies and licenses |
| `prompt-rejector-1.1.0.mcpb` | Same runtime in Claude Desktop's extension format, with secret configuration fields |
| `prompt-rejector-skill.zip` | Standalone provider-neutral skill and its setup/use/web references |
| `SHA256SUMS`, `build.json` | Archive hashes, runtime identity, version and package inventory |

Bundles exclude `.env`, TLS keys/certificates, local feed/cache/canary state, tests, Git metadata and development dependencies. The application code includes both the REST API and remote MCP launcher, but installing the plugin starts **only stdio MCP**, so it does not claim port 3001 or interfere with other services.

The packaging workflow uploads these outputs as downloadable GitHub Actions artifacts. These are repository build artifacts, not public-directory approval or an npm release. Use the artifact for the commit you intend to install; verify `SHA256SUMS` after downloading.

### Install a built local ZIP

Extract the ZIP into an empty directory; it contains `prompt-rejector/`. Keep that directory. Claude Code can test it directly with:

```sh
claude --plugin-dir /absolute/path/prompt-rejector
```

For Codex, use the repository marketplace source installation above, or place the extracted plugin at `plugins/prompt-rejector` in your own local marketplace and register that marketplace. Do not unpack it over a working source checkout.

The first bundled launch copies its runtime into `~/.local/share/prompt-rejector/runtimes/<content-hash>/`. This makes feed and canary files writable without modifying the plugin cache. Subsequent launches reuse that runtime. A changed bundle creates a new runtime; existing state is retained in its old directory, not migrated automatically. A configured `installationPath` takes precedence in the local plugin. Use `PROMPT_REJECTOR_BUNDLED_ONLY=true` to select its bundle instead; the Desktop extension already sets this.

Configure a private environment file for the bundled local plugin with `PROMPT_REJECTOR_ENV_FILE`, or a paths-only settings file containing `envFile`. Avoid embedding keys in a manifest. For a different model configuration use `PROMPT_REJECTOR_AI_CONFIG` or `configFile` in the same settings. Paths must be absolute.

## Claude Desktop chat

1. Build or download the `.mcpb` above.
2. Open it with Claude Desktop and review/install the local extension. If your version uses an extension settings screen, install the file there.
3. Enter the **TypeSafe** and **Gemini** keys in extension settings for the default profile. The host stores sensitive fields. Optional Anthropic/OpenAI keys and a custom configuration file let you switch the reasoning model without changing the plugin.
4. Enable the extension and verify that its 11 tools appear. The extension bundles dependencies; no repository build is required on the receiving machine.
5. Upload `prompt-rejector-skill.zip` through Claude's skill settings to add setup and review guidance. An MCPB archive does not automatically register its contained skill in Claude chat.

If a provider key is missing, the tool inventory can still load but inference will not be healthy. Confirm a real result before calling setup complete. Client plan/workspace policy can control extension and skill installation.

## Standalone skill

The canonical skill is [SKILL.md](../plugins/prompt-rejector/skills/prompt-rejector/SKILL.md), with three references. Install the generated skill ZIP through a supported skill-upload screen, or copy the **whole folder** into a client's skill directory (`~/.agents/skills/prompt-rejector` for Codex, `~/.claude/skills/prompt-rejector` for Claude Code). Avoid installing both standalone and plugin copies in the same client unless you intend duplicate discovery.

The skill teaches an agent to clone `main`, protect keys, build, configure the plugin, choose MCP/HTTPS/remote setup, verify actual TypeSafe behavior, discover tool schemas, and interpret allow/block/review and incomplete coverage. It does not install global hooks or scan every message automatically.

## Verify and update

```sh
npm run plugin:doctor          # real MCP initialize/list/integrity; no inference
npm run plugin:doctor -- --live # one synthetic descriptor scan using TypeSafe
```

The live check must report `liveTypeSafe: passed` and `decision: block`. It uses provider credits. Other prompt/skill checks can also invoke your chosen reasoning provider. Read the report's coverage; HTTP success and credential presence are insufficient evidence.

For source installations, update the checkout without discarding local changes, run `npm ci` and `npm run build`, then:

```sh
codex plugin marketplace upgrade prompt-rejector
codex plugin add prompt-rejector@prompt-rejector
claude plugin marketplace update prompt-rejector
claude plugin update prompt-rejector@prompt-rejector
```

Run only your client's commands, restart its session, and rerun the doctor. Maintainers must bump all plugin/package manifest versions for published updates; Claude caches explicit versions. Reinstall a new `.mcpb` through Desktop extension management. Neither update path changes a separately running API service until that service is restarted.

Remove with `codex plugin remove prompt-rejector@prompt-rejector` or `claude plugin uninstall prompt-rejector@prompt-rejector`; remove the Desktop extension in its settings. User settings, private keys and persistent runtime data remain until you deliberately remove them.

## Data and permissions

Scanning sends the supplied content to TypeSafe and, where the configured pipeline requires it, the selected reasoning provider. The plugin adds no telemetry service. Existing optional feed and model-metadata tools contact their documented external services. Local environment files and extension secret fields provide provider credentials; the plugin settings file contains only paths. Feed caches, staged patterns and canary state remain in the selected installation or writable bundle runtime. Uninstalling the plugin does not erase that state. For provider handling and retention, consult the provider policies linked in the Desktop manifest and your account agreement.

The remote service also processes OAuth subject/scope claims from your authorization server. Deployments share one provider account/configuration and state; separate trust boundaries need separate installations. The skill uses tool permissions already granted by the client and does not add global interception hooks.

## Web clients and publication

Follow [Remote MCP and web clients](operations/remote-mcp.md). ChatGPT's secure tunnel works with the existing stdio server. Claude web needs a hosted connector. The repository's remote transport is an OAuth resource server: it validates tokens from your authorization server; it does not create accounts or issue login tokens.

Public directory listing requires separate platform submission, domain ownership and review. This repository does not include a fabricated connection ID, an unauthenticated public service, or a claim of approval by OpenAI/Anthropic.

## Maintainer architecture and evidence

See [research and decisions](plugin-architecture.md) and [verification results](plugin-verification.md). The portable `plugin.json`/`mcp.json` is canonical for current OpenAI hosts; `.codex-plugin/plugin.json` with inline MCP wiring supports compatibility hosts; Claude uses `.claude-plugin/plugin.json` plus `.mcp.json`. All point at the same launcher and skill. Remote packages replace only the MCP connection with a real HTTPS endpoint.
