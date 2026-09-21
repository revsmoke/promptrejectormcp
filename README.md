# Prompt Rejector

**Screen prompts, skill files and MCP tool descriptions before an AI agent acts on them.**

Prompt Rejector combines deterministic security checks, focused **TypeSafe Jev judgments**, and a configurable reasoning model. The active configuration uses TypeSafe and Gemini; Claude and OpenAI adapters are available through model configuration.

| Use it from | Connection | Start command |
| --- | --- | --- |
| An application or script | **HTTPS API:** `https://localhost:3001` | `npm start` |
| Codex / Claude Code | **Plugin + MCP over stdio** | [Install the plugin](#plugins-and-skill) or configure the Node launcher |
| Claude Desktop chat | **Bundled `.mcpb` extension + skill** | [Desktop installation](docs/plugins.md#claude-desktop-chat) |
| ChatGPT / Claude web | **Skill + tunnel or authenticated remote MCP** | [Web connection guide](docs/operations/remote-mcp.md) |

The local API and MCP connections can run together and use the same analysis configuration. Prompt checks use **`POST /v2/check-prompt`**. `/v2` is the only current API; `/v1` is retired. MCP keeps all 11 tool names and needs no version selector.

**Already using Bryan's local installation?** The HTTPS service and Codex MCP entry are configured. Go to the [local service runbook](docs/operations/local-server.md#installed-macos-service) for status and restart instructions; do not start a second server on port 3001.

- [Plugins and skill](#plugins-and-skill)
- [Installation](#installation)
- [HTTPS API setup](#https-api-setup)
- [MCP setup](#mcp-setup)
- [Check a prompt](#check-a-prompt)
- [Choose a different model](#choose-a-different-model)
- [Update an existing installation](#update-an-existing-installation)
- [Troubleshooting](#troubleshooting)
- [Tools and endpoints](#tools-and-endpoints)
- [Development and documentation](#development-and-documentation)

## Plugins and skill

For **Codex or Claude Code**, complete the [source installation](#installation), then run:

```sh
npm run plugin:setup
npm run plugin:doctor
```

Register and install the plugin for your client from the checkout:

```sh
# Codex CLI / desktop
codex plugin marketplace add "$PWD"
codex plugin add prompt-rejector@prompt-rejector

# Claude Code
claude plugin marketplace add "$PWD"
claude plugin install prompt-rejector@prompt-rejector --scope user
```

Start a new session and ask the agent to use **Prompt Rejector**. The included [skill](plugins/prompt-rejector/skills/prompt-rejector/SKILL.md) explains cloning, configuration, startup, verification and tool use. Keys remain in your private environment file; plugin settings save only paths. Use one connection if you already have a manual MCP entry.

For **Claude Desktop chat**, download the `.mcpb` extension and standalone skill ZIP from [GitHub Releases](https://github.com/revsmoke/promptrejectormcp/releases/latest), or build them locally. `npm run plugin:build` creates complete local packages under `artifacts/plugins/`, including the app and production dependencies. [GitHub Actions builds](https://github.com/revsmoke/promptrejectormcp/actions/workflows/plugins.yml) provide downloadable artifacts for `main`.

For **ChatGPT or Claude on the web**, a skill alone does not connect to your computer. Use OpenAI's private MCP tunnel or the included OAuth-protected remote transport on your own HTTPS host. See the [platform installation guide](docs/plugins.md), [web connection guide](docs/operations/remote-mcp.md), and [verified coverage](docs/plugin-verification.md). Public plugin-directory publication and cloud account setup are separate steps.

## Installation

Complete these steps once, then set up **HTTPS**, **MCP**, or **both**. Local stdio MCP installations do not need a certificate or an API port.

### 1. Check prerequisites

- **Node.js 24 with npm** is the recommended tested runtime. Get it from [Node.js](https://nodejs.org/en/download). The test matrix also covers Node 18.20.8, 22 and 26.
- **Git** to download the source.
- A **TypeSafe API key** from the [TypeSafe dashboard](https://console.typesafe.ai/keys).
- A **Gemini API key** from [Google AI Studio](https://aistudio.google.com/apikey) for the default reasoning profile. You can switch providers after setup.

Check that the tools are available:

```sh
node --version
npm --version
git --version
```

The commands below use a macOS/Linux shell. Actual scans send input to the configured model providers and can use paid API credits; configuration and health checks do not call models.

### 2. Download and build

The current application, plugins and skill are included on **`main`**. GitHub releases and optional npm publishing are described in the [release guide](CONTRIBUTING.md#release--publishing); MCP Registry publication is not required. If you already have a checkout with local changes, choose a different destination directory instead of overwriting it.

```sh
git clone --branch main https://github.com/revsmoke/promptrejectormcp.git
cd promptrejectormcp
npm ci
npm run build
```

`npm ci` installs the versions recorded in the lockfile. Run the remaining setup commands from this directory.

### 3. Add your keys

Create `.env` only if it does not already exist:

```sh
if [ ! -f .env ]; then cp .env.example .env; fi
chmod 600 .env
```

Open `.env` in your editor and replace these two placeholder values:

```dotenv
TYPESAFE_API_KEY=your-typesafe-key
GEMINI_API_KEY=your-gemini-key
AI_CONFIG_PATH=config/ai.active.json
```

The example file already selects `config/ai.active.json`. Keep that setting for the default active TypeSafe setup. Other provider keys and optional feature settings can stay blank or at their defaults. `.env` is ignored by Git; keep the real keys there, not in client commands.

Check configuration:

```sh
npm run ai:config
```

Look for `inferencePerformed: false`, `missingCredentialEnvironmentVariables: []`, and TypeSafe modes `enforce` or `cascade`. This confirms configuration and key presence; the first real scan confirms account/model access. Placeholder text is not a working key.

Now continue with [HTTPS API setup](#https-api-setup), [MCP setup](#mcp-setup), or both.

## HTTPS API setup

### 1. Create a trusted localhost certificate

If you already have a trusted certificate covering `localhost`, reuse its certificate and key paths and skip generation. Otherwise, use [mkcert](https://github.com/FiloSottile/mkcert#installation).

On macOS with Homebrew:

```sh
brew install mkcert
mkcert -install
```

`mkcert -install` creates and trusts a local certificate authority; macOS may ask for your password. On Linux, follow mkcert's linked installation instructions first, then run `mkcert -install`.

From the project directory, generate the server certificate:

```sh
mkdir -p .certs
mkcert -cert-file .certs/localhost.pem -key-file .certs/localhost-key.pem localhost 127.0.0.1 ::1
chmod 600 .certs/localhost-key.pem
```

`.certs/` is excluded from Git and npm packaging. If those files already exist, reuse them; generation is a one-time setup step. Keep both the server private key and mkcert's CA private key private.

### 2. Set the HTTPS paths

Edit these existing entries in `.env`:

```dotenv
HOST=127.0.0.1
PORT=3001
API_PROTOCOL=https
TLS_CERT_FILE=.certs/localhost.pem
TLS_KEY_FILE=.certs/localhost-key.pem
```

These relative paths resolve from the installation directory. You may also use absolute paths to existing certificate files. Do not put `~` or `$HOME` in `.env` paths; they are not expanded.

### 3. Start and check the server

In your first terminal:

```sh
npm start
```

Leave it open. The startup message should say `https://127.0.0.1:3001`. In a **second terminal**, check the server without spending model credits:

```sh
curl --fail --silent --show-error https://localhost:3001/health
```

Expect `status: "ok"`, `reports.restPrefix: "/v2"`, and TypeSafe readiness `"ready"` when the required key is present. Readiness is a local configuration check, not a prediction-quality measurement.

Continue with [a real prompt check](#check-a-prompt). Press **Ctrl+C** in the server terminal to stop a manual server. This command does not install a background service; Bryan's existing automatic startup is documented separately in the [runbook](docs/operations/local-server.md).

The default binding is local to this computer. Keep Mapbox or other applications on their existing ports. If 3001 is occupied, choose a free `PORT` in `.env` and use it in every API URL.

## MCP setup

MCP does **not** connect to the HTTPS URL. Your MCP client starts `startMcp.js` and exchanges messages through that process's input/output pipes. You can use it without starting the API; no TLS setup is needed for this connection.

From the installation directory, print the exact paths for your client:

```sh
node -p 'JSON.stringify({command:process.execPath,args:[process.cwd()+"/dist/scripts/startMcp.js","--env-file",process.cwd()+"/.env"]},null,2)'
```

Paste those `command` and `args` values into your client's MCP settings. For clients that use `mcpServers`, the complete structure is:

```json
{
  "mcpServers": {
    "prompt-rejector": {
      "command": "/absolute/path/to/node",
      "args": [
        "/absolute/path/to/promptrejectormcp/dist/scripts/startMcp.js",
        "--env-file",
        "/absolute/path/to/promptrejectormcp/.env"
      ]
    }
  }
}
```

For **Codex CLI**, register it from the installation directory:

```sh
codex mcp add prompt-rejector -- "$(node -p 'process.execPath')" \
  "$PWD/dist/scripts/startMcp.js" --env-file "$PWD/.env"
```

Then start a new client session or reconnect the server. It should expose **11 tools**, including `check_prompt`. Ask the client to call it with:

```json
{ "prompt": "Summarize the weather forecast." }
```

The call uses the configured model accounts and can incur API charges. Configure the client to invoke **Node directly**, as shown: `npm run` writes a banner to stdout that can interfere with MCP. Keep the installation directory in place, and refresh the Node path if a Node upgrade moves the executable.

## Check a prompt

With the HTTPS API running:

```sh
curl --fail --silent --show-error --max-time 25 \
  https://localhost:3001/v2/check-prompt \
  -H 'Content-Type: application/json' \
  --data '{"prompt":"Summarize the weather forecast."}'
```

A response includes these fields (abbreviated example):

```json
{
  "schemaVersion": 2,
  "decision": "allow",
  "safe": true,
  "analysisMode": "cascade"
}
```

| Decision | What your application should do |
| --- | --- |
| `allow` | Continue; `safe` is true |
| `block` | Reject the input |
| `review` | Hold the input for review |
| `unavailable` | Do not approve; required analysis could not complete |

Always check `decision`, not just HTTP status or severity. The full report includes findings, completed/skipped checks, provider/model attribution, the configuration hash and usage. TypeSafe can block a conclusive attack before larger reasoning runs; a clean prompt still needs contextual reasoning.

Opening `/v2/check-prompt` in a browser sends **GET**, which does not scan anything. Use the POST example above. You can open [the health URL](https://localhost:3001/health) in a browser.

## Choose a different model

TypeSafe task modes and the reasoning model are separate settings. To switch contextual reasoning while keeping TypeSafe active:

1. Copy `config/ai.active.json` to `config/ai.local.json` and set `AI_CONFIG_PATH=config/ai.local.json` in `.env`.
2. Add the chosen provider's key: `ANTHROPIC_API_KEY` for Claude or `OPENAI_API_KEY` for OpenAI.
3. Change `roles.semantic.primary` to `claude-semantic` or `openai-reasoning`. Leave the other roles unchanged unless you also want to switch them.
4. Restart the API and reconnect MCP, then make a real scan and check its provider/model attribution.

The supplied profiles are declared in that file. A key must have access to the chosen model; an adapter's existence alone does not establish account access. Drafting, Taster and Monitor are independently selectable. See [model selection](docs/operations/ai-models.md) for profiles, bounded access probes and adding models.

The active configuration uses TypeSafe in decisions now. Formal held-out qualification is a separate optional assurance process, described in [TypeSafe operations](docs/operations/typesafe-rollout.md).

## Update an existing installation

In the installation directory, check your branch and local changes first:

```sh
git status --short
git branch --show-current
```

For a clean checkout already on `main`:

```sh
git pull --ff-only origin main
npm ci
npm run build
npm run ai:config
```

Keep your existing `.env`, keys and certificates. Restart the API and reconnect MCP after rebuilding. If you have local changes, preserve them before updating. For a clean checkout on the earlier `codex/typesafe-model-routing` branch, run `git fetch origin` and `git switch main`, then follow the commands above. A separate clone is also available when you need to keep an older installation intact.

For older installations, set `AI_CONFIG_PATH=config/ai.active.json`, configure the TLS paths, change API clients to `https://localhost:3001/v2/...`, and remove `mcpDefaultReportVersion` from custom configuration. The launcher commands select HTTPS or MCP themselves; an old `START_MODE` entry does not override them.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `node`, `npm` or `git` is not found | Install the prerequisite, reopen the terminal, and repeat the version checks. |
| `dist/scripts/startApi.js` or `startMcp.js` is missing | Run `npm ci` and `npm run build` in the correct checkout. |
| API startup fails | Check the two TLS file paths, key/certificate pairing, port availability and `npm run ai:config`. Missing TLS never falls back to plaintext HTTP. |
| Port 3001 is already in use | If it is your existing Prompt Rejector service, use that service. Otherwise select another free port; do not stop an unrelated application. |
| Certificate is not trusted | Run `mkcert -install` on the client machine and use a certificate covering `localhost`. Some runtimes need an explicit CA file; see [client trust](docs/operations/local-server.md#client-certificate-trust). Keep verification enabled. |
| `Cannot GET /v2/check-prompt` | Send a JSON **POST**. Use `GET /health` for a browser check. |
| HTTP 410 / `api_version_retired` | Replace `/v1` with `/v2` and use the current response fields. |
| `unavailable`, or missing/degraded credentials | Replace placeholder keys; check account access, quota and the selected model. A healthy listener does not guarantee working inference. |
| TypeSafe modes show `off` | Select `config/ai.active.json`. Check whether an exported `AI_CONFIG_PATH` is overriding `.env`, then restart/reconnect. |
| MCP cannot connect or reports invalid JSON | Use absolute Node/launcher paths, build first, pass the right `.env`, and invoke Node directly rather than `npm run`. |
| API and MCP appear to use different models | Restart both after configuration changes; compare `/health.configHash` with a new MCP scan's `configHash`. |

## Tools and endpoints

| MCP tool | Purpose |
| --- | --- |
| `check_prompt` | Screen a prompt |
| `scan_skill` | Scan skill content and its capabilities/model references |
| `scan_mcp_tool` | Check tool descriptions and nested schema text for poisoning |
| `check_lethal_trifecta` | Evaluate private-data access, untrusted input and external egress together |
| `taste_test` | Run an opt-in Taster/Monitor analysis using mocked tools |
| `list_patterns` | Browse detection patterns |
| `update_vuln_feeds` | Refresh advisory feeds and draft patterns for review |
| `verify_pattern_integrity` | Check pattern hashes/signatures |
| `query_cve` | Search the configured vulnerability sources |
| `deploy_canary` | Create a memory/RAG canary token |
| `verify_canary` | Check content for a canary echo |

| HTTPS method | Path |
| --- | --- |
| POST | `/v2/check-prompt` |
| POST | `/v2/scan-skill` |
| GET | `/v2/patterns` |
| POST | `/v2/patterns/update-feeds` |
| POST | `/v2/patterns/verify` |
| GET | `/health` |

REST exposes the endpoints listed above; the other tools are available through MCP. The Taste-Tester is disabled until `TASTE_TESTER_ENABLED=true`. Optional provider/feed/canary settings are explained in [.env.example](.env.example) and the [feature reference](docs/feature-reference.md).

## Development and documentation

```sh
npm run lint
npm run test:offline
```

The guarded offline runner builds first, blocks unexpected network calls and needs no real API keys. It includes HTTPS/MCP startup tests; **OpenSSL** must be available for the temporary test certificates. The original 57-suite delivery is recorded in the [delivery ledger](docs/implementation/typesafe-progress.md); the plugin upgrade adds authenticated remote MCP coverage plus separate package/install tests in [plugin verification](docs/plugin-verification.md). These tests do not guarantee detection of every attack.

- [Plugin installation, bundles and standalone skill](docs/plugins.md)
- [Plugin architecture research](docs/plugin-architecture.md)
- [Remote MCP and web connectors](docs/operations/remote-mcp.md)
- [Local service, HTTPS trust and restart runbook](docs/operations/local-server.md)
- [Model selection and native adapters](docs/operations/ai-models.md)
- [Language integration examples](docs/integration-examples.md)
- [Features, detection categories, feeds and architecture](docs/feature-reference.md)
- [Skill security guide](SKILLS_SECURITY.md)
- [TypeSafe evaluation and rollout](docs/operations/typesafe-rollout.md)
- [Live HTTPS and MCP verification](evaluations/ai/runs/2026-09-20-single-api/README.md)
- [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [ISC license](LICENSE)

Prompt Rejector is one security layer. Combine screening with restricted tool permissions, sandboxing and application-level controls; a model verdict is not a guarantee that an input or action is safe.
