# Running the HTTPS API and MCP together

Prompt Rejector has one current analysis pipeline, available through two connections:

| Connection | Address or command | How it runs |
| --- | --- | --- |
| HTTPS REST API | `POST https://localhost:3001/v2/check-prompt` | A persistent local server |
| MCP | The registered `prompt-rejector` stdio server | Each MCP client starts its own process |

Both select `config/ai.active.json`, enabling TypeSafe Jev judgments and Gemini contextual reasoning. They can run simultaneously. The MCP connection uses the client's input/output pipes and does not need a network port or certificate. The REST connection uses HTTPS with a trusted local certificate. Port 3000 remains available to the existing Mapbox service.

`/v2` is the sole current API prefix. The old `/v1/*` routes return HTTP 410 without running analysis. The number identifies the response format; it does not mean that two scanning versions remain available. All 11 MCP tool names remain, with no advertised version selector.

## Use the running local installation

```sh
# Checks the local service without a model call:
curl --fail https://localhost:3001/health

# Performs a real analysis using the configured models:
curl --fail https://localhost:3001/v2/check-prompt \
  -H 'Content-Type: application/json' \
  --data '{"prompt":"Summarize the weather forecast."}'
```

Prompt checks require a JSON **POST**. Opening that URL in a browser sends a GET and does not check a prompt. `/health` is a GET endpoint. It reports configuration and credential readiness; the saved [live checks](../../evaluations/ai/runs/2026-09-20-single-api/README.md) separately prove actual model access.

Use the returned `decision`: `allow`, `block`, `review` or `unavailable`. Only `allow` has `safe: true`. An HTTP 200 alone does not establish safety. Prompt and skill requests retain their `prompt` and `skillContent` fields.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/v2/check-prompt` | Check a prompt |
| POST | `/v2/scan-skill` | Check skill content |
| GET | `/v2/patterns` | List patterns |
| POST | `/v2/patterns/update-feeds` | Refresh advisory feeds |
| POST | `/v2/patterns/verify` | Verify pattern integrity |
| GET | `/health` | Read local readiness without inference |

## Installed macOS service

The current local deployment uses:

- Installation: `/Users/twoedge/.codex/worktrees/typesafe-model-routing/promptrejectormcp`
- Credentials: `/Users/twoedge/Dev/promptrejectormcp/.env` (untracked)
- API LaunchAgent: `~/Library/LaunchAgents/net.promptrejector.api.plist`
- API log directory: `~/Library/Logs/PromptRejector/`
- Certificate: `/opt/homebrew/etc/httpd/certs/localhost.pem`
- Private key: `/opt/homebrew/etc/httpd/certs/localhost-key.pem`

The LaunchAgent starts at user login and restarts the API if it exits. It explicitly selects port 3001, HTTPS, the active configuration and the credential file. It reads the existing trusted localhost certificate without changing Apache. It binds to `127.0.0.1`, so the API is local to this Mac. This user-login service does not promise availability before login or while the Mac sleeps.

Inspect or restart this API service:

```sh
launchctl print gui/$(id -u)/net.promptrejector.api
launchctl kickstart -k gui/$(id -u)/net.promptrejector.api
tail -n 80 ~/Library/Logs/PromptRejector/api.stderr.log
```

Do not start a second manual API process while the LaunchAgent already owns port 3001. A port-in-use failure is deliberate; the launcher does not move itself to another port or replace another application's process. Keep the installation directory and built files available while the service points there.

## Manual startup or another installation

Build from the installation directory. Keep credentials and local certificate paths in an untracked environment file:

```dotenv
TYPESAFE_API_KEY=your-typesafe-key
GEMINI_API_KEY=your-gemini-key
HOST=127.0.0.1
PORT=3001
API_PROTOCOL=https
TLS_CERT_FILE=/absolute/path/to/localhost.pem
TLS_KEY_FILE=/absolute/path/to/localhost-key.pem
```

```sh
npm ci
npm run build
npm run start:api -- --env-file /absolute/path/to/.env
# npm start is the same API launcher.
```

The certificate must cover `localhost` and be trusted by the connecting client. On Bryan's Mac, the existing certificate also covers `127.0.0.1`. Missing or invalid certificate/key files stop HTTPS startup; the server never silently falls back to plaintext. An explicit `API_PROTOCOL=http` is available for a separately configured TLS-terminating reverse proxy, but the installed local service uses HTTPS directly.

API options are `--env-file`, `--config`, `--port`, `--tls-cert` and `--tls-key`. Explicit arguments take precedence over environment values. The dedicated launchers choose their own transport even if an older `.env` contains `START_MODE`. Both default to the active configuration unless `AI_CONFIG_PATH` or `--config` selects another file.

## MCP client setup

The local Codex client already has `prompt-rejector` registered. New client sessions launch the built MCP server. For another client, use an absolute Node path and the installation's built launcher:

```json
{
  "mcpServers": {
    "prompt-rejector": {
      "command": "/absolute/path/to/node",
      "args": [
        "/absolute/path/to/promptrejectormcp/dist/scripts/startMcp.js",
        "--env-file",
        "/absolute/path/to/.env"
      ]
    }
  }
}
```

Configure the client to invoke Node directly, as above: an ordinary `npm run` command prints a banner to stdout that can interfere with MCP. For a manual terminal launch, `npm run start:mcp` is available. The MCP launcher itself anchors the working directory and keeps stdout for protocol messages. It never starts another API listener. Invoke `check_prompt` with `{"prompt":"Summarize the weather forecast."}`; no version field is needed. A redundant `reportVersion: 2` is accepted for existing callers, while version 1 is rejected before inference.

## Change models or restart after changes

Select role profiles in a copy of `config/ai.active.json`, then select that file for **both** launchers. See [model selection](ai-models.md). Rebuild after source changes, restart the API LaunchAgent, and reconnect or start a new MCP client session. Each process loads an immutable configuration snapshot and keeps its own bounded caches. A model switch in one running process does not update the other automatically.

Compare `/health.configHash` with a new MCP scan's `configHash` to confirm both loaded the same configuration. An invalid configuration stops startup rather than serving with a different model silently.

## Client certificate trust

If a client rejects the local certificate, configure its trust store with the local CA. For example, Node clients can use `NODE_EXTRA_CA_CERTS` and Python Requests can use `REQUESTS_CA_BUNDLE`, pointing to the public CA certificate from `mkcert -CAROOT`. Keep certificate verification enabled. Check certificate expiry and restart the API after renewing its files.
