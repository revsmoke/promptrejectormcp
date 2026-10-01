# CLI and JavaScript SDK

The CLI runs the same local services and current structured reports as MCP and HTTPS. It covers all 11 MCP operations plus configuration health, without starting a server or requiring a certificate. Use a long-lived SDK client or JSONL batch for repeated work; each retains its own service graph and existing judgment caches. Prompt judgments remain uncached by policy. Separate CLI processes do not share in-memory caches.

## Install and discover

Build the current source as described in the [installation guide](../README.md#installation):

```sh
npm ci
npm run build
node dist/cli/main.js --help
node dist/cli/main.js commands --pretty
node dist/cli/main.js check-prompt --help
```

`commands` emits an array of command names and JSON input schemas for agents. Command-specific help emits its input schema. These commands and `--version` need no configuration, keys, server, or inference. Both hyphenated commands and existing MCP names with underscores are accepted.

To install this checkout as an executable, first build it, then run:

```sh
npm install --global .
prompt-rejector --version
```

Choose a user-writable npm prefix if needed. Alternatively, use the absolute `node /path/to/promptrejectormcp/dist/cli/main.js` entrypoint. For machines without a checkout, `npm pack` builds a tarball which can be installed with `npm install --global /path/to/prompt-rejector-<version>.tgz`. Use source or a tarball containing this change until a new npm release is published; the previously published 1.2.0 package does not have the CLI. `npm run --silent cli -- ...` also works from a built checkout; avoid ordinary npm banners when parsing stdout.

## Configuration and paths

The CLI loads the installation's `.env` when present. `--env /path/to/private.env` selects another file; inherited environment variables take precedence, including empty values. An explicit missing file is an error. Credentials are never accepted as command options. The CLI uses `--env` to avoid Node 22+ interpreting its reserved `--env-file` flag before the application starts. API/MCP launchers keep their existing options.

`--config` overrides `AI_CONFIG_PATH`, which overrides the installation's `config/ai.active.json`. Explicit `--file`, `--env`, and `--config` paths resolve relative to the caller's working directory. A relative `AI_CONFIG_PATH` resolves relative to the installation, matching the API/MCP launchers. Paths inside the JSON configuration resolve beside that file. Neither the CLI nor SDK changes the caller's working directory.

```sh
prompt-rejector health --env /path/to/private.env --pretty
prompt-rejector verify-pattern-integrity
```

`health` performs no inference and returns the same local readiness details as `/health`; missing required credentials give exit 3. Ready means configuration/key presence, not verified account access or detection quality. An invalid inherited config path must be corrected or overridden with `--config`; it is never silently ignored. Other operations return configuration errors when their service graph cannot initialize.

Scans use the configured providers and may incur inference charges. See [model configuration](operations/ai-models.md) for limits and provider selection. Feed updates write staged candidates; canary deployment writes token state. These use the same installation-local storage as MCP (`patterns/`, including staging and canary state). Serialize state-changing operations across processes. An installation used for these operations must be writable. A read-only installed package is suitable for scans and read operations when its configuration/state allow initialization.

## Single commands

```sh
printf '%s' 'Summarize the weather forecast.' | prompt-rejector check-prompt
prompt-rejector scan-skill --file ./SKILL.md
prompt-rejector check-prompt --text 'Summarize this public report.' --pretty
prompt-rejector scan-mcp-tool --file ./tool-request.json
prompt-rejector list-patterns --input '{"category":"xss","enabled":true}'
prompt-rejector query-cve --input '{"keyword":"agent","inKev":true,"limit":10}'
prompt-rejector check-lethal-trifecta --input '{"tools":["read_file","fetch_url","send_email"]}'
```

Choose one input source: `--text`, `--file`, or `--input`. `--file -` reads stdin. Without a source, commands requiring input read piped stdin; optional-input commands use `{}`. In an interactive terminal, required input must be supplied explicitly. Empty or malformed required input is rejected before scanning.

`check-prompt`, `scan-skill`, `verify-canary`, and `taste-test` read raw UTF-8 text from files/stdin, or accept `--text`. Other commands read a complete JSON arguments object. **`--input` always takes a JSON arguments object**, so use it to include optional fields, or when the text begins with `--`. For example, a tool request file contains `{"tool":{"name":"search","description":"Public search","inputSchema":{"type":"object"}}}`, with optional `priorHash` beside `tool`.

| Command | JSON arguments | Result |
| --- | --- | --- |
| `check-prompt` | `prompt` | Current prompt report |
| `scan-skill` | `skillContent` | Current skill report |
| `scan-mcp-tool` | `tool`, optional `priorHash` | Current descriptor report |
| `check-lethal-trifecta` | At least one of `tools`, `capabilities`, `skillContent` | Current capability report |
| `taste-test` | `prompt`, optional `mode` (`fast`/`thorough`), `context` | Taster/Monitor report; requires enabled Taster |
| `list-patterns` | Optional `category`, `scope` (`general`/`skill`), `enabled` | `count`, `patterns` |
| `update-vuln-feeds` | Optional `lookbackDays` (1–365) | Feed counts and errors; stages candidates |
| `verify-pattern-integrity` | `{}` | Hash/HMAC integrity report |
| `query-cve` | Optional `keyword`, `ecosystem`, `atlasTechnique`, `severity`, `inKev`, `limit` (1–200) | Local cached/staged CVE records |
| `deploy-canary` | Optional `context`, `ttlSeconds` (1–2,592,000) | Token, watch handle, expiration |
| `verify-canary` | `content`, optional `watchHandle` | Echo detection and matches |
| `health` | `{}` | Local configuration and credential presence |

`commands` is the machine-readable field/type reference. Unknown fields are rejected; request data cannot override trusted models, provider endpoints, credentials, or configuration. Existing per-command character limits apply (100,000 for prompts; 500,000 for skills), plus a 4 MiB input/JSONL-line byte ceiling. A detected oversized JSONL line ends the stream with exit 2.

## Automation contract

Successful command execution writes exactly one JSON result and a newline to stdout, even when the security decision rejects the input. `--pretty` indents that result. Diagnostics and a redacted JSON error such as `{"error":"invalid_input"}` go to stderr; operational errors produce no single-command result. Help/version are the only plain-text stdout modes. No progress banners or provider keys are written to stdout. Reports can contain scanned content and canary tokens; handle them accordingly.

| Exit code | Meaning |
| --- | --- |
| `0` | Scan explicitly allowed (`decision: "allow"`, `safe: true`), complete clean Taster, or successful non-scan operation |
| `1` | Block/review, canary echo, failed pattern integrity, or complete suspicious/malicious Taster |
| `2` | Invalid command/options/input, JSON, schema, or size |
| `3` | Unavailable/incomplete analysis, configuration/I/O/internal failure, partial feed errors, or degraded health |
| `124` | Explicit invocation timeout |
| `130` / `143` | SIGINT / SIGTERM cancellation |

A non-scan command's success says nothing about prompt safety. Only an explicit allow permits a scanned input to proceed. Preserve the report for coverage, evidence, usage and provider failures. No severity threshold overrides this decision.

```sh
if prompt-rejector check-prompt --file prompt.txt --timeout-ms 30000 > report.json; then
  echo 'Input allowed'
else
  code=$?
  echo "Input not approved (exit $code); inspect report.json and stderr" >&2
  exit "$code"
fi
```

`--timeout-ms 1..3600000` limits the whole invocation, including stdin and all batch records. Without it, configured provider/task budgets apply, but there is no outer CLI deadline. A timeout or signal aborts supported inference and terminates the CLI, including non-cooperative work. A feed/canary write that already completed is not rolled back. A consumer closing stdout early exits 3. Read all results when the exit code matters.

## Streaming batches

```sh
prompt-rejector batch --file requests.jsonl > results.jsonl
```

Each nonblank input line is a JSON object with `command`, optional `input` (default `{}`), and optional `id` (string, number, or null):

```jsonl
{"id":"pattern-check","command":"verify-pattern-integrity"}
{"id":"prompt-1","command":"check-prompt","input":{"prompt":"Summarize public weather."}}
{"id":"tool-1","command":"scan-mcp-tool","input":{"tool":{"name":"weather","description":"Read public forecasts."}}}
```

Records execute sequentially with one reusable client. Each output line is flushed before reading the next request, so a producer can keep stdin open. Successful operations emit `{line,id?,command,result,exitCode}`. Invalid/failed records emit `{line,id?,error,exitCode}` and processing continues. `line` is the original one-based line number; an ID is retained once its envelope validates. The process returns the highest record exit code (3 over 2 over 1 over 0). Empty batches are invalid. Stream I/O/size errors, deadlines and signals end the batch immediately; prior lines remain valid. `--pretty`, `--input` and `--text` are rejected in batch mode. Consume output concurrently with writing requests to respect pipe backpressure.

## JavaScript and TypeScript

Install the built source or tarball into your application (`npm install /path/to/promptrejectormcp` after building), then use the ESM package entry:

```ts
import { createPromptRejector, PromptRejectorError } from 'prompt-rejector';

// Set provider environment variables before construction. No dotenv is loaded by the SDK.
const scanner = createPromptRejector();
try {
  const report = await scanner.run('check-prompt', {
    prompt: 'Summarize this public report.'
  }, { signal: AbortSignal.timeout(30_000) });
  if (report.decision !== 'allow') throw new Error('Input was not approved');
  // Process the approved input here.
} catch (error) {
  if (error instanceof PromptRejectorError) console.error(error.code);
  throw error; // An exception never permits processing.
}
```

`run` infers input and result types from the command. Exported types include `Command`, `CommandInput<C>`, `CommandResult<C>`, `PromptRejectorClient`, `ClientOptions`, `RunOptions`, and `ErrorCode`. `commandNames`, `normalizeCommand`, and `resultExitCode` are also exported. TypeScript uses hyphenated names; normalize an MCP name before calling `run` from generic code. Runtime validation applies to JavaScript callers too. Errors expose a stable redacted `code`, never the raw provider error or submitted input.

`createPromptRejector({configPath: '/path/to/ai.json'})` overrides the configuration. The SDK uses inherited `AI_CONFIG_PATH` relative to the application's cwd, or defaults to the installed active config. It never loads `.env`, opens listeners, changes cwd, changes console, or installs signal handlers. Importing performs no construction/inference. Client construction reads configuration and local state. Advanced callers can supply an existing `services` graph. Reuse the client for application requests; no `close()` is needed. Restart/recreate it to select changed configuration.

Pass an `AbortSignal` to cancel supported scanner/provider work. Pre-aborted calls dispatch nothing; cancellation throws `PromptRejectorError('cancelled')`. Feed updates and synchronous filesystem operations do not support interrupting in-flight work; the SDK checks cancellation before/after them. Security decisions and provider unavailability are normally returned as reports; callers must inspect the decision rather than rely on exceptions alone.

For Python or another language, invoke the CLI with an argument array and feed text on stdin, or use the existing [HTTPS integrations](integration-examples.md):

```python
import json
import subprocess

completed = subprocess.run(
    ["prompt-rejector", "check-prompt", "--timeout-ms", "30000"],
    input="Summarize public weather.", text=True, capture_output=True, timeout=35,
)
report = json.loads(completed.stdout) if completed.stdout else None
allowed = completed.returncode == 0 and report is not None and report.get("decision") == "allow"
```

The package root now exports the SDK. Applications that previously imported the root to launch servers must use the dedicated `dist/scripts/startApi.js` or `dist/scripts/startMcp.js` entrypoint. `npm start` and existing MCP launcher configurations continue to work.
