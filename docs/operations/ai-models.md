# Selecting and switching AI models

Prompt Rejector separates focused TypeSafe judgments from generative analysis. Scanners consume three typed contracts: `StructuredReasoner`, `JudgmentProvider` and `ToolConversationProvider`. Code validates responses, preserves deterministic findings and decides what to block or review. A probability or valid JSON response is not proof of correctness.

## Run with TypeSafe active

```sh
npm run build
npm run start:api -- --env-file /absolute/path/to/.env
# MCP clients launch this separately using absolute paths:
/absolute/path/to/node /absolute/path/to/promptrejectormcp/dist/scripts/startMcp.js \
  --env-file /absolute/path/to/.env
```

Both launchers use `config/ai.active.json` and anchor the project directory. The API serves HTTPS on port 3001 and requires certificate/key paths; see [HTTPS and MCP setup](local-server.md). The MCP launcher keeps stdout exclusively for protocol messages. The active profile uses Jev for all five judgment tasks and Gemini for contextual reasoning. Both transports always return current structured reports. It needs `TYPESAFE_API_KEY` and `GEMINI_API_KEY` in the local environment file. Taster remains separately opt-in. `--config /absolute/path/ai.json` explicitly selects another configuration; otherwise an existing `AI_CONFIG_PATH` takes precedence over the active default.

For Codex, register the built launcher (use absolute paths):

```sh
codex mcp add prompt-rejector -- /absolute/path/to/node \
  /absolute/path/to/promptrejectormcp/dist/scripts/startMcp.js \
  --env-file /absolute/path/to/.env
```

A new Codex session loads the configured server. Keep the installation directory available; the launcher resolves patterns and catalogs there. Normal client tool-approval preferences still apply. Bryan's local server is registered against the implementation worktree and was verified through the native Codex client.

The active profile sets `qualificationPolicy: "optional"`: this is explicit activation, with formal qualification reported as not performed. Supplying an `evaluationFile` still requires that evidence to pass every validation. The earlier required-qualification workflow remains available by selecting `qualificationPolicy: "required"`. Model adapters, response validation and security policy are the same in both cases.

## Roles and credentials

| Role | Purpose | Providers |
| --- | --- | --- |
| `semantic` | Contextual security analysis | Gemini, Anthropic Claude, OpenAI |
| `patternDraft` | Draft structured detection patterns | Gemini, Anthropic Claude, OpenAI |
| `taster` | Act inside an entirely mocked sandbox | Gemini, Anthropic Claude, OpenAI |
| `monitor` | Assess the resulting sandbox transcript | Gemini, Anthropic Claude, OpenAI |
| TypeSafe task modes | Descriptor, intent, capability and reference judgments | TypeSafe Jev |

Credentials are `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `TYPESAFE_API_KEY`. Keep them in the server environment or a local untracked `.env`. Configuration and logs contain no key values. Possessing a key does not enable a role or prove the account can use its selected model.

`npm start` is the HTTPS API launcher and selects the active configuration unless you explicitly choose another file. Missing required inference credentials produce degraded/unavailable analysis rather than a safe verdict. The low-level configuration loader and standalone diagnostic tools retain environment defaults when no config is selected; set `AI_CONFIG_PATH` explicitly when checking the running installation.

## Configuration and a model switch

Copy `config/ai.active.json` beside the original (for example, `config/ai.local.json`) to keep TypeSafe enabled and preserve relative catalog paths while changing models. Use `config/ai.example.json` only when you want an initially disabled rollout. Set `AI_CONFIG_PATH` to its absolute path and restart the process after changes. The service loads a single immutable snapshot after dotenv; REST and MCP share its configuration hash. Relative capability, price and evaluation files resolve beside that configuration file.

For example, select the existing Claude semantic profile:

```json
"semantic": { "primary": "claude-semantic" }
```

Then change only that role to the configured OpenAI profile:

```json
"semantic": { "primary": "openai-reasoning" }
```

Taster, Monitor and drafting settings remain independent. A Monitor-only switch changes `roles.monitor.primary`. Use profile names actually present in your file; the configuration checker rejects unknown references. With required qualification or a supplied evaluation file, every decision-affecting primary and fallback profile must have matching qualification evidence. The optional active profile permits an explicit provider switch without manufacturing qualification records; test the selected account/model before relying on it.

A configured fallback runs once only for eligible availability failures, within the same request deadline and attempt allowance. It does not run because a model judged a prompt suspicious, refused a request, returned incomplete output or hit a budget limit. Taster sessions never switch provider halfway through a conversation. Monitor may use its independently configured availability fallback.

## Native adapters

| Provider | Native interface | Adapter responsibilities |
| --- | --- | --- |
| Claude | Messages, structured output and tool-use blocks | Parse refusal/stop reasons; preserve private thinking/signatures between turns; normalize cache-read and cache-write usage |
| OpenAI | Responses, JSON schema and function calls | Handle completed/incomplete/refusal status; preserve private reasoning items; normalize output/reasoning and cached input subsets |
| Gemini | `generateContent`, response schema and function calls | Handle candidates/finish reasons; preserve thought signatures; account separately for candidate and thought tokens; enforce array/string limits in the local parser because complex native array bounds can reject valid skill schemas |
| TypeSafe | `/v1/systemone`, batched Noul and Choice | Validate exact question IDs, probabilities, selected source IDs, pinned/resolved model and usage |

Only public text and normalized valid/rejected tool-call evidence enter the Taster report and Monitor prompt. Private continuation objects remain inside the provider adapter, are disposed after the run and are never logged. The eight tools return deterministic synthetic results; no shell command, email, transfer, database operation or external URL supplied by a model is executed.

Model names are configuration strings. Adding a model from an existing provider generally means adding its documented capabilities/options to `model-capabilities.json` or a local catalog and selecting a profile. Unsupported options fail before inference. A new provider needs a native adapter and contract tests; an OpenAI-shaped HTTP endpoint is not assumed to be interchangeable. Provider endpoints cannot be overridden by scan input or profile configuration.

## Check access without accidental spending

```sh
AI_CONFIG_PATH=config/ai.active.json npm run ai:config
AI_CONFIG_PATH=config/ai.active.json npm run ai:probe -- --live --profile typesafe --pricing config/ai-pricing.example.json --max-requests 1 --max-usd 0.01
AI_CONFIG_PATH=config/ai.active.json npm run ai:probe -- --live --profile claude-semantic --pricing config/ai-pricing.example.json --max-requests 1 --max-usd 0.15
```

The Claude profile is available in the active and example configurations; it requires a working Anthropic account. `--env-file /absolute/path/.env` loads an explicit local secret file for a probe. Probes use synthetic input, require live opt-in and count physical retries against the request cap. They do not establish security quality. A missing rate, unsupported profile or insufficient conservative reservation stops dispatch. Inspect `actualAttempts`: a failed preflight is not an attempted model call.

The example price card is dated, uses standard text rates, and deliberately overestimates OpenAI Astra with its long-context upper rates. Review prices for your account before spending. Missing usage or billable token details remain unknown; a known conservative reservation remains held. Limits are process-local, not a shared account-wide cap.

## One current API and MCP interface

REST uses `/v2/check-prompt` and `/v2/scan-skill`. Bodies keep their existing `prompt` or `skillContent` fields. Reports provide `decision`, `safe`, coverage, provider/model attribution, usage and routing. Only `decision: "allow"` gives `safe: true`. HTTPS is the default; the local URL is `https://localhost:3001`.

The former `/v1/*` routes are retired. They return HTTP 410 with `api_version_retired` and the replacement path before parsing the body or performing analysis. Pattern operations also use `/v2/patterns`. There is no separate legacy scanning mode exposed to clients.

The existing 11 MCP tools remain. MCP always uses the current pipeline and advertises no version selector. Remove `mcpDefaultReportVersion` from trusted configuration; it is no longer accepted. Existing callers that send `reportVersion: 2` are tolerated, while `reportVersion: 1` is rejected before inference. New callers omit that field:

```json
{ "prompt": "Summarize this public article." }
```

For REST, send `POST /v2/check-prompt` with `{"prompt":"Summarize this public article."}`. A response may contain this abbreviated decision fragment when the configured semantic key is absent:

```json
{
  "schemaVersion": 2,
  "task": "prompt",
  "decision": "unavailable",
  "safe": false,
  "analysisMode": "off"
}
```

The full response also includes required coverage, local findings, typed provider results, routing, usage and the config hash. Clients should check `decision` rather than infer safety from HTTP 200, a low severity or a numeric confidence. In a conclusive-block cascade, unperformed checks explicitly say `not_requested` with a reason; that is not completed clean coverage.

Provider failure is now explicitly unavailable and cannot quietly become benign. This reliability fix also applies when TypeSafe is off. Migrate clients to handle `allow`, `block`, `review` and `unavailable`; a successful HTTP status alone is not a safe result. Invalid bodies return 400, oversized inputs 413 and unexpected server errors 500. Valid v2 domain reports return 200 even when analysis is unavailable.

## Verification status

See the [implementation ledger](../implementation/typesafe-progress.md) for exact commits, reviewed gates, runtime tests and live access results. Adapter fixtures and green tests do not establish that Claude, OpenAI or Gemini is best for this project's data. Use the same task schema, independently reviewed corpus and total latency/cost measurements when comparing them.

## Plugin configuration

Local plugins reuse these profiles and adapters. `npm run plugin:setup -- --config /absolute/path/config.json` saves the selected configuration path; reconnect MCP after changes. Bundled clients can use `PROMPT_REJECTOR_AI_CONFIG`. Claude Desktop exposes an optional configuration-file picker and secret fields for TypeSafe, Gemini, Anthropic and OpenAI. A client brand does not select the model provider. Keep TypeSafe active when changing reasoning roles. See [plugin installation](../plugins.md).
