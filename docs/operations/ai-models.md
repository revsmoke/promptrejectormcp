# Selecting and switching AI models

Prompt Rejector separates focused TypeSafe judgments from generative analysis. Scanners consume three typed contracts: `StructuredReasoner`, `JudgmentProvider` and `ToolConversationProvider`. Code validates responses, preserves deterministic findings and decides what to block or review. A probability or valid JSON response is not proof of correctness.

## Roles and credentials

| Role | Purpose | Providers |
| --- | --- | --- |
| `semantic` | Contextual security analysis | Gemini, Anthropic Claude, OpenAI |
| `patternDraft` | Draft structured detection patterns | Gemini, Anthropic Claude, OpenAI |
| `taster` | Act inside an entirely mocked sandbox | Gemini, Anthropic Claude, OpenAI |
| `monitor` | Assess the resulting sandbox transcript | Gemini, Anthropic Claude, OpenAI |
| TypeSafe task modes | Descriptor, intent, capability and reference judgments | TypeSafe Jev |

Credentials are `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `TYPESAFE_API_KEY`. Keep them in the server environment or a local untracked `.env`. Configuration and logs contain no key values. Possessing a key does not enable a role or prove the account can use its selected model.

Without `AI_CONFIG_PATH`, semantic analysis and drafting keep `gemini-3-flash-preview`; Taster and Monitor use the legacy Anthropic profile. TypeSafe defaults off. Existing installations need no new key merely to start, although missing required inference credentials produce degraded/unavailable analysis rather than a safe verdict.

## Configuration and a model switch

Copy `config/ai.example.json` to a local file. Set `AI_CONFIG_PATH` to its absolute path and restart the process after changes. The service loads a single immutable snapshot after dotenv; REST and MCP share its configuration hash. Relative capability, price and evaluation files resolve beside that configuration file.

For example, select the existing Claude semantic profile:

```json
"semantic": { "primary": "claude-semantic" }
```

Then change only that role to the configured OpenAI profile:

```json
"semantic": { "primary": "openai-reasoning" }
```

Taster, Monitor and drafting settings remain independent. A Monitor-only switch changes `roles.monitor.primary`. Use profile names actually present in your file; the configuration checker rejects unknown references. In enforced modes, every decision-affecting primary and fallback profile must have matching qualification evidence. Switching back to an old profile also requires current evidence.

A configured fallback runs once only for eligible availability failures, within the same request deadline and attempt allowance. It does not run because a model judged a prompt suspicious, refused a request, returned incomplete output or hit a budget limit. Taster sessions never switch provider halfway through a conversation. Monitor may use its independently configured availability fallback.

## Native adapters

| Provider | Native interface | Adapter responsibilities |
| --- | --- | --- |
| Claude | Messages, structured output and tool-use blocks | Parse refusal/stop reasons; preserve private thinking/signatures between turns; normalize cache-read and cache-write usage |
| OpenAI | Responses, JSON schema and function calls | Handle completed/incomplete/refusal status; preserve private reasoning items; normalize output/reasoning and cached input subsets |
| Gemini | `generateContent`, response schema and function calls | Handle candidates/finish reasons; preserve thought signatures; account separately for candidate and thought tokens |
| TypeSafe | `/v1/systemone`, batched Noul and Choice | Validate exact question IDs, probabilities, selected source IDs, pinned/resolved model and usage |

Only public text and normalized valid/rejected tool-call evidence enter the Taster report and Monitor prompt. Private continuation objects remain inside the provider adapter, are disposed after the run and are never logged. The eight tools return deterministic synthetic results; no shell command, email, transfer, database operation or external URL supplied by a model is executed.

Model names are configuration strings. Adding a model from an existing provider generally means adding its documented capabilities/options to `model-capabilities.json` or a local catalog and selecting a profile. Unsupported options fail before inference. A new provider needs a native adapter and contract tests; an OpenAI-shaped HTTP endpoint is not assumed to be interchangeable. Provider endpoints cannot be overridden by scan input or profile configuration.

## Check access without accidental spending

```sh
npm run ai:config
npm run ai:probe -- --live --profile typesafe --pricing config/ai-pricing.example.json --max-requests 1 --max-usd 0.01
npm run ai:probe -- --live --profile claude-semantic --pricing config/ai-pricing.example.json --max-requests 1 --max-usd 0.15
```

The last profile requires the example configuration to be selected. `--env-file /absolute/path/.env` loads an explicit local secret file for a probe. Probes use synthetic input, require live opt-in and count physical retries against the request cap. They do not establish security quality. A missing rate, unsupported profile or insufficient conservative reservation stops dispatch. Inspect `actualAttempts`: a failed preflight is not an attempted model call.

The example price card is dated, uses standard text rates, and deliberately overestimates OpenAI Astra with its long-context upper rates. Review prices for your account before spending. Missing usage or billable token details remain unknown; a known conservative reservation remains held. Limits are process-local, not a shared account-wide cap.

## Versioned clients

REST v1 remains at `/v1/check-prompt` and `/v1/scan-skill`; v2 is `/v2/check-prompt` and `/v2/scan-skill`. Bodies keep their existing `prompt` or `skillContent` fields. V2 reports provide `decision`, `safe`, coverage, provider/model attribution, usage and routing. Only `decision: "allow"` gives `safe: true`.

**TypeSafe enforcement and cascade apply only to version 2.** Version 1 prompt and skill calls retain their validated legacy analysis path even when the server is configured for enforce/cascade. Existing Gemini clients must explicitly migrate to v2 before expecting those policies. Version 1 descriptor/capability calls likewise remain local.

The existing 11 MCP tools remain. Set `reportVersion: 2` on `check_prompt`, `scan_skill`, `scan_mcp_tool`, `check_lethal_trifecta` or `taste_test` to opt in. Default version is 1. Non-Gemini semantic primary/fallback profiles require v2; v1 returns `report_version_required` before inference (REST 409, MCP error). Version 1 Taster requires Anthropic for both Taster and Monitor routes. Legacy descriptor/capability paths remain local and do not acquire TypeSafe enforcement silently.

Example MCP arguments:

```json
{ "prompt": "Summarize this public article.", "reportVersion": 2 }
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
