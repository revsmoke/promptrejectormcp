# AI role configuration

For active TypeSafe use, build and run `npm run start:api -- --env-file /absolute/path/.env` for HTTPS, or configure your MCP client with an absolute Node executable and `dist/scripts/startMcp.js --env-file /absolute/path/.env`. HTTPS requires the certificate/key paths described in [local server setup](../docs/operations/local-server.md). Both launchers select `ai.active.json` unless `AI_CONFIG_PATH` or `--config` selects another file. They enable all five Jev tasks with Gemini contextual reasoning and always use current structured reports.

Copy `ai.active.json` to customize active use, or `ai.example.json` for an initially disabled rollout. Select named profiles independently for `semantic`, `patternDraft`, `taster`, and `monitor`, then set `AI_CONFIG_PATH` to that file. Restart after changes. Relative catalog/rate paths resolve beside the config file. Credentials stay in environment variables, never these JSON files. Keys do not select providers or enable TypeSafe.

`AI_CONFIG_PATH=config/ai.active.json npm run ai:config` validates the active configuration without inference and reports credential environment-variable names and presence, model declarations, enabled role references and unused or disabled profiles. Primary/fallback references are labeled; missing fallback credentials are reported without preventing startup. It does not check account access or claim detection quality. With no explicit config, legacy Gemini semantic/drafting and Anthropic Taster/Monitor profiles remain; TypeSafe is off.

Model identifiers are strings. Add a new identifier to a capability catalog and declare its supported native options before choosing it in a profile. Catalog metadata records documentation evidence; an explicit live conformance probe and task evaluation remain separate requirements. Unsupported options fail before inference. Provider endpoint URLs cannot be configured. The default catalog is included in the package; `capabilitiesFile` selects another local catalog. Catalog and pricing contents participate in immutable configuration hashing.

A live synthetic probe requires all safeguards explicitly:

```sh
AI_CONFIG_PATH=config/ai.active.json npm run ai:probe -- --live --profile claude-semantic --pricing config/ai-pricing.example.json --max-requests 2 --max-usd 1
AI_CONFIG_PATH=config/ai.active.json npm run ai:probe -- --live --profile typesafe --pricing config/ai-pricing.example.json --max-requests 2 --max-usd 1
```

The profile must exist in the selected AI config; `typesafe` selects the separate configured judgment model. `--env-file /absolute/path/.env` optionally loads a local key file without copying it. The request cap includes transport retries. Each command makes one logical call, never a provider fallback; limits are 1–20 attempts and at most $1. No inference runs without `--live`. Missing rates refuse a bounded probe before dispatch. Missing usage stays unknown. Synthetic conformance is not security qualification.

`ai-pricing.example.json` contains dated estimates and source URLs. It deliberately applies OpenAI's long-context upper rates to shorter calls and labels that overestimate. Gemini 3 Flash Preview uses the verified standard text rates ($0.50 input, $3.00 output including thinking, and $0.05 cached input per million tokens). Rates must be reviewed when models, account tiers or pricing change. OpenAI cache reads and writes are distinct subsets of input tokens; the adapter reads documented `input_tokens_details.cached_tokens` and `cache_write_tokens`. If either billed count is missing, estimated actual cost remains unknown and the conservative budget reservation remains held. See the [official cache usage documentation](https://developers.openai.com/api/docs/guides/prompt-caching).

All providers use the same current structured reports. MCP exposes no version selector. REST uses `/v2`; retired `/v1` paths return 410 without analysis. Taster sessions never switch providers midway.

For task modes, qualification, candidate evaluation and rollback, see [TypeSafe operations](../docs/operations/typesafe-rollout.md). `evaluationFile` is trusted local evidence, not a request override. `qualificationPolicy` defaults to `required`; `ai.active.json` explicitly uses `optional`. With optional policy and no evidence file, enforce/cascade run while reporting qualification as not performed. Required qualification rejects missing evidence; either policy rejects supplied evidence with expired or changed bindings. Pattern bindings are rechecked during analysis when qualification is required or supplied. Returned model identities are always checked against the selected route and any supplied resolution. Off/shadow can be used while qualification is pending. `/health` and `ai:config` report local readiness without inference; they do not establish live account access.

Both the HTTPS API and MCP use the active configuration through their dedicated launchers. See [combined setup](../docs/operations/local-server.md). The removed `mcpDefaultReportVersion` field must be deleted from custom config files.
