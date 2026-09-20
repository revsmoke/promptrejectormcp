# AI role configuration

Copy `ai.example.json`, select named profiles independently for `semantic`, `patternDraft`, `taster`, and `monitor`, then set `AI_CONFIG_PATH` to that file. Restart after changes. Relative catalog/rate paths resolve beside the config file. Credentials stay in environment variables, never these JSON files. Keys do not select providers or enable TypeSafe.

`npm run ai:config` validates configuration without inference and reports credential environment-variable names and presence, model declarations, enabled role references and unused or disabled profiles. Primary/fallback references are labeled; missing fallback credentials are reported without preventing startup. It does not check account access or claim detection quality. With no explicit config, legacy Gemini semantic/drafting and Anthropic Taster/Monitor profiles remain; TypeSafe is off.

Model identifiers are strings. Add a new identifier to a capability catalog and declare its supported native options before choosing it in a profile. Catalog metadata records documentation evidence; an explicit live conformance probe and task evaluation remain separate requirements. Unsupported options fail before inference. Provider endpoint URLs cannot be configured. The default catalog is included in the package; `capabilitiesFile` selects another local catalog. Catalog and pricing contents participate in immutable configuration hashing.

A live synthetic probe requires all safeguards explicitly:

```sh
npm run ai:probe -- --live --profile claude-semantic --pricing config/ai-pricing.example.json --max-requests 2 --max-usd 1
npm run ai:probe -- --live --profile typesafe --pricing config/ai-pricing.example.json --max-requests 2 --max-usd 1
```

The profile must exist in the selected AI config; `typesafe` selects the separate configured judgment model. `--env-file /absolute/path/.env` optionally loads a local key file without copying it. The request cap includes transport retries. Each command makes one logical call, never a provider fallback; limits are 1–20 attempts and at most $1. No inference runs without `--live`. Missing rates refuse a bounded probe before dispatch. Missing usage stays unknown. Synthetic conformance is not security qualification.

`ai-pricing.example.json` contains dated estimates and source URLs. It deliberately applies OpenAI's long-context upper rates to shorter calls and labels that overestimate. Gemini 3 Flash Preview uses the verified standard text rates ($0.50 input, $3.00 output including thinking, and $0.05 cached input per million tokens). Rates must be reviewed when models, account tiers or pricing change. OpenAI cache reads and writes are distinct subsets of input tokens; the adapter reads documented `input_tokens_details.cached_tokens` and `cache_write_tokens`. If either billed count is missing, estimated actual cost remains unknown and the conservative budget reservation remains held. See the [official cache usage documentation](https://developers.openai.com/api/docs/guides/prompt-caching).

Anthropic and OpenAI require version 2 semantic scan reports. A configured non-Gemini fallback also requires version 2 before inference. Native Taster conversations support Gemini, Claude and OpenAI; Monitor selection is independent. Version 1 Taster reports require Anthropic for both roles, including any configured fallback. Other combinations require version 2. Taster sessions never switch providers midway.

For task modes, qualification, candidate evaluation and rollback, see [TypeSafe operations](../docs/operations/typesafe-rollout.md). `evaluationFile` is trusted local evidence, not a request override. Enforced serving rejects missing, expired or changed bindings; mutable patterns and returned model identities are checked during analysis as well. Off/shadow can be used while qualification is pending. `/health` and `ai:config` report local readiness without inference; they do not establish live account access.

TypeSafe enforcement and cascade apply only to v2 clients, including prompt and skill scans. Configuring enforcement does not upgrade v1 Gemini requests; migrate REST routes or set MCP `reportVersion: 2` before relying on those policies.
