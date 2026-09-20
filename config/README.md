# AI role configuration

Copy `ai.example.json`, select named profiles independently for `semantic`, `patternDraft`, `taster`, and `monitor`, then set `AI_CONFIG_PATH` to that file. Restart after changes. Relative catalog/rate paths resolve beside the config file. Credentials stay in environment variables, never these JSON files. Keys do not select providers or enable TypeSafe.

`npm run ai:config` validates configuration without inference and reports credential presence, model declarations and selected roles. It does not check account access or claim detection quality. With no explicit config, legacy Gemini semantic/drafting and Anthropic Taster/Monitor profiles remain; TypeSafe is off.

Model identifiers are strings. Add a new identifier to a capability catalog and declare its supported native options before choosing it in a profile. Catalog metadata records documentation evidence; an explicit live conformance probe and task evaluation remain separate requirements. Unsupported options fail before inference. Provider endpoint URLs cannot be configured. The default catalog is included in the package; `capabilitiesFile` selects another local catalog. Catalog and pricing contents participate in immutable configuration hashing.

A live synthetic probe requires all safeguards explicitly:

```sh
npm run ai:probe -- --live --profile claude-semantic --pricing config/ai-pricing.example.json --max-requests 2 --max-usd 1
npm run ai:probe -- --live --profile typesafe --pricing config/ai-pricing.example.json --max-requests 2 --max-usd 1
```

The profile must exist in the selected AI config; `typesafe` selects the separate configured judgment model. `--env-file /absolute/path/.env` optionally loads a local key file without copying it. The request cap includes transport retries. Each command makes one logical call, never a provider fallback; limits are 1–20 attempts and at most $1. No inference runs without `--live`. Missing rates refuse a bounded probe before dispatch. Missing usage stays unknown. Synthetic conformance is not security qualification.

`ai-pricing.example.json` contains dated estimates and source URLs. It deliberately applies OpenAI's long-context upper rates to shorter calls and labels that overestimate. The current Gemini pricing page no longer lists the legacy preview identifier, so that model needs an explicitly verified rate before a budgeted probe. Rates must be reviewed when models, account tiers or pricing change.

Anthropic and OpenAI require version 2 semantic scan reports. A configured non-Gemini fallback also requires version 2 before inference. The Taster conversation migration and its versioned report are the next rollout pass; the present Taster loop remains Anthropic-backed while Monitor selection is independent.
