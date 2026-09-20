# TypeSafe evaluation and rollout

TypeSafe handles narrow, typed judgments; the chosen reasoning model handles context and ambiguity. Deterministic code retains parsing, exact source references, permissions, hashes, mock execution, budgets and the final decision. TypeSafe probabilities are evidence, never an authorization mechanism.

## Default state and modes

Legacy configurations keep TypeSafe off. The dedicated `start:mcp` launcher selects `config/ai.active.json` unless another config is explicitly selected: descriptor/capability/modelReference enforce, prompt/skill cascade, and MCP version 2 by default. `descriptor`, `capability` and `modelReference` accept off/shadow/enforce; `prompt` and `skill` also accept cascade. Modes are independent. Inside a skill, a child cannot exceed its parent: off disables child inference, shadow caps enabled children to shadow, and enforce/cascade permit each child's configured mode. Standalone capability scans use their own mode.

- **Off:** existing deterministic/reasoning analysis, with reliability fixes retained.
- **Shadow:** observe TypeSafe answers without changing authoritative decisions or the HF lookup set. Optional failures do not downgrade required coverage.
- **Enforce:** apply the configured task policy, preserving existing local blocks.
- **Cascade:** prompt/skill reasoning may be skipped only after a conclusive block. Low TypeSafe probabilities never allow a clean prompt or skill without required reasoning.

The active profile uses trusted `qualificationPolicy: "optional"` and does not claim held-out qualification. It uses real judgments in decisions. `qualificationPolicy: "required"` retains the evidence-gated process described below; supplying an evaluation file always validates it strictly, even under optional policy. No request can override activation policy. Consult the ledger for actual local activation and transport evidence.

## Limits and evidence boundaries

Prompts support 100,000 UTF-16 code units; skills 500,000. Descriptors support 100,000 serialized UTF-16 units, 512 string fields and depth 32. REST has a 4 MiB JSON body ceiling. Jev's initial conservative preflight is 24,000 UTF-8 bytes for state plus longest question and 48,000 total; it is not an exact tokenizer. Oversized requests use complete supported reasoning or explicit incomplete/unavailable coverage. No source is silently truncated.

The descriptor Choice has at most 254 generated field IDs plus `none`. Code checks selected IDs against the full source map. Model descriptions and arbitrary request fields cannot manufacture verified capabilities. Only the in-process trusted resolver can supply runtime permission facts. Capability buckets are present/absent/unknown, with declared/inferred/verified provenance.

HF parsing distinguishes models, datasets and Spaces. Off/shadow preserve the corrected baseline lookup set. Qualified semantic additions can expand it, never remove incumbent candidates. At most 16 unique repositories are audited; required overflow or failed metadata lookups cannot become safe by omission.

Ordinary analysis has a 20-second request deadline; reasoning calls default to 15 seconds and Jev to 2 seconds. Prompt/descriptor/capability permit three required attempts; skills six. Shadow has a separately scheduled allowance of at most three initial batches. Physical retries and configured availability fallback count against the same request allowance. Descriptor/capability cache entries last at most ten minutes with a 1,000-entry bound; exact source/model/rubric/context changes invalidate reuse, and final policy decisions are always recomputed.

Taster permits two fast or at most five thorough turns, eight mock calls per turn and forty total. Taster and Monitor each have a 30-second phase cap and share a 60-second run ceiling. Partial evidence cannot be converted into a clean result.

## Reproducible evaluation

Offline evaluation is the default and ignores ambient API keys. It starts no listener or advisory feed. Live HF and semantic coverage is explicitly unavailable when not supplied by fixtures.

```sh
npm run evaluate:ai -- --offline --dataset evaluations/ai/datasets/exploratory-v1/manifest.json --scenarios off,shadow --output evaluations/ai/runs/my-offline-run
```

Output directories must be empty before a run. Artifacts include case/source/config hashes, individual reports, confusion counts, review/unavailable rates, family failures, p50/p95, attempts and usage. Repeats use fresh judgment caches and separately report final-decision changes and normalized model-answer changes; a single observation is not a stability result. Result files are exclusively reserved before any inference, preventing output-permission failures or concurrent ownership conflicts from spending first. Historical primitive replay tests preserve old thresholds and counts without treating them as the current service policy.

A live demonstration must explicitly select profiles and spending limits:

```sh
npm run evaluate:ai -- --live --dataset evaluations/ai/datasets/descriptor-smoke-v1/manifest.json --profiles typesafe --scenarios off,shadow --max-requests 16 --max-usd 0.02 --pricing config/ai-pricing.example.json --output evaluations/ai/runs/my-descriptor-smoke
```

Use `--env-file /absolute/path/.env` if needed. Larger qualification runs require explicitly larger request and USD limits; the tool never expands them automatically. A request that lacks a conservative rate estimate cannot dispatch. Unknown actual usage retains its conservative reservation. Each case retains its ordinary deadlines/attempt limits within the run cap. API billing can still differ from estimates; multiple processes require an external shared account cap.

The exploratory corpus has 107 unique development inputs from 111 historical occurrences. Its labels are authored hypotheses. The synthetic stress corpus has 1,200 development cases with correlated templates. Neither corpus qualifies enforcement. Do not promote those observed examples into held-out evidence. The acceptance classifier cannot label its own ground truth.

## Optional formal qualification

The following procedure applies when qualification is required or an `evaluationFile` is supplied. It provides stronger measured assurance; it is separate from explicit operator activation through the active profile.

Use distinct development, calibration and untouched held-out families. Obtain two independent label reviews and resolve disagreements before evaluation. Freeze thresholds, rubrics, source policy, model options and dataset hashes before viewing acceptance results. Descriptor, prompt and skill each require at least 200 risky and 200 benign cases; capability/reference criteria must be independently labeled and predeclared. Require zero newly missed known high/critical attacks versus baseline and no more than a one percentage point increase in benign blocks. Report review/unavailable separately; abstention does not count as a correct prediction.

The local evaluator may exercise candidate policies without a prior activation manifest. Its configuration cannot start REST/MCP serving services. Public requests and environment flags cannot enable that evaluation privilege.

Qualified serving configuration selects trusted local evidence through `evaluationFile`. Manifests bind the task/mode, all decision-affecting primary/fallback profiles, options, model resolution, deployed code, schemas, rubrics, thresholds, source policy and price card. Expired, failed or changed supplied bindings reject startup under either policy. Evaluate and deploy the same built artifact. Formal qualification of a model alias needs checked resolution evidence and expiry; all TypeSafe enforcement uses pinned `jev-1.13.0`.

Passing security qualification precedes staging exercises; production activation requires recorded runtime and rollback proof. A failed gate leaves the task off/shadow. Changing behavior after inspecting held-out failures turns those examples into regressions and requires a fresh untouched acceptance set.

## Qualified rollout sequence

1. Validate configuration without inference; record commit and config hash.
2. Run a bounded synthetic access probe for every selected primary/fallback role and inspect actual model attribution.
3. Run development and calibration comparisons, then freeze the policy and independently reviewed held-out corpus.
4. Evaluate every decision-affecting route, including fallback; create a manifest only from passing evidence.
5. In staging, restart through off → shadow → qualified enforcement. Check actual REST/MCP v2 reports, shadow equality, timeouts, outages, cancellation and usage.
6. Switch the semantic provider while leaving Taster/Monitor unchanged; separately switch Monitor. Verify post-restart config hash and actual provider/model attribution.
7. Roll back by selecting off/shadow or a previously qualified profile and restart. Reliability fixes and explicit unavailable decisions remain active.
8. Record deployment revision, production task modes and operational proof before claiming activation.

`/health` performs no inference or account discovery. It reports configured/readiness/degraded roles and the v2 scope; legacy descriptor/capability clients still use local compatibility paths. In MCP mode diagnostic logs go to stderr, leaving stdout for JSON-RPC. Raw prompts, credentials, private continuation state and hidden reasoning must not enter operational logs.

## Rollout record template

| Field | Value |
| --- | --- |
| Date / operator / environment | |
| Commit / runtime / built artifact hash | |
| Task / mode / report version | |
| Config / manifest / dataset hashes | |
| Primary and fallback provider / requested and resolved models | |
| Contract and live access gate | pending / pass / fail |
| Held-out quality / coverage / cost / latency gate | pending / pass / fail |
| Staging endpoint / cancellation / restart proof | |
| Production revision and active modes | |
| Rollback target and observed result | |
| Remaining blockers / expiry / next action | |

Keep four statuses separate: **code ready**, **live qualified**, **staged**, and **production active**. A published branch or successful test suite is not deployment evidence.

### Candidate policy comparisons

Use `--scenarios off,shadow,enforce` to compare a descriptor/capability policy locally; use `--tasks prompt,skill --scenarios off,enforce,cascade` for prompt/skill cascades. Cascade is rejected for other selected task types. Start from an ordinary off/shadow configuration and supply any checked `modelResolutions` there; offline candidate reasoning without matching resolved-model evidence remains unavailable. Live enforce/cascade jobs reject missing, mismatched, expired or mutable identities before any provider dispatch, using the same identity checks as serving qualification. The CLI builds private evaluation-only snapshots, shares the actual pattern corpus, and records policy bindings. It never creates a passed manifest or exposes a public evaluation bypass. All potential semantic routes need rates before a live descriptor/capability enforcement run can dispatch. Reference metrics score the authoritative baseline-plus-qualified-additions set; shadow-only suggestions do not count as authoritative extraction.
