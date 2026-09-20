# AI evaluation evidence

Run `npm run evaluate:ai -- --offline --dataset <manifest>`. The default uses no provider credentials and starts no listeners. Complete online semantic/HF coverage is unavailable in an offline service run unless a test supplies saved native fixtures. `npm run test:offline` separately runs those native contract and report fixtures under a network guard.

Live runs require `--live --profiles <names> --dataset <manifest> --max-requests <N> --max-usd <N> --pricing <file>`. See [rollout operations](../../docs/operations/typesafe-rollout.md). Never put secrets in datasets, profiles, artifacts or commands. Supplied corpus inputs may be sent to the selected provider only in explicit live mode.

## Corpora

- `exploratory-v1`: 107 unique development inputs from 111 historical occurrences. `import-exploratory.mjs` preserves original labels and source occurrence hashes. Historical labels are hypotheses, not independent acceptance ground truth.
- `synthetic-stress-v1`: 1,200 development cases, 20 correlated templates across domains and three tasks. Independent binary label reviews are recorded, with limitations. This is deliberately ineligible for qualification.
- `descriptor-smoke-v1`: first eight risky and first eight benign descriptor examples from the exploratory corpus, selected in source order before this service run. Original IDs, hashes and labels are preserved.

Acceptance datasets need a hashed case file and reviewed split registry. The manifest supplies `reviewFile`, `splitFile` and `splitSha256`. The strict review record requires explicit identities for at least two distinct independent reviewers, approvals tied to both hashes, resolved adjudication, no unresolved cases and a pre-run review date. The split records each family and each `task:sourceSha256` as development, calibration or held-out. Acceptance runs cross-check the committed corpus registry; known development/calibration sources cannot become held-out by renaming families. Near-duplicate family review remains an explicit annotation responsibility, not an inferred promise from exact hashing.

Code-generated offline test fixtures can exercise manifest validation, but are not real passing activation evidence. No real passing qualification manifest is claimed. The explicit active profile runs under optional qualification; that policy does not fabricate or bypass validation of supplied evidence.

## Runs

- `2026-09-20-single-api`: persistent HTTPS on localhost:3001 and stdio MCP, both using the sole current pipeline. Normal TLS verification, real benign/attack responses, matching config hashes and rejection of retired paths are recorded in the [run record](runs/2026-09-20-single-api/README.md).

- `2026-09-19-active-mcp`: real active-policy MCP/REST and native Codex verification, with retained initial failures and corrective follow-ups. See its [run record](runs/2026-09-19-active-mcp/README.md). These activation checks are separate from the earlier 19-call implementation demonstration below.

- `2026-09-19-exploratory-offline-v2`: 214 service evaluations (107 inputs × off/shadow), no network inference. This verifies execution/reporting and incomplete-coverage behavior, not live model quality.
- `2026-09-19-implementation-smoke/probes`: bounded synthetic access checks. TypeSafe and Gemini succeeded; Claude account access was unavailable; OpenAI's initial inference preflight exceeded its conservative cost envelope and a separate read-only credential check rejected the saved key. Missing billable cache details leave Gemini actual cost unknown.
- `2026-09-19-descriptor-shadow-smoke`: 16 physical TypeSafe calls, 32 paired local/off-shadow reports, estimated $0.000458892. Shadow median service latency 189 ms, p95 420 ms; authoritative decisions/severity/categories are unchanged. All eight risky examples had poisoning Noul >=0.9; none of eight benign examples did. Those primitive observations do not override local findings or qualify enforcement.

The bounded implementation demonstration has used 19 physical inference requests so far: one TypeSafe probe, one Claude attempt, one Gemini probe and sixteen TypeSafe descriptor requests. OpenAI preflight dispatched zero. Read-only account checks are separate from inference. Total known estimates exclude unreported failed-call/Gemini billing; conservative command limits remained below the original $1 demonstration envelope. No production prompts or secrets were sent.

`experiments/typesafe` preserves the original experiment unchanged. Its historical verifier intentionally demonstrates now-fixed benign-on-error behavior and is excluded from acceptance execution. The read-only historical replay test reproduces original primitive counts and latency without running that verifier or changing original artifacts.

### Candidate policy comparisons

Use `--scenarios off,shadow,enforce` to compare a descriptor/capability policy locally; use `--tasks prompt,skill --scenarios off,enforce,cascade` for prompt/skill cascades. Cascade is rejected for other selected task types. Start from an ordinary off/shadow configuration and supply any checked `modelResolutions` there; offline candidate reasoning without matching resolved-model evidence remains unavailable. Live enforce/cascade jobs reject missing, mismatched, expired or mutable identities before any provider dispatch, using the same identity checks as serving qualification. The CLI builds private evaluation-only snapshots, shares the actual pattern corpus, and records policy bindings. It never creates a passed manifest or exposes a public evaluation bypass. All potential semantic routes need rates before a live descriptor/capability enforcement run can dispatch. Reference metrics score the authoritative baseline-plus-qualified-additions set; shadow-only suggestions do not count as authoritative extraction.
