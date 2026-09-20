# TypeSafe and model-routing implementation ledger

This ledger tracks the [implementation plan](../superpowers/plans/2026-09-19-typesafe-model-routing.md) against the [specification](../specs/2026-09-19-typesafe-model-routing-spec.md). Code completion, offline verification, live model qualification, and activation are separate statuses.

## Starting state

- Baseline: `2f3a83c266009afa84cc235c43abd7db3d7e6fe3`, package `prompt-rejector@1.1.0`.
- Isolated implementation branch: `codex/typesafe-model-routing`.
- Initial runtime: Node `v24.13.0`, npm `11.8.0`; the package declares Node `>=18.0.0`. This was the initial checkpoint; the later runtime matrix is recorded below.
- Locked dependencies installed with `npm ci --ignore-scripts`. Existing dependency audit findings are outside the baseline task; no dependency versions were changed.
- Original scripts: `build` runs `tsc`, `lint` runs `tsc --noEmit`, and `test` chains 17 source suites through `npx tsx`. The new `test:offline` uses the installed compiler and current Node executable instead of downloading a runner.
- Existing `docs/` and `experiments/` were copied into the worktree as planning/evaluation inputs. Original worktree changes, including `.env.example`, skill directories, and skill-lock metadata, are preserved. No `.env` values are copied into this ledger or the offline test environment. Baseline work stages only its own explicitly listed files.
- Existing experiment outputs remain development evidence and are unchanged. No paid API calls are part of Pass 0.

## Pass status

| Pass | Deliverable | Code / documentation | Offline verification | Live qualification | Activation |
| --- | --- | --- | --- | --- | --- |
| 0 | Reproducible offline baseline | Implemented; independent spec and quality reviews approved | 18/18 suites pass, Node 24.13.0 | Not applicable | No changes |
| 1 | Contracts, configuration, service construction, truthful v2 results | Implemented; independent SPEC and quality reviews approved at d37b9e7 | 27/27 suites pass at reviewed snapshot; lint passes, Node 24.13.0 | Pending where needed | TypeSafe off; enforcement blocked |
| 2 | Claude/OpenAI structured adapters and role selection | Implemented; independent SPEC and quality reviews approved through a921fec | 37/37 suites at provider checkpoint; 7 focused suites rerun from isolated commit | TypeSafe probe succeeds; Claude account unavailable; OpenAI saved credential rejected | Off |
| 3 | Portable Taste-Tester conversations and monitor role | Implemented; SPEC and quality approved through a629bd3 | Native 3-provider conversation/service/MCP suites pass, including review regressions | Claude/OpenAI access unavailable; live behavior qualification pending | Off |
| 4 | TypeSafe client, bounded requests, cache, accounting | Implemented and reviewed, including shared budgets and service graph | Adapter/cache/shared-budget suites pass | Pinned Jev smoke succeeds; qualification pending | Off |
| 5 | Descriptor shadow analysis | Implemented; SPEC and quality reviews approved at 9587c66 | Wrapper, bounds, source-map and MCP tests pass | 16-case development shadow smoke recorded; qualification pending | Off |
| 6 | Prompt and skill shadow analysis | Implemented; SPEC and quality reviews approved at 9587c66 | Equality, source isolation, scheduling and transport tests pass | Paired live qualification pending | Off |
| 7 | Capability provenance and analysis | Implemented; SPEC and independent quality approved through a00a891 | Provenance, complete-scope reasoning and native adapter regressions pass | Independent live qualification pending | Off |
| 8 | HF extraction corrections and semantic candidates | Implemented; SPEC and independent quality approved through a00a891 | Parser, exact-source additive union, overflow and preserved HF block tests pass | Independent live qualification pending | Off |
| 9 | Evaluation harness and qualification evidence | Implemented; SPEC and quality approved through 16842c0 | Corpus, quota, private candidate, identity preflight and manifest suites pass | Exploratory probes only; no passing activation manifest | Off |
| 10 | Qualified descriptor/capability/HF enforcement | Implemented e2e831d; native-schema/HF repair a00a891; SPEC and independent quality approved through a00a891 | Enforcement and transport regressions pass | Held-out and staging gates pending | Off |
| 11 | Prompt/skill block-only cascade | Implemented e2e831d; SPEC and independent quality approved through a00a891 | Routing, full-skill budget, source provenance and REST/MCP parity pass | Held-out and staging gates pending | Off |
| 12 | Operations, migration documentation, final rollout verification | Documentation and CI configuration reviewed; implementation verification complete | 54/54 suites on Node 18/22/24/26; build, lint and config checks pass | Actual live switch/rollback drill pending | Off |

## Pass 0 evidence

The guard's initial regression test failed as expected before implementation: a caught forbidden loopback fetch left zero recorded violations instead of one. After implementing the guard, regression checks pass for caught fetch failures, TCP/TLS and HTTP(S), named builtin imports, UDP, forbidden listeners, marked loopback traffic, existing fetch mocks, credential filtering, and aggregate failure despite a successful child exit.

`npm run test:offline` passes all 18 registered suites (17 original suites plus the guard suite) with zero unexpected network violations on Node 24.13.0. `npm run build` also passes as part of that command. Production patterns, experiment artifacts, and production service implementations are not modified by this pass. The commit is identifiable by `test: establish reproducible AI rollout baseline`; independent spec/quality reviews remain pending at commit time.

The first isolated run exposed four pre-existing test-setup failures; all were resolved in test files only:

1. `integrationTests.ts` failed at `new SkillScanService()` because its legacy Gemini constructor required a key before local checks could run. The test now supplies an explicit non-credential constructor placeholder.
2. `huggingFaceTests.ts` had the same constructor issue before its mocked SkillScanService calls. It now supplies the same explicit placeholder; existing fetch mocks and assertions remain intact.
3. `v11SkeletonTests.ts` made an actual KEV refresh and would also make an actual HF lookup. The guard recorded and rejected that request. Both calls now consume canned in-memory responses, preserving the empty-KEV and HF report-shape assertions.
4. `atlasKevTests.ts` passed its first 19 assertions, then timed out at 120 seconds in its mocked VulnFeedService test. This was a rate-limit wait, not an assertion failure or unexpected network call: the test supplied a dummy NVD key but omitted a dummy GitHub token. Adding a clearly synthetic token avoids the unauthenticated GitHub delay; its existing GraphQL mock already supports the resulting call. The coordinating agent separately verified the repaired isolated suite, and the complete rerun passed.

Quality-review follow-up: isolated child deadlines now use `SIGKILL`, preventing tests that ignore `SIGTERM` from hanging the runner. A short injected-deadline regression verifies aggregate failure and bounded completion after a child installs a `SIGTERM` handler. Child `TEMP`/`TMP`/`TMPDIR` now resolve to the suite directory; a regression creates an `os.tmpdir()` fixture and verifies its location and cleanup. Both new regressions failed before their respective fixes. These changes affect test subprocesses only.

## Evidence required for later updates

For each completed pass, record the commit, commands and results, any known pre-existing failures, reviewer outcomes, and remaining dependencies. A green offline test count does not mark live quality or activation complete. Record actual provider/model IDs and qualification manifest hashes when live gates are run; never record API keys or raw sensitive prompts. Preserve an explicit blocked/pending gate whenever the necessary evidence is absent.

## Pass 1 evidence

Implementation commit: `bfc8ea4` (`feat: validate semantic results and centralize AI configuration`). The foundation includes strict typed reasoning results, immutable nonsecret configuration/profile hashes, independent role contracts, native Gemini structured output, task attempt/deadline/usage budgets, bounded transport queues and response reads, and a shared dependency graph built after dotenv. The registry exposes the provider seam for subsequent Claude/OpenAI adapters; those adapters and TypeSafe activation remain separate passes.

The initial semantic regression was observed before its repair: a native HTTP fixture containing the text `{}` produced `error: undefined`. After strict validation, it is `invalid_response`. A second observed regression showed that a clean local scan plus unavailable semantic analysis returned `safe: true`; it now returns `safe: false`. Valid v1 results retain the historical severity/isInjection/confidence formula and real numeric model self-assessment; null confidence is unavailable in v1 and stays nullable in v2. The new v2 policy uses explicit allow/block/review/unavailable and required coverage. Existing static and skill-specific, HF, ATLAS and trifecta findings remain in the aggregate.

REST `/v2/check-prompt` and `/v2/scan-skill` and MCP `reportVersion:2` use the same semantic service. Non-Gemini semantic v1 requests receive a migration error before inference. Input schemas, UTF-16 character ceilings and the 4 MiB REST JSON ceiling are checked with ASCII, multibyte and escaped-string boundary fixtures. MCP startup is tested in a child process with a synthetic `.env`; it proves dotenv-before-construction and JSON-RPC-only stdout. The offline runner now copies the real nonsecret package metadata for version reporting.

Skill scans preserve rejected/failed HF lookups as incomplete coverage and audit at most 16 references; overflow cannot become safe. HF calls honor the shared deadline/cancellation and failure reports do not enter the success cache. The existing HF integration tests now inject semantic fixtures rather than relying on a constructor key or a captured SDK fetch. The private skill-check test seam and positional HF injection remain available.

Transport regressions cover pre-aborted work never starting, queued cancellation, queue overflow, slow/missing response bodies, bounded reads, redirects, sanitized errors, transient retry limits including overload, Retry-After preserving the original deadline, and event-loop stalls completing after an absolute deadline. Earlier transient attempts each contribute unknown usage, so final-response token counts cannot masquerade as complete run totals. Unknown prices/usage remain unknown; monetary caps reject dispatch without a conservative estimate. Optional shadow calls have a separate attempt pool and are shed under monetary caps until an explicit required-spend envelope is implemented.

Verification: `npm run test:offline` reports **25 passed, 0 failed, zero unexpected network violations**; `npm run lint` passes. The focused foundation suites and `git diff --check` also pass after final cleanup. No paid API calls were performed. Node 18.20/22/24 conformance beyond this Node 24.13 run, live profile probes, qualification manifests, shared judgment-call budget envelopes, portable Taster/Monitor execution, and enforcement activation remain for their specified later passes. The historical unsafe experiment verifier remains unchanged and excluded from offline execution. Independent foundation SPEC and quality reviews approved the corrected d37b9e7 snapshot; the quality reviewer reran all 27 suites from that isolated commit.

Foundation spec review identified and reproduced two additional blockers. Real HF HTTP 200 responses containing `null`, an array, `{}`, a missing file inventory, or malformed security metadata previously completed required coverage as benign. Native repository identity and file-inventory validation now produces uncached `lookup_failed` evidence, preserves any positive risk signals, and prevents skill allowance; valid model/dataset shapes remain supported. The fallback coordinator previously imposed one reasoning timeout across both primary and fallback. It now retains the original task deadline while each adapter caps its own call, allowing a timed-out primary to use the configured fallback only within remaining task time. Both regressions were observed failing before repair, then passed with real service/native HTTP fixtures. Verification after these fixes: **27/27 offline suites**, zero network violations, and `npm run lint` pass on Node 24.13.0. The two extra registered suites are the independently integrated TypeSafe adapter/cache checks. No live inference was used.

## Pass 4 core evidence

The native TypeSafe adapter and raw judgment cache have passed independent SPEC and quality review. Both suites were first observed failing at their unimplemented methods, then passed after implementation. The adapter validates complete Noul/Choice batches, exact source-option keys, probabilities (sum tolerance 0.005), pinned model identity, resolved versions for shadow aliases, and mandatory native token usage. It preserves unreported token categories as unknown, rejects oversized requests before dispatch, retains unknown retry usage, and never includes reflected error bodies. Invalid pricing cannot bypass a monetary reservation. No source input is truncated.

Cache tests cover immutable copies, exact source/model/options/rubric/context/coverage keys, 1,000-entry/10-minute defaults, bounded active work, error non-caching, independent waiter deadlines, one/all caller cancellation, and overdue completion when the event loop delays timers. The shared operation runs once; a provider result after its absolute deadline cannot be cached. Integration with a shared prepaid request-budget envelope, off/shadow scheduling and the application service graph is still pending. No live inference or activation is claimed by this core checkpoint.

## Prepared task primitives (Passes 5–8)

Independent SPEC and quality reviews approved the prepared primitives, with application wiring still pending. Descriptor traversal is iterative and bounded before the existing recursive scanner; stable IDs and JSON pointers distinguish ambiguous dot paths. All descriptor text remains in state, and Choice options contain only generated field references. The 18 original descriptor cases are copied as clearly labeled development fixtures; original experiment artifacts are unchanged.

Prompt rubrics retain the original experiment and defensive revision under distinct versions. Capability questions establish positive presence only; low probabilities cannot establish absence. The trusted resolver creates graph-local opaque handles bound to agent, scope and configuration version; request JSON, copied handles and another graph's handles cannot create verified runtime facts.

HF parsing exposes the exact incumbent ablation separately from corrected baseline IDs and broad semantic candidates. Model/dataset/Space URLs are classified before heuristics; adjacent Markdown links, semicolons, pipes, unusual punctuation and escaped newlines cannot erase references. Malformed ambiguous HF paths preserve incumbent IDs. Short and file-like model names remain semantic candidates even when the original heuristic omitted them. No optional semantic model selection is used for authoritative lookups yet.

Primitive checkpoint verification: `npm run test:offline` passes **31/31 suites**, with zero unexpected network violations on Node 24.13.0. Endpoint, policy and runtime activation gates remain pending.

## Provider and shadow integration checkpoint

Pass 2 implementation `a8c23be`, fixes `dcea91c` and `a921fec`, passed independent SPEC and quality reviews. Monitor token caps apply across every primary/fallback provider. Operator config output identifies credential variable names and active versus unused profiles without values. Native OpenAI cache-write tokens are parsed when reported; omitted values remain unknown. The quality reviewer independently tested the exact committed snapshot, excluding concurrent TypeSafe work.

TypeSafe shared budget/service commit `2b13fac` passed independent SPEC and quality review. Descriptor component `41977d9` is also approved: iterative structural validation precedes cloning/local recursion; routing and cache outcomes identify physical calls correctly, including joining waiters that time out. Integration now includes prompt/skill intent batches, capability presence diagnostics and provenance, corrected model-reference parsing, and MCP v2 descriptor/capability dispatch. Integration SPEC and independent quality reviews approved commit `9587c66`. The final review fixed optional-candidate overflow incorrectly affecting baseline coverage and corrected inferred capability provenance.

The complete integration checkpoint passes **43/43 offline suites** with zero unexpected network violations on Node **18.20.8, 22.23.2, 24.13.0 and 26.9.0**. Native MCP tests preserve 11 tool names, v1 inference scope and unchanged shadow decisions, while exposing exact source candidate mappings. Skill shadow uses at most three initial batches; a cached capability retry reservation cannot starve its siblings. No qualifying enforcement or deployment is claimed.

Bounded live probes are saved under `evaluations/ai/runs/2026-09-19-implementation-smoke/probes/`. TypeSafe resolved exactly `jev-1.13.0`: 464 ms, 310 input tokens, estimated $0.00001302. Claude's probe returned unavailable; a subsequent read-only account check confirmed an account availability issue. OpenAI's initial probe was rejected before dispatch by its conservative $0.40 envelope; its read-only account check rejected the saved credential. These are smoke/account-access results, not model-quality evidence. The original `.env` remains only in the original workspace.

## Pricing correction and review

CodeRabbit reviewed committed changes `1ad4afc..9587c66` after a credential scan. No warning/critical findings were reported. Its minor findings identified this stale pass table and the missing Gemini rate; both are corrected. The official Gemini pricing page does list `gemini-3-flash-preview`: standard text input $0.50/M, output including thinking $3.00/M, cached input $0.05/M. Price-card v2 records those rates; historical probe records retain their original v1 pricing provenance. This does not imply model account access or qualification.

## Evaluation and live shadow checkpoint

Evaluation implementation `9b840b0` and strict review/split correction `58cf5fe` add immutable provenance, validated input schemas, separate abstention metrics, fresh-cache repeat observations, read-only historical replay, explicit live preflight and run-wide conservative limits. The isolated evaluator cannot start serving services. The recorded offline command used `evaluations/ai/datasets/exploratory-v1/manifest.json` with `--scenarios off,shadow`; artifact `evaluations/ai/runs/2026-09-19-exploratory-offline-v2` contains 214 reports with no live inference. Evaluation corrections through `c1184d0` passed independent SPEC and quality review. Qualification corrections through `56b5a87` also passed both reviews; the pre-enforcement integration checkpoint passes 51/51 isolated offline suites on Node 24.13.0.

Gemini live probe succeeded in 2,002 ms with 623 input, 58 candidate and 160 thought tokens. Missing cache billing details leave actual estimated cost unknown, preserving the conservative reservation. Descriptor shadow smoke used `descriptor-smoke-v1/manifest.json`: 16 physical Jev calls, estimated $0.000458892; p50 189 ms, p95 420 ms. All 16 authoritative decision/severity/category results match off. All eight risky examples had Noul >=0.9 and none of eight benign examples did; two benign low-poison cases selected a speculative field and would need contextual review under the conservative policy. These are previously observed development cases, not qualification. The implementation demonstration has used 19 inference attempts and remains within its 20-request/$1 envelope.

## Taster review closure

Pass 3 `1ca0950`, `babbf58`, and `a629bd3` passed independent SPEC and quality review. Native regressions reproduced and repaired loss of tool evidence from excessive text-block counts, late Monitor timeout/cancellation accounting, and inherited object-property names in rejected tool calls. All three providers preserve valid and rejected action evidence and final severity floors; Monitor primary/fallback usage is settled before serialization. These checks use synthetic native HTTP fixtures, not paid inference.

## Qualification and operations checkpoint

Qualification fixes `1a54fb8` and `56b5a87` bind evidence to each primary/fallback route, exact runtime code and nested schemas/rubrics, the actual loaded pattern corpus and integrity state, checked model identities and expiry. Runtime consumers recheck model identity and pattern qualification around asynchronous analysis. Two distinct normalized reviewer identities and pre-run label approval are required; optional post-run result approval is separately hash-bound. Unit-test passing manifests are explicitly synthetic. No real passing activation manifest is included. Qualified staging may load with an operational gate still pending, permitting the restart/rollback drill to occur before production activation.

Evaluation correction `c1184d0` records normalized model-answer changes separately from policy-decision changes and reserves its output files exclusively before inference. A second process or unwritable output directory cannot spend first and lose the artifacts. Read-only metadata checkpoint `6a000fc` exposes role readiness, qualification and legacy/v2 scope without calling a provider.

Checkpoint `8c78eed` saves the 16-case descriptor shadow run and verifies cache behavior through the native MCP client: repeated source reuses a judgment, changed source/rubric invalidates it, and descriptor drift is recomputed even when inference is cached. Focused operator, MCP shadow and health suites passed with zero unexpected network access. A scan of the implementation checkout found no exact values from the original credential file. The original checkout and its user changes remain untouched.

## Enforcement review and final corrections

Policy checkpoint `e2e831d` implements complete descriptor reasoning, provenance-aware capability composition, source-exact additive reference selection and prompt/skill enforce/cascade routes. A skill uses one logical full-context reasoning response to resolve security and unresolved capability/reference evidence. Native REST/MCP fixtures cover scope/version compatibility, injected host-only capability facts, six-attempt skill budgeting, cancellation, source limits and qualification changes. Existing deterministic and HF blockers are retained; missing analysis never authorizes allow. All task defaults remain off.

Independent SPEC review reproduced two issues that were not caught by the initial 54-suite run. Repair `a00a891` replaces unrepresentable empty-ID native schemas with provider-compatible arrays and local no-invented-ID checks, then verifies native Claude/OpenAI/Gemini dispatch. It also preserves critical HF block precedence during pattern qualification changes while reporting incomplete qualification. Both regressions failed first and passed after repair.

Root evaluator extension `16842c0` passed independent SPEC and quality review. It enables private enforce/cascade comparisons and records bindings; live candidate preflight rejects invalid identity evidence before even a preceding TypeSafe call. Regressions cover missing, stale, future-dated, mismatched and mutable identities, invalid later jobs and a valid mocked live candidate. Offline/off/shadow exploration remains available.

CodeRabbit's second committed review covered `9587c66..16842c0` and completed with one minor historical replay finding. Repair `38e9a2a` prevents a `no candidates` marker from treating missing prompt/descriptor/capability inference as evaluated; that special empty result is only valid for reference extraction. The historical aggregate still matches its original saved counts and latency. No warning or critical CodeRabbit findings were reported. Independent policy review remains a separate gate.

Documentation review corrected the remaining generic latency claim and made all TypeSafe enforcement/cascade explicitly v2-only, including Gemini prompt/skill callers. Contributor guidance no longer recommends benign defaults on provider failure. Historical root SPEC/PLAN retain their release record with clear links to the current design. Compatibility facades and legacy SDK support are retained where public/positional callers still use them; unrelated cleanup is excluded.

Independent policy quality review archived exact commit `38e9a2a`, rebuilt it and passed six isolated enforcement/cascade/transport/bootstrap/qualification/historical-replay suites with zero unexpected network access. The policy SPEC reviewer separately rebuilt and passed five affected suites. Both approve the repaired policy integration; neither approval claims live model quality or activation.

## Deadline boundary repair

The final parallel runtime matrix at `38e9a2a` exposed an early timer callback on Node 26: the callback could abort before the absolute wall-clock deadline and misclassify a timeout as a transport failure. Two fixtures also assumed unrealistically short process/Taster startup under parallel load. Node 22 and 24 passed all 54 suites at that checkpoint; Node 18 passed 53 and Node 26 passed 52. These failures were investigated before repeating verification.

Repair `4d9fee2` uses a shared timer that rechecks the absolute deadline and reschedules an early callback. It covers the operation wrapper, native transport, cache provider and independent cache waiters; external cancellation remains distinct. Deterministic regressions failed before the repair, then passed while checking physical attempts and timer/listener cleanup. The two fixture startup allowances were increased while retaining bounded completion, phase, severity and accounting assertions. Five affected suites passed concurrently on Node 18.20.8, 22.23.2, 24.13.0 and 26.9.0 with zero network violations.

The prompt regression in `bb38252` uses explicit dispatch gates to verify that cancelling one concurrent prompt cannot affect another prompt's source hash or judgment. A repeated prompt dispatches again, proving prompt judgments remain uncached. Independent SPEC review approved the timing patch and this regression after rebuilding and passing six isolated suites. Independent quality review also approved both changes after an isolated build and five focused suites, with zero network violations.

The next complete parallel matrix passed all 54 suites on Node 18, 24 and 26. Node 22 exposed another fixture assumption in `judgmentServiceTests`: a 20 ms provider window could expire before native dispatch, correctly reporting zero physical attempts while the test expected one. Fixture-only repair `f71bba9` controls the clock and gates advancement on actual dispatch. It explicitly verifies zero attempts before dispatch and one physical attempt afterward, shared operation identity, independent waiter cancellation and settled usage. It passed three consecutive runs on each of the four runtimes (12/12, zero network violations).

## Final implementation verification

The final code/test checkpoint is `f71bba9`, including production timing repair `4d9fee2` and concurrent prompt regression `bb38252`. Independent SPEC and quality reviewers approved all three changes. Each reviewer rebuilt and independently ran the affected guarded tests; no blockers remain in the implementation reviews.

From that checkpoint, `npm run build`, `npm run lint` and `git diff --check` pass. After the build, the complete `dist/scripts/runOfflineTests.js` runner—the runner used by `npm run test:offline`—was run concurrently under each runtime below. All four processes exited zero, and every suite reported zero unexpected network violations.

| Runtime | Complete offline suites | Result |
| --- | --- | --- |
| Node 18.20.8 | 54 passed, 0 failed | Pass |
| Node 22.23.2 | 54 passed, 0 failed | Pass |
| Node 24.13.0 | 54 passed, 0 failed | Pass |
| Node 26.9.0 | 54 passed, 0 failed | Development smoke pass |

Read-only configuration validation reports `inferencePerformed:false`, all five TypeSafe tasks off and no active qualification tasks for both configurations. Legacy config hash: `292092198e59751a791194e485ee91c8b1806aa9d5e5864d039da8a0ca6f452d`. Example config hash: `0d66d1c3098472f1fdf078afe7d9339c8b4c73c6550de160adc819bd48633783`. The example selects Claude semantic analysis with OpenAI availability fallback; legacy installations retain Gemini until explicitly reconfigured. This check validates configuration, not account access.

The final documentation covers model roles, native API adaptation, v1/v2 migration, bounded evaluation, qualification and rollback. The README, contributor guide, changelog, configuration guide, historical SPEC/PLAN notices, current checklist, skill-security guide and evaluation guide are updated. The new offline CI workflow runs Node 18/22/24 plus a non-blocking Node 26 smoke job; local results above do not claim a remote CI run.

Delivery is on `codex/typesafe-model-routing`. The original checkout's pre-existing changes are preserved. A credential-value scan covered 240 tracked or unignored implementation files and found zero saved secret values. Package version remains 1.1.0; no tag, registry publication, deployment or production activation is part of this delivery.

**Remaining rollout gates:** restore Claude/OpenAI account access, create and independently review untouched calibration/held-out labels, authorize bounded qualification runs beyond the completed 19-attempt demonstration, qualify every selected primary/fallback route, then perform the actual staging switch/restart/rollback drill. TypeSafe remains off until those gates pass. Smoke timings and development examples do not establish deployed quality, savings or deterministic model answers.
