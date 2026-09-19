# TypeSafe and model-routing implementation ledger

This ledger tracks the [implementation plan](../superpowers/plans/2026-09-19-typesafe-model-routing.md) against the [specification](../specs/2026-09-19-typesafe-model-routing-spec.md). Code completion, offline verification, live model qualification, and activation are separate statuses.

## Starting state

- Baseline: `2f3a83c266009afa84cc235c43abd7db3d7e6fe3`, package `prompt-rejector@1.1.0`.
- Isolated implementation branch: `codex/typesafe-model-routing`.
- Initial runtime: Node `v24.13.0`, npm `11.8.0`; the package declares Node `>=18.0.0`. Other supported Node runtimes still require verification.
- Locked dependencies installed with `npm ci --ignore-scripts`. Existing dependency audit findings are outside the baseline task; no dependency versions were changed.
- Original scripts: `build` runs `tsc`, `lint` runs `tsc --noEmit`, and `test` chains 17 source suites through `npx tsx`. The new `test:offline` uses the installed compiler and current Node executable instead of downloading a runner.
- Existing `docs/` and `experiments/` were copied into the worktree as planning/evaluation inputs. Original worktree changes, including `.env.example`, skill directories, and skill-lock metadata, are preserved. No `.env` values are copied into this ledger or the offline test environment. Baseline work stages only its own explicitly listed files.
- Existing experiment outputs remain development evidence and are unchanged. No paid API calls are part of Pass 0.

## Pass status

| Pass | Deliverable | Code / documentation | Offline verification | Live qualification | Activation |
| --- | --- | --- | --- | --- | --- |
| 0 | Reproducible offline baseline | Implemented; independent spec and quality reviews approved | 18/18 suites pass, Node 24.13.0 | Not applicable | No changes |
| 1 | Contracts, configuration, service construction, truthful v2 results | Implemented; independent review pending | 25/25 suites pass; lint passes, Node 24.13.0 | Pending where needed | TypeSafe off; enforcement blocked |
| 2 | Claude/OpenAI structured adapters and role selection | Pending | Pending | Pending | Off |
| 3 | Portable Taste-Tester conversations and monitor role | Pending | Pending | Pending | Off |
| 4 | TypeSafe client, bounded requests, cache, accounting | Core implemented and independently reviewed; service integration pending | Adapter/cache focused suites pass | Pending | Off |
| 5 | Descriptor shadow analysis | Pending | Pending | Pending | Off |
| 6 | Prompt and skill shadow analysis | Pending | Pending | Pending | Off |
| 7 | Capability provenance and analysis | Pending | Pending | Pending | Off |
| 8 | HF extraction corrections and semantic candidates | Pending | Pending | Pending | Off |
| 9 | Evaluation harness and qualification evidence | Pending | Pending | Pending | Off |
| 10 | Qualified descriptor/capability/HF enforcement | Pending | Pending | Pending | Off |
| 11 | Prompt/skill block-only cascade | Pending | Pending | Pending | Off |
| 12 | Operations, migration documentation, final rollout verification | Pending | Pending | Pending | Off |

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

Verification: `npm run test:offline` reports **25 passed, 0 failed, zero unexpected network violations**; `npm run lint` passes. The focused foundation suites and `git diff --check` also pass after final cleanup. No paid API calls were performed. Node 18.20/22/24 conformance beyond this Node 24.13 run, live profile probes, qualification manifests, shared judgment-call budget envelopes, portable Taster/Monitor execution, and enforcement activation remain for their specified later passes. The historical unsafe experiment verifier remains unchanged and excluded from offline execution. Independent foundation spec/quality review is pending.

## Pass 4 core evidence

The native TypeSafe adapter and raw judgment cache have passed independent SPEC and quality review. Both suites were first observed failing at their unimplemented methods, then passed after implementation. The adapter validates complete Noul/Choice batches, exact source-option keys, probabilities (sum tolerance 0.005), pinned model identity, resolved versions for shadow aliases, and mandatory native token usage. It preserves unreported token categories as unknown, rejects oversized requests before dispatch, retains unknown retry usage, and never includes reflected error bodies. Invalid pricing cannot bypass a monetary reservation. No source input is truncated.

Cache tests cover immutable copies, exact source/model/options/rubric/context/coverage keys, 1,000-entry/10-minute defaults, bounded active work, error non-caching, independent waiter deadlines, one/all caller cancellation, and overdue completion when the event loop delays timers. The shared operation runs once; a provider result after its absolute deadline cannot be cached. Integration with a shared prepaid request-budget envelope, off/shadow scheduling and the application service graph is still pending. No live inference or activation is claimed by this core checkpoint.
