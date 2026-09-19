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
| 0 | Reproducible offline baseline | Implemented; independent review pending | 18/18 suites pass, Node 24.13.0 | Not applicable | No changes |
| 1 | Contracts, configuration, service construction, truthful v2 results | Pending | Pending | Pending where needed | Off |
| 2 | Claude/OpenAI structured adapters and role selection | Pending | Pending | Pending | Off |
| 3 | Portable Taste-Tester conversations and monitor role | Pending | Pending | Pending | Off |
| 4 | TypeSafe client, bounded requests, cache, accounting | Pending | Pending | Pending | Off |
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

## Evidence required for later updates

For each completed pass, record the commit, commands and results, any known pre-existing failures, reviewer outcomes, and remaining dependencies. A green offline test count does not mark live quality or activation complete. Record actual provider/model IDs and qualification manifest hashes when live gates are run; never record API keys or raw sensitive prompts. Preserve an explicit blocked/pending gate whenever the necessary evidence is absent.
