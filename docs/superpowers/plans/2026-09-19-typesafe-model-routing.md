# TypeSafe and Interchangeable Reasoning Models Implementation Plan

> **For agentic workers:** Use `subagent-driven-development` if subagents are available and tasks are independent; otherwise use `executing-plans`. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add evaluated TypeSafe judgments and configuration-driven Claude/OpenAI/Gemini selection while preserving deterministic protections, explicit availability, and bounded execution.

**Architecture:** Shared configuration and a single application dependency graph inject separate structured-reasoning, typed-judgment and tool-conversation interfaces. Small native-HTTP adapters translate provider APIs; services own their task schemas, and deterministic policy owns allow/block/review/unavailable decisions. TypeSafe progresses from descriptor shadow analysis to separately qualified additive enforcement and a prompt/skill cascade.

**Tech Stack:** Existing Node >=18, TypeScript/ESM, Zod, Express and MCP SDK; native fetch adapters; compiled Node test scripts; no new model framework.

---

**Status:** Implementation, independent reviews, documentation and final offline verification complete on `codex/typesafe-model-routing`. All 54 registered suites pass on Node 18.20.8, 22.23.2, 24.13.0 and 26.9.0. Live qualification and deployment remain pending. Checked items have recorded evidence in [the progress ledger](../../implementation/typesafe-progress.md); live qualification and activation are tracked separately.

**Implementation file consolidation:** The delivered tests consolidate planned `skillShadowTests`/`coverageTests` into `promptShadowTests`, `shadowTransportTests` and policy suites; `manifestTests`/`rolloutConfigTests` into `qualificationTests`; and capability/reference integration into `enforcementTests`, `capabilityReferenceShadowTests` and `cascadeTests`. The reference wrapper is `ModelReferenceService.ts`; deterministic extraction is `HuggingFaceReferences.ts`. Manifest validation is `src/ai/qualification.ts`, with the private evaluator factory in `src/evaluation/candidateConfig.ts`. These are naming/consolidation changes, not omitted gates.

**Specification:** [SPEC](../../specs/2026-09-19-typesafe-model-routing-spec.md).
**Baseline evidence:** [REPORT](../../../experiments/typesafe/REPORT.md), run `experiments/typesafe/results/2026-09-19T20-27-01.476Z/`.
**Location convention:** All code paths below are repository-relative to `/Users/twoedge/Dev/promptrejectormcp`. Commands run from that root or its implementation worktree. The historical root `SPEC.md`/`PLAN.md` are not replaced.

## Execution rules and dependencies

- Finish each pass's focused tests and runnable behavior before the next dependent pass. A provider smoke response alone does not satisfy quality or rollout gates.
- Use @typesafe-ai for judgment design, @verification-before-completion for gate claims, and @executing-plans or @subagent-driven-development for implementation. Keep named passes and record exact remaining blockers.
- Create a `codex/` implementation branch/worktree when execution begins. Include these documents and the experiment artifacts explicitly: currently untracked files are not copied into a worktree automatically. Preserve the pre-existing `.env.example`/skill changes and do not copy credentials into commits.
- Each checklist item is one bounded action. If a coding item exceeds one short session, split it by the listed test scenario or method before proceeding. Do not collapse validation and activation into one step.
- Use targeted explicit-path commits after a pass is green. Do not stage unrelated user files. Commit checkpoints are in scope for execution; pushing, publishing, merging and production activation are separately recorded delivery gates, not implicit results of unit tests.
- Implementation dependencies: `0 → 1 → 2 → 3`; `1 → 4 → 5 → 6`; `4 → 7 → 8`; `2,3,5,6,7,8 → 9 → 10 → 11 → 12`. Qualification/activation is a separate per-task chain: implemented policy → isolated evaluation → passing manifest → staging drill → authorized production activation. Missing live evidence leaves those checkboxes pending without blocking independent policy implementation. A later adapter pass must not be skipped merely because the currently selected model works.

### Shared verification commands

```sh
npm run build
npm run lint
node dist/test/trifectaTests.js
node dist/test/mcpToolScannerTests.js
node dist/test/huggingFaceTests.js
```

Expected: zero exit status; no production pattern/config mutations. Existing mocked-provider error logs can be expected; unexplained errors require investigation. The original project `npm test` invokes `npx tsx`, which was not locally installed in the experiment session. Pass 0 provides a reproducible offline runner rather than relying on an implicit download.

## Chunk 1: contracts, providers and model switching

### Pass 0 — Preserve evidence and make the test baseline reproducible

**Create:** `src/scripts/runOfflineTests.ts`, `evaluations/ai/README.md`, `docs/implementation/typesafe-progress.md`.
**Modify:** `package.json` only for explicit test/config/evaluation script entries as they become available.
**Read:** existing `src/test/*Tests.ts`, `experiments/typesafe/README.md`; no production behavior change.

- [x] Record `git status --short`, commit ID, Node version, current package scripts and the untracked experiment files in the progress ledger; never record `.env` values.
- [x] Prepare the implementation checkout and verify the spec, plan, rubrics and saved evidence are present without overwriting user changes.
- [x] Audit every existing test entry for real network access and writes; keep live `advancedTests.ts`, `skillScanTests.ts` or calibration scripts out of the offline suite unless their networking is mocked.
- [x] Create a deterministic runner with an explicit allowlist of the existing 17 `npm test` suites plus new AI suites as introduced. Compile first; copy compiled output and needed source/pattern/JSON fixtures to an isolated temporary test root with no `.env` files and use it as subprocess cwd, providing ESM dependencies through a controlled `node_modules` link. Existing tests call dotenv themselves, so clearing inherited keys alone is insufficient. Inherit only necessary nonsecret test settings; permit explicitly marked loopback server tests, block/report other socket/fetch attempts, and fail the aggregate on unexpected networking even if a test catches the error. Ensure fixture paths resolve in the isolated root.
- [x] Add `test:offline` to build and run that allowlist without npx/package downloads. Do not change package engine support as a side effect.
- [x] Run `npm run test:offline` and save its actual results. If the baseline fails, record the failure and reproduce it before attributing it to this work.
- [x] Write the evaluation README distinguishing development/regression, calibration, held-out labels, intent and enacted behavior; retain original experiment artifacts unchanged.
- [x] Commit only the test runner, script entry and ledger/docs: `test: establish reproducible AI rollout baseline`.

**Exit gate:** Offline baseline is reproducible or specific pre-existing failures are isolated; no hidden live provider calls. Subsequent passes must not claim a full green suite while such failures remain.

### Pass 1 — Validated reasoning contract and shared construction, with Gemini parity

**Create:** `src/ai/contracts.ts`, `src/ai/schemas.ts`, `src/ai/taskSchemas.ts`, `src/ai/config.ts`, `src/ai/modelProfiles.ts`, `src/ai/transport.ts`, `src/ai/budget.ts`, `src/ai/usage.ts`, `src/ai/registry.ts`, `src/ai/providers/GeminiAdapter.ts`; `src/bootstrap.ts`; `src/services/SemanticAnalysisService.ts`, `src/services/DecisionPolicy.ts`, `src/services/AnalysisCoverage.ts`; `src/schemas/AnalysisReportSchemas.ts`; `src/api/reportSerializers.ts`; `src/test/ai/contractsTests.ts`, `src/test/ai/bootstrapTests.ts`, `src/test/ai/geminiAdapterTests.ts`, `src/test/ai/decisionPolicyTests.ts`, `src/test/ai/apiVersionTests.ts`, `src/test/ai/transportTests.ts`, `src/test/ai/budgetTests.ts`.
**Modify:** `src/index.ts`, `src/api/server.ts`, `src/mcp/mcpServer.ts`, `src/services/GeminiService.ts`, `SecurityService.ts`, `SkillScanService.ts` and affected test construction seams.

- [x] Write failing contract tests for `{}`, empty arrays, missing fields, invalid enum/type, nonfinite/out-of-range confidence, extra properties and invalid evidence IDs. No test may accept benign defaults for malformed provider data.
- [x] Write the task-specific decision-table tests in SPEC §7.1: prompt/skill require benign reasoning; local-only descriptor/capability off/shadow use explicitly scoped local coverage; enforced descriptor/capability use their qualified evidence rules; Taster has a behavior verdict rather than global safe. Include static critical + unavailable reasoning → block/partial; clean prompt + unavailable reasoning → unavailable/safe false; valid suspicious → review; missing required coverage → never allow.
- [x] Define the discriminated `CallResult`, metadata/usage, structured request, judgment and tool-session contracts from SPEC §4. Treat optional usage as null, not zero.
- [x] Implement strict task/report schemas and transport-independent result validation. Use a compact complete schema pattern such as the following, extending the category/evidence enums from the actual task contract:

```ts
const SemanticVerdict = z.strictObject({
  verdict: z.enum(['benign', 'suspicious', 'malicious', 'undetermined']),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  categories: z.array(z.string().min(1)).max(32),
  evidenceIds: z.array(z.string().min(1)).max(32),
  explanation: z.string().min(1).max(2000),
  isInjection: z.boolean(),
  selfReportedConfidence: z.number().min(0).max(1).nullable(),
});
// After parsing, check categories against the task taxonomy and evidenceIds
// against the exact source map. No defaults and no coercion to safe values.
const isSafeDecision = (decision: 'allow'|'block'|'review'|'unavailable') =>
  decision === 'allow';
```

- [x] Write failing `transportTests.ts` cases for queued cancellation, slow response bodies, response overflow, credential-bearing redirects and sanitized errors; run `npm run build && node dist/test/ai/transportTests.js` and confirm the new behavior fails before implementation.
- [x] Implement absolute deadlines, bounded reads, abort propagation and redirect rejection with injected fetch; run the transport test command and require all cases pass.
- [x] Write failing `budgetTests.ts` cases for reservation release, unknown usage, retry/fallback exhaustion, authoritative-versus-shadow priority and deadline preservation. Test the full skill workload of three judgment batches plus one reasoner within its six-attempt cap; ordinary prompt cap is three, and optional shadow allowance is separate.
- [x] Implement bounded queues and per-task reservations; run `npm run build && node dist/test/ai/budgetTests.js` and require passing resource/cancellation assertions before integrating services.
- [x] Implement Gemini structured HTTP serialization/deserialization from SPEC §5; require native schema mode, candidate/finish validation and local Zod validation. Preserve the incumbent security rubric and category coverage for the initial parity comparison.
- [x] Retain `GeminiService` temporarily as a validated compatibility facade; move shared category-to-ATLAS mapping to provider-neutral task code while keeping an alias for existing imports until they migrate.
- [x] Add `createServices(config, dependencies)` in `bootstrap.ts` and `createApiApp(services)` in the API module. Inject the same services into `PromptRejectorMCPServer`; remove all provider construction from module evaluation. Load dotenv and establish stderr logging before construction.
- [x] Wire `SecurityService` and `SkillScanService` to the injected semantic service and coverage policy while retaining every existing static/skill/HF/trifecta severity contribution. Add v2 routes and report-version parsing; keep Gemini-only v1 serialization truthful.
- [x] Set the REST JSON ceiling to 4 MiB and share character/schema limits with MCP; test ASCII, multibyte and escaped skills plus consistent size-error handling. Migrate the HF integration tests to an injected semantic stub while retaining their real HF aggregation assertions; the historical experiment verifier remains excluded from acceptance.
- [x] Map successful v1 Gemini fields from validated `isInjection`/`selfReportedConfidence` as SPEC §7.2 specifies, preserving the historical success decision formula, including skill dangerous-tool/network-exfiltration boolean branches. Null self-reported confidence cannot become a successful v1 number. Add success snapshots for prompt and skill.
- [x] Make v1 malformed/unavailable semantic results `safe:false` with explicit availability/error information; only the error sentinel may contain legacy confidence zero. Add compatibility error snapshots documenting this intentional security change.
- [x] Run the focused new compiled tests, `npm run lint`, and `npm run test:offline`; assert REST and MCP both receive the same config hash and no `.env` import-order dependency remains.
- [x] Commit the working Gemini-backed slice: `feat: validate semantic results and centralize AI configuration`.

**Exit gate:** Existing Gemini-backed successful behavior remains available, both transports run through the shared graph, and empty responses/outages can no longer produce safe reports.

### Pass 2 — Claude/OpenAI structured adapters and role configuration

**Create:** `src/ai/providers/AnthropicAdapter.ts`, `OpenAIAdapter.ts`; `config/ai.example.json`, `config/model-capabilities.json`, `config/ai-pricing.example.json`; `src/scripts/checkAiConfig.ts`, `probeAi.ts`; `src/test/ai/anthropicAdapterTests.ts`, `openaiAdapterTests.ts`, `modelConfigTests.ts`, `roleRoutingTests.ts`, `usageTests.ts`; native response fixtures under `src/test/fixtures/ai/providers/`.
**Modify:** registry/config/model profiles, `VulnFeedService.ts`, `TasteTesterService.ts` Monitor path, `.env.example` (merge existing TypeSafe entry), package scripts.

- [x] Save minimal nonsecret fixture responses for successful structured output, refusal, truncation, empty content and usage from each provider's documented native format; label synthetic fixtures as synthetic.
- [x] Write failing request-shape assertions for Anthropic `output_config.format` and OpenAI Responses `text.format`; verify trusted system instructions and untrusted state occupy their intended fields.
- [x] Implement Anthropic structured generation, typed content selection, native refusal/stop handling, headers and cache token accounting.
- [x] Implement OpenAI Responses structured generation with `store:false`, output-item traversal and incomplete/refusal checks. Do not read SDK-only convenience fields from raw HTTP JSON.
- [x] Implement provider-discriminated profile options, per-model capabilities and config validation; reject unsupported temperature/reasoning/schema combinations before dispatch. Support model IDs as strings with catalog/evaluation metadata rather than source-code enums.
- [x] Implement role primary/fallback selection. Missing unused-provider credentials must not matter; configured role failure must be explicit. Bound fallback by the original deadline/reservation and forbid verdict-shopping or refusal-driven fallback.
- [x] Implement the canonical `PatternDraft` schema and migrate `VulnFeedService` from `generateRaw()` to the injected `patternDraft` role. Preserve compilation/category/severity checks, staging and human review; an invalid draft produces an error record and no candidate promotion.
- [x] Migrate the Monitor to the `monitor` structured role, retaining transcript data boundaries, intent/action schema, raw tool-call severity floor and timeout/partial behavior. Keep the Taster Anthropic-backed until Pass 3.
- [x] Add offline `ai:config` and explicit live `ai:probe` package commands. Config output reports names/readiness and never performs inference. A probe uses synthetic input, an explicit budget/rate card and one selected profile.
- [x] Add tests proving the same scan/draft/Monitor fixtures work when only the role profile changes; non-Gemini v1 semantic requests must return `report_version_required` before calls. Add env compatibility/precedence/missing-key tests.
- [x] Run focused adapter/config/role tests and `npm run test:offline`; record separately any live profile probes permitted by the implementation task and budget. Missing keys leave live qualification pending rather than blocking local development or being treated as a pass.
- [x] Commit: `feat: switch structured reasoning between Claude OpenAI and Gemini`.

**Exit gate:** All three providers satisfy the structured contract in tests; each generative non-Taster role is independently selectable by configuration. No claim of Claude/OpenAI quality superiority until Pass 9 evidence exists.

### Pass 3 — Interchangeable Taster conversation adapters

**Create:** `src/services/tasteTester/MockTools.ts`, `Transcript.ts`; `src/test/ai/toolConversationTests.ts`, `tasterPortabilityTests.ts`; multi-turn fixtures for all three providers.
**Modify:** all three generative adapters, `TasteTesterService.ts`, existing `tasteTesterTests.ts`, `tasteTesterCorpusTests.ts`, `scripts/calibrate-taste-tester.ts` and its labeling/usage assumptions.

- [x] Write fixtures for one and multiple tool calls, arbitrary call ordering, malformed argument JSON, unknown tool names, duplicate call IDs, text-only completion, refusal, truncation and timeout after a recorded tool call. Include one valid `exec_shell` call beside malformed JSON and a tool-bearing truncated response; both must retain raw severity evidence.
- [x] Move the eight mock definitions and pure router into `MockTools.ts` without behavior changes; keep separate runtime input validators and deterministic severity defaults.
- [x] Implement the canonical public transcript and private opaque session handles. A parseable mixed turn returns valid calls plus bounded rejected-call evidence with partial completeness; all observed known action names contribute the severity floor. Reject all members of duplicate-ID collisions and never dispatch invalid calls. Tests must prove hidden reasoning/signatures cannot enter public reports or logs.
- [x] Implement Anthropic `start/resume/dispose`, preserving required content blocks and translating tool results to matching IDs; migrate existing `anthropicFactory` test seams to adapter injection with a temporary compatibility bridge if needed.
- [x] Implement OpenAI stateless Responses continuation with preserved required reasoning items, `store:false`, strict function schemas and `function_call_output`. Reject a selected model's Taster role if its required continuation cannot be supported under this policy.
- [x] Implement Gemini function-call/result mapping and preserve full model content/thought signatures. Test repeated tool names and parallel calls rather than mapping by name alone.
- [x] Route all normalized tool calls through schema validation and the pure mock router; no adapter receives filesystem/network/shell execution callbacks. Reject unknown or malformed calls and mark coverage accordingly.
- [x] Split Taster and Monitor model settings. Enforce fast/thorough turn limits, 8 calls/turn, 40 total, 60-second combined wall clock and shared run spending; cleanly dispose session state on every termination path.
- [x] Test no mid-conversation provider switch, partial-evidence preservation after failure, independent Monitor fallback and final severity floor. Version 1 requests must fail migration checks before calls when either the Taster or only the Monitor changes to a non-Anthropic provider.
- [x] Run new portability tests and existing Taste-Tester suites; compare **enacted behavior** labels, not the direct-input malicious-intent corpus's historical agreement percentage.
- [x] Commit: `feat: make sandbox taster and monitor models independently selectable`.

**Exit gate:** The same bounded mock scenario completes with each provider's native conversation fixtures; no real tool executes, no continuation state crosses providers, and Monitor selection is independent.

## Chunk 2: TypeSafe judgments and complete shadow slices

### Pass 4 — Bounded TypeSafe client, reusable judgments and caching

**Create:** `src/ai/providers/TypeSafeAdapter.ts`, `src/services/JudgmentService.ts`, `src/services/JudgmentCache.ts`; `src/test/ai/typesafeAdapterTests.ts`, `src/test/ai/judgmentCacheTests.ts`. **Extend:** `src/test/ai/budgetTests.ts` from Pass 1.
**Modify:** `src/ai/config.ts`, `src/ai/registry.ts`, `src/ai/schemas.ts`, `src/ai/usage.ts`, `src/bootstrap.ts`; add `TYPESAFE_API_KEY`/AI configuration documentation without duplicating the existing example key entry.

- [x] Write failing request/answer tests for Noul and Choice, mismatched IDs/types/model, omitted/extra answers, unknown Choice keys, nonfinite/out-of-bounds probabilities, distribution sum tolerance and missing usage. Specify the probability-sum tolerance in one tested constant (initial 0.005).
- [x] Implement the native `/v1/systemone` adapter using the shared transport and pinned model profile. Read Noul `noul`; never substitute Choice confidence or invent a Noul confidence field.
- [x] Require complete answer-map validation before a batch is usable. A partial batch returns unavailable with coverage metadata; no absent answer is treated as false.
- [x] Implement model/request preflight limits from SPEC §9 and tests for the separate state-plus-longest-question and total budget checks. Mark overflow before inference, without truncating or silently dropping questions.
- [x] Enforce the documented maximum of 255 Choice options; test 254 descriptor fields plus `none` at the boundary and route larger complete descriptors to full-input reasoning/unavailable without shrinking the source map. Preserve the 512-field public local-scan limit.
- [x] Implement shared-state independent batching, explicit rubric IDs/versions and immutable source maps. Keep expected test labels out of inference payloads.
- [x] Implement descriptor/capability cache keys, TTL, maximum entries and in-flight coalescing. Test changed model/options/rubric/context/source invalidation, changed priorHash drift recalculation, partial/error non-caching, different waiter deadlines, one waiter cancelling and all waiters cancelling. The underlying bounded call is independent of the first waiter's deadline and its actual usage is reconciled once.
- [x] Test 429/529 Retry-After, authentication/no-retry, timeout abort, queue overflow, total-attempt limit, caller cancellation, missing/unknown pricing and conservative budget reservations. Ensure retries cannot reset request deadlines or spend reservations.
- [x] Provide disabled/off behavior with zero network calls and no missing-key startup exception; enabled missing-key analysis returns unavailable.
- [x] Run compiled TypeSafe/cache/budget tests and `npm run test:offline`; optionally use `ai:probe` for the configured TypeSafe profile with a fixed synthetic request and recorded budget.
- [x] Commit: `feat: add bounded TypeSafe judgments and versioned caching`.

**Exit gate:** TypeSafe returns validated reusable data through its own port; failures cannot become clean findings, and disabled installations behave normally.

### Pass 5 — MCP descriptor shadow analysis, end to end

**Create:** `src/ai/rubrics/descriptor.ts`, `src/services/DescriptorAnalysisService.ts`, `src/test/ai/descriptorAnalysisTests.ts`, `src/test/ai/mcpVersionTests.ts`, descriptor fixtures under `src/test/fixtures/ai/descriptors/`.
**Modify:** `src/bootstrap.ts`, `src/mcp/mcpServer.ts`, v2 report schemas/serializers. Preserve the local `McpToolScanner.scan()` contract.

- [x] Import the 18 development descriptor cases and the final experiment's source-only-in-state question shape; label them development regressions rather than held-out evidence.
- [x] Write baseline-versus-shadow equality tests for safe/severity/categories/findings, plus required shadow metadata tests. Include ordinary “must” requirements, benign comments, quoted attacks, nested fields and a split-field malicious dependency.
- [x] Build stable source IDs for every inspected string field and full-descriptor context; enforce size/depth/field-count bounds before traversal and compare coverage to the local scanner.
- [x] Implement the poisoning Noul and speculative field Choice with generated criteria such as `f3: 'The source string at fields[3].text'` and `none`; never interpolate descriptor text into instructions/options.
- [x] Ignore an evidence selection when poisoning is low; invalidate a reference that does not map back to inspected source. Preserve the original text/path for the report without allowing it to create new options or executable instructions.
- [x] Wire v2 `scan_mcp_tool` to the async wrapper. Report local hash/drift unchanged; keep shadow output in a separate labeled branch. Version 1 behavior remains the documented compatibility path.
- [x] Make shadow scheduling bounded and best-effort: a shadow failure must not consume the authoritative reasoning fallback reservation, delay its deadline, or change its decision. Test with exhausted shadow queue/budget and provider outage.
- [x] Add cache-hit, changed-descriptor, same-descriptor/different-priorHash and incompatible-rubric tests through MCP, including strict stdout behavior.
- [x] Run `descriptorAnalysisTests`, `mcpVersionTests`, existing `mcpToolScannerTests` and the offline suite.
- [x] Commit: `feat: shadow MCP descriptor judgments with TypeSafe`.

**Exit gate:** Real v2 tool dispatch exposes inspectable TypeSafe evidence while the authoritative decision remains unchanged; all existing descriptor integrity mechanics remain deterministic.

### Pass 6 — Prompt and skill shadow analysis with truthful coverage

**Create:** `src/ai/rubrics/prompt.ts`, `src/test/ai/promptShadowTests.ts`, `src/test/ai/skillShadowTests.ts`, `src/test/ai/coverageTests.ts`; prompt/skill development fixtures under `src/test/fixtures/ai/prompts/` and `skills/`.
**Modify:** `src/services/SemanticAnalysisService.ts`, `src/services/SecurityService.ts`, `src/services/SkillScanService.ts`, `src/services/AnalysisCoverage.ts`, API/MCP v2 handling and bootstrap.

- [x] Preserve initial and revised experiment rubrics as separately named versions; write regressions for defensive instructions, harmless roleplay, changing one's own request, quoted attacks and consequential-action labels.
- [x] Define source-origin and task context as a trusted application envelope. Public input may provide claims but cannot set verified authorization or permission scope; test spoofed trusted fields.
- [x] Build the three-question TypeSafe batch and full reasoning request from the same complete source. Keep score semantics separate from generated reasoning confidence.
- [x] Wire `/v2/check-prompt`, `/v2/scan-skill` and matching MCP calls to off/shadow paths. Verify equivalent request limits and policy outputs across transports.
- [x] Preserve all eight existing Gemini attack categories as task-level reasoning requirements across providers, plus existing static/skill/HF/trifecta checks. The three TypeSafe questions must not silently replace this broader coverage.
- [x] Add full coverage accounting: optional shadow failure leaves baseline decisions unchanged; required reasoner failure cannot allow; unresolved HF lookup/overflow and incomplete capability scope are visible and handled according to required-check policy.
- [x] Test oversize Jev state with a sufficiently large reasoning profile, and with no capable profile. Expected: full-input fallback or explicit unavailable/partial coverage; never a truncated clean judgment.
- [x] Test two simultaneous requests with different source context and cancellation to detect cache/state leakage. Prompt caching stays disabled.
- [ ] Run new prompt/skill/coverage suites, `npm run lint`, and `npm run test:offline`; save off-versus-shadow decision equality and actual extra latency/cost separately.
- [x] Commit: `feat: shadow prompt and skill risk judgments without changing policy`.

**Exit gate:** Both transports expose a complete, attributable shadow comparison without losing any pre-existing detection layer or treating missing analysis as safety.

### Pass 7 — Capability interpretation with present/absent/unknown

**Create:** `src/ai/rubrics/capability.ts`, `src/services/CapabilityAnalysisService.ts`, `src/services/TrustedCapabilityResolver.ts`, `src/test/ai/capabilityAnalysisTests.ts`; capability fixtures under `src/test/fixtures/ai/capabilities/`.
**Modify:** bootstrap, v2 `check_lethal_trifecta`, v2 skill orchestration, report schemas. Preserve `TrifectaAnalyzer.analyze()`.

- [x] Write three-bucket fixtures for private mailbox/external sender overlap, offline uploads, arbitrary GET queries, fixed external payload destinations, remote images, negated warnings and misleading tool names.
- [x] Add provenance fixtures: verified denial versus enabled capability, mere promises, missing scope and bare `read_file`. Lock expected unknown states before model evaluation.
- [x] Implement an injected private `TrustedCapabilityResolver` bound to agent identity, scope and configuration version; only this seam constructs verified facts. Public capability descriptions remain declared. Add standalone MCP and skill endpoint tests for forged `verified_runtime` denials and evidence reused for a different agent/scope.
- [x] Implement deterministic precedence for verified runtime capability facts; untrusted descriptions cannot disable known permissions.
- [x] Add three independent presence questions; unresolved buckets go to one structured reasoning assessment of the whole configuration. Do not introduce a second sufficiency classifier. Verified denial can establish runtime absence; explicit complete declared restrictions can support only declared absence; otherwise preserve unknown. Low Noul alone never proves absence.
- [x] Implement three-valued composition: 3 present → critical; 2 present + unknown → review; verified absence breaks only this chain; preserve existing local blocking findings in the aggregate.
- [x] Wire shadow comparison into standalone capability and skill v2 reports, with provenance/evidence for each bucket and the appropriate cache key.
- [x] Test off/shadow equality, source-context changes, provider timeout and contradictory evidence. Ensure unavailable/unknown never maps to an unqualified safe report.
- [x] Run capability tests, existing trifecta tests and the offline suite.
- [x] Commit: `feat: add provenance-aware capability judgments`.

**Exit gate:** Capability uncertainty is explicit and cannot be hidden behind a boolean; TypeSafe supplements declared text without granting or revoking actual permissions.

### Pass 8 — Deterministic HF parsing plus semantic reference selection

**Create:** `src/ai/rubrics/modelReference.ts`, `src/services/ModelReferenceAnalysisService.ts`, `src/test/ai/modelReferenceTests.ts`; extraction fixtures under `src/test/fixtures/ai/model-references/`.
**Modify:** `src/services/HuggingFaceService.ts`, `src/services/SkillScanService.ts`, bootstrap, configuration and coverage schemas.

- [x] Write failing URL tests for model URLs, `/datasets/`, `/spaces/`, trailing punctuation, explicit IDs, GitHub URLs and local paths; specify the correct resource kind rather than accepting any `owner/name` substring.
- [x] Implement deterministic URL/resource parsing and source-span candidates first. Keep a separately reported baseline ablation so model benefits are not confused with parser fixes.
- [x] Write candidate-coverage tests before inference, including auditing/warning references, distant context, multiple IDs, missing values and references in code.
- [x] Implement one Noul per bounded candidate with explicit “named model even when audited or discouraged” wording. Batch questions; return only existing candidates and preserve exact normalized source IDs.
- [x] Split lookup sets by mode. Off/shadow authoritative lookups use corrected incumbent accepted references plus explicit model URLs; semantic additions are diagnostic only. Qualified enforce adds semantic references to that union. Exact parser corrections may separately reclassify proven datasets/Spaces; record that ablation. All remaining incumbent heuristic IDs survive a low Jev score. Test that low-score preservation and off/shadow equality when a newly suggested reference would yield critical HF flags; shadow must not launch that extra authoritative lookup.
- [x] Keep actual HF security metadata lookups, caching and deduplication; bound unique lookups to 16, marking overflow/incomplete lookup coverage visibly rather than ignoring the remainder.
- [x] Test no-candidate/no-call, hallucinated candidate IDs, uncertainty, provider errors, metadata lookup failure, duplicate normalization and resource-type correctness end to end in skill v2 reports.
- [x] Run model-reference/HF/skill tests and the offline suite; record parser-only, parser-plus-Jev and existing behavior separately.
- [x] Commit: `feat: resolve model references with deterministic parsing and typed judgments`.

**Exit gate:** Cheap exact parsing is corrected; optional semantic selection can safely expand audit coverage without letting uncertain classification erase a model reference.

## Chunk 3: qualification, staged enforcement and delivery

### Pass 9 — Reproducible evaluation and qualification manifests

**Create:** `src/scripts/evaluateAi.ts`, `src/evaluation/Corpus.ts`, `src/evaluation/Metrics.ts`, `src/evaluation/Manifest.ts`, `src/test/ai/evaluationTests.ts`, `src/test/ai/manifestTests.ts`; versioned dataset manifests/label records under `evaluations/ai/datasets/`, calibration records under `evaluations/ai/calibration/`, run artifacts under `evaluations/ai/runs/` and qualification manifests under `evaluations/ai/qualifications/`.
**Modify:** `package.json`, configuration/profile validation, evaluation README, usage/pricing fixtures and the progress ledger. Keep raw production inputs out of committed evaluation data.

- [x] Register `evaluate:ai` as `npm run build && node dist/scripts/evaluateAi.js`; make offline replay the default. Add CLI tests proving omitted `--live` cannot access a provider, missing limits/rate data prevent dispatch, and selected profile keys are never printed.
- [x] Implement immutable case IDs, source hashes, task/source provenance and development/calibration/held-out partition validation. Detect exact duplicates and record a reviewed paraphrase-family split; reject family leakage in acceptance runs.
- [x] Import the 107 exploratory inputs as development cases. Preserve historical labels/results and annotate revised labels separately rather than silently rewriting the experiment evidence.
- [ ] Create the held-out descriptor corpus with at least 200 risky and 200 benign cases, then independent prompt and skill strata with at least 200 risky and 200 benign each. Include quoted attacks, legitimate consequential requests, defensive text, multilingual/obfuscated payloads, nested/split descriptor attacks and parser boundary cases. Consequential intent alone must not be mislabeled malicious.
- [ ] Obtain two independent label reviews and adjudicate disagreements before running the acceptance classifier. Record labeler identity/provenance, rationale, task-specific meaning and unresolved cases; the evaluated classifier cannot manufacture its own ground truth.
- [ ] Add independently labeled capability bucket/reference cases and enacted Taster scenarios. Keep intent accuracy, declared capability, exact reference extraction and enacted sandbox behavior as distinct metrics; do not combine them into one success percentage.
- [ ] Use calibration data to select task thresholds and gray bands, then freeze the rubric, profile/options, source-envelope policy, thresholds and dataset hashes before held-out evaluation. Predeclare measurable capability/reference acceptance criteria, including preserved incumbent candidates, no new missed known risky configurations, benign-block change and unknown/review rates. Do not choose a threshold from held-out outcomes. If behavior/thresholds change after inspecting failures, retain them as regressions and require a fresh untouched acceptance set.
- [x] Implement confusion counts, missed high/critical risks, benign blocks, review/unavailable/coverage rates, family-level failures, repeated-answer changes and end-to-end p50/p95 latency. Treat review as abstention, not a correct benign/risky classification. Report sample size and sampling limits with any uncertainty intervals.
- [x] Implement per-run actual attempts and provider-specific token/cost accounting, including cache/reasoning subsets, retries, fallback and shared calls. Test missing usage/rates as unknown; compare actual spend with conservative reservations without double-counting coalesced requests.
- [x] Add offline report tests using saved experiment outputs; reproduce historical counts within documented rounding. Keep original TypeSafe-versus-Gemini primitive comparisons labeled as narrower than full service behavior.
- [x] Run `npm run evaluate:ai -- --offline --dataset <versioned-manifest>` against committed synthetic/saved fixtures and save its artifacts. The actual manifest path must be recorded in the progress ledger before this command is considered complete.
- [ ] When live evaluation is authorized for execution, first run bounded probes for the actual selected profiles, then paired evaluations of Gemini, Claude and OpenAI through the same task schema and rubric. Require explicit `--live --profiles <names> --dataset <path> --max-requests <N> --max-usd <N> --pricing <path>`. A demonstration caps at 20 requests/$1; qualifying hundreds of cases requires explicitly larger limits, never automatic expansion. Count fallback/retry attempts against the request cap.
- [ ] Compare the implemented paths: incumbent, parser-only, reasoning-adapter parity and TypeSafe shadow. Hold input families and context constant; report missing credentials, unsupported profiles or budget exhaustion as incomplete qualification. Register enforcement/cascade scenarios as pending until Passes 10/11 implement them; do not invent their endpoint results from primitive-level outputs.
- [x] Implement a private evaluation service-construction path that may exercise a proposed policy without an already-passing activation manifest. Keep this local to the evaluator, with no listeners and no public request/environment override for a serving process; retain all other capability, validation, privacy and budget checks. Test that evaluation artifacts are labeled and that REST/MCP bootstrap still rejects the same unqualified configuration. This breaks the implementation/evaluation/activation circular dependency.
- [x] Implement qualification manifests with task/mode, dataset hashes, model resolution policy, all decision-affecting primary/fallback profiles, options, rubric/schema/policy hashes, thresholds, pricing version, metrics, limitations, review date and expiry. Use deterministic validation; only local trusted configuration selects a manifest, never scan input.
- [x] Add tests for stale/failed/mismatched manifests, drifting aliases, changed primary or fallback profile, changed threshold and changed source policy. A candidate model may be explored in shadow, but unsupported roles fail preflight and enforcement requires matching passing evidence for every decision-affecting route.
- [x] Run evaluation/manifest/usage tests and the offline suite. Publish actual pass/pending/fail status by task/profile; do not mark an unavailable live run complete.
- [x] Commit harness and reviewed artifacts using explicit paths: `feat: qualify AI profiles with reproducible task evaluations`.

**Exit gate:** Offline replay, bounded live evaluation and manifest validation are implemented and tested; every task/profile has explicit qualification status. Passes 10/11 may implement their policies and evaluate them through the isolated runner. Their staging/production activation remains pending until the relevant evidence passes; a working evaluation tool alone is insufficient.

### Pass 10 — Qualified descriptor and additive capability/reference enforcement

**Create:** `src/test/ai/enforcementTests.ts`, `src/test/ai/rolloutConfigTests.ts`; small sanitized acceptance fixtures for passing and rejected manifests.
**Modify:** configuration/manifest validation, descriptor/capability/reference services, decision policy, skill orchestration, v2 serializers, `/health` readiness reporting and the progress ledger.

- [x] Write failing startup tests for task-specific mode selection, missing/expired/mismatched qualification, unsupported model features and incompatible fallback profiles. Fail invalid enforcement configuration before accepting scans; do not silently downgrade the configured mode.
- [x] Implement independent task modes and validate the qualified route on startup. Keep existing installations off; make enabling descriptors incapable of enabling prompt/skill or capability/reference enforcement as a side effect. Test SPEC §6's complete skill-parent/capability-reference-child mode table: a child's enforce setting cannot escape a skill off/shadow ceiling, and prompt and skill activation remain independent.
- [x] Implement descriptor decisions from SPEC §7.1/§8.1: preserve local blocks, use qualified high-risk evidence to add findings, require contextual review for ambiguous or contradictory evidence, and apply the explicit low-risk coverage rule. Revalidate selected source IDs against the inspected descriptor.
- [x] Test borderline Nouls, low poisoning with a speculative selected field, invalid evidence references, static block plus model benign, unavailable reasoning and changed priorHash. Treat the low-poisoning selection as a conservative policy-review condition, not invalid provider data, and measure its review burden separately. Every emitted `safe:true` must satisfy the descriptor's task-specific allow predicate.
- [x] Enable qualified capability composition using provenance and three-valued buckets. Test verified absence, complete declared restrictions, untrusted denial, present/present/unknown and all-present outcomes through standalone MCP and skill requests; preserve every existing local block.
- [x] Enable only qualified additive HF reference selection; test that the enforced lookup union expands correctly and that shadow/off still perform exactly their baseline lookup set. Preserve all corrected incumbent candidates regardless of low semantic scores; report candidate/lookup overflow as incomplete coverage.
- [x] Add transport-level tests showing version 1 compatibility paths and v2 scope explicitly. A version 1 descriptor/capability result must never claim TypeSafe enforcement; `/health` must disclose that v2 coverage does not mean every legacy client uses it.
- [ ] Exercise the newly implemented descriptor/capability/reference enforce policies in the isolated evaluator on frozen held-out sets; compare against their baseline, parser-only and shadow paths. Record complete service-path latency/cost and create passing manifests only for tasks/routes meeting the frozen gates. Run public transport serialization with injected providers; evaluation mode must not be a public request option.
- [ ] After qualification, exercise each task's off → shadow → enforce → shadow/off transition with an explicitly selected staging profile. Record config/manifest hashes, actual response examples, decision equality in shadow and rollback behavior. Missing or failing evidence leaves activation pending but does not prevent implementing an independent subsequent task.
- [ ] Run focused enforcement/version/config tests and `npm run test:offline`. Compare held-out/staging evidence to the frozen gates; leave failed tasks in shadow and record the blocker without weakening thresholds.
- [x] Commit the feature with defaults still off: `feat: gate TypeSafe enforcement by task qualification`.

**Exit gate:** Each activated task has a passing matching manifest and end-to-end proof. Prompt/skill reasoning remains required; capability/reference enforcement inside skills cannot remove any baseline protection.

### Pass 11 — Prompt/skill cascade with complete clean-path reasoning

**Create:** `src/test/ai/cascadeTests.ts`, `src/test/ai/cascadeTransportTests.ts`; cascade fixtures covering ordering, fallback, budget and partial coverage.
**Modify:** `SecurityService.ts`, `SkillScanService.ts`, semantic/judgment orchestration, task-specific policy/configuration, evaluation scenario definitions and the progress ledger.

- [x] Write a routing table and failing tests for deterministic block, qualified TypeSafe block, ambiguous judgment, low-risk judgment, TypeSafe failure, reasoner failure and complete clean analysis. The only inference shortcut in this release is a conclusive block; low-risk TypeSafe output never authorizes an early allow.
- [x] Implement deterministic checks first, followed by the bounded task-appropriate TypeSafe batches in enforce/cascade mode. An already conclusive block may return with remaining checks marked skipped and a reason; it must not claim completed clean coverage.
- [x] For undecided prompts, call the full structured reasoner once logically; for undecided skills, use one full-skill reasoning request incorporating relevant unresolved capability/reference evidence. Preserve all required category, HF and capability checks. Do not create a separate generative call per wrapper or bucket.
- [x] Implement the request-wide 20-second deadline and ordinary three-/skill six-attempt limits with reservations from Pass 1. Test a skill needing three judgment calls plus one reasoner, one transient retry and one permitted availability fallback; extra attempts must stop explicitly. Give authoritative work priority over separately bounded shadow work.
- [x] Test complete-input handling for Jev overflow, unsupported reasoning context, valid model refusal, malformed structured output and lost response bodies. Expected: complete supported fallback or explicit review/unavailable with `safe:false`; never a silently truncated or guessed benign report.
- [x] Test that model fallback cannot run because of a suspicious verdict, cannot erase a blocking result and cannot use an unqualified profile in enforced policy. Reject incompatible manifest/configuration changes before serving requests.
- [x] Run REST/MCP paired fixtures through both scan types and confirm identical decision, coverage, finding provenance and actual selected model. Verify no TypeSafe Noul is relabeled as reasoning confidence or as the old Gemini result.
- [ ] Evaluate the newly implemented cascade through the isolated evaluator on frozen prompt and skill held-out strata independently against SPEC §10; no prior passing cascade manifest is required for this evaluation-only run. Compare total service-path p50/p95, all inference costs, HF calls, fallback frequency and review burden; report savings only where measured. Measure additional clean-path latency explicitly, then verify public endpoint overhead during qualified staging.
- [ ] Enable cascade only for each task/profile combination that satisfies its acceptance manifest and staging exercise. If quality, cost or latency disappoints, retain the implementation in shadow and record the measured reason.
- [x] Run cascade/transport/budget/coverage tests and the offline suite; commit: `feat: route conclusive risks through a qualified reasoning cascade`.

**Exit gate:** No clean input bypasses required reasoning, no existing blocker is weakened, and any claimed speed/cost benefit is measured for the full deployed task path.

### Pass 12 — Migration, model-switch drill, rollback and release handoff

**Create:** `docs/operations/ai-models.md`, `docs/operations/typesafe-rollout.md`, `src/test/ai/operationsTests.ts`.
**Modify:** `README.md`, `.env.example`, configuration/pricing examples, `/health`, CI workflow(s) after inspecting the existing setup, package/release documentation only when preparing an authorized release; complete the progress ledger.

- [x] Document each role, supported provider contract, model capability constraints, key name, independent profile selection and restart behavior. Show a concrete Claude ↔ OpenAI semantic switch with Taster/Monitor unchanged, and a separate Monitor-only switch. Explain that model quality and account access require qualification.
- [x] Document v1/v2 request/response examples, MCP `reportVersion`, the intentional fail-closed error change, `report_version_required`, and the limited TypeSafe scope of legacy callers. Keep the existing 11 MCP tool names; provide a client migration sequence before retiring any compatibility path in a future major release.
- [x] Document native API differences handled by adapters, supported model options, token accounting, explicit availability fallback and cases that cannot fall back. Explain how to add a model ID/profile without scanner edits and when a genuinely new provider requires a new adapter.
- [x] Publish a rollout record template with task/mode, commit/config/manifest hashes, selected/resolved model, qualification result, endpoint/runtime evidence, operator/date, remaining blockers and rollback target. Distinguish code ready, live qualified, staged and production active.
- [x] Add health/log tests for no inference during checks, sanitized missing-key information, degraded roles, v2 scope, stderr-only MCP logs and absence of raw prompts/secret values/private continuation blocks. Test generated mock secret strings too, not only API-key patterns.
- [x] Add supported-runtime CI coverage for Node 18.20, 22 and 24 using the offline suite; retain Node 26 as a development smoke check. Verify native fetch/cancellation behavior without raising the engine requirement accidentally.
- [ ] Run config-check and the full offline suite in a clean implementation checkout, then perform the permitted bounded live model-switch drill for actual selected profiles. Exercise REST and MCP with the same config hash and record provider attribution before/after restart. Missing credentials leave this drill pending.
- [ ] Perform outage/cancellation drills, cache invalidation on model/rubric change, expired-manifest startup rejection and rollback to a previously qualified profile. Switch TypeSafe off/shadow and verify fail-closed fixes remain active; rollback must never restore benign defaults for provider errors.
- [x] Audit transitional Gemini-specific shims and SDK dependencies before removal. Import/compatibility checks retain the positional/public facade and legacy SDK paths for this release; no unrelated dependency cleanup is included. Public compatibility serializers remain until their documented retirement.
- [x] Run final build, lint and the compiled `test:offline` runner, config validation and the focused transport/operations tests. Inspect the diff and confirm no credentials, raw production data or unrelated user changes are staged.
- [x] Commit the documented delivery state: `docs: document AI model selection and qualified TypeSafe rollout`. Record exact completed gates and remaining live/operational dependencies; leave every unperformed item unchecked.
- [ ] When separately authorized for delivery, prepare the release/PR, publish or deploy through the project's established process, verify the running revision and public behavior, and record production modes. This checkbox remains pending if the assignment ends at implementation or staging.

**Exit gate:** Model selection and rollback are reproducible, documented and verified for the actual selected profiles. Production activation is complete only after deployment/runtime evidence is recorded; green code tests are not deployment evidence.

## Requirement-to-checklist traceability

| Requirement | Implementing passes | Primary proof |
|---|---|---|
| R1 Deterministic control | 1, 3, 5, 7, 8, 10 | Policy/source-map/hash/parser/mock-router tests |
| R2 Truthful availability | 1, 4, 6, 10, 11 | Malformed response, outage and coverage decision tables |
| R3 Provider switching | 1–3, 9, 12 | Native API fixtures, role routing and live switch drill |
| R4 Bounded TypeSafe | 4–8 | Primitive validation, state separation, batching and bounds |
| R5 Preserved protections | 1, 3, 5–8, 10, 11 | Static/raw-call severity floors and candidate-preservation regressions |
| R6 Controlled activation | 5–11 | Shadow equality, manifests and independent task modes |
| R7 Observable quality | 0, 9, 11, 12 | Frozen labels, complete endpoint measurements and rollout ledger |
| R8 Compatibility | 1–3, 5, 6, 10, 12 | v1/v2 REST/MCP snapshots and attribution checks |
| R9 Bounded execution | 1, 3, 4, 9, 11 | Deadlines, cancellation, attempts, reservations and usage tests |
| R10 Privacy/provenance | 3, 6, 7, 9, 12 | Trusted resolver, source envelopes and log-redaction tests |
| R11 Mock-only tools | 3 | No real execution callbacks and bounded conversation fixtures |
| R12 Reversible rollout | 10–12 | Actual configuration/restart/rollback drill with reliability fixes retained |

## Completion ledger rules

The implementation ledger tracks each pass with: state (`pending`, `in progress`, `blocked`, `complete`), commit, test evidence, dataset/manifest/config hashes when applicable, runtime evidence, remaining work and next dependency. Mark a checkbox only after its stated evidence exists. Use a separate task/profile matrix for live qualification and activation so an unavailable provider does not make all other work appear unfinished or falsely qualified.

At the end of implementation, report the current modes, chosen models per role, measured benefits and tradeoffs, compatibility status, exact completed gate and pending deployment/qualification work. No production implementation or activation is performed by authoring this plan.

## Delivery gate interpretation

Checked implementation items are backed by committed code, offline/native fixtures and independent reviews. Unchecked mixed items that include live latency, held-out quality, restart, model-switch or rollback evidence remain open even when their offline portion has passed. The bounded demonstration is complete; larger qualifying runs, restored Claude/OpenAI account access, independently reviewed untouched labels and staging are the next rollout gates. No acceptance threshold is weakened to close a checkbox.
