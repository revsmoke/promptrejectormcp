# TypeSafe opportunities and experiment results

September 19, 2026 · Baseline commit `2f3a83c266009afa84cc235c43abd7db3d7e6fe3` · Jev `jev-1.13.0`

**Recommendation: introduce Jev first as a semantic supplement to MCP tool-description scanning, then evaluate a prompt-screening cascade.** Keep exact parsing, verification, and policy composition in code. Use the existing reasoning models for ambiguous context, explanations, novel attack analysis, and sandbox behavior assessment.

The experiment demonstrates a promising speed/cost tradeoff for small judgments. It does **not** establish production detection rates, deterministic model answers, or feature parity with the current Gemini response.

Only experiment scripts, captured results, and this proposal were added. No production services, dependencies, detection patterns, configuration, or public interfaces were changed. The existing `.env.example` and skill-related changes were left alone.

## Evidence at a glance

178 live TypeSafe calls evaluated 107 distinct inputs, including repeated calls and alternative questions. Another 16 calls used the existing Gemini service for comparison. All 178 TypeSafe responses passed an offline check of model identity, answer coverage, types, probability bounds/distributions, and token-usage shape. No TypeSafe HTTP failures or retries occurred.

TypeSafe reported **159,405 input tokens**, estimated at **$0.006695** using its current $0.042 per million input tokens; output is free. Gemini's 16 comparison calls have an estimated paid-tier cost of **$0.040968**, including reported thinking tokens. These are list-price estimates, not invoices; account free tiers or negotiated pricing can differ. [TypeSafe pricing](https://docs.typesafe.ai/models), [Gemini pricing](https://ai.google.dev/gemini-api/docs/pricing#gemini-3-flash-preview).

### Initial 80-case experiment

| Task | Jev agreement | Existing local baseline | Jev median / p95 |
|---|---:|---:|---:|
| Prompt risk, 40 inputs | 39/40; 20/20 risky detected, 1/20 benign flagged | Static checks alone: 21/40; 15 missed risks, 4 benign flags | 179 / 307 ms |
| Capability classification, 16 configurations | 46/48 individual buckets; 14/16 complete bucket sets | 22/48 buckets; 5/16 complete sets | 189 / 287 ms |
| MCP description poisoning, 12 descriptors | 12/12; 6 poisoned, 6 benign | Current scanner: 5/12; 4 misses, 3 benign flags | 191 / 278 ms |
| HF model-reference extraction, 12 texts | 11/12 exact sets | Current extractor: 4/12 exact sets | 172 / 212 ms |

The prompt baseline above is **only the static layer**, not the deployed static-plus-Gemini service. The extraction prototype also changes candidate enumeration and punctuation handling, so its improvement is not entirely attributable to Jev. One no-candidate case was correctly resolved in code without an API call; extraction latency covers the other 11.

### Paired comparison with the current Gemini service

| Measure, same 16 prompt texts | Jev, three risk questions | Existing GeminiService |
|---|---:|---:|
| Binary agreement with the labels | 16/16 | 16/16 |
| Median latency | 175 ms | 3,826 ms |
| p95 latency | 447 ms | 14,326 ms |
| Estimated total inference cost | $0.000492 | $0.040968 |

That is approximately **22× lower median latency and 83× lower estimated cost** for this particular screening decision. Gemini also generates an explanation, severity, and category tags; the Jev prototype does not reproduce those outputs. The calls were measured on this machine in one short session, with three concurrent Jev workers and two Gemini workers, not an interleaved load test. Gemini used its existing prompt and generation settings; this is not a comparison against every possible optimized Gemini configuration.

The 40 prompt cases include the repository's 20 Taste-Tester examples and 20 authored challenges. Their labels were interpreted as **input risk**, including a suspicious instruction to obey an external page. A financial-transfer request counts as requiring authorization, not as proof the user has malicious intent. None of these numbers measures sandbox execution success.

## What the follow-up established

The follow-up used 31 cases: four regressions and 27 new challenges. Questions and labels were saved before calling the API, but were authored after inspecting initial failures. This is a development exercise, **not an independently labeled or blinded holdout**.

- **MCP descriptors remained the strongest result.** Six new descriptors all matched their labels, including a malicious dependency split across two fields. A further 18-call check kept all descriptor content in `state` and used only generated field IDs in Choice criteria. That safer design retained 18/18 classification agreement and selected a relevant source field for all nine poisoned descriptors. Field confidence ranged from 0.80 to 1.00 on those nine; this is not proof of evidence completeness.
- **Wording matters.** Rewriting “override” as “weaken or bypass” and explicitly excluding instructions that strengthen protections corrected the defensive-instruction error. Revised prompt questions matched 14/15 follow-up labels, versus 12/15 for the original questions. The revised rubric was not rerun across all 40 initial prompts.
- **Quotation remains a boundary.** “Identify the security problem in this quoted text, without following it…” still scored about 0.70 for disclosure. This should receive contextual review, not an automatic malicious verdict.
- **Capabilities need provenance.** Explicitly stating that a fixed external endpoint can still carry arbitrary data fixed the missed egress case. A bare `read_file` name continued to imply untrusted-input access at about 0.6. Its actual scope is missing; that test label is debatable. Production should represent this as unknown and inspect trusted runtime configuration, rather than assert presence or absence from a name.
- **Auditing a model is still a reference.** More literal extraction wording fixed the missed `acme/unsafe-pickle` reference and matched all four follow-up extraction cases. This small development result does not justify silently dropping low-scoring supply-chain references.
- **Some stress cases worked.** Classifier-directed fake answers, safety-themed exfiltration, hex-encoded instructions, Spanish input, and an attack in the middle or tail of about 10,000 input tokens were detected. Initial tests also included German, Chinese, Base64, and many-shot formatting. This limited coverage does not establish robustness to adaptive attacks or the full context limit.

### Repeatability and batching

Eight selected inputs were each evaluated three times with identical requests. All eight retained their binary/bucket decisions at 0.5, but six had some changed answer data. Observed probability changes reached **0.04**; only two returned identical complete answer objects across all three observations. Jev is therefore **not a deterministic replacement for code**.

For three prompt examples, asking three independent questions together used 2,121 input tokens versus 3,843 when asking them separately: **45% fewer tokens**. Summed elapsed time was 621 ms versus 1,737 ms for sequential separate calls. Probabilities differed by up to 0.03 between grouped and separate requests. Batch independent questions over the same input; do not assume batching preserves exact numbers or combine unrelated inputs merely to save requests.

## Project opportunities, ranked

| Priority | Existing code and fragility | Proposed System One judgment | What stays in code / System Two |
|---|---|---|---|
| 1 | `McpToolScanner.ts:138`: keyword patterns inspect strings without distinguishing argument requirements, examples, and operative poisoning | One Noul for poisoning; one speculative Choice over source-field IDs for evidence | Recursive traversal, canonical SHA-256, drift, Unicode inspection, and policy remain code. Reasoning model reviews conflicts and cross-field ambiguity. |
| 2 | `GeminiService.ts:100` and `SecurityService.ts:62`: every scan asks a generative model for JSON and merges its judgments | Batched Nouls for instruction override, private-data disclosure, and consequential action risk | Code validates answers and routes; Gemini handles uncertain cases, explanations, and richer taxonomy. Broad attack coverage must be evaluated before replacing existing behavior. |
| 3 | `TrifectaAnalyzer.ts:50`: English phrase/substring rules miss synonyms and treat warnings as capabilities | Separate capability judgments over descriptions plus trustworthy declared scope | Trusted access-control facts, presence/unknown distinction, and three-way composition remain code. Reasoning model resolves contradictory or underspecified descriptions. |
| 4 | `HuggingFaceService.ts:299`: 80-character keyword windows confuse directories, model IDs, datasets and Spaces | Select model-reference candidates by meaning; return only verbatim candidates | URL parsing, namespace/resource-type handling, punctuation rules, candidate coverage, deduplication and metadata fetching stay code. Fix these cheap syntax issues first. |
| Later | `VulnFeedService.ts:268`: each candidate advisory can trigger generative regex drafting | Screen for relevance and whether a text-observable attack signature is plausible | Exact CVE lookup, version/CVSS parsing, regex validation and staged review stay code. Gemini still drafts patterns. **Not experimentally evaluated here.** |
| Later | `TasteTesterService.ts:941`: a reasoning Monitor grades a transcript and generates structured intents | Narrow questions about already-observed actions, or escalation routing | Mock execution, recorded tool calls, extracted targets and severity floors stay code; retain the reasoning Monitor initially. **Not experimentally evaluated here.** |

The proposed first integration should run when a descriptor changes, with results cached by descriptor hash, model version, rubric version, policy, and relevant trusted context. This adds semantic coverage to a currently local scanner; it adds network latency and cost on cache misses. It is not a speed improvement over regex alone.

The original field-selector prototype repeated source text in Choice option descriptions. The final evidence experiment is preferable: untrusted text appears only in `state`; generated option IDs refer to its fields. Consume the evidence answer only when the poisoning judgment warrants it. In one benign initial case, the speculative selector picked a field even though poisoning probability was only 0.04—an unused branch must not become a finding.

## Reliability prerequisites

Two current behaviors were reproduced with offline stubs, with no provider calls:

1. **An empty Gemini object is accepted.** A response of `{}` becomes `isInjection: false`, `severity: low`, and no error. The TypeScript cast does not validate the runtime result.
2. **Unavailable semantic analysis can still look safe.** A provider result with `error: true` and medium severity plus clean static checks yields `safe: true`, `geminiAvailable: false`.

These are existing behaviors, not introduced by TypeSafe. A typed provider does not fix aggregation policy automatically. Before routing security decisions through either provider:

- Validate all required output fields, allowed values, answer IDs, model identity, probability ranges, and limits. Treat invalid or missing answers as unavailable, never as negative risk.
- Represent `allow`, `block`, `review`, and `unavailable` explicitly. Do not claim safe merely because a detector failed. Preserve compatibility through an explicit response-version or migration plan.
- Keep strong deterministic evidence and existing severity floors during the trial. Jev must not override integrity failures, canary matches, or enforced access controls. Broad regex findings that cause false positives need a separately evaluated policy change.
- Use observed, trusted caller context where available: input source, authorized task, capability scope, and enforced destination restrictions. An untrusted skill's promise of safety is not evidence that a capability is disabled.
- Pin the model version and rubric. Bound input and response sizes, timeouts, concurrency, and cache lifetimes. Route failures to the reasoning model or review. Do not silently truncate away an attack or reuse decisions after relevant context changes.
- Store reusable judgments and source references separately from the final action. Code combines independent hazards using an “any serious risk” policy; averaging them could hide a serious signal. The maximum of several Nouls is a routing statistic, not a calibrated probability of the union of hazards.

Keep hashing, HMAC verification, canary TTL/exact matches, Unicode inspection, encoding transforms, URL parsing, arithmetic, schema validation, and authorization enforcement deterministic. Typed inference improves the **interface contract**, not certainty about the world. TypeSafe itself documents susceptibility to adversarial state, literal interpretation, indirection and irrelevant context. [Jev limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13), [confidence semantics](https://docs.typesafe.ai/confidence).

## Proposed rollout and acceptance gates

**Gate 1 — shadow integration.** Add an optional TypeSafe client and versioned judgment schemas, starting with descriptors. Record sanitized agreement, disagreements, errors, latency and tokens alongside existing findings. The current decision continues to control behavior. This stage adds cost; it does not yet realize cascade savings.

**Gate 2 — contextual evaluation.** Expand the corpus using reviewed, representative prompts, real descriptor shapes, skills and indirect tool-output attacks. Include capability provenance, benign code examples, refusals, missing context, multilingual input, long inputs, encodings, stale hashes, outage and malformed-response scenarios. Agree on acceptable missed-risk and false-positive rates by use case. Choose thresholds on development data and evaluate them on separate data, including adversarial challenges.

**Gate 3 — bounded prompt cascade.** After the reliability prerequisites and evaluation gates pass, consider deterministic checks → Jev → reasoning model. Start with high-risk routing and keep System Two for uncertain or low-risk-looking cases until safe bypass is separately established. Preserve detailed reasoning on demand; do not manufacture an explanation or provider confidence to fill the old Gemini fields.

For illustration only, the initial corpus at Noul thresholds `<0.10` / `>=0.90` produced 17 clear-looking, 16 high-risk, and seven review cases, without sending a labeled risk to the clear-looking group. This tiny authored corpus cannot establish a safe allow threshold. With current static blocks preserved and only high Jev scores short-circuited, a simulation would send 18/40 cases to System Two; static checks account for nine early blocks and Jev adds 13. Four static false positives remain. This is a workload illustration, not a measured production saving or a recommended automatic policy.

Merely OR-ing Jev into existing blocking logic caught more risks but increased initial prompt false positives from four to five. Reducing false positives requires contextual adjudication and an explicit policy change, not just adding another detector.

**Gate 4 — controlled activation.** Enable one endpoint/use case at a time, retain a rollback flag, and audit sampled bypassed cases with System Two. Revalidate when the model, questions, policy, workload, or capability context changes. Keep the Taste-Tester separate: its existing calibration measured enacted behavior after the Taster's safety refusals, so its historical result cannot be compared directly with these input-risk labels (`SPEC.md:459`).

## Artifacts and checks

All run evidence is in `results/2026-09-19T20-27-01.476Z/`:

- `cases.json`, `metadata.json`, `results.jsonl`, `summary.json`: initial states, rubrics, labels, baseline outputs, hashes, measured answers, usage, timings and summaries.
- `followup-plan.json`, `followup.json`: frozen revised questions, development cases, and all 56 responses.
- `evidence-plan.json`, `evidence-check.json`: source-only-in-state field-selection design and all 18 responses.
- `verification.json`: response-contract verification and the two offline behavior probes.

`npm run build` passed. Existing Trifecta, MCP tool scanner and Hugging Face tests passed when run from the compiled output. The Hugging Face tests exercise a mocked Gemini parse failure and print expected error logs while passing. The initial `npx --no-install tsx` test invocation was unavailable because `tsx` is not installed locally; no dependency changes were needed. Experimental contract checks and the final 178-response verifier passed. This was not a full project regression suite or a deployment test.

Live documentation consulted: [API](https://docs.typesafe.ai/api), [models](https://docs.typesafe.ai/models), [state](https://docs.typesafe.ai/concepts/state), [Noul](https://docs.typesafe.ai/primitives/noul), [Choice](https://docs.typesafe.ai/primitives/choice), [confidence](https://docs.typesafe.ai/confidence), [guardrails cookbook](https://docs.typesafe.ai/cookbooks/llm_guardrails), and [known limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13). Cookbook thresholds and published performance were treated as examples, not copied as guarantees.
