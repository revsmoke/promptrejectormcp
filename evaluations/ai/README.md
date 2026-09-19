# AI evaluation evidence

This directory will hold versioned, reviewable evaluation definitions and results for the TypeSafe and provider-routing rollout. The implementation specification is [the rollout spec](../../docs/specs/2026-09-19-typesafe-model-routing-spec.md); the executable work checklist is [the implementation plan](../../docs/superpowers/plans/2026-09-19-typesafe-model-routing.md). Current progress and evidence are recorded in [the rollout ledger](../../docs/implementation/typesafe-progress.md).

## Offline baseline

Run `npm ci --ignore-scripts` once to install the locked dependencies, then `npm run test:offline`. The test command compiles with the installed TypeScript compiler and runs compiled JavaScript with the current Node executable. It does not invoke `npx`, download a test runner, or use provider credentials.

`src/scripts/runOfflineTests.ts` registers the existing 17 `npm test` suites explicitly, plus its own offline-guard regression suite. Live `advancedTests.ts` and `skillScanTests.ts` are excluded. Each suite runs in a fresh temporary working directory containing copied compiled code, TypeScript/JSON test fixtures, and patterns, with a controlled link to the installed `node_modules`. The source copies also support existing tests that inspect service source files. Production fixture files are not test output locations.

The child environment is an allowlist: it excludes provider keys, arbitrary secrets, `NODE_OPTIONS`, and dotenv path overrides, and uses a temporary home. `TEMP`, `TMP`, and `TMPDIR` also point to the suite directory, so fixtures created through `os.tmpdir()` are included in cleanup. No `.env` file is copied. Each isolated child has a 120-second deadline enforced with `SIGKILL`, including when the test ignores `SIGTERM`. A preload guard blocks real fetch, TCP/TLS, UDP, and listener calls. Every blocked attempt is recorded synchronously and fails the aggregate result even when a test catches the error or exits successfully. Only suites explicitly registered with `allowLoopback: true` may use literal `127.0.0.1`/`::1` TCP endpoints; wildcard binds and external requests remain blocked. None of the original 17 suites requires that exception. In-memory network mocks remain supported.

This is protection against accidental network regressions in trusted tests, not an operating-system sandbox for malicious code. New suites must be explicitly registered, with any loopback exception reviewed. The runner prints failed-suite output and violation metadata, and removes temporary files afterward. Tests never record URLs, request bodies, headers, or credentials in guard violations.

## Dataset boundaries

- **Development:** cases used while changing prompts, schemas, policy, or code. The existing `experiments/typesafe/` artifacts belong here and remain unchanged as historical evidence. In particular, the old experiment verifier intentionally records existing fail-open behavior; it is not an acceptance test for the new implementation.
- **Calibration:** a separately identified split used to choose question wording and thresholds. Once used for tuning, its scores cannot be described as held-out results.
- **Held-out:** frozen cases not used to tune the implementation. Record dataset version/hash, independent labels and adjudication, model and prompt/rubric versions, adapter settings, policy version, usage, cost assumptions, coverage, and latency. Report errors, reviews, and unavailable results separately from successful classifications.

Prompt or descriptor **intent** labels describe a text's attack characteristics. Taste-Tester **enacted behavior** labels describe what the simulated agent actually did in its mocked transcript. These are different evaluation targets and must not share an accuracy denominator or silently substitute for one another.

Offline contract tests prove reproducibility and failure handling, not model quality or readiness to enforce TypeSafe decisions. Paid live comparisons, activation manifests, and rollout acceptance require their own evidence and gates in the plan. Saved development experiments do not satisfy those gates.
