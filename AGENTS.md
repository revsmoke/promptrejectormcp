# Repository guide

## Resources

- `README.md`: installation, current endpoints, MCP setup and command reference.
- `CONTRIBUTING.md`: offline development and contributor tasks; `SECURITY.md`: private vulnerability reporting; `.github/ISSUE_TEMPLATE/`: report forms.
- `docs/operations/local-server.md`: installed service/worktree paths, HTTPS certificates and restart procedure. Check here before changing a running service.
- `config/README.md`, `docs/operations/ai-models.md`: active configuration, provider roles, model switching and access probes.
- `docs/how-we-use-jev-from-typesafe-ai.md`: TypeSafe design and measured results; `docs/operations/typesafe-rollout.md`: modes and bounded live tests.
- `docs/plugins.md`: installation; `plugins/prompt-rejector/`: manifests, setup skill and launchers; `scripts/build-plugins.mjs`: packaging.
- `docs/feature-reference.md`: other detectors/feeds; `CONTRIBUTING.md#release--publishing`: release/version procedure.
- `docs/specs/`, `docs/superpowers/plans/`, `docs/implementation/typesafe-progress.md`: design and delivery history. Root `SPEC.md`/`PLAN.md` describe v1.1; earlier off-by-default and dual-API plans are superseded.
- `experiments/typesafe/results/`, `evaluations/ai/runs/`: saved evidence; development results are not held-out qualification.

## Code map

- `src/bootstrap.ts`: shared service wiring; `src/api/` and `src/mcp/`: transports.
- `src/services/`: scanners, `DecisionPolicy.ts`, `AnalysisCoverage.ts`, `JudgmentService.ts` and `JudgmentCache.ts`.
- `src/ai/`: provider contracts/adapters, versioned questions (`rubrics/`), configuration, budgets and usage; `src/schemas/`: report validation.
- `patterns/`: detection library/manifest; `src/services/PatternService.ts`: integrity and updates.

## Easy-to-miss constraints

- REST is HTTPS on local port 3001, `/v2` only; `/v1` returns 410. MCP has no version selector. Use dedicated `src/scripts/start*.ts` launchers; stdio clients invoke compiled Node entrypoints directly, not npm's stdout banners.
- Launchers select `config/ai.active.json` unless overridden; low-level environment-only defaults differ. Model changes require restart/reconnection.
- Only `decision: "allow"` means safe. Prompt/skill cascades may skip reasoning after a conclusive block, never because Jev scores are low. Missing analysis is not a benign result. Policy lives in `DecisionPolicy.ts`.
- Use `npm run test:offline` (builds, isolates suites, guards network); `npm test` is an incomplete legacy chain. Register offline suites in `src/scripts/runOfflineTests.ts`. Plugin tests: `npm run test:plugins`.
