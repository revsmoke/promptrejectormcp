# Active TypeSafe verification

Local activation, 2026-09-19 America/Detroit (artifact timestamps cross into 2026-09-20 UTC). These are synthetic functional checks, not held-out accuracy qualification.

The active configuration enables Jev `jev-1.13.0` for descriptor/capability/model-reference enforcement and prompt/skill block-only cascades. Gemini `gemini-3-flash-preview` performs contextual reasoning. Ordinary MCP requests default to report version 2. Explicit `qualificationPolicy: "optional"` reports that formal qualification was not performed; supplied qualification evidence still receives all strict checks.

## Observed application behavior

| Check | Result | Physical inference calls | Observed service time |
| --- | --- | ---: | ---: |
| Poisoned nested tool description | Local rules said safe; Jev added a block with exact `/inputSchema/properties/q/description` evidence | 1 | 520 ms |
| Identical descriptor repeat | Same block from cache | 0 | 0 ms reported |
| Benign public-weather descriptor | Allow | 1 | 400 ms |
| Benign weather prompt | Allow, after Jev and full Gemini reasoning | 2 | 1,907 ms |
| Prompt demanding credential disclosure to an outside recipient | Local severity low; Jev blocked; full reasoning skipped with explicit conclusive-block coverage | 1 | 203 ms |
| Complete arithmetic-only skill | Allow after intent, capability and full-skill reasoning; all absent capabilities carry declared-source evidence | 3 | 4,611 ms |
| `openai/whisper-tiny` reference | Jev classified the exact candidate; the actual HF lookup ran; overall review retained because the skill lacked complete capability restrictions | 4 | 6,322 ms |
| REST benign prompt | Allow, with real Jev/Gemini and the same active configuration hash as health | 2 | 2,049 ms |
| Native Codex `scan_mcp_tool`, version omitted | Version 2 block, local severity safe, resolved `jev-1.13.0`, exact nested evidence | 1 | 698 ms |

The service also listed all 11 MCP tools, advertised version 2 defaults on all five versioned tools, answered health without inference and rejected caller-supplied qualification policy through both transports. Capability inference is exercised inside the full skill scan; standalone capability behavior is covered by the offline integration suite.

These observations demonstrate concrete added detection, one-call attack handling and cache reuse. They do not establish population accuracy, a general latency improvement, or deterministic model answers. Strict parsing, source binding, coverage, caching, limits and policy composition are deterministic; model judgments remain probabilistic. The native descriptor repeat across separate processes returned poisoning 0.93 and 0.94, while both final decisions were block.

## Artifacts and repairs

- `live-smoke.json`: initial run, eight physical calls. Five checks passed; the clean skill failed because Gemini returned HTTP 400 for the combined response schema. The artifact deliberately retains `success: false`.
- Three single-call Gemini diagnostics followed. The unchanged schema failed. Removing only `maxItems: 0` still failed. Removing all seven native `maxItems` constraints succeeded with a locally valid complete skill response. The production adapter now expresses those bounds as guidance and retains the unchanged strict local parser. Regression fixtures reject oversized arrays and invented references.
- `live-completion.json`: corrected clean skill passed with three calls. Its subsequent reference fixture was already blocked by an existing local rule and made zero additional calls. This was unsuitable for exercising reference inference; the artifact remains `success: false`. No local protection was weakened to pass the check.
- `live-reference-rest.json`: a plain reference fixture reached inference and the actual HF lookup; REST, health and negative-input checks passed. Six calls, `success: true`.
- `native-codex.jsonl`: the first isolated native-client test stopped at its default tool approval setting before inference. No provider call occurred.
- `native-codex-completion.jsonl`: the already-authorized read-only synthetic scan was allowed for that tool in the isolated test invocation; native Codex completed the real MCP call. No global approval setting was changed. Other MCP servers were excluded from the isolated test.

Earlier artifacts have the earlier active configuration hash. Adding unused Claude/OpenAI profile choices changed the final hash to `188cb62f30cfaad7bda38aeb3fe3a5bbf82ed426f4bba73eaf73bc28b3612871`. The final skill, reference, REST and native-client results use this configuration.

Activation verification used **22 upstream physical inference attempts**: one initial Gemini access check, eight initial smoke attempts, three schema diagnostics, three corrected-skill attempts, six reference/REST attempts and one native-client Jev call. Read-only HF requests and the Codex client sessions are separate. Every experimental run used explicit request/USD limits; the original 20-call working allocation was extended by two calls to finish REST and native-client verification after diagnosis. The combined upstream conservative envelope remained below $0.23. Gemini's missing billable cache details leave actual total spend unknown; reservations are not actual cost. The native Jev call's estimate was $0.000034272.

## Reproduction

Build first, then run selected synthetic cases with explicit limits. Output files must not already exist:

```sh
node experiments/typesafe/activation-smoke.mjs --live \
  --env-file /absolute/path/to/.env \
  --output /absolute/path/to/new-activation-result.json \
  --max-requests 7 --max-usd 0.15 \
  --cases skill_model_reference,rest_prompt_benign
```

Omit `--cases` to run all cases, with a suitable bounded request allowance. The harness uses the real application service graph and provider adapters, an in-memory MCP protocol transport and loopback REST. The separate native Codex artifact verifies the actual stdio launcher from an unrelated working directory. The global `prompt-rejector` server entry points to that launcher and reads credentials from the original checkout's untracked `.env`; no key is embedded in tracked configuration or client arguments.
