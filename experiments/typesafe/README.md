# TypeSafe exploratory experiments

Read [REPORT.md](REPORT.md) for findings and the proposed integration. These scripts are isolated development experiments, not production detection services. They use synthetic/authored examples and the existing public test fixture. Labels are not sent to the inference providers.

The saved run used `jev-1.13.0`: 178 requests, 159,405 input tokens, about $0.0067 at the documented rate. The optional 16-request Gemini comparison was about $0.041 at paid-tier list prices. Saved results can be inspected without API keys or new spending.

## Inspect existing results

From the project root:

```sh
npm run build
node experiments/typesafe/summarize.mjs experiments/typesafe/results/2026-09-19T20-27-01.476Z
node experiments/typesafe/verify.mjs experiments/typesafe/results/2026-09-19T20-27-01.476Z
```

The verifier makes no provider calls. It validates the saved responses and reproduces two current error-handling behaviors with offline stubs. Its expected assertions describe existing defects; they are not desired future behavior. It is deliberately tied to this 178-response experiment and will need updating for a differently sized suite.

## Reproduce with live calls

Set `TYPESAFE_API_KEY` in the existing root `.env`. The optional Gemini comparison also requires `GEMINI_API_KEY`. Keys are loaded locally, sent only as provider authentication, and excluded from result files. No new package is required.

```sh
npm run build
node experiments/typesafe/run.mjs
node experiments/typesafe/run.mjs --live --gemini
```

The first command after building is a dry run. The live run creates a fresh timestamped directory under `experiments/typesafe/results/`; omit `--gemini` to avoid the Gemini comparison. The base run permits at most 160 TypeSafe HTTP attempts and reserves capacity under a $0.10 estimated TypeSafe cap. Requests have a 20-second timeout and at most one retry for 429/529; three observed failures stop the experiment. The optional Gemini baseline intentionally uses the project's existing service settings and has a fixed 16-call workload. It is outside the TypeSafe cost cap.

Then, substituting the newly created directory:

```sh
node experiments/typesafe/followup.mjs --live experiments/typesafe/results/RUN_DIRECTORY
node experiments/typesafe/evidence-check.mjs --live experiments/typesafe/results/RUN_DIRECTORY
node experiments/typesafe/summarize.mjs experiments/typesafe/results/RUN_DIRECTORY
```

The follow-up is a fixed 56-call development comparison; the evidence check makes 18 calls. They have 20-second timeouts, no retries, and stop on an HTTP/contract error. They refuse to overwrite their completed or partial evidence. These supplemental calls are separate from the base-run cost cap. Without `--live`, each prints its planned request count.

The original rubrics remain in `questions.mjs` for reproducibility. Revised development rubrics live in `followup.mjs`; the preferred source-field selection design is in `evidence-check.mjs`. Each live stage saves its exact states and questions before inference. Do not use an experimental 0.5 threshold as a production blocking policy, or use the illustrative routing bands as proof that an input is safe.
