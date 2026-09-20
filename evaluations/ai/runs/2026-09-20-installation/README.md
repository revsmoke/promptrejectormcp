# README installation verification

Verified on 2026-09-20 using Node 24.13.0 and npm 11.8.0 on macOS.

A fresh clone of `codex/typesafe-model-routing` at `89282f3` was created in a temporary directory. The revised README, environment template and certificate-ignore rules were applied before following the installation steps. Executable source was unchanged.

- `npm ci` and `npm run build` completed successfully.
- A new `.env` used the revised template, only the saved TypeSafe/Gemini keys, and an available temporary port. `npm run ai:config` selected the active profile without inference and reported no missing required credentials.
- The README's path-generation command produced the actual Node and MCP launcher paths. The first MCP launch occurred before TLS files existed, discovered all 11 tools and obtained a real TypeSafe block for a synthetic poisoned description.
- The documented mkcert command generated a new localhost certificate using the already trusted local CA. No system trust settings were changed. A new user's one-time `mkcert -install` step is documented from mkcert's official instructions; it was already satisfied on this machine.
- `npm start` served HTTPS with the relative `.certs` paths. Normal curl certificate/hostname validation passed. A real benign weather prompt returned `allow` after TypeSafe and Gemini reasoning.
- API and MCP reports matched the active config hash. `git check-ignore` and `npm pack --dry-run --json` confirmed `.env` and `.certs` were excluded. Required key values were absent from captured output.
- README/skill-guide shell blocks passed syntax checks; moved documentation links and anchors resolved.

The temporary verification harness initially checked the wrong prompt-report field after both live analyses had succeeded. Its assertion was corrected from `judgments.result` to `judgments.intent.result`, and the checks were repeated successfully. No application change was needed. The saved reports describe the successful repeat: three physical model requests. They do not represent the earlier attempt's billing or a new quality benchmark.

Artifacts: [summary](summary.json), [health](health.json), [HTTPS prompt](https_prompt.json), [MCP descriptor](mcp_descriptor.json). Temporary processes were stopped and the temporary checkout, credentials and private key were removed after verification. The existing API and Mapbox services were preserved.
