# Plugin integration evidence

Synthetic checks only; no user prompts or credentials were saved.

- `live.json`: a relocated full plugin bundle and an ephemeral authenticated HTTPS MCP listener each listed 11 tools and returned a complete real TypeSafe block for the same synthetic malicious descriptor. TLS verification and the production remote JWKS loader were enabled. Ephemeral signing keys and bearer tokens were discarded.
- `api-health.json`: the existing API's configuration after restart.
- `api-benign.json`: a benign prompt allowed through the existing HTTPS REST endpoint with complete TypeSafe and Gemini coverage.

The final saved live run made two TypeSafe calls. Earlier development checks made three additional TypeSafe calls (the source doctor and an earlier two-transport smoke run). The saved REST request made two provider calls. These are functional smoke tests, not a held-out quality study, an aggregate billing report, or proof of a cloud OAuth login. See `docs/plugin-verification.md` for the complete evidence boundary.
