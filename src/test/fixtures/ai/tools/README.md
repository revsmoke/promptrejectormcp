# Native Taster fixtures

Synthetic wire fixtures, never captured production conversations. Each provider returns two parallel calls to the same mock tool, followed by text-only completion. Private sentinel content must be preserved in the next native request and absent from public transcripts and reports.

Contract tests also construct malformed arguments, ID collisions, unknown tools, overflow, refusal and truncated turns from these native shapes. No fixture proves account access or model quality.

API references checked 2026-09-19:

- [Anthropic thinking preservation](https://platform.claude.com/docs/en/build-with-claude/adaptive-thinking)
- [OpenAI reasoning and stateless continuation](https://developers.openai.com/api/docs/guides/reasoning)
- [Gemini function calls](https://ai.google.dev/gemini-api/docs/function-calling) and [thought signatures](https://ai.google.dev/gemini-api/docs/generate-content/thought-signatures)

The temporary `anthropicFactory` seam is exclusively for legacy injected test clients. Production construction always uses the native adapters and shared budgets.
