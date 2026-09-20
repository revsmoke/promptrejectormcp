# Native structured response fixtures

These responses are synthetic, written from documented native wire formats. They contain no account identifiers, credentials, production inputs or captured reasoning. The deliberately marked private thinking/encrypted placeholders verify that adapters never mistake continuation or reasoning fields for structured output.

Each provider fixture contains success, refusal, truncation, empty-content and invalid-schema cases. The OpenAI empty fixture includes a misleading SDK-only `output_text` convenience field; raw HTTP parsing must still reject it.

References checked September 19, 2026:

- [Anthropic structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs): `output_config.format`, content text blocks and native stop handling. Unsupported numeric/string bounds remain descriptions plus original local validation.
- [OpenAI structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs): Responses `text.format`, native output blocks, refusal and incomplete handling; requests use `store:false`.
- [Gemini content generation](https://ai.google.dev/api/generate-content): `responseJsonSchema`, candidates, parts and usage metadata. The Gemini contract suite also exercises malformed fields and transport fallback.
