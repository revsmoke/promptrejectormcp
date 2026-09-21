# Security reporting

Report vulnerabilities and security-sensitive detection bypasses through [GitHub private vulnerability reporting](https://github.com/revsmoke/promptrejectormcp/security/advisories/new). This includes failures that could expose private data, bypass required analysis or incorrectly allow a dangerous input or action. Please do not disclose these in a public issue or pull request.

Include:

- The affected release or commit.
- Relevant configuration and provider/model names, without keys or secret values.
- Minimal steps and a synthetic or redacted example that reproduces the problem.
- Expected behavior, actual behavior and potential impact.

Do not include `.env` files, credentials, private prompts or customer data. Share only what is needed to reproduce the finding safely.

Ordinary installation problems, documentation fixes and non-sensitive test suggestions belong in [public issues](https://github.com/revsmoke/promptrejectormcp/issues/new/choose). If a test case demonstrates a security-sensitive bypass, use the private route above instead.
