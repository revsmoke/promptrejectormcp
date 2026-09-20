# ChatGPT and Claude on the web

An installed skill gives instructions. It does not deploy the app, supply credentials, or make the user's localhost reachable from a cloud service.

**ChatGPT:** a private stdio MCP can connect through OpenAI's Secure MCP Tunnel. On the machine running Prompt Rejector, configure the official `tunnel-client` with the absolute Node path and `dist/scripts/startMcp.js`, its private environment file and active configuration. The user needs a tunnel ID, the required Platform/workspace permissions and a runtime key stored privately. Run the tunnel's doctor, keep the tunnel client running, and select it when creating a developer-mode connection in ChatGPT Plugins. Public plugin-directory submission instead requires a stable public HTTPS MCP endpoint and review.

**Claude web:** use a reachable remote MCP connector; local Claude Desktop extensions do not become remote servers. This repository provides `npm run start:mcp:http` for an OAuth-protected `/mcp` endpoint. Hosting, a public HTTPS URL, and an OAuth authorization server must be configured by the service owner. The local REST `/v2/check-prompt` endpoint is not a substitute.

Read the repository's `docs/operations/remote-mcp.md` for configuration, authentication, testing, and platform connection steps. Use the real endpoint/connection ID supplied by the operator. Do not invent one, expose an unauthenticated public listener, or claim a cloud integration works before its client actually lists and calls the tools.

If no connector exists and this chat has no terminal access, explain that installation must be performed in a local coding environment or by an operator. Continue with a manual review if useful, clearly labeling it as a review without a Prompt Rejector scan.
