# Remote MCP and web clients

The regular HTTPS application API remains `https://localhost:3001/v2/check-prompt`. It is REST, not MCP. Local plugins use the existing stdio server. Use one of the paths below when a cloud client needs the MCP tools.

## ChatGPT: private Secure MCP Tunnel

This is the shortest route for an existing local installation; no public listener or new app transport is required.

1. In [OpenAI Platform tunnel settings](https://platform.openai.com/settings/organization/tunnels), create a tunnel associated with the intended Platform organization and ChatGPT workspace. The operator needs Tunnels Read/Manage to create it and Read/Use to run it. Developer-mode permission in ChatGPT is separate.
2. Install the official [tunnel-client](https://github.com/openai/tunnel-client/releases/latest). Read `tunnel-client help quickstart` for the installed version. Store its runtime credential as `CONTROL_PLANE_API_KEY` privately; it is separate from TypeSafe and model-provider keys.
3. Configure a stdio profile using your **real tunnel ID**, absolute Node executable, and absolute app paths. The documented CLI form is:

   ```sh
   tunnel-client init --sample sample_mcp_stdio_local --profile prompt-rejector \
     --tunnel-id "$PROMPT_REJECTOR_TUNNEL_ID" \
     --mcp-command 'node /absolute/path/promptrejectormcp/dist/scripts/startMcp.js --env-file /absolute/path/private.env --config /absolute/path/promptrejectormcp/config/ai.active.json'
   tunnel-client doctor --profile prompt-rejector --explain
   tunnel-client run --profile prompt-rejector
   ```

   Replace all example paths; quote paths containing spaces according to the installed tunnel client's configuration syntax. Prefer its structured configuration when available. A missing ID or permission is not evidence that the local MCP server failed.
4. Keep the tunnel client running. In [ChatGPT Plugins](https://chatgpt.com/plugins), create a developer-mode connection, choose **Tunnel**, and select that tunnel. Start a new chat, list the tools, verify patterns, then perform a small real scan.
5. Add the standalone skill through the available skill/plugin import flow. If composing an OpenAI package around an already registered connection, use its actual `plugin_asdk_app...` ID; this repository does not invent or pre-register an account-specific ID.

Tunnels serve private connections and testing, not public plugin-directory distribution. See the [official Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

## Hosted MCP for Claude web or ChatGPT

The app includes a stateless Streamable HTTP transport with the same 11 tools:

```sh
npm run start:mcp:http
# Or, outside the checkout:
node /absolute/path/promptrejectormcp/dist/scripts/startMcpHttp.js --env-file /absolute/path/private.env
```

This starts a **separate** server on loopback port **3002** by default. It does not replace/start/stop the REST service on 3001 or stdio processes. It starts only after OAuth and TLS configuration are valid. A public deployment needs a trusted certificate covering its public hostname; a local mkcert certificate is for local tests. The default listener uses HTTPS; the one optional HTTP mode is loopback-only behind a local HTTPS reverse proxy.

### What the operator must supply

- A real, stable public HTTPS URL ending in `/mcp`.
- A reachable OAuth 2.1 authorization server with discovery, authorization-code/PKCE support, and client registration or preregistered clients accepted by the target platform. This project is the **resource server**; it does not implement login, registration, token issuance or user storage.
- Asymmetrically signed JWT access tokens (RS256 or ES256), with `iss` exactly matching the configured issuer, `aud` containing the public `/mcp` URL, `exp`, `iat`, `sub`, and a space-separated `scope` claim containing the configured scope. Opaque tokens and ID tokens for another audience are not supported.
- Explicit account subject IDs allowed to use this deployment. Anyone who can get a token from the issuer is not automatically authorized.
- The app's normal private TypeSafe/reasoning keys and active configuration.

Add these to the private environment file, replacing the example values with your actual deployment:

```dotenv
MCP_PUBLIC_URL=https://your-real-host/mcp
MCP_OAUTH_ISSUER=https://your-authorization-server/
MCP_OAUTH_JWKS_URL=https://your-authorization-server/.well-known/jwks.json
MCP_ALLOWED_SUBJECTS=your-real-account-subject
MCP_OAUTH_SCOPE=prompt-rejector:use
MCP_HOST=127.0.0.1
MCP_PORT=3002
TLS_CERT_FILE=/absolute/path/certificate.pem
TLS_KEY_FILE=/absolute/path/private-key.pem
```

Issuer trailing slashes matter. JWKS and issuer endpoints must use HTTPS. Provider API keys are not MCP login tokens and must never be sent as MCP bearer tokens.

The service exposes `/mcp`, `/health`, `/.well-known/oauth-protected-resource`, and `/.well-known/oauth-protected-resource/mcp`. An unauthenticated MCP request returns 401 with resource metadata discovery. Authenticated GET/DELETE requests return 405 because this transport uses stateless POST requests rather than persistent SSE sessions. Tool responses can take time while models run; configure the proxy/client request timeout accordingly.

Tokens are validated for signature, issuer, audience, expiry, account and scope before JSON parsing or tool execution. Browser requests must use the public endpoint's origin or an explicit HTTPS origin in comma-separated `MCP_ALLOWED_ORIGINS`. Cloud-to-cloud connector requests usually have no Origin header. Denied origin requests return 403. Do not add a wildcard to bypass this check.

### Reverse proxy

With a local reverse proxy terminating public HTTPS, use:

```dotenv
MCP_BEHIND_PROXY=true
MCP_HOST=127.0.0.1
MCP_PORT=3002
```

Proxy only `/mcp` and the protected-resource metadata paths to that listener, preserving Authorization and request bodies. Do not expose the separate REST application as an authenticated MCP endpoint. The launcher rejects HTTP proxy mode on a non-loopback host. A remote/container proxy instead needs a correctly configured TLS connection to this service.

This deployment uses one shared configuration, provider account and feed/canary state. It is suitable for an owner or trusted team, **not tenant-isolated SaaS**. Use separate installations/state/accounts for separate trust boundaries. Apply deployment-level request and spend limits before giving access to more users; the existing model budgets bound each request but are not a global billing quota.

### Connect the clients

- **Claude web:** add a custom remote MCP connector using the real HTTPS `/mcp` URL, complete OAuth, then confirm tool discovery and a real call. A local `.mcpb` does not provide this web connection. See [Claude custom connectors](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).
- **ChatGPT:** enable developer mode where permitted, add the HTTPS MCP endpoint in Plugins, complete OAuth, refresh metadata, and start a new chat. See [Connect and test](https://developers.openai.com/plugins/deploy/connect-chatgpt).

For either client, verify patterns without inference, then authorize a small live TypeSafe descriptor check. Record actual results, not just an HTTP 200. Test missing/invalid credentials and a denied account as well.

### Package the real remote connection

Once you know your real endpoint:

```sh
node scripts/create-remote-plugin.mjs "$PROMPT_REJECTOR_PUBLIC_MCP_URL" /absolute/path/prompt-rejector-remote.zip
```

The generated archive contains the shared skill and portable/Codex/Claude connection manifests pointing to that HTTPS URL. It contains no server, credentials, or fake connection ID. Install it **instead of** the local plugin with the same name. For OpenAI's public directory, submit the endpoint through **With MCP**, add the skills, verify the domain, meet OAuth/UserInfo and listing requirements, and complete review. A local install or generated archive does not establish public approval.

No hosted endpoint, authorization-server account, tunnel identity, platform registration, or public listing is provisioned by the build scripts. Those are account-specific deployment steps; the repository provides the transport, packages and verification procedures.

## Reproduce the local live smoke test

After `npm run plugin:build`, `scripts/verify-plugin-live.mjs` can test the relocated bundle and an ephemeral local HTTPS MCP listener with actual TypeSafe calls. It generates temporary signing keys, serves their public JWKS over HTTPS, verifies the signature/audience/account checks, makes two synthetic descriptor scans, then closes and removes the temporary installation. It does not provision OAuth login or a cloud connector.

```sh
NODE_EXTRA_CA_CERTS="/absolute/path/to/mkcert/rootCA.pem" node scripts/verify-plugin-live.mjs \
  --env-file /absolute/path/private.env \
  --tls-cert /absolute/path/localhost.pem \
  --tls-key /absolute/path/localhost-key.pem \
  --output /absolute/path/live-results.json
```

Node may not use the macOS certificate trust store automatically. `NODE_EXTRA_CA_CERTS` supplies the trusted development CA at process startup while keeping verification enabled. Never disable certificate verification. Use public-CA trust for a hosted endpoint.
