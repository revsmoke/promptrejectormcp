import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createServices } from "../../bootstrap.js";
import { createMcpHttpApp, remoteMcpConfig } from "../../mcp/httpServer.js";

const env = { MCP_PUBLIC_URL: "https://mcp.example.test/mcp", MCP_OAUTH_ISSUER: "https://issuer.example.test", MCP_OAUTH_JWKS_URL: "https://issuer.example.test/keys", MCP_ALLOWED_SUBJECTS: "owner" };
const config = remoteMcpConfig(env);
for (const invalid of [ {}, { ...env, MCP_PUBLIC_URL: "http://localhost/mcp" }, { ...env, MCP_PUBLIC_URL: "https://mcp.example.test/v2/check-prompt" }, { ...env, MCP_ALLOWED_SUBJECTS: "" }, { ...env, MCP_OAUTH_JWKS_URL: "https://key:secret@issuer.example.test/keys" }, { ...env, MCP_OAUTH_SCOPE: 'bad"scope' } ])
    assert.throws(() => remoteMcpConfig(invalid));
const { publicKey, privateKey } = await generateKeyPair("RS256");
const getKey = createLocalJWKSet({ keys: [{ ...await exportJWK(publicKey), kid: "test", alg: "RS256" }] });
const token = (options: { subject?: string; audience?: string; issuer?: string; scope?: string; expiry?: string; omitExpiry?: boolean } = {}) => {
    let jwt = new SignJWT({ scope: options.scope ?? config.scope }).setProtectedHeader({ alg: "RS256", kid: "test" })
        .setIssuer(options.issuer ?? config.issuer).setAudience(options.audience ?? config.publicUrl)
        .setSubject(options.subject ?? "owner").setIssuedAt();
    if (!options.omitExpiry) jwt = jwt.setExpirationTime(options.expiry ?? "2m");
    return jwt.sign(privateKey);
};
const app = createMcpHttpApp(createServices(), config, getKey);
const server = createServer(app);
await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
assert.ok(address && typeof address === "object");
const base = `http://127.0.0.1:${address.port}`;
let client: Client | undefined;
try {
    const metadata = await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json() as any;
    assert.equal(metadata.resource, config.publicUrl);
    assert.deepEqual(metadata.authorization_servers, [config.issuer]);
    // Even malformed/oversized data cannot reach parsing or tools without auth.
    const unauthorized = await fetch(`${base}/mcp`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{invalid" });
    assert.equal(unauthorized.status, 401);
    assert.ok(unauthorized.headers.get("www-authenticate")?.includes("resource_metadata="));
    assert.equal((await fetch(`${base}/mcp?access_token=${await token()}`, { method: "POST" })).status, 401);
    for (const [options, status] of [
        [{ audience: "https://other.example/mcp" }, 401], [{ issuer: "https://other.example" }, 401],
        [{ subject: "outsider" }, 403], [{ scope: "other:read" }, 403], [{ expiry: "-1s" }, 401], [{ omitExpiry: true }, 401],
    ] as const) {
        const response = await fetch(`${base}/mcp`, { method: "POST", headers: { Authorization: `Bearer ${await token(options)}` } });
        assert.equal(response.status, status);
    }
    const authorization = `Bearer ${await token()}`;
    const parts = (await token()).split(".");
    parts[2] = (parts[2][0] === "A" ? "B" : "A") + parts[2].slice(1);
    assert.equal((await fetch(`${base}/mcp`, { method: "POST", headers: { Authorization: `Bearer ${parts.join(".")}` } })).status, 401);
    const preflight = await fetch(`${base}/mcp`, { method: "OPTIONS", headers: { Origin: new URL(config.publicUrl).origin } });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get("access-control-allow-origin"), new URL(config.publicUrl).origin);
    const rejectedOrigin = await fetch(`${base}/mcp`, { method: "POST", headers: { Authorization: authorization, Origin: "https://attacker.example" } });
    assert.equal(rejectedOrigin.status, 403);
    assert.equal((await fetch(`${base}/mcp`, { headers: { Authorization: authorization } })).status, 405);
    assert.equal((await fetch(`${base}/mcp`, { method: "POST", headers: { Authorization: authorization, "Content-Type": "application/json" }, body: "{bad" })).status, 400);
    assert.equal((await fetch(`${base}/mcp`, { method: "POST", headers: { Authorization: authorization, "Content-Type": "application/json" }, body: JSON.stringify({ padding: "x".repeat(4 * 1024 * 1024) }) })).status, 413);
    assert.equal((await fetch(`${base}/v2/check-prompt`, { method: "POST" })).status, 404, "Remote server must not expose the unauthenticated REST app");
    client = new Client({ name: "remote-plugin-test", version: "1" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { Authorization: authorization } } }));
    const { tools } = await client.listTools();
    assert.equal(tools.length, 11);
    assert.equal(tools.find(t => t.name === "deploy_canary")?.annotations?.readOnlyHint, false);
    assert.equal(tools.find(t => t.name === "check_prompt")?.annotations?.readOnlyHint, true);
    const result = await client.callTool({ name: "verify_pattern_integrity", arguments: {} });
    assert.ok(JSON.parse((result.content as any)[0].text).valid);
    const invalid = await client.callTool({ name: "check_prompt", arguments: { prompt: "" } });
    assert.ok(JSON.parse((invalid.content as any)[0].text).error);
} finally {
    await client?.close();
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
}
console.log("PASS OAuth-protected Streamable HTTP: discovery, JWT claims, subject/scope/origin policy, body limits, real SDK client and unchanged tool inventory");
