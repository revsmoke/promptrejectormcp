import express from "express";
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { PromptRejectorMCPServer } from "./mcpServer.js";
import type { Services } from "../bootstrap.js";

export interface RemoteMcpConfig {
    publicUrl: string;
    issuer: string;
    jwksUrl: string;
    subjects: string[];
    scope: string;
    origins: string[];
}

function httpsUrl(value: string | undefined, name: string): string {
    const url = new URL(value || "invalid:");
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash)
        throw new Error(`Invalid ${name}: use an HTTPS URL without credentials, query or fragment`);
    return url.href;
}

/** This is an OAuth resource server, not an authorization server. Fail closed. */
export function remoteMcpConfig(env: NodeJS.ProcessEnv = process.env): RemoteMcpConfig {
    const publicUrl = httpsUrl(env.MCP_PUBLIC_URL, "MCP_PUBLIC_URL");
    if (new URL(publicUrl).pathname !== "/mcp") throw new Error("MCP_PUBLIC_URL must end in /mcp");
    const issuer = httpsUrl(env.MCP_OAUTH_ISSUER, "MCP_OAUTH_ISSUER");
    const jwksUrl = httpsUrl(env.MCP_OAUTH_JWKS_URL, "MCP_OAUTH_JWKS_URL");
    const subjects = (env.MCP_ALLOWED_SUBJECTS || "").split(",").map(s => s.trim()).filter(Boolean);
    if (!subjects.length) throw new Error("MCP_ALLOWED_SUBJECTS must identify authorized account subjects");
    const scope = env.MCP_OAUTH_SCOPE || "prompt-rejector:use";
    if (!/^[A-Za-z0-9:._/-]+$/.test(scope)) throw new Error("Invalid MCP_OAUTH_SCOPE");
    const origins = (env.MCP_ALLOWED_ORIGINS || "").split(",").filter(Boolean).map(s => {
        const url = httpsUrl(s.trim(), "MCP_ALLOWED_ORIGINS");
        if (new URL(url).pathname !== "/") throw new Error("MCP_ALLOWED_ORIGINS must contain origins, not paths");
        return new URL(url).origin;
    });
    // JWT issuer matching is exact, including a trailing slash when configured.
    return { publicUrl, issuer: env.MCP_OAUTH_ISSUER!, jwksUrl, subjects, scope, origins };
}

/** Stateless Streamable HTTP, sharing the same deterministic services as stdio. */
export function createMcpHttpApp(services: Services, config: RemoteMcpConfig, getKey?: JWTVerifyGetKey) {
    const app = express();
    app.disable("x-powered-by");
    const keys = getKey ?? createRemoteJWKSet(new URL(config.jwksUrl), { timeoutDuration: 5000 });
    const publicOrigin = new URL(config.publicUrl).origin;
    const metadataUrl = `${publicOrigin}/.well-known/oauth-protected-resource/mcp`;
    const challenge = `Bearer resource_metadata="${metadataUrl}", scope="${config.scope}"`;
    app.get(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"], (_req, res) => {
        res.set("Access-Control-Allow-Origin", "*").json({ resource: config.publicUrl, authorization_servers: [config.issuer],
            scopes_supported: [config.scope], bearer_methods_supported: ["header"] });
    });
    app.get("/health", (_req, res) => res.json({ status: "ok", transport: "streamable-http", authentication: "oauth-jwt" }));
    app.use("/mcp", async (req, res, next) => {
        res.set("Cache-Control", "no-store");
        const origin = req.get("origin");
        if (origin && origin !== publicOrigin && !config.origins.includes(origin))
            return res.status(403).json({ error: "origin_not_allowed" });
        if (origin) {
            res.set("Access-Control-Allow-Origin", origin).vary("Origin");
            res.set("Access-Control-Expose-Headers", "WWW-Authenticate, MCP-Protocol-Version");
        }
        if (req.method === "OPTIONS") {
            res.set("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS");
            res.set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version");
            return res.sendStatus(204);
        }
        const authorization = req.get("authorization");
        const token = authorization?.match(/^Bearer ([^\s]+)$/i)?.[1];
        if (!token || token.length > 16384)
            return res.status(401).set("WWW-Authenticate", challenge).json({ error: "authentication_required" });
        try {
            const { payload } = await jwtVerify(token, keys, {
                issuer: config.issuer, audience: config.publicUrl,
                algorithms: ["RS256", "ES256"], requiredClaims: ["exp", "sub", "iat"],
            });
            if (!payload.sub || !config.subjects.includes(payload.sub))
                return res.status(403).json({ error: "account_not_allowed" });
            if (typeof payload.scope !== "string" || !payload.scope.split(" ").includes(config.scope))
                return res.status(403).set("WWW-Authenticate", `${challenge}, error="insufficient_scope"`).json({ error: "insufficient_scope" });
            next();
        } catch {
            return res.status(401).set("WWW-Authenticate", `${challenge}, error="invalid_token"`).json({ error: "invalid_token" });
        }
    });
    // Authenticate before parsing a body or allocating an MCP service connection.
    app.post("/mcp", express.json({ limit: "4mb" }), async (req, res) => {
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
        const server = new PromptRejectorMCPServer(services);
        res.once("close", () => { void server.close(); });
        try {
            await server.connect(transport);
            await transport.handleRequest(req, res, req.body);
        } catch {
            if (!res.headersSent) res.status(500).json({ error: "mcp_request_failed" });
            await server.close();
        }
    });
    app.all("/mcp", (_req, res) => res.status(405).set("Allow", "POST").json({ error: "method_not_allowed" }));
    app.use((error: { type?: string }, _req: express.Request, res: express.Response, _next: express.NextFunction) =>
        res.status(error.type === "entity.too.large" ? 413 : 400).json({ error: "invalid_request_body" }));
    return app;
}
