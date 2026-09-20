import { readFileSync } from "node:fs";
import { createServer as http } from "node:http";
import { createServer as https } from "node:https";
import { prepareLaunch } from "./prepareLaunch.js";

async function main() {
    prepareLaunch("mcp");
    console.log = console.error;
    const { remoteMcpConfig, createMcpHttpApp } = await import("../mcp/httpServer.js");
    const config = remoteMcpConfig();
    const { createServices } = await import("../bootstrap.js");
    const app = createMcpHttpApp(createServices(), config);
    const port = Number(process.env.MCP_PORT || 3002);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid MCP_PORT");
    const host = process.env.MCP_HOST || "127.0.0.1";
    const proxy = process.env.MCP_BEHIND_PROXY === "true";
    // Plain HTTP is only permitted on loopback behind a local HTTPS proxy.
    if (proxy && !["127.0.0.1", "::1"].includes(host)) throw new Error("MCP_BEHIND_PROXY requires a loopback host");
    if (!proxy && (!process.env.TLS_CERT_FILE || !process.env.TLS_KEY_FILE)) throw new Error("MCP HTTPS requires TLS_CERT_FILE and TLS_KEY_FILE");
    const server = proxy ? http(app) : https({ cert: readFileSync(process.env.TLS_CERT_FILE!), key: readFileSync(process.env.TLS_KEY_FILE!), minVersion: "TLSv1.2" }, app);
    server.requestTimeout = 120_000;
    await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => { server.off("error", reject); resolve(); });
    });
    console.error(`[MCP] Authenticated ${proxy ? "HTTP (local proxy upstream)" : "HTTPS"} on ${host}:${port}/mcp`);
}
main().catch(error => {
    console.error("Remote MCP startup failed:", error instanceof Error && /^(Invalid MCP_|MCP_)/.test(error.message) ? error.message : "check OAuth, HTTPS, environment and AI configuration");
    process.exitCode = 1;
});
