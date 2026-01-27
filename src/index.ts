import dotenv from "dotenv";
import { startApiServer } from "./api/server.js";
import { PromptRejectorMCPServer } from "./mcp/mcpServer.js";

dotenv.config({ quiet: true });

const mode = process.env.START_MODE || "both";

// CRITICAL: If we are in MCP mode (or both), we must ensure stdout is strictly for JSON-RPC.
// Third-party libraries (like dotenv or GCP SDKs) might log to stdout.
// We redirect console.log to console.error (stderr) to prevent protocol corruption.
if (mode === "mcp" || mode === "both") {
    const originalLog = console.log;
    console.log = (...args) => {
        console.error(...args);
    };
}

async function main() {
    if (mode === "api" || mode === "both") {
        startApiServer();
    }

    if (mode === "mcp" || mode === "both") {
        const mcpServer = new PromptRejectorMCPServer();
        await mcpServer.run();
    }
}

main().catch((error) => {
    console.error("Startup error:", error);
    process.exit(1);
});
