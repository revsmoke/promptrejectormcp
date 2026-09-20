import dotenv from "dotenv";

dotenv.config({ quiet: true });

const mode = process.env.START_MODE || "both";

// CRITICAL: If we are in MCP mode (or both), we must ensure stdout is strictly for JSON-RPC.
// Third-party libraries (like dotenv or GCP SDKs) might log to stdout.
// We redirect console.log to console.error (stderr) to prevent protocol corruption.
if (mode === "mcp" || mode === "both") {
    console.log = (...args) => {
        console.error(...args);
    };
}

async function main() {
    if (!["api", "mcp", "both"].includes(mode)) throw new Error("START_MODE must be api, mcp or both");
    // Dynamic imports make environment and stdout ordering explicit, even if
    // a future provider module introduces initialization side effects.
    const { createServices } = await import("./bootstrap.js");
    const { startApiServer } = await import("./api/server.js");
    const { PromptRejectorMCPServer } = await import("./mcp/mcpServer.js");
    const services = createServices();
    if (mode === "api" || mode === "both") {
        await startApiServer(services);
    }

    if (mode === "mcp" || mode === "both") {
        const mcpServer = new PromptRejectorMCPServer(services);
        await mcpServer.run();
    }
}

main().catch((error) => {
    console.error("Startup failed:", error instanceof Error && error.message.startsWith("Invalid AI configuration") ? error.message : "invalid configuration or unavailable local resource");
    process.exit(1);
});
