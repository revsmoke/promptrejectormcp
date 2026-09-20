import { prepareLaunch } from "./prepareLaunch.js";

// MCP clients may launch from any directory. Keep patterns, configuration and
// package metadata anchored to this installation, with secrets in a local file.
async function main(): Promise<void> {
    prepareLaunch("mcp");
    await import("../index.js");
}

main().catch(() => {
    console.error("MCP launcher failed. Check --env-file and --config paths and build the project first.");
    process.exitCode = 1;
});
