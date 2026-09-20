import dotenv from "dotenv";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// MCP clients may launch from any directory. Keep patterns, configuration and
// package metadata anchored to this installation, with secrets in a local file.
async function main(): Promise<void> {
    const root = fileURLToPath(new URL("../../", import.meta.url));
    const options: Record<string, string> = {};
    const args = process.argv.slice(2);
    for (let index = 0; index < args.length; index += 2) {
        const name = args[index];
        const value = args[index + 1];
        if (!["--env-file", "--config"].includes(name) || options[name] || !value || value.startsWith("--")) throw new Error("Invalid launcher arguments");
        options[name] = resolve(value);
    }
    const environment = dotenv.config({ path: options["--env-file"] ?? resolve(root, ".env"), quiet: true });
    if (options["--env-file"] && environment.error) throw new Error("Explicit environment file is unavailable");
    process.chdir(root);
    process.env.AI_CONFIG_PATH = options["--config"] ?? resolve(process.env.AI_CONFIG_PATH || "config/ai.active.json");
    process.env.START_MODE = "mcp";
    await import("../index.js");
}

main().catch(() => {
    console.error("MCP launcher failed. Check --env-file and --config paths and build the project first.");
    process.exitCode = 1;
});
