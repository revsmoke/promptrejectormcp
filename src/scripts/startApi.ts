import { prepareLaunch } from "./prepareLaunch.js";

async function main(): Promise<void> {
    prepareLaunch("api");
    await import("../index.js");
}

main().catch(() => {
    console.error("API launcher failed. Check environment, configuration, port and TLS paths, and build the project first.");
    process.exitCode = 1;
});
