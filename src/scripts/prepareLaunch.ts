import dotenv from "dotenv";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Both transports load the same installation and trusted configuration. */
export function prepareLaunch(mode: "api" | "mcp"): void {
    const root = fileURLToPath(new URL("../../", import.meta.url));
    const options: Record<string, string> = {};
    const args = process.argv.slice(2);
    const allowed = mode === "api" ? ["--env-file", "--config", "--port", "--tls-cert", "--tls-key"] : ["--env-file", "--config"];
    for (let index = 0; index < args.length; index += 2) {
        const name = args[index], value = args[index + 1];
        if (!allowed.includes(name) || options[name] || !value || value.startsWith("--")) throw new Error("Invalid launcher arguments");
        options[name] = name === "--port" ? value : resolve(value);
    }
    const environment = dotenv.config({ path: options["--env-file"] ?? resolve(root, ".env"), quiet: true });
    if (options["--env-file"] && environment.error) throw new Error("Explicit environment file is unavailable");
    process.chdir(root);
    process.env.AI_CONFIG_PATH = options["--config"] ?? resolve(process.env.AI_CONFIG_PATH || "config/ai.active.json");
    process.env.START_MODE = mode;
    if (mode === "api") {
        process.env.PORT = options["--port"] ?? (process.env.PORT || "3001");
        if (!/^\d+$/.test(process.env.PORT) || Number(process.env.PORT) < 1 || Number(process.env.PORT) > 65535) throw new Error("Invalid API port");
        process.env.HOST ||= "127.0.0.1";
        process.env.API_PROTOCOL ||= "https";
        if (options["--tls-cert"]) process.env.TLS_CERT_FILE = options["--tls-cert"];
        if (options["--tls-key"]) process.env.TLS_KEY_FILE = options["--tls-key"];
    }
}
