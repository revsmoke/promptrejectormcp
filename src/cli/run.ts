import { createRequire } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import dotenv from "dotenv";
import { z } from "zod";
import { createPromptRejector, type PromptRejectorClient } from "../client/index.js";
import { commandNames, normalizeCommand, operationSchemas, validateInput, resultExitCode, type Command } from "../client/operations.js";
import { PromptRejectorError } from "../client/errors.js";
import { inputStream, readInput, readLines, parseJson, MAX_INPUT_BYTES } from "./input.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const { version } = createRequire(import.meta.url)("../../package.json");
const textFields: Partial<Record<Command, string>> = { "check-prompt": "prompt", "scan-skill": "skillContent", "verify-canary": "content", "taste-test": "prompt" };
const requiredInput = new Set<Command>(["check-prompt", "scan-skill", "scan-mcp-tool", "check-lethal-trifecta", "verify-canary", "taste-test"]);
const batchSchema = z.strictObject({ id: z.union([z.string().max(1000), z.number().finite(), z.null()]).optional(), command: z.string(), input: z.unknown().optional() });

export const HELP = `Usage: prompt-rejector <command> [options]

Commands (MCP names with underscores are also accepted):
  ${commandNames.join("\n  ")}
  commands                   Print command JSON schemas for agents
  batch                      Stream JSONL {id?, command, input} requests

Input (choose one):
  --text TEXT                Raw text for prompt, skill, canary or taste-test
  --file PATH                UTF-8 text for those commands; JSON for others
  --file -                   Read the same format from stdin
  --input JSON               Complete JSON arguments for any command
  Required-input commands read stdin when piped without an input option.
  batch reads JSONL from stdin or --file; one result is emitted per line.

Options:
  --env PATH                 Load a private env file (existing variables win)
  --config PATH              Select trusted AI config, relative to caller cwd
  --timeout-ms N             Whole-invocation deadline (default: no outer limit)
  --pretty                   Indent single-command JSON output
  --help, -h                 Show help (with a command: show its JSON schema)
  --version, -v              Show version

stdout: JSON results only (except help/version); diagnostics go to stderr.
Exit: 0 allow/success, 1 block/review/finding, 2 input/usage error,
      3 unavailable/operational failure, 124 timeout, 130 interrupt.
Only an explicit allow passes a scan. health checks configuration, not access.
Scans may use paid providers. Feed updates and canary deployment persist state.
`;

interface Arguments { command?: string; values: Record<string, string>; pretty: boolean; help: boolean; version: boolean }
export function parseArguments(args: string[]): Arguments {
    const parsed: Arguments = { values: {}, pretty: false, help: false, version: false };
    const flags = new Set<string>();
    for (let index = 0; index < args.length; index++) {
        const token = args[index];
        if (["--help", "-h"].includes(token)) parsed.help = true;
        else if (["--version", "-v"].includes(token)) parsed.version = true;
        else if (token === "--pretty") parsed.pretty = true;
        else if (["--text", "--file", "--input", "--env", "--config", "--timeout-ms"].includes(token)) {
            if (flags.has(token) || args[index + 1] === undefined || args[index + 1].startsWith("--")) throw new PromptRejectorError("invalid_input");
            flags.add(token);
            parsed.values[token] = args[++index];
            if (["--file", "--env", "--config"].includes(token) && !parsed.values[token]) throw new PromptRejectorError("invalid_input");
        } else if (!token.startsWith("-") && !parsed.command) parsed.command = token;
        else throw new PromptRejectorError("invalid_input");
    }
    if (["--text", "--file", "--input"].filter(key => key in parsed.values).length > 1) throw new PromptRejectorError("invalid_input");
    const timeout = parsed.values["--timeout-ms"];
    if (timeout !== undefined && (!/^\d+$/.test(timeout) || Number(timeout) < 1 || Number(timeout) > 3600000)) throw new PromptRejectorError("invalid_input");
    return parsed;
}

function prepareClient(values: Record<string, string>): PromptRejectorClient {
    const envPath = values["--env"] ? resolve(values["--env"]) : resolve(root, ".env");
    try {
        // Loading is confined to the CLI. SDK imports never load files or change process.env.
        const content = readFileSync(envPath);
        for (const [name, value] of Object.entries(dotenv.parse(content))) {
            if (process.env[name] === undefined) process.env[name] = value;
        }
    } catch (error) {
        if (values["--env"] || (error as NodeJS.ErrnoException).code !== "ENOENT") throw new PromptRejectorError("configuration_error");
    }
    const configPath = values["--config"] ? resolve(values["--config"])
        : resolve(root, process.env.AI_CONFIG_PATH || "config/ai.active.json");
    return createPromptRejector({ configPath });
}

export function errorExitCode(error: unknown): number {
    if (!(error instanceof PromptRejectorError)) return 3;
    if (error.code === "timeout") return 124;
    if (error.code === "cancelled") return 130;
    return ["invalid_input", "input_too_large", "invalid_json", "unknown_command"].includes(error.code) ? 2 : 3;
}

export interface CliIO {
    stdout(text: string): Promise<void>;
    stderr(text: string): Promise<void>;
    signal?: AbortSignal;
    /** The executable installs a hard deadline to also stop non-cooperative feed work. */
    setDeadline?(milliseconds: number): void;
}

export async function runCli(args: string[], io: CliIO): Promise<number> {
    try {
        const parsed = parseArguments(args);
        const { values } = parsed;
        if (parsed.version) { await io.stdout(version + "\n"); return 0; }
        if (parsed.help || !parsed.command) {
            await io.stdout(parsed.command && !["batch", "commands"].includes(parsed.command) ? JSON.stringify(z.toJSONSchema(operationSchemas[normalizeCommand(parsed.command)]), null, 2) + "\n" : HELP);
            return 0;
        }
        if (parsed.command === "commands") {
            await io.stdout(JSON.stringify(commandNames.map(command => ({ command, inputSchema: z.toJSONSchema(operationSchemas[command]) })), null, parsed.pretty ? 2 : undefined) + "\n");
            return 0;
        }
        if (values["--timeout-ms"]) io.setDeadline?.(Number(values["--timeout-ms"]));
        let client: PromptRejectorClient | undefined;
        const execute = async (command: Command, input: unknown) => {
            const valid = validateInput(command, input);
            client ??= prepareClient(values);
            return client.run(command, valid, { signal: io.signal });
        };
        if (parsed.command === "batch") {
            if (parsed.pretty || "--text" in values || "--input" in values || ((!values["--file"] || values["--file"] === "-") && process.stdin.isTTY)) throw new PromptRejectorError("invalid_input");
            let aggregate = 0;
            let line = 0;
            let count = 0;
            for await (const text of readLines(inputStream(values["--file"]))) {
                line++;
                if (!text.trim()) continue;
                count++;
                let id: string | number | null | undefined;
                try {
                    const request = batchSchema.safeParse(parseJson(text));
                    if (!request.success) throw new PromptRejectorError("invalid_input");
                    id = request.data.id;
                    const command = normalizeCommand(request.data.command);
                    const result = await execute(command, request.data.input === undefined ? {} : request.data.input);
                    const exitCode = resultExitCode(command, result);
                    aggregate = Math.max(aggregate, exitCode);
                    await io.stdout(JSON.stringify({ line, id, command, result, exitCode }) + "\n");
                } catch (error) {
                    const exitCode = errorExitCode(error);
                    aggregate = Math.max(aggregate, exitCode);
                    await io.stdout(JSON.stringify({ line, id, error: error instanceof PromptRejectorError ? error.code : "internal_error", exitCode }) + "\n");
                }
            }
            if (!count) throw new PromptRejectorError("invalid_input");
            return aggregate;
        }
        const command = normalizeCommand(parsed.command);
        let input: unknown = {};
        if ("--input" in values) input = parseJson(values["--input"]);
        else if ("--text" in values) {
            if (!textFields[command]) throw new PromptRejectorError("invalid_input");
            if (Buffer.byteLength(values["--text"]) > MAX_INPUT_BYTES) throw new PromptRejectorError("input_too_large");
            input = { [textFields[command]!]: values["--text"] };
        } else if ("--file" in values || requiredInput.has(command)) {
            if ((!values["--file"] || values["--file"] === "-") && process.stdin.isTTY) throw new PromptRejectorError("invalid_input");
            const text = await readInput(inputStream(values["--file"]));
            input = textFields[command] ? { [textFields[command]!]: text } : parseJson(text);
        }
        const result = await execute(command, input);
        await io.stdout(JSON.stringify(result, null, parsed.pretty ? 2 : undefined) + "\n");
        return resultExitCode(command, result);
    } catch (error) {
        await io.stderr(JSON.stringify({ error: error instanceof PromptRejectorError ? error.code : "internal_error" }) + "\n");
        return errorExitCode(error);
    }
}
