import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { createServices, type Services } from "../bootstrap.js";
import { loadAIConfig } from "../ai/config.js";
import { operationHandlers, normalizeCommand, validateInput, type Command, type CommandInput, type CommandResult } from "./operations.js";
import { PromptRejectorError } from "./errors.js";

export { commandNames, normalizeCommand, resultExitCode } from "./operations.js";
export type { Command, CommandInput, CommandResult } from "./operations.js";
export { PromptRejectorError } from "./errors.js";
export type { ErrorCode } from "./errors.js";

export interface ClientOptions {
    /** Explicit path resolves from the caller's cwd; default is the installed active config. */
    configPath?: string;
    /** Advanced embedding/testing: reuse an existing service graph. */
    services?: Services;
}
export interface RunOptions { signal?: AbortSignal }

/** No server, dotenv, cwd change, or inference on import. Reuse a client to retain judgment caches. */
export function createPromptRejector(options: ClientOptions = {}) {
    let services: Services;
    try {
        const configPath = options.configPath ? resolve(options.configPath)
            : process.env.AI_CONFIG_PATH ? resolve(process.env.AI_CONFIG_PATH)
            : fileURLToPath(new URL("../../config/ai.active.json", import.meta.url));
        services = options.services ?? createServices(loadAIConfig({ ...process.env, AI_CONFIG_PATH: configPath }));
    } catch { throw new PromptRejectorError("configuration_error"); }
    const handlers = operationHandlers(services);
    return {
        async run<C extends Command>(command: C, input: CommandInput<C>, options: RunOptions = {}): Promise<CommandResult<C>> {
            const name = normalizeCommand(command);
            const parsed = validateInput(name, input);
            if (options.signal?.aborted) throw new PromptRejectorError("cancelled");
            try {
                // TypeScript cannot correlate indexed function unions; validation above preserves the mapping.
                const handler = handlers[name] as (input: CommandInput<Command>, signal?: AbortSignal) => unknown;
                const result = await handler(parsed, options.signal);
                if (options.signal?.aborted) throw new PromptRejectorError("cancelled");
                return result as CommandResult<C>;
            } catch (error) {
                if (error instanceof PromptRejectorError) throw error;
                throw new PromptRejectorError(options.signal?.aborted ? "cancelled" : "internal_error");
            }
        },
    };
}
export type PromptRejectorClient = ReturnType<typeof createPromptRejector>;
