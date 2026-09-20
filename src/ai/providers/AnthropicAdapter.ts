import type { CallContext, CallResult, StructuredReasoner, StructuredRequest } from "../contracts.js";
import { emptyUsage, tokenCount } from "../usage.js";
import { anthropicJsonSchema, object, structuredHttp, type StructuredHttpOptions } from "./structuredHttp.js";

export class AnthropicAdapter implements StructuredReasoner {
    constructor(private readonly options: StructuredHttpOptions = {}) {}
    generate<T>(request: StructuredRequest<T>, call: CallContext): Promise<CallResult<T>> {
        return structuredHttp("anthropic", request, call, this.options, () => ({
            url: "https://api.anthropic.com/v1/messages",
            headers: { "x-api-key": this.options.apiKey!, "anthropic-version": "2023-06-01" },
            body: { model: request.profile.model, system: request.systemInstruction,
                messages: [{ role: "user", content: request.state }], max_tokens: request.maxOutputTokens,
                ...request.profile.options,
                output_config: { ...(object(request.profile.options?.output_config) ?? {}), format: { type: "json_schema", schema: anthropicJsonSchema(request.jsonSchema) } } },
        }), (response) => {
            const native = object(response.usage);
            const usage = { ...emptyUsage(), inputTokens: tokenCount(native?.input_tokens), outputTokens: tokenCount(native?.output_tokens),
                cachedReadTokens: tokenCount(native?.cache_read_input_tokens), cacheWriteTokens: tokenCount(native?.cache_creation_input_tokens),
                cachedReadIsInputSubset: false, cacheWriteIsInputSubset: false };
            const base = { usage, model: typeof response.model === "string" && response.model ? response.model : null };
            if (response.stop_reason === "refusal") return { ...base, code: "refusal" };
            if (response.stop_reason === "max_tokens") return { ...base, code: "incomplete" };
            if (response.stop_reason !== "end_turn" || !Array.isArray(response.content)) return { ...base, code: "invalid_response" };
            const text: string[] = [];
            for (const raw of response.content) {
                const block = object(raw);
                if (!block) return { ...base, code: "invalid_response" };
                if (block.type === "refusal") return { ...base, code: "refusal" };
                if (["thinking", "redacted_thinking"].includes(String(block.type))) continue;
                if (block.type !== "text" || typeof block.text !== "string") return { ...base, code: "invalid_response" };
                text.push(block.text);
            }
            return { ...base, text: text.join("") };
        });
    }
}
