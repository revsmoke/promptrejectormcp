import type { CallContext, CallResult, StructuredReasoner, StructuredRequest } from "../contracts.js";
import { emptyUsage, tokenCount } from "../usage.js";
import { object, structuredHttp, type StructuredHttpOptions } from "./structuredHttp.js";

export class OpenAIAdapter implements StructuredReasoner {
    constructor(private readonly options: StructuredHttpOptions = {}) {}
    generate<T>(request: StructuredRequest<T>, call: CallContext): Promise<CallResult<T>> {
        return structuredHttp("openai", request, call, this.options, () => ({
            url: "https://api.openai.com/v1/responses",
            headers: { Authorization: `Bearer ${this.options.apiKey}` },
            body: { model: request.profile.model, instructions: request.systemInstruction,
                input: [{ role: "user", content: [{ type: "input_text", text: request.state }] }], store: false,
                max_output_tokens: request.maxOutputTokens, ...request.profile.options,
                text: { format: { type: "json_schema", name: request.schemaId, strict: true, schema: openaiJsonSchema(request.jsonSchema) } } },
        }), (response) => {
            const native = object(response.usage);
            const usage = { ...emptyUsage(), inputTokens: tokenCount(native?.input_tokens), outputTokens: tokenCount(native?.output_tokens),
                cachedReadTokens: tokenCount(object(native?.input_tokens_details)?.cached_tokens),
                cacheWriteTokens: tokenCount(object(native?.input_tokens_details)?.cache_write_tokens),
                reasoningTokens: tokenCount(object(native?.output_tokens_details)?.reasoning_tokens) };
            const base = { usage, model: typeof response.model === "string" && response.model ? response.model : null };
            if (response.status === "incomplete") return { ...base, code: "incomplete" };
            if (response.status !== "completed" || response.error || !Array.isArray(response.output)) return { ...base, code: "invalid_response" };
            const text: string[] = [];
            for (const raw of response.output) {
                const item = object(raw);
                if (!item) return { ...base, code: "invalid_response" };
                if (item.type === "reasoning") continue; // Private content is never emitted.
                if (item.type !== "message" || item.role !== "assistant" || item.status !== "completed" || !Array.isArray(item.content)) return { ...base, code: "invalid_response" };
                for (const rawBlock of item.content) {
                    const block = object(rawBlock);
                    if (block?.type === "refusal") return { ...base, code: "refusal" };
                    if (block?.type !== "output_text" || typeof block.text !== "string") return { ...base, code: "invalid_response" };
                    text.push(block.text);
                }
            }
            return { ...base, text: text.join("") };
        });
    }
}
/** Fail preflight for unsupported grammar instead of silently dropping rules. */
export function openaiJsonSchema(schema: Record<string, unknown>): Record<string, unknown> {
    const allowed = new Set(["type", "description", "title", "enum", "const", "properties", "additionalProperties", "required", "items", "anyOf", "$defs", "definitions", "$ref", "pattern", "minimum", "maximum", "multipleOf", "minItems", "maxItems", "minLength", "maxLength"]);
    const visit = (node: unknown): void => {
        if (typeof node === "boolean") return;
        const value = object(node);
        if (!value || Object.keys(value).some((key) => !allowed.has(key))) throw new Error("Unsupported schema");
        if (value.type === "object") {
            const keys = Object.keys(object(value.properties) ?? {});
            if (value.additionalProperties !== false || !Array.isArray(value.required) || keys.some((key) => !(value.required as unknown[]).includes(key))) throw new Error("OpenAI requires every object field and closed objects");
        }
        for (const [key, child] of Object.entries(value)) {
            if (["properties", "$defs", "definitions"].includes(key)) Object.values(object(child) ?? {}).forEach(visit);
            else if (["items", "additionalProperties"].includes(key)) visit(child);
            else if (key === "anyOf" && Array.isArray(child)) child.forEach(visit);
        }
    };
    visit(schema);
    return schema;
}
