import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ProviderRegistry } from "../../ai/registry.js";
import { loadAIConfig, parseAIConfig } from "../../ai/config.js";
import { SemanticAnalysisService } from "../../services/SemanticAnalysisService.js";
import type { ReasoningProviderId } from "../../ai/contracts.js";

export async function verifyStructuredProvider(provider: "anthropic" | "openai") {
    const fixtures = JSON.parse(readFileSync(`src/test/fixtures/ai/providers/${provider}.json`, "utf8"));
    const base = loadAIConfig({}).config;
    const snapshot = parseAIConfig({ ...base, profiles: { ...base.profiles, selected: { provider, model: fixtures.model, maxOutputTokens: 2048, options: provider === "openai" ? { reasoning: { effort: "low" } } : {} } }, roles: { ...base.roles, semantic: { primary: "selected" } } });
    let sent: any;
    let headers: any;
    let calls = 0;
    let body = fixtures.success;
    const registry = new ProviderRegistry(snapshot, { env: { ANTHROPIC_API_KEY: "synthetic-anthropic", OPENAI_API_KEY: "synthetic-openai" }, fetch: async (_url, init) => {
        calls++; sent = JSON.parse(String(init?.body)); headers = init?.headers;
        return new Response(JSON.stringify(body));
    } });
    const service = new SemanticAnalysisService(snapshot, registry);
    const context = service.createContext("prompt");
    const result = await service.analyze("UNTRUSTED_MARKER", "prompt", context);
    assert.equal(result.status, "ok", `${provider} native structured response must be supported`);
    assert.equal(result.meta.provider, provider);
    assert.equal(result.meta.resolvedModel, fixtures.model);
    assert.equal(result.meta.usage.inputTokens, 100);
    assert.equal(result.meta.usage.outputTokens, 20);
    assert.equal(result.meta.usage.cachedReadTokens, 30);
    assert.equal(result.meta.attempts, 1);
    assert.ok(!JSON.stringify(provider === "anthropic" ? sent.system : sent.instructions).includes("UNTRUSTED_MARKER"));
    if (provider === "anthropic") {
        assert.ok(sent.messages[0].content.includes("UNTRUSTED_MARKER"));
        assert.equal(sent.output_config.format.type, "json_schema");
        assert.equal(sent.output_config.format.schema.additionalProperties, false);
        assert.equal(headers["anthropic-version"], "2023-06-01");
        assert.equal(headers["x-api-key"], "synthetic-anthropic");
        assert.equal(result.meta.usage.cacheWriteTokens, 10);
        assert.equal(result.meta.usage.cachedReadIsInputSubset, false);
        assert.equal(result.meta.usage.cacheWriteIsInputSubset, false);
    } else {
        assert.ok(JSON.stringify(sent.input).includes("UNTRUSTED_MARKER"));
        assert.equal(sent.store, false);
        assert.equal(sent.text.format.type, "json_schema");
        assert.equal(sent.text.format.strict, true);
        assert.equal(sent.temperature, undefined);
        assert.deepEqual(sent.reasoning, { effort: "low" });
        assert.equal(result.meta.usage.cacheWriteTokens, 10);
        assert.equal(result.meta.usage.cacheWriteIsInputSubset, true);
        assert.equal(result.meta.usage.reasoningTokens, 5);
        assert.equal(result.meta.usage.reasoningIsOutputSubset, true);
    }
    for (const [name, code] of [["refusal", "refusal"], ["truncated", "incomplete"], ["empty", "invalid_response"], ["invalid", "invalid_response"]]) {
        body = fixtures[name];
        const before = calls;
        const answer = await service.analyze("synthetic fixture");
        assert.equal(answer.status === "unavailable" && answer.code, code, name);
        assert.equal(calls - before, 1, `${name} must not trigger a transport retry`);
    }
    body = { ...fixtures.success, usage: undefined, model: undefined };
    const unknownUsage = await service.analyze("synthetic fixture");
    assert.equal(unknownUsage.meta.usage.inputTokens, null);
    assert.equal(unknownUsage.meta.resolvedModel, null);
    assert.equal(new SemanticAnalysisService(snapshot, new ProviderRegistry(snapshot, { env: {} })).supportsV1, false);
    const before = calls;
    const profile = snapshot.config.profiles.selected;
    const unsupported = await registry.generate({ profile: { ...profile, options: { temperature: 0 } }, maxOutputTokens: 1024,
        systemInstruction: "trusted", state: "synthetic", schemaId: "unsupported", schemaVersion: "1", rubricVersion: "1",
        jsonSchema: { type: "object", properties: {}, required: [], additionalProperties: false }, parse: (value) => value,
    }, service.createContext("prompt"));
    assert.equal(unsupported.status === "unavailable" && unsupported.code, "unsupported");
    assert.equal(calls, before, "unsupported model options fail before HTTP");
    const unsupportedSchema = await registry.generate({ profile, maxOutputTokens: 1024,
        systemInstruction: "trusted", state: "synthetic", schemaId: "unsupported", schemaVersion: "1", rubricVersion: "1",
        jsonSchema: { type: "object", properties: {}, required: [], additionalProperties: false, not: { type: "null" } }, parse: (value) => value,
    }, service.createContext("prompt"));
    assert.equal(unsupportedSchema.status === "unavailable" && unsupportedSchema.code, "unsupported");
    assert.equal(calls, before, "unsupported schema fails before HTTP");
    const invalidFormat = await registry.generate({ profile, maxOutputTokens: 1024,
        systemInstruction: "trusted", state: "synthetic", schemaId: "unsupported", schemaVersion: "1", rubricVersion: "1",
        jsonSchema: { type: "object", properties: { value: { type: "string", format: "invented-format" } }, required: ["value"], additionalProperties: false }, parse: (value) => value,
    }, service.createContext("prompt"));
    assert.equal(invalidFormat.status === "unavailable" && invalidFormat.code, "unsupported");
    assert.equal(calls, before, "unsupported format fails before HTTP");
    assert.ok(["anthropic", "openai"].includes(provider satisfies ReasoningProviderId));
}
