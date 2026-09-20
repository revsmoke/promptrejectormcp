import { tokenPrices, type PriceCard } from "./pricing.js";
import { randomUUID } from "node:crypto";
import type { CallContext, CallResult, ReasoningProviderId, StructuredReasoner, StructuredRequest } from "./contracts.js";
import type { ConfigSnapshot } from "./config.js";
import { keyNames } from "./config.js";
import { profileHash } from "./modelProfiles.js";
import { AnthropicAdapter } from "./providers/AnthropicAdapter.js";
import { OpenAIAdapter } from "./providers/OpenAIAdapter.js";
import { GeminiAdapter } from "./providers/GeminiAdapter.js";
import { NativeTransport, type FetchLike } from "./transport.js";
import { emptyUsage } from "./usage.js";

export class ProviderRegistry {
    private reasoners = new Map<ReasoningProviderId, StructuredReasoner>();
    private readonly transport: NativeTransport;
    private readonly env: NodeJS.ProcessEnv;
    private readonly pricing?: PriceCard;
    constructor(private readonly snapshot: ConfigSnapshot, options: { env?: NodeJS.ProcessEnv; fetch?: FetchLike; pricing?: PriceCard } = {}) {
        this.env = options.env ?? process.env;
        this.pricing = options.pricing ?? snapshot.pricing;
        this.transport = new NativeTransport({ fetch: options.fetch, maxConcurrent: snapshot.config.limits.maxConcurrentReasoning, maxQueue: snapshot.config.limits.maxQueue });
    }
    register(provider: ReasoningProviderId, reasoner: StructuredReasoner): void { this.reasoners.set(provider, reasoner); }
    async generate<T>(request: StructuredRequest<T>, call: CallContext): Promise<CallResult<T>> {
        const options = { apiKey: this.env[keyNames[request.profile.provider]], transport: this.transport,
            timeoutMs: this.snapshot.config.limits.reasoningTimeoutMs, capabilities: this.snapshot.capabilities,
            prices: tokenPrices(this.pricing, request.profile.provider, request.profile.model) };
        const reasoner = this.reasoners.get(request.profile.provider) ?? ({
            anthropic: () => new AnthropicAdapter(options), openai: () => new OpenAIAdapter(options), gemini: () => new GeminiAdapter(options),
        }[request.profile.provider])?.();
        if (reasoner) return reasoner.generate(request, call);
        return { status: "unavailable", code: "unsupported", meta: { callId: randomUUID(), provider: request.profile.provider,
            requestedModel: request.profile.model, resolvedModel: null, profileHash: profileHash(request.profile),
            rubricVersion: request.rubricVersion, schemaVersion: request.schemaVersion, elapsedMs: 0, attempts: 0,
            usage: emptyUsage(), failureCode: "unsupported" } };
    }
}
