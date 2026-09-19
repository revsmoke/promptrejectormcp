import { randomUUID } from "node:crypto";
import type { CallContext, CallResult, ReasoningProviderId, StructuredReasoner, StructuredRequest } from "./contracts.js";
import type { ConfigSnapshot } from "./config.js";
import { keyNames } from "./config.js";
import { profileHash } from "./modelProfiles.js";
import { GeminiAdapter } from "./providers/GeminiAdapter.js";
import { NativeTransport, type FetchLike } from "./transport.js";
import { emptyUsage } from "./usage.js";

export class ProviderRegistry {
    private reasoners = new Map<ReasoningProviderId, StructuredReasoner>();
    constructor(snapshot: ConfigSnapshot, options: { env?: NodeJS.ProcessEnv; fetch?: FetchLike } = {}) {
        const env = options.env ?? process.env;
        const transport = new NativeTransport({ fetch: options.fetch, maxConcurrent: snapshot.config.limits.maxConcurrentReasoning, maxQueue: snapshot.config.limits.maxQueue });
        this.reasoners.set("gemini", new GeminiAdapter({ apiKey: env[keyNames.gemini], transport, timeoutMs: snapshot.config.limits.reasoningTimeoutMs }));
    }
    register(provider: ReasoningProviderId, reasoner: StructuredReasoner): void { this.reasoners.set(provider, reasoner); }
    async generate<T>(request: StructuredRequest<T>, call: CallContext): Promise<CallResult<T>> {
        const reasoner = this.reasoners.get(request.profile.provider);
        if (reasoner) return reasoner.generate(request, call);
        return { status: "unavailable", code: "unsupported", meta: { callId: randomUUID(), provider: request.profile.provider,
            requestedModel: request.profile.model, resolvedModel: null, profileHash: profileHash(request.profile),
            rubricVersion: request.rubricVersion, schemaVersion: request.schemaVersion, elapsedMs: 0, attempts: 0,
            usage: emptyUsage(), failureCode: "unsupported" } };
    }
}
