import type { Usage } from "./contracts.js";

export interface TokenPrices {
    version: string;
    inputPerMillion: number;
    outputPerMillion: number;
    cachedReadPerMillion?: number;
    cacheWritePerMillion?: number;
}
export function emptyUsage(): Usage {
    return { inputTokens: null, outputTokens: null, cachedReadTokens: null, cacheWriteTokens: null,
        reasoningTokens: null, reasoningIsOutputSubset: true, cachedReadIsInputSubset: true, cacheWriteIsInputSubset: true };
}
export function tokenCount(value: unknown): number | null {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
/** Price a single native usage record, before combining different providers. */
export function estimateCost(usage: Usage, prices?: TokenPrices): number | null {
    if (!prices || usage.inputTokens === null || usage.outputTokens === null) return null;
    if (Object.values(prices).some((value) => typeof value === "number" && (!Number.isFinite(value) || value < 0))) return null;
    let input = usage.inputTokens;
    let extra = 0;
    for (const [count, subset, rate] of [
        [usage.cachedReadTokens, usage.cachedReadIsInputSubset, prices.cachedReadPerMillion],
        [usage.cacheWriteTokens, usage.cacheWriteIsInputSubset, prices.cacheWritePerMillion],
    ] as const) {
        if (count === null) {
            if (!subset || (rate !== undefined && rate !== prices.inputPerMillion)) return null;
        } else if (count > 0) {
            if (rate === undefined) return null;
            if (subset) input -= count;
            extra += count * rate;
        }
    }
    if (input < 0 || (!usage.reasoningIsOutputSubset && usage.reasoningTokens === null)) return null;
    const output = usage.outputTokens + (usage.reasoningIsOutputSubset ? 0 : usage.reasoningTokens!);
    return (input * prices.inputPerMillion + output * prices.outputPerMillion + extra) / 1_000_000;
}
export function reserveCost(inputUpperBound: number, outputUpperBound: number, prices?: TokenPrices): number | null {
    if (!prices || !Number.isSafeInteger(inputUpperBound) || inputUpperBound < 0 || !Number.isSafeInteger(outputUpperBound) || outputUpperBound < 0) return null;
    const inputRate = Math.max(prices.inputPerMillion, prices.cachedReadPerMillion ?? 0, prices.cacheWritePerMillion ?? 0);
    if (![inputRate, prices.outputPerMillion].every((value) => Number.isFinite(value) && value >= 0)) return null;
    return (inputUpperBound * inputRate + outputUpperBound * prices.outputPerMillion) / 1_000_000;
}
export class UsageLedger {
    private calls = new Map<string, { usage: Usage; estimatedUsd: number | null; pricingVersion: string | null }>();
    record(callId: string, usage: Usage, prices?: TokenPrices): void {
        if (!this.calls.has(callId)) this.calls.set(callId, { usage: { ...usage }, estimatedUsd: estimateCost(usage, prices), pricingVersion: prices?.version ?? null });
    }
    summary(): { calls: number; usage: Usage; estimatedUsd: number | null; pricingVersions: string[] } {
        const values = [...this.calls.values()];
        const usage = emptyUsage();
        for (const key of ["inputTokens", "outputTokens", "cachedReadTokens", "cacheWriteTokens", "reasoningTokens"] as const) {
            usage[key] = values.length && values.every((item) => item.usage[key] !== null) ? values.reduce((sum, item) => sum + item.usage[key]!, 0) : null;
        }
        for (const key of ["reasoningIsOutputSubset", "cachedReadIsInputSubset", "cacheWriteIsInputSubset"] as const) usage[key] = values.every((item) => item.usage[key]);
        return { calls: values.length, usage,
            estimatedUsd: values.length && values.every((item) => item.estimatedUsd !== null) ? values.reduce((sum, item) => sum + item.estimatedUsd!, 0) : null,
            pricingVersions: [...new Set(values.flatMap((item) => item.pricingVersion ? [item.pricingVersion] : []))],
        };
    }
}
