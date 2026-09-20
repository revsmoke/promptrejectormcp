import { readFileSync } from "node:fs";
import { z } from "zod";
import type { TokenPrices } from "./usage.js";
const rate = z.number().finite().nonnegative();
export const priceCardSchema = z.strictObject({
    schemaVersion: z.literal(1), version: z.string().min(1), asOf: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    notes: z.array(z.string()), sources: z.array(z.string().url()),
    rates: z.record(z.string().regex(/^(anthropic|openai|gemini|typesafe):[a-zA-Z0-9._-]+$/), z.strictObject({
        inputPerMillion: rate, outputPerMillion: rate, cachedReadPerMillion: rate.optional(), cacheWritePerMillion: rate.optional(),
    })),
});
export type PriceCard = z.infer<typeof priceCardSchema>;
export function loadPriceCard(path: string): PriceCard { return priceCardSchema.parse(JSON.parse(readFileSync(path, "utf8"))); }
export function tokenPrices(card: PriceCard | undefined, provider: string, model: string): TokenPrices | undefined {
    const rate = card?.rates[`${provider}:${model}`];
    return rate && card ? { ...rate, version: card.version } : undefined;
}
