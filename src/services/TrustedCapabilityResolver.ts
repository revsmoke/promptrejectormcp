export type CapabilityBucket = "privateDataRead" | "untrustedContentFetch" | "externalEgress";
export interface CapabilityBinding { agentId: string; scope: string; configurationVersion: string }
export interface RuntimeCapabilityRecord { binding: CapabilityBinding; bucket: CapabilityBucket; state: "present" | "absent"; evidenceId: string; description: string }
export interface VerifiedCapabilityFact extends RuntimeCapabilityRecord { provenance: "verified_runtime" }
declare const trustedContext: unique symbol;
export type TrustedCapabilityContext = { readonly [trustedContext]: true };

const bindingSchema = z.strictObject({ agentId: z.string().min(1).max(128), scope: z.string().min(1).max(256), configurationVersion: z.string().min(1).max(128) });
const recordSchema = z.strictObject({ binding: bindingSchema, bucket: z.enum(["privateDataRead", "untrustedContentFetch", "externalEgress"]), state: z.enum(["present", "absent"]), evidenceId: z.string().min(1).max(128), description: z.string().min(1).max(2000) });
/** Created by trusted application configuration only, never from a scan body.
 * Context handles are in-memory identities: strings, JSON and another graph's
 * handles cannot attest to host permissions. No public attestation endpoint. */
export class TrustedCapabilityResolver {
    private readonly contexts = new WeakMap<object, string>();
    private readonly records = new Map<string, readonly VerifiedCapabilityFact[]>();
    constructor(private readonly configurationVersion: string, records: readonly RuntimeCapabilityRecord[] = []) {
        if (!configurationVersion) throw new Error("Missing configuration version");
        for (const input of records) {
            const record = recordSchema.parse(input);
            if (record.binding.configurationVersion !== configurationVersion) throw new Error("Runtime capability configuration version mismatch");
            const key = hashConfiguration(record.binding);
            const prior = this.records.get(key) ?? [];
            if (prior.some((fact) => fact.bucket === record.bucket)) throw new Error("Duplicate runtime capability bucket");
            const fact: VerifiedCapabilityFact = Object.freeze({ ...record, binding: Object.freeze({ ...record.binding }), provenance: "verified_runtime" });
            this.records.set(key, Object.freeze([...prior, fact]));
        }
    }
    contextFor(binding: CapabilityBinding): TrustedCapabilityContext {
        const parsed = bindingSchema.parse(binding);
        if (parsed.configurationVersion !== this.configurationVersion) throw new Error("Runtime capability configuration version mismatch");
        const context = Object.freeze({}) as TrustedCapabilityContext;
        this.contexts.set(context, hashConfiguration(parsed));
        return context;
    }
    resolve(context?: unknown): readonly VerifiedCapabilityFact[] {
        if (context === null || typeof context !== "object") return Object.freeze([]);
        const key = this.contexts.get(context);
        return key ? this.records.get(key) ?? Object.freeze([]) : Object.freeze([]);
    }
}
import { z } from "zod";
import { hashConfiguration } from "../ai/modelProfiles.js";
