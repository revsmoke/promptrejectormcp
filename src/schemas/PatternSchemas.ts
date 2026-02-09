import { z } from "zod";

// Detection mode: simple (match = finding) or threshold (requires count/length checks)
export const SimpleDetectionSchema = z.object({
    mode: z.literal("simple"),
});

export const ThresholdDetectionSchema = z.object({
    mode: z.literal("threshold"),
    countThreshold: z.number().int().min(1).optional(),
    singleMatchLength: z.number().int().min(1).optional(),
});

export const DetectionSchema = z.discriminatedUnion("mode", [
    SimpleDetectionSchema,
    ThresholdDetectionSchema,
]);

export const PatternEntrySchema = z.object({
    id: z.string().regex(/^[a-z0-9-]+$/, "ID must be lowercase alphanumeric with hyphens"),
    name: z.string().min(1),
    description: z.string().optional(),
    pattern: z.string().min(1),
    flags: z.string().regex(/^[gimsuy]*$/, "Flags must be valid RegExp flags"),
    severity: z.enum(["low", "medium", "high", "critical"]),
    category: z.string().min(1),
    flagGroup: z.string().min(1),
    scope: z.enum(["general", "skill"]),
    detection: DetectionSchema,
    enabled: z.boolean(),
    source: z.enum(["original", "nvd", "github_advisory", "manual"]).optional(),
    cveRefs: z.array(z.string()).default([]),
    dateAdded: z.string(),
    /** Informational only — whitelisting is baked into regex negative lookaheads, not enforced at runtime */
    whitelistedDomains: z.array(z.string()).default([]),
});

export type PatternEntry = z.infer<typeof PatternEntrySchema>;

export const PatternFileSchema = z.object({
    version: z.literal(1),
    patterns: z.array(PatternEntrySchema),
});

export type PatternFile = z.infer<typeof PatternFileSchema>;

export const ManifestFileEntrySchema = z.object({
    sha256: z.string(),
    patternCount: z.number().int().min(0),
});

export const ManifestSchema = z.object({
    version: z.literal(1),
    generatedAt: z.string(),
    files: z.record(z.string(), ManifestFileEntrySchema),
    rootHash: z.string(),
    signature: z.string(),
});

export type ManifestFile = z.infer<typeof ManifestSchema>;

export interface IntegrityCheckResult {
    valid: boolean;
    errors: string[];
    checkedAt: string;
    fileResults: Record<string, { valid: boolean; error?: string }>;
    hmacValid: boolean | null; // null if HMAC not configured
}
