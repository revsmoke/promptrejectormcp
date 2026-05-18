// GhsaGraphQLService — queries GitHub's GraphQL `securityVulnerabilities`
// endpoint, post-filtered to the AI-package allowlist. Degrades gracefully
// (returns []) when GITHUB_TOKEN is not set so tests/offline runs don't fail.

import { isAllowedGhsaPackage } from "./aiPackageAllowlist.js";

export type GhsaSeverity = "LOW" | "MODERATE" | "HIGH" | "CRITICAL";

export interface GhsaAdvisory {
    ghsaId: string;
    summary: string;
    description: string;
    severity: GhsaSeverity;
    cweIds: string[];
    cveId?: string;
    publishedAt: string;
    updatedAt: string;
    vulnerablePackage?: { ecosystem: string; name: string };
}

const GITHUB_GRAPHQL_URL = "https://api.github.com/graphql";
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
const DEFAULT_TIMEOUT_MS = 30_000;

const QUERY = `query($ecosystem: SecurityAdvisoryEcosystem!, $first: Int!) {
    securityVulnerabilities(ecosystem: $ecosystem, first: $first, orderBy: {field: UPDATED_AT, direction: DESC}) {
        nodes {
            advisory {
                ghsaId
                summary
                description
                severity
                cwes(first: 5) { nodes { cweId } }
                identifiers { type value }
                publishedAt
                updatedAt
            }
            package { ecosystem name }
        }
    }
}`;

interface GraphQLResponse {
    data?: {
        securityVulnerabilities?: {
            nodes: Array<{
                advisory: {
                    ghsaId: string;
                    summary: string;
                    description: string;
                    severity: GhsaSeverity;
                    cwes?: { nodes?: Array<{ cweId: string }> };
                    identifiers?: Array<{ type: string; value: string }>;
                    publishedAt: string;
                    updatedAt: string;
                };
                package?: { ecosystem: string; name: string };
            }>;
        };
    };
    errors?: Array<{ message: string }>;
}

/**
 * Queries GitHub's GraphQL `securityVulnerabilities` API for recent advisories,
 * post-filtered to the AI-package allowlist.
 *
 * Pulled per ecosystem (npm/pip/etc.) and ordered by most-recently-updated.
 * Without `GITHUB_TOKEN`, returns `[]` and logs to stderr — never throws — so
 * tests and offline runs remain green.
 *
 * @remarks
 * Key methods:
 * - `query(ecosystem, limit?)` — single GraphQL POST, then in-memory filter via `isAllowedGhsaPackage`. Limit is clamped to `[1, 100]`.
 *
 * Environment variables consumed:
 * - `GITHUB_TOKEN` — required for non-empty results. Without it the method returns `[]` after logging a warning.
 *
 * Network behavior:
 * - Endpoint: `https://api.github.com/graphql` (POST).
 * - Timeout: 30s via `AbortController`.
 * - Cache: none — caller handles staging.
 *
 * @example
 * ```ts
 * const svc = new GhsaGraphQLService();
 * const advs = await svc.query("PIP", 50);
 * ```
 */
export class GhsaGraphQLService {
    /**
     * Fetch recent GHSA advisories for an ecosystem, then post-filter to the
     * AI-package allowlist (langchain, transformers, vllm, etc.).
     *
     * Without GITHUB_TOKEN: returns [] and logs to stderr. This intentionally
     * does NOT throw — tests and offline environments must still work.
     *
     * @param ecosystem - A GHSA ecosystem identifier (e.g. `"PIP"`, `"NPM"`, `"MAVEN"`).
     * @param limit - Number of advisories to request; clamped to `[1, 100]`. Defaults to 50.
     * @returns Allowlist-filtered advisories. Empty if `GITHUB_TOKEN` is missing.
     * @throws On HTTP failure or GraphQL `errors` payload.
     */
    async query(ecosystem: string, limit: number = DEFAULT_LIMIT): Promise<GhsaAdvisory[]> {
        const token = process.env.GITHUB_TOKEN;
        if (!token) {
            console.error("[GhsaGraphQLService] GITHUB_TOKEN not set — skipping GHSA GraphQL fetch");
            return [];
        }

        const first = Math.min(Math.max(1, limit), MAX_LIMIT);

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

        let body: GraphQLResponse;
        try {
            const resp = await fetch(GITHUB_GRAPHQL_URL, {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                    Accept: "application/vnd.github+json",
                },
                body: JSON.stringify({
                    query: QUERY,
                    variables: { ecosystem, first },
                }),
                signal: controller.signal,
            });

            if (!resp.ok) {
                const txt = await resp.text().catch(() => "");
                throw new Error(`GHSA GraphQL failed: ${resp.status} ${txt.slice(0, 200)}`);
            }

            body = (await resp.json()) as GraphQLResponse;
        } finally {
            clearTimeout(timeout);
        }

        if (body.errors && body.errors.length > 0) {
            throw new Error(`GHSA GraphQL errors: ${body.errors.map((e) => e.message).join("; ")}`);
        }

        const nodes = body.data?.securityVulnerabilities?.nodes || [];
        const out: GhsaAdvisory[] = [];

        for (const node of nodes) {
            const pkg = node.package;
            // Post-filter to AI allowlist. If the package shape is missing we
            // skip (we can't decide relevance without it).
            if (!pkg || !isAllowedGhsaPackage(pkg.ecosystem, pkg.name)) continue;

            const adv = node.advisory;
            const cveId = adv.identifiers?.find((i) => i.type === "CVE")?.value;
            const cweIds = (adv.cwes?.nodes || []).map((c) => c.cweId).filter(Boolean);

            out.push({
                ghsaId: adv.ghsaId,
                summary: adv.summary,
                description: adv.description,
                severity: adv.severity,
                cweIds,
                cveId,
                publishedAt: adv.publishedAt,
                updatedAt: adv.updatedAt,
                vulnerablePackage: { ecosystem: pkg.ecosystem, name: pkg.name },
            });
        }

        return out;
    }
}
