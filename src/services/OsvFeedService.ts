// OsvFeedService — pulls advisories from OSV.dev /v1/querybatch.
// No auth required. Used to surface AI-package vulnerabilities (langchain,
// transformers, vllm, etc.) that wouldn't normally show up in our CWE-filtered
// NVD/GHSA scan.

import type { EcosystemPackage } from "./aiPackageAllowlist.js";

export interface OsvVuln {
    id: string; // OSV ID — e.g. "GHSA-xxxx-xxxx-xxxx", "PYSEC-2024-..."
    summary?: string;
    details?: string;
    aliases?: string[]; // CVE IDs etc.
    modified?: string;
    published?: string;
    affected: Array<{
        package: { ecosystem: string; name: string };
        ranges?: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string }> }>;
        versions?: string[];
    }>;
    references?: Array<{ type: string; url: string }>;
    severity?: Array<{ type: string; score: string }>;
}

// Back-compat alias for callers still using the v1.1 skeleton shape.
export type OsvPackageQuery = EcosystemPackage;

interface OsvQueryBatchResponse {
    // Each result corresponds positionally to the input queries.
    // Tests / fixtures may inline full vuln objects; live OSV returns ID+modified only.
    results: Array<{
        vulns?: OsvVuln[];
    }>;
}

const OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns";
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Queries OSV.dev's `/v1/querybatch` for vulnerabilities affecting an
 * AI-package allowlist (langchain, transformers, vllm, etc.).
 *
 * Surfaces AI-ecosystem advisories that would not otherwise appear in the
 * CWE-filtered NVD/GHSA pipeline. Caller supplies the package list (typically
 * `AI_PACKAGE_ALLOWLIST` from `aiPackageAllowlist.ts`); empty input
 * short-circuits without a network call.
 *
 * @remarks
 * Key methods:
 * - `query(packages)` — batched POST followed by per-id hydration (live OSV returns id+modified stubs; full detail comes from `GET /v1/vulns/{id}`). Results are deduped by id.
 *
 * Environment variables consumed: none.
 *
 * Network behavior:
 * - Endpoint: `https://api.osv.dev/v1/querybatch` (POST) and `https://api.osv.dev/v1/vulns/{id}` (GET hydration).
 * - Timeout: 30s per request via `AbortController`.
 * - Cache: none — caller (VulnFeedService) handles staging/dedup.
 *
 * @example
 * ```ts
 * const svc = new OsvFeedService();
 * const vulns = await svc.query(AI_PACKAGE_ALLOWLIST);
 * ```
 */
export class OsvFeedService {
    /**
     * Query OSV for vulnerabilities affecting any of the given packages.
     * Calls POST /v1/querybatch with one query per package. If a vuln entry
     * lacks full detail (only id+modified, the live API shape), we fall back
     * to GET /v1/vulns/{id} to hydrate it. Results are deduped by id.
     *
     * @param packages - AI-ecosystem packages to query. Empty array short-circuits to `[]`.
     * @returns Deduped vulnerability records. Stubs with no `affected` get an empty array.
     */
    async query(packages: EcosystemPackage[]): Promise<OsvVuln[]> {
        // Short-circuit — no fetch needed, preserves Pass 0 skeleton test contract.
        if (packages.length === 0) return [];

        const body = {
            queries: packages.map((p) => ({
                package: { ecosystem: p.ecosystem, name: p.name },
            })),
        };

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

        let batchData: OsvQueryBatchResponse;
        try {
            const resp = await fetch(OSV_QUERYBATCH_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
                signal: controller.signal,
            });

            if (!resp.ok) {
                const txt = await resp.text().catch(() => "");
                throw new Error(`OSV query failed: ${resp.status} ${txt.slice(0, 200)}`);
            }

            batchData = (await resp.json()) as OsvQueryBatchResponse;
        } finally {
            clearTimeout(timeout);
        }

        // Flatten + dedup by id. If a vuln lacks `affected` (live API returns
        // only id+modified), hydrate via per-ID GET.
        const byId = new Map<string, OsvVuln>();
        for (const r of batchData.results || []) {
            for (const v of r.vulns || []) {
                if (!v.id || byId.has(v.id)) continue;
                if (!v.affected) {
                    // Live API: hydrate from /v1/vulns/{id}
                    try {
                        const full = await this.fetchVuln(v.id);
                        if (full) {
                            byId.set(v.id, full);
                            continue;
                        }
                    } catch {
                        // fall through and store the stub
                    }
                    byId.set(v.id, { ...v, affected: [] });
                } else {
                    byId.set(v.id, v);
                }
            }
        }
        return Array.from(byId.values());
    }

    private async fetchVuln(id: string): Promise<OsvVuln | null> {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
        try {
            const resp = await fetch(`${OSV_VULN_URL}/${encodeURIComponent(id)}`, {
                signal: controller.signal,
            });
            if (!resp.ok) return null;
            return (await resp.json()) as OsvVuln;
        } finally {
            clearTimeout(timeout);
        }
    }
}
