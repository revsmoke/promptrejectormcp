import { VulnFeedService, type StagedCandidate } from "./VulnFeedService.js";
import { AtlasService, type AtlasTechnique } from "./AtlasService.js";
import { KevFeedService, type KevEntry } from "./KevFeedService.js";

/**
 * Pass 9: Unified read-side view across all staged CVE-derived candidates.
 *
 * `update_vuln_feeds` (Pass 6/7) writes staged candidates from NVD + GHSA REST
 * + GHSA GraphQL + OSV into `patterns/staging/pending-review.json`. Each
 * candidate carries the source it came from plus optional KEV/ATLAS flags
 * applied at staging time. This service merges those candidates by cveId so
 * a single CVE seen by multiple feeds collapses into one record, and exposes
 * filtering via the `query_cve` MCP tool surface.
 */

export interface UnifiedCveRecord {
    cveId: string;
    /**
     * Deduped origin labels. We expand beyond the feed type:
     *   "kev" appears when any merged candidate is on the KEV catalog.
     *   "atlas" appears when any candidate has an ATLAS technique tag.
     */
    sources: Array<"nvd" | "osv" | "ghsa_graphql" | "github_advisory" | "kev" | "atlas">;
    title: string;
    description: string;
    severity: "low" | "medium" | "high" | "critical";
    cvss?: number;
    ecosystem?: string;
    affectedPackages: Array<{ name: string; versions?: string }>;
    cweIds: string[];
    atlasTechniques: AtlasTechnique[];
    inKev: boolean;
    kevEntry?: KevEntry;
    publishedAt?: string;
    lastModifiedAt?: string;
    references: string[];
    /** Audit aid: how many staged rows folded into this record. */
    sourceCandidates: number;
}

export interface QueryCveFilters {
    keyword?: string;
    ecosystem?: string;
    atlasTechnique?: string;
    severity?: "low" | "medium" | "high" | "critical";
    inKev?: boolean;
    limit?: number;
}

export interface QueryCveResult {
    /** Total unified records that exist (after merging, before filtering). */
    total: number;
    /** How many records survived all filters; record array is then truncated to `limit`. */
    matched: number;
    records: UnifiedCveRecord[];
}

const SEVERITY_RANK: Record<string, number> = {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
};

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

export class UnifiedCveCache {
    constructor(
        private vulnFeedService: VulnFeedService,
        private atlasService: AtlasService,
        private kevFeedService: KevFeedService,
    ) {}

    /**
     * Group staged candidates by cveId (case-insensitive) and project each
     * group into a `UnifiedCveRecord`. The file is small enough that we
     * rebuild on every call rather than cache invalidate — keeps Pass 9
     * simple and avoids staleness between `update_vuln_feeds` runs.
     */
    rebuild(): UnifiedCveRecord[] {
        const candidates = this.vulnFeedService.listStagedCandidates();

        // Group: normalize cveId to upper-case so "cve-2026-1" and "CVE-2026-1"
        // collapse together. We keep the original cveId casing on the first
        // candidate encountered for display.
        const groups = new Map<string, StagedCandidate[]>();
        for (const c of candidates) {
            if (!c?.cveId) continue;
            const key = c.cveId.toUpperCase();
            const list = groups.get(key) || [];
            list.push(c);
            groups.set(key, list);
        }

        const records: UnifiedCveRecord[] = [];
        for (const group of groups.values()) {
            records.push(this.mergeGroup(group));
        }
        return records;
    }

    query(filters: QueryCveFilters): QueryCveResult {
        const all = this.rebuild();
        const total = all.length;

        // Resolve limit defensively — undefined/NaN/negatives all collapse to default.
        let limit = filters.limit ?? DEFAULT_LIMIT;
        if (!Number.isFinite(limit) || limit <= 0) limit = DEFAULT_LIMIT;
        if (limit > MAX_LIMIT) limit = MAX_LIMIT;

        const keyword = filters.keyword?.toLowerCase().trim();
        const ecosystem = filters.ecosystem?.toLowerCase().trim();
        const atlasTechnique = filters.atlasTechnique?.toLowerCase().trim();
        const severity = filters.severity;
        const inKev = filters.inKev;

        const matched = all.filter((r) => {
            // keyword: substring across title + description
            if (keyword) {
                const hay = `${r.title} ${r.description}`.toLowerCase();
                if (!hay.includes(keyword)) return false;
            }
            // ecosystem: match the resolved ecosystem field OR any package name
            // includes the ecosystem prefix (because we serialize affectedPackages
            // as "<eco>:<pkg>").
            if (ecosystem) {
                const ecoMatch =
                    (r.ecosystem && r.ecosystem.toLowerCase() === ecosystem) ||
                    r.affectedPackages.some((p) =>
                        p.name.toLowerCase().includes(`${ecosystem}:`),
                    );
                if (!ecoMatch) return false;
            }
            if (atlasTechnique) {
                const hit = r.atlasTechniques.some(
                    (t) => t.id.toLowerCase() === atlasTechnique,
                );
                if (!hit) return false;
            }
            if (severity && r.severity !== severity) return false;
            if (typeof inKev === "boolean" && r.inKev !== inKev) return false;
            return true;
        });

        return {
            total,
            matched: matched.length,
            records: matched.slice(0, limit),
        };
    }

    /**
     * Fold one cveId's worth of staged candidates into a single record.
     * Every field is defensive about missing data — StagedCandidate is
     * generated by several mappers and we'd rather emit a partial record
     * than throw.
     */
    private mergeGroup(group: StagedCandidate[]): UnifiedCveRecord {
        // cveId display value: take the first candidate's literal casing.
        const cveId = group[0].cveId;

        // sources: dedup feed origins, then augment with kev/atlas tags.
        const sourceSet = new Set<UnifiedCveRecord["sources"][number]>();
        for (const c of group) {
            if (c.source) sourceSet.add(c.source);
            if (c.inKev) sourceSet.add("kev");
            if (c.atlasTechnique) sourceSet.add("atlas");
        }

        // title: longest non-empty name across the group (more descriptive wins).
        const title = this.longest(group.map((c) => c.name).filter(Boolean)) || cveId;

        // description: longest non-empty description.
        const description =
            this.longest(group.map((c) => c.description).filter(Boolean)) || "";

        // severity: max across the group via the standard 4-level ladder.
        let maxSev: "low" | "medium" | "high" | "critical" = "low";
        for (const c of group) {
            const sev = this.normalizeSeverity(c.severity);
            if ((SEVERITY_RANK[sev] || 0) > (SEVERITY_RANK[maxSev] || 0)) {
                maxSev = sev;
            }
        }

        // inKev / kevEntry: any candidate hot OR a fresh KEV check matches.
        const inKev = group.some((c) => c.inKev === true) || this.kevFeedService.isInKev(cveId);
        const kevEntry = inKev ? this.kevFeedService.get(cveId) ?? undefined : undefined;

        // ATLAS: dedupe technique IDs from candidates, then expand via lookup.
        // Fall back to an id-only stub when lookup misses so the caller can
        // still filter by ID without a refreshed bundle.
        const atlasIds = new Set<string>();
        for (const c of group) {
            if (c.atlasTechnique) atlasIds.add(c.atlasTechnique);
        }
        const atlasTechniques: AtlasTechnique[] = [];
        for (const id of atlasIds) {
            const resolved = this.atlasService.lookup(id);
            atlasTechniques.push(
                resolved || {
                    id,
                    name: id,
                    tactic: "Unknown",
                    description: "ATLAS technique not in loaded bundle (refresh AtlasService).",
                },
            );
        }

        // affectedPackages: parse from each candidate.name following the
        // Pass 6 mapper convention: "<ID> (<ECOSYSTEM>:<pkg>)". We grab the
        // parenthesized suffix when present and dedupe.
        const pkgMap = new Map<string, { name: string; versions?: string }>();
        for (const c of group) {
            const pkg = this.parsePackageFromName(c.name);
            if (pkg) pkgMap.set(pkg.name, pkg);
        }
        const affectedPackages = Array.from(pkgMap.values());

        // ecosystem: take the first ecosystem prefix we can find.
        let ecosystem: string | undefined;
        for (const p of affectedPackages) {
            const idx = p.name.indexOf(":");
            if (idx > 0) {
                ecosystem = p.name.slice(0, idx);
                break;
            }
        }

        // publishedAt / lastModifiedAt best-effort: from generatedAt timestamps.
        const timestamps = group.map((c) => c.generatedAt).filter(Boolean).sort();
        const publishedAt = timestamps[0];
        const lastModifiedAt = timestamps[timestamps.length - 1];

        return {
            cveId,
            sources: Array.from(sourceSet),
            title,
            description,
            severity: maxSev,
            cvss: undefined,
            ecosystem,
            affectedPackages,
            cweIds: [], // Future pass: thread CWE IDs through StagedCandidate.
            atlasTechniques,
            inKev,
            kevEntry,
            publishedAt,
            lastModifiedAt,
            references: [], // Future pass: extract URLs from descriptions.
            sourceCandidates: group.length,
        };
    }

    /**
     * Pulls "<ecosystem>:<pkg>" from a candidate name like
     * "GHSA-xxxx-yyyy-zzzz (PyPI:litellm)". Returns null when no parenthesized
     * package suffix is present (NVD/GitHub-REST candidates take this path).
     */
    private parsePackageFromName(
        name: string | undefined,
    ): { name: string; versions?: string } | null {
        if (!name) return null;
        const m = name.match(/\(([^)]+)\)\s*$/);
        if (!m) return null;
        const inner = m[1].trim();
        // Sanity: looks like "ecosystem:package", not random parentheses.
        if (!inner.includes(":")) return null;
        return { name: inner };
    }

    private longest(values: string[]): string | undefined {
        let best: string | undefined;
        for (const v of values) {
            if (!best || v.length > best.length) best = v;
        }
        return best;
    }

    private normalizeSeverity(sev: string | undefined): "low" | "medium" | "high" | "critical" {
        const s = (sev || "").toLowerCase();
        if (s === "critical" || s === "high" || s === "medium" || s === "low") return s;
        // GHSA sometimes emits "moderate"; treat unknowns as medium so they're
        // visible but not over-promoted.
        if (s === "moderate") return "medium";
        return "medium";
    }
}
