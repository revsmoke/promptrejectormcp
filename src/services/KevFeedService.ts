import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

/**
 * CISA Known Exploited Vulnerabilities — one entry per actively-exploited CVE.
 * Field names mirror the CISA catalog JSON (camelCase as documented).
 */
export interface KevEntry {
    cveID: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    dateAdded: string;
    shortDescription: string;
    knownRansomwareUse: string;
}

export interface KevRefreshResult {
    count: number;
    fetchedAt: string;
}

export interface KevFeedServiceOptions {
    cacheDir?: string;
    feedUrl?: string;
    ttlMs?: number;
}

const DEFAULT_FEED_URL =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Wraps the CISA KEV catalog as an O(1) lookup. We don't ship a fallback
 * table here (KEV is high-churn and stale data would be misleading); instead
 * a missing/empty cache returns isInKev=false, and the VulnFeedService
 * orchestrator logs the refresh failure for the operator.
 */
export class KevFeedService {
    private cacheDir: string;
    private cachePath: string;
    private feedUrl: string;
    private ttlMs: number;
    private entries: Map<string, KevEntry> = new Map();

    constructor(opts: KevFeedServiceOptions = {}) {
        this.feedUrl = opts.feedUrl || DEFAULT_FEED_URL;
        this.ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;

        if (opts.cacheDir) {
            this.cacheDir = opts.cacheDir;
        } else {
            const thisFile = fileURLToPath(import.meta.url);
            let dir = dirname(thisFile);
            while (dir !== "/" && !existsSync(join(dir, "package.json"))) {
                dir = dirname(dir);
            }
            this.cacheDir = join(dir, "patterns", "feed-cache");
        }
        this.cachePath = join(this.cacheDir, "kev.json");

        // Warm the in-memory map from cache if available.
        this.tryLoadCache();
    }

    private tryLoadCache(): void {
        if (!existsSync(this.cachePath)) return;
        try {
            const raw = readFileSync(this.cachePath, "utf-8");
            const parsed = JSON.parse(raw);
            this.ingestCatalog(parsed);
        } catch {
            // Corrupt cache — skip; next refresh will rebuild.
        }
    }

    private cacheIsFresh(): boolean {
        if (!existsSync(this.cachePath)) return false;
        try {
            const stat = statSync(this.cachePath);
            return Date.now() - stat.mtimeMs < this.ttlMs;
        } catch {
            return false;
        }
    }

    /**
     * Parse a KEV catalog JSON document into the lookup map. Tolerates either
     * the official catalog shape (`{ vulnerabilities: [...] }`) or a
     * pre-flattened array, since some mirrors flatten the response.
     */
    private ingestCatalog(parsed: any): void {
        const list = Array.isArray(parsed?.vulnerabilities)
            ? parsed.vulnerabilities
            : Array.isArray(parsed)
              ? parsed
              : [];
        this.entries.clear();
        for (const v of list) {
            const cveID = String(v?.cveID || "").trim();
            if (!cveID) continue;
            const entry: KevEntry = {
                cveID,
                vendorProject: String(v.vendorProject || ""),
                product: String(v.product || ""),
                vulnerabilityName: String(v.vulnerabilityName || ""),
                dateAdded: String(v.dateAdded || ""),
                shortDescription: String(v.shortDescription || ""),
                knownRansomwareUse: String(v.knownRansomwareUse || ""),
            };
            // Normalize for case-insensitive lookup.
            this.entries.set(cveID.toUpperCase(), entry);
        }
    }

    /**
     * Fetch the KEV catalog and persist to cache. Skips the network if the
     * cache is already within TTL. Throws on fetch failure.
     */
    async refresh(): Promise<KevRefreshResult> {
        if (this.cacheIsFresh()) {
            this.tryLoadCache();
            return { count: this.entries.size, fetchedAt: new Date().toISOString() };
        }

        let body: any;
        try {
            const resp = await fetch(this.feedUrl);
            if (!resp.ok) {
                throw new Error(`KEV catalog fetch failed: HTTP ${resp.status}`);
            }
            body = await resp.json();
        } catch (err: any) {
            throw new Error(`KEV refresh failed: ${err?.message || err}`);
        }

        if (!existsSync(this.cacheDir)) {
            mkdirSync(this.cacheDir, { recursive: true });
        }
        const tmp = this.cachePath + ".tmp";
        writeFileSync(tmp, JSON.stringify(body, null, 2), "utf-8");
        renameSync(tmp, this.cachePath);

        this.ingestCatalog(body);
        return { count: this.entries.size, fetchedAt: new Date().toISOString() };
    }

    /** Case-insensitive membership test. */
    isInKev(cveId: string): boolean {
        if (!cveId) return false;
        return this.entries.has(cveId.toUpperCase());
    }

    get(cveId: string): KevEntry | null {
        if (!cveId) return null;
        return this.entries.get(cveId.toUpperCase()) || null;
    }

    list(): KevEntry[] {
        return Array.from(this.entries.values());
    }
}
