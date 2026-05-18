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
    timeoutMs?: number;
}

const DEFAULT_FEED_URL =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const DEFAULT_TIMEOUT_MS = 30_000; // 30 seconds — match OsvFeedService default.

/**
 * Wraps the CISA Known Exploited Vulnerabilities catalog as an O(1) lookup
 * keyed by CVE ID.
 *
 * Used by `VulnFeedService` as a severity escalator: any staged candidate
 * whose CVE appears in KEV gets bumped one level (low→medium→high→critical).
 * We do not ship a built-in fallback table — KEV churns frequently and stale
 * data is worse than none — so a missing/empty cache returns `isInKev = false`
 * and the orchestrator surfaces the refresh failure.
 *
 * @remarks
 * Key methods:
 * - `refresh()` — fetches catalog, writes atomic JSON cache, rebuilds map. Skips network if cache is within TTL. Throws on fetch/parse failure with a clean error message; on abort surfaces `"KEV refresh failed: timeout after Xms"`.
 * - `isInKev(cveId)` — case-insensitive O(1) membership.
 * - `get(cveId)` — full record or `null`.
 * - `list()` — array of all entries.
 *
 * Environment variables consumed: none directly. All inputs (`feedUrl`,
 * `cacheDir`, `ttlMs`, `timeoutMs`) flow through constructor options.
 *
 * Network behavior:
 * - Endpoint: CISA KEV JSON (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`).
 * - Timeout: 30s via `AbortController` (constructor-tunable).
 * - Cache: `patterns/feed-cache/kev.json`, 24h TTL by default. Atomic write via `.tmp` + rename. Root finder walks up looking for `package.json` and stops when `dirname()` becomes idempotent (POSIX `/` / Windows drive root) so it can't loop forever.
 *
 * @example
 * ```ts
 * const kev = new KevFeedService();
 * await kev.refresh();
 * if (kev.isInKev("CVE-2024-1234")) escalateSeverity();
 * ```
 */
export class KevFeedService {
    private cacheDir: string;
    private cachePath: string;
    private feedUrl: string;
    private ttlMs: number;
    private timeoutMs: number;
    private entries: Map<string, KevEntry> = new Map();

    constructor(opts: KevFeedServiceOptions = {}) {
        this.feedUrl = opts.feedUrl || DEFAULT_FEED_URL;
        this.ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
        this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

        if (opts.cacheDir) {
            this.cacheDir = opts.cacheDir;
        } else {
            const thisFile = fileURLToPath(import.meta.url);
            let dir = dirname(thisFile);
            // Walk up looking for package.json. Stop when dirname() no longer
            // changes — on POSIX dirname("/") === "/", on Windows
            // dirname("C:\\") === "C:\\". The previous `dir !== "/"` check
            // would loop forever on Windows-style roots.
            while (!existsSync(join(dir, "package.json"))) {
                const parent = dirname(dir);
                if (parent === dir) break;
                dir = parent;
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
     *
     * @returns Count of entries in the warmed map and an ISO `fetchedAt` timestamp.
     * @throws `"KEV refresh failed: timeout after Xms"` on abort; other fetch errors bubble up with their underlying detail.
     */
    async refresh(): Promise<KevRefreshResult> {
        if (this.cacheIsFresh()) {
            this.tryLoadCache();
            return { count: this.entries.size, fetchedAt: new Date().toISOString() };
        }

        // Bounded fetch — CISA endpoint stalls would otherwise hang refresh().
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);

        let body: any;
        try {
            const resp = await fetch(this.feedUrl, { signal: controller.signal });
            if (!resp.ok) {
                throw new Error(`KEV catalog fetch failed: HTTP ${resp.status}`);
            }
            body = await resp.json();
        } catch (err: any) {
            // AbortError surfaces with a clear timeout message; everything else
            // bubbles up with its underlying detail.
            if (err?.name === "AbortError") {
                throw new Error(`KEV refresh failed: timeout after ${this.timeoutMs}ms`);
            }
            throw new Error(`KEV refresh failed: ${err?.message || err}`);
        } finally {
            clearTimeout(timer);
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

    /**
     * Case-insensitive membership test.
     *
     * @param cveId - CVE identifier (any case). Empty string returns `false`.
     * @returns `true` if the CVE is present in the in-memory map.
     */
    isInKev(cveId: string): boolean {
        if (!cveId) return false;
        return this.entries.has(cveId.toUpperCase());
    }

    /**
     * Fetch the full KEV entry for a CVE.
     *
     * @param cveId - CVE identifier (any case).
     * @returns Entry or `null` if absent.
     */
    get(cveId: string): KevEntry | null {
        if (!cveId) return null;
        return this.entries.get(cveId.toUpperCase()) || null;
    }

    /**
     * Snapshot of all known KEV entries.
     *
     * @returns Array copy of the current map values.
     */
    list(): KevEntry[] {
        return Array.from(this.entries.values());
    }
}
