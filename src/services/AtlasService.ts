import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

/**
 * MITRE ATLAS technique. ATLAS = Adversarial Threat Landscape for AI Systems.
 * IDs look like "AML.T0051" (technique) or "AML.M0001" (mitigation).
 */
export interface AtlasTechnique {
    id: string;
    name: string;
    description: string;
    tactic: string;
}

export interface AtlasRefreshResult {
    count: number;
    fetchedAt: string;
}

export interface AtlasServiceOptions {
    cacheDir?: string;
    bundleUrl?: string;
    ttlMs?: number;
}

const DEFAULT_BUNDLE_URL =
    "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json";
const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

/**
 * Built-in fallback table — covers the ATLAS techniques referenced by SPEC §7
 * mapping. Lets the service answer lookup() offline before any refresh().
 * Entries are intentionally minimal — the description suffix signals operators
 * should refresh for canonical text. Some IDs marked [unverified] in SPEC §13
 * are kept as-is; Pass 13 will reconcile against the live ATLAS bundle.
 */
const FALLBACK_TECHNIQUES: Record<string, AtlasTechnique> = {
    "AML.T0051": {
        id: "AML.T0051",
        name: "LLM Prompt Injection",
        tactic: "Initial Access",
        description:
            "Adversary injects malicious instructions into LLM input to override developer or user intent (fallback entry — refresh ATLAS service for canonical text).",
    },
    "AML.T0054": {
        id: "AML.T0054",
        name: "LLM Jailbreak",
        tactic: "Defense Evasion",
        description:
            "Adversary bypasses LLM safety/policy guardrails to elicit prohibited behavior (fallback entry — refresh ATLAS service for canonical text).",
    },
    "AML.T0024": {
        id: "AML.T0024",
        name: "Exfiltration via AI Inference API",
        tactic: "Exfiltration",
        description:
            "Adversary exfiltrates sensitive data through model inference outputs, side-channels, or markdown image fetches (fallback entry — refresh ATLAS service for canonical text).",
    },
    "AML.T0070": {
        id: "AML.T0070",
        name: "Publish Poisoned AI Agent Tool",
        tactic: "Initial Access",
        description:
            "Adversary publishes a tool (e.g. MCP server) carrying hidden instructions that hijack agents on install [unverified ID — pending ATLAS Feb-2026 release] (fallback entry — refresh ATLAS service for canonical text).",
    },
    "AML.T0071": {
        id: "AML.T0071",
        name: "AI Agent Context Poisoning",
        tactic: "Persistence",
        description:
            "Adversary poisons an agent's persistent context (memory, tool results, retrieved docs) to bias future behavior [unverified ID — pending ATLAS Feb-2026 release] (fallback entry — refresh ATLAS service for canonical text).",
    },
};

export class AtlasService {
    private cacheDir: string;
    private cachePath: string;
    private bundleUrl: string;
    private ttlMs: number;
    private cache: Map<string, AtlasTechnique> = new Map();
    private loadedFromCache = false;

    constructor(opts: AtlasServiceOptions = {}) {
        this.bundleUrl = opts.bundleUrl || DEFAULT_BUNDLE_URL;
        this.ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;

        if (opts.cacheDir) {
            this.cacheDir = opts.cacheDir;
        } else {
            // Resolve project-root patterns/feed-cache
            const thisFile = fileURLToPath(import.meta.url);
            let dir = dirname(thisFile);
            while (dir !== "/" && !existsSync(join(dir, "package.json"))) {
                dir = dirname(dir);
            }
            this.cacheDir = join(dir, "patterns", "feed-cache");
        }
        this.cachePath = join(this.cacheDir, "atlas-stix.json");

        // Best-effort: load cache if present at construction so lookup() works offline.
        this.tryLoadCache();
    }

    private tryLoadCache(): void {
        if (!existsSync(this.cachePath)) return;
        try {
            const raw = readFileSync(this.cachePath, "utf-8");
            const parsed = JSON.parse(raw);
            if (parsed && Array.isArray(parsed.techniques)) {
                this.cache.clear();
                for (const t of parsed.techniques as AtlasTechnique[]) {
                    this.cache.set(t.id, t);
                }
                this.loadedFromCache = true;
            }
        } catch {
            // Bad cache — ignore; refresh() will rebuild.
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
     * Fetch + parse the STIX bundle and persist to cache. Skips the network
     * call if the cache is fresh (within TTL). Throws on hard failure so the
     * caller (typically VulnFeedService) can record the error and continue.
     */
    async refresh(): Promise<AtlasRefreshResult> {
        // Cache-hit short-circuit: keeps us off the network in CI/loops.
        if (this.cacheIsFresh()) {
            this.tryLoadCache();
            return { count: this.cache.size, fetchedAt: new Date().toISOString() };
        }

        let bundleJson: any;
        try {
            const resp = await fetch(this.bundleUrl);
            if (!resp.ok) {
                throw new Error(`ATLAS bundle fetch failed: HTTP ${resp.status}`);
            }
            bundleJson = await resp.json();
        } catch (err: any) {
            throw new Error(`ATLAS refresh failed: ${err?.message || err}`);
        }

        const techniques = this.parseStixBundle(bundleJson);

        // Persist cache atomically so a partial write can't poison future loads.
        if (!existsSync(this.cacheDir)) {
            mkdirSync(this.cacheDir, { recursive: true });
        }
        const payload = JSON.stringify(
            { fetchedAt: new Date().toISOString(), techniques },
            null,
            2,
        );
        const tmp = this.cachePath + ".tmp";
        writeFileSync(tmp, payload, "utf-8");
        renameSync(tmp, this.cachePath);

        this.cache.clear();
        for (const t of techniques) this.cache.set(t.id, t);
        this.loadedFromCache = true;

        return { count: techniques.length, fetchedAt: new Date().toISOString() };
    }

    /**
     * Lookup by ATLAS technique ID. Tries the loaded cache first, then falls
     * back to the built-in mapping table. Logs to stderr the first time we
     * answer with nothing loaded so the operator knows to refresh.
     */
    lookup(techniqueId: string): AtlasTechnique | null {
        const fromCache = this.cache.get(techniqueId);
        if (fromCache) return fromCache;

        const fromFallback = FALLBACK_TECHNIQUES[techniqueId];
        if (fromFallback) {
            if (!this.loadedFromCache) {
                console.error(
                    `[AtlasService] Using fallback entry for ${techniqueId} — call refresh() to load canonical bundle.`,
                );
            }
            return fromFallback;
        }
        return null;
    }

    list(): AtlasTechnique[] {
        if (this.cache.size > 0) return Array.from(this.cache.values());
        return Object.values(FALLBACK_TECHNIQUES);
    }

    /**
     * STIX bundles wrap their objects in `objects`. ATLAS techniques are STIX
     * `attack-pattern`s with the ATLAS id under `external_references[].external_id`.
     * We're defensive — the bundle shape has shifted between releases, and we'd
     * rather return a partial set than crash. Sub-techniques are dropped; tactics
     * are resolved from `kill_chain_phases` where present.
     */
    private parseStixBundle(bundle: any): AtlasTechnique[] {
        const out: AtlasTechnique[] = [];
        if (!bundle || !Array.isArray(bundle.objects)) return out;

        for (const obj of bundle.objects) {
            if (obj?.type !== "attack-pattern") continue;
            // Skip sub-techniques — Pass 7 only needs top-level technique IDs.
            if (obj.x_mitre_is_subtechnique === true) continue;

            // Find ATLAS external_id (AML.Txxxx / AML.Mxxxx).
            const refs = Array.isArray(obj.external_references) ? obj.external_references : [];
            const atlasRef = refs.find(
                (r: any) => typeof r?.external_id === "string" && /^AML\.[TM][0-9]{4}/.test(r.external_id),
            );
            if (!atlasRef) continue;
            const id = (atlasRef.external_id as string).match(/^AML\.[TM][0-9]{4}/)?.[0];
            if (!id) continue;

            // Tactic best-effort: kill_chain_phases[].phase_name, or "Unknown".
            let tactic = "Unknown";
            if (Array.isArray(obj.kill_chain_phases) && obj.kill_chain_phases.length > 0) {
                tactic = String(obj.kill_chain_phases[0]?.phase_name || "Unknown");
            }

            out.push({
                id,
                name: String(obj.name || id),
                description: String(obj.description || ""),
                tactic,
            });
        }
        return out;
    }
}
