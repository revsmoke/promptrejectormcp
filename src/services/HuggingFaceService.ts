// Pass 8: Hugging Face Hub security signals.
//
// HF exposes per-model / per-dataset metadata at:
//   GET https://huggingface.co/api/models/{owner}/{name}
//   GET https://huggingface.co/api/datasets/{owner}/{name}
//
// The response shape is loose and field names have shifted over time (HF
// occasionally adds/renames keys like `securityStatus`, `protectAiScanResult`,
// `siblings`, `cardData`, `tags`, `gated`, etc.). We parse defensively: every
// field is optional, missing keys never throw, and unknown shapes degrade to
// `lookup_failed` rather than crashing the caller.
//
// Snyk's Feb 2026 ToxicSkills report observed that 36% of marketplace agent
// skills reference HF model IDs — so any skill loading a model inherits that
// model's security posture. We surface those flags in scan_skill output.

/** Severity ladder shared with other services for consistent rollup. */
const SEVERITIES = ["safe", "low", "medium", "high", "critical"] as const;
type Severity = typeof SEVERITIES[number];

/** One flagged finding on a single HF model / dataset. */
export interface HuggingFaceModelFlag {
    class:
        | "unsafe_serialization"   // pickle / dill / marshal warning (legacy formats)
        | "code_execution_risk"    // trust_remote_code / custom code execution
        | "scanner_warning"        // Protect AI scanner output other than the above
        | "gated"                  // model requires acceptance/license
        | "no_safetensors"         // no .safetensors variant — falls back to .bin / .pkl
        | "lookup_failed";         // network/404/auth issue — surfaced, never thrown
    note: string;
    rawField?: string;             // which API field the flag came from (debug aid)
}

/** Aggregated report for one model/dataset id. */
export interface HuggingFaceModelReport {
    modelId: string;
    fetchedAt: string;
    flags: HuggingFaceModelFlag[];
    severity: Severity;
}

/** Per-flag severity contribution. Max across all flags becomes report.severity. */
const FLAG_SEVERITY: Record<HuggingFaceModelFlag["class"], Severity> = {
    code_execution_risk: "critical",
    unsafe_serialization: "high",
    scanner_warning: "medium",
    gated: "low",
    no_safetensors: "low",
    lookup_failed: "safe", // can't block on lookup failure; surface only
};

interface CacheEntry {
    report: HuggingFaceModelReport;
    fetchedAtMs: number;
}

/** Default cache TTL: 6 hours. Tunable via constructor opts. */
const DEFAULT_CACHE_TTL_MS = 6 * 60 * 60 * 1000;
/** Default network timeout: 15s. */
const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * Pulls security signals from Hugging Face Hub for models and datasets and
 * extracts HF model IDs referenced in free-form text.
 *
 * Hits `GET /api/models/{owner}/{name}` (or `/datasets/...`) and parses the
 * response defensively — every field is optional and unknown shapes degrade
 * to a single `lookup_failed` flag rather than throwing. Used by the skill
 * scanner because marketplace skills commonly load HF models and thereby
 * inherit those models' posture (gated, unsafe serialization, code-execution
 * risk via `trust_remote_code`, scanner warnings, etc.).
 *
 * @remarks
 * Key methods:
 * - `checkModel(modelId)` / `checkDataset(datasetId)` — fetch + analyze; returns a `HuggingFaceModelReport` with `flags[]` and a rolled-up `severity`.
 * - `extractModelIds(text)` — conservative scan for `owner/name` references. Requires either a `huggingface.co/...` URL or a context keyword (`model`/`pretrained`/`huggingface`/`hf_hub`/`transformers`/`from_pretrained`) within an 80-char window; rejects `host.tld` owners to avoid file-path false positives.
 *
 * Severity rollup (max across flags):
 * - `code_execution_risk` → critical
 * - `unsafe_serialization` → high
 * - `scanner_warning` → medium
 * - `gated`, `no_safetensors` → low
 * - `lookup_failed` → safe (surface only; never blocks)
 *
 * Environment variables consumed:
 * - `HF_TOKEN` — optional. HF allows anonymous reads of public metadata; the token raises rate limits and unlocks gated models the caller has accepted.
 *
 * Network behavior:
 * - Endpoint: `https://huggingface.co/api/{models|datasets}/{id}`.
 * - Timeout: 15s via `AbortController` (constructor-tunable).
 * - Cache: in-memory `Map`, keyed by `kind:id`, default TTL 6h.
 *
 * @example
 * ```ts
 * const hf = new HuggingFaceService();
 * const report = await hf.checkModel("bert-base-uncased");
 * if (report.severity !== "safe") flag(report);
 * ```
 */
export class HuggingFaceService {
    private baseUrl: string;
    private token: string | null;
    private timeoutMs: number;
    private cacheTtlMs: number;
    private cache: Map<string, CacheEntry>;

    constructor(opts?: { baseUrl?: string; token?: string; timeoutMs?: number; cacheTtlMs?: number }) {
        this.baseUrl = opts?.baseUrl ?? "https://huggingface.co";
        // Token is optional: HF allows anonymous reads of public model metadata.
        this.token = opts?.token ?? process.env.HF_TOKEN ?? null;
        this.timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
        this.cacheTtlMs = opts?.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
        this.cache = new Map();
    }

    /**
     * Fetch and interpret security signals for one HF model id.
     *
     * @param modelId - HF model identifier in `owner/name` form.
     * @returns Report with flag list and severity. Network/parse failures degrade to a single `lookup_failed` flag.
     */
    async checkModel(modelId: string): Promise<HuggingFaceModelReport> {
        return this.fetchAndAnalyze(modelId, "models");
    }

    /**
     * Same shape as {@link HuggingFaceService.checkModel} but hits the datasets endpoint.
     *
     * @param datasetId - HF dataset identifier in `owner/name` form.
     * @returns Report with flag list and severity.
     */
    async checkDataset(datasetId: string): Promise<HuggingFaceModelReport> {
        return this.fetchAndAnalyze(datasetId, "datasets");
    }

    private async fetchAndAnalyze(id: string, kind: "models" | "datasets"): Promise<HuggingFaceModelReport> {
        // Cache lookup — keyed by kind + id so a model "x/y" and dataset "x/y" don't collide.
        const cacheKey = `${kind}:${id}`;
        const cached = this.cache.get(cacheKey);
        if (cached && Date.now() - cached.fetchedAtMs < this.cacheTtlMs) {
            return cached.report;
        }

        const url = `${this.baseUrl}/api/${kind}/${id}`;
        const headers: Record<string, string> = { Accept: "application/json" };
        if (this.token) headers["Authorization"] = `Bearer ${this.token}`;

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);

        let report: HuggingFaceModelReport;
        try {
            const resp = await globalThis.fetch(url, { headers, signal: controller.signal });
            if (!resp.ok) {
                // 401/403 typically means gated/private; 404 means typo or deleted.
                // We surface as lookup_failed — caller decides what to do.
                report = this.buildReport(id, [{
                    class: "lookup_failed",
                    note: `HF API returned HTTP ${resp.status} for ${kind}/${id}`,
                    rawField: "http_status",
                }]);
            } else {
                const data = (await resp.json()) as unknown;
                const flags = this.analyzeApiPayload(data);
                report = this.buildReport(id, flags);
            }
        } catch (err: any) {
            // Network errors, aborts, JSON parse failures — all degrade to lookup_failed.
            report = this.buildReport(id, [{
                class: "lookup_failed",
                note: `HF fetch error: ${err?.message || String(err)}`,
                rawField: "exception",
            }]);
        } finally {
            clearTimeout(timer);
        }

        this.cache.set(cacheKey, { report, fetchedAtMs: Date.now() });
        return report;
    }

    private buildReport(id: string, flags: HuggingFaceModelFlag[]): HuggingFaceModelReport {
        // Roll up severity = max across flags. Empty → safe.
        let maxIdx = 0;
        for (const f of flags) {
            const idx = SEVERITIES.indexOf(FLAG_SEVERITY[f.class]);
            if (idx > maxIdx) maxIdx = idx;
        }
        return {
            modelId: id,
            fetchedAt: new Date().toISOString(),
            flags,
            severity: SEVERITIES[maxIdx],
        };
    }

    /**
     * Parse the HF API response defensively. Every field is optional; we never
     * throw on missing/unexpected shapes — worst case, we return empty flags.
     */
    private analyzeApiPayload(data: unknown): HuggingFaceModelFlag[] {
        const flags: HuggingFaceModelFlag[] = [];
        if (!data || typeof data !== "object") return flags;
        const obj = data as Record<string, any>;

        // 1. Gated. HF returns `gated: false | "auto" | "manual"`. Anything truthy
        //    means the user must accept terms — relevant signal for skill consumers
        //    because the model isn't freely loadable without HF_TOKEN + acceptance.
        if (obj.gated && obj.gated !== false && obj.gated !== "false") {
            flags.push({
                class: "gated",
                note: `Model is gated (${JSON.stringify(obj.gated)}); requires license acceptance`,
                rawField: "gated",
            });
        }

        // 2. siblings[].rfilename → look for legacy serialization formats.
        //    .pkl / .bin / .pt / .pth are pickle-backed and arbitrarily runnable
        //    at load time. We flag if those exist without a .safetensors twin.
        const siblings = Array.isArray(obj.siblings) ? obj.siblings : [];
        const filenames: string[] = siblings
            .map((s: any) => (s && typeof s.rfilename === "string" ? s.rfilename : null))
            .filter((f: string | null): f is string => !!f);

        const hasUnsafe = filenames.some((f) =>
            /\.(pkl|pickle|bin|pt|pth|dill|joblib)$/i.test(f),
        );
        const hasSafetensors = filenames.some((f) => /\.safetensors$/i.test(f));

        if (hasUnsafe && !hasSafetensors) {
            flags.push({
                class: "unsafe_serialization",
                note: `Model ships pickle-backed weights (.bin/.pkl/.pt) with no .safetensors alternative`,
                rawField: "siblings.rfilename",
            });
        } else if (!hasSafetensors && filenames.length > 0 && !hasUnsafe) {
            // No safetensors and no clearly-unsafe formats either — surface as low.
            flags.push({
                class: "no_safetensors",
                note: `No .safetensors variant published; consumers fall back to legacy formats`,
                rawField: "siblings.rfilename",
            });
        }

        // 3. cardData.tags / top-level tags → trust_remote_code, custom_code, etc.
        //    These mean the model loader will run arbitrary Python from the repo.
        const tags: string[] = [];
        if (Array.isArray(obj.tags)) tags.push(...obj.tags.filter((t: any) => typeof t === "string"));
        if (obj.cardData && Array.isArray(obj.cardData.tags)) {
            tags.push(...obj.cardData.tags.filter((t: any) => typeof t === "string"));
        }
        // Some configs set trust_remote_code on the cardData directly.
        const trustRemoteCode = obj.cardData?.trust_remote_code === true
            || tags.some((t) => /trust[-_]?remote[-_]?code|custom[-_]?code/i.test(t));
        if (trustRemoteCode) {
            flags.push({
                class: "code_execution_risk",
                note: `Model requires trust_remote_code — loader runs arbitrary Python from repo`,
                rawField: "cardData.tags / cardData.trust_remote_code",
            });
        }

        // 4. securityStatus / protectAiScanResult — HF's scanner output.
        //    Shape varies; we look for any explicit "unsafe"/"malicious" string
        //    anywhere in the security object and classify accordingly.
        const security = obj.securityStatus || obj.security || obj.protectAiScanResult;
        if (security && typeof security === "object") {
            const serialized = JSON.stringify(security).toLowerCase();
            if (/malicious|unsafe|suspicious|infected/.test(serialized)) {
                // Already covered by unsafe_serialization if it's a pickle hit;
                // otherwise classify as scanner_warning.
                const isPickle = /pickle|dill|marshal/.test(serialized);
                flags.push({
                    class: isPickle ? "unsafe_serialization" : "scanner_warning",
                    note: `HF scanner reports issues: ${serialized.slice(0, 200)}`,
                    rawField: "securityStatus",
                });
            }
        }

        return flags;
    }

    /**
     * Scan free-form text for HF model identifiers.
     *
     * Strategy: an HF id is shaped `owner/name` where both segments are
     * `[A-Za-z0-9_.-]+`. That regex alone has *huge* false-positive surface
     * (file paths, dates, URLs, etc.), so we require one of:
     *   (a) a `huggingface.co/<owner>/<name>` URL prefix, or
     *   (b) a context keyword (`model|pretrained|huggingface|hf_hub|transformers`)
     *       within 80 chars before or after the candidate.
     *
     * Returns a deduped array.
     *
     * @param text - Free-form input to scan (skill body, prompt, etc.).
     * @returns Deduped array of `owner/name` HF model identifiers found.
     */
    extractModelIds(text: string): string[] {
        if (!text || typeof text !== "string") return [];
        const found = new Set<string>();

        // (a) Direct huggingface.co URLs — strongest signal.
        const urlRe = /huggingface\.co\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)/g;
        let m: RegExpExecArray | null;
        while ((m = urlRe.exec(text)) !== null) {
            const candidate = m[1];
            if (this.looksLikeModelId(candidate)) found.add(candidate);
        }

        // (b) Context-keyword proximity. Walk every owner/name candidate, check
        //     for a keyword in the 80-char window on either side.
        const KEYWORD_RE = /\b(model|pretrained|huggingface|hf_hub|transformers|from_pretrained)\b/i;
        const candRe = /\b([A-Za-z0-9_.][A-Za-z0-9_.-]*\/[A-Za-z0-9_.][A-Za-z0-9_.-]*)\b/g;
        while ((m = candRe.exec(text)) !== null) {
            const candidate = m[1];
            if (!this.looksLikeModelId(candidate)) continue;
            const start = Math.max(0, m.index - 80);
            const end = Math.min(text.length, m.index + candidate.length + 80);
            const window = text.slice(start, end);
            if (KEYWORD_RE.test(window)) found.add(candidate);
        }

        return Array.from(found);
    }

    /** Sanity filter for owner/name pairs to weed out obvious non-IDs. */
    private looksLikeModelId(s: string): boolean {
        // Reject anything that looks like a file path (more than one slash, or
        // ends in a known file extension).
        if (s.split("/").length !== 2) return false;
        if (/\.(json|md|txt|js|ts|py|html|css|png|jpe?g|gif|svg|yaml|yml|toml|lock|sh|cfg|ini)$/i.test(s)) {
            return false;
        }
        const [owner, name] = s.split("/");
        // Reject pure numerics like "2024/01" (date-ish).
        if (/^\d+$/.test(owner) && /^\d+$/.test(name)) return false;
        // Minimum length guard.
        if (owner.length < 2 || name.length < 2) return false;
        // Reject domain-shaped owners ("huggingface.co", "github.com", "x.io" etc.).
        // The huggingface.co URL path is handled by the dedicated URL regex; this
        // prevents the generic owner/name regex from re-extracting "huggingface.co/owner"
        // as if "huggingface.co" were the owner.
        if (/^[a-z0-9-]+\.(co|com|org|io|net|ai|app|dev|gg|me)$/i.test(owner)) return false;
        return true;
    }

    /** Test/debug helper — drops cache so a re-fetch will hit the network. */
    clearCache(): void {
        this.cache.clear();
    }
}
