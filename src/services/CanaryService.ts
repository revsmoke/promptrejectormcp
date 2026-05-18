// Pass 10: Real CanaryService — issues UUID canary tokens, persists state with
// HMAC integrity, supports TTL expiry + revocation, and scans content for
// echoes (memory/RAG poisoning detection: PoisonedRAG, MINJA, MemoryGraft).
import { createHash, createHmac, randomUUID } from "crypto";
import {
    existsSync,
    mkdirSync,
    readFileSync,
    renameSync,
    writeFileSync,
} from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

export interface CanaryToken {
    token: string; // UUIDv4
    watchHandle: string; // first 12 hex chars of SHA-256(token)
    context?: string;
    deployedAt: string; // ISO
    expiresAt: string; // ISO
}

export interface IssueCanaryOptions {
    context?: string;
    ttlSeconds?: number;
}

export interface IssueCanaryResult {
    token: string;
    watchHandle: string;
    expiresAt: string;
    context?: string;
}

export interface CheckEchoMatch {
    token: string;
    watchHandle: string;
    context?: string;
    deployedAt: string;
}

export interface CheckEchoResult {
    echoDetected: boolean;
    matches: CheckEchoMatch[];
    severity: "safe" | "critical";
}

export interface CanaryServiceOptions {
    statePath?: string;
    hmacSecret?: string;
    defaultTtlSeconds?: number;
}

interface CanaryStateFile {
    version: number;
    tokens: CanaryToken[];
    hmac: string;
}

const STATE_VERSION = 1;

/**
 * Canary-token issuer + verifier for memory/RAG poisoning detection.
 *
 * Issues UUIDv4 tokens (the full canary string the model would echo)
 * paired with a 12-char `watchHandle` (first 12 hex chars of
 * SHA-256(token)) used as an opaque public reference. State is
 * persisted in `patterns/canary-state.json` with HMAC integrity.
 *
 * **Detection flow**: caller plants the token in a RAG document, agent
 * memory, system prompt, or any context the model might ingest. Later,
 * caller scans model output (or any downstream content) via
 * {@link checkEcho}. A match means the model echoed a planted canary
 * back — strong evidence of context contamination / poisoning.
 * Detected echoes return `severity: "critical"`.
 *
 * **State persistence**:
 * - Atomic write via tmp + rename, matching {@link PatternService}'s style.
 * - HMAC-signed when a secret is available; load refuses corrupted state.
 * - TTL-pruned on every operation (expired tokens are silently dropped).
 *
 * **Public surface**: `issueToken`, `checkEcho`, `list`, `revoke`,
 * `verifyStateIntegrity`. {@link checkEcho} accepts an optional
 * `watchHandle` — when supplied, scans only that token; otherwise scans
 * against every active (non-expired) token in the store.
 *
 * Environment variables:
 * - `CANARY_HMAC_SECRET` — preferred HMAC key for state-file integrity.
 * - `PATTERN_INTEGRITY_SECRET` — fallback if `CANARY_HMAC_SECRET` unset.
 * - If both unset, state is stored unsigned and a one-time warning is
 *   logged. Tampering becomes undetectable but the service still works.
 * - `CANARY_DEFAULT_TTL_SECONDS` — default token TTL (default 86400 = 24h).
 *
 * @example
 * ```ts
 * const cs = new CanaryService();
 * const { token, watchHandle } = cs.issueToken({ context: "rag-doc-42" });
 * // ...plant `token` in your RAG corpus, run the model...
 * const result = cs.checkEcho(modelOutput);
 * if (result.echoDetected) alert("memory poisoning detected");
 * ```
 */
export class CanaryService {
    private statePath: string;
    private hmacSecret: string | null;
    private defaultTtlSeconds: number;
    private warnedNoSecret = false;

    constructor(opts?: CanaryServiceOptions) {
        if (opts?.statePath) {
            this.statePath = opts.statePath;
        } else {
            // Walk up to project root and place state under patterns/
            const thisFile = fileURLToPath(import.meta.url);
            let dir = dirname(thisFile);
            while (dir !== "/" && !existsSync(join(dir, "package.json"))) {
                dir = dirname(dir);
            }
            this.statePath = join(dir, "patterns", "canary-state.json");
        }

        // Secret resolution: constructor → CANARY_HMAC_SECRET → PATTERN_INTEGRITY_SECRET
        this.hmacSecret =
            opts?.hmacSecret ||
            process.env.CANARY_HMAC_SECRET ||
            process.env.PATTERN_INTEGRITY_SECRET ||
            null;

        const ttlEnv = process.env.CANARY_DEFAULT_TTL_SECONDS;
        const ttlFromEnv = ttlEnv ? Number(ttlEnv) : NaN;
        this.defaultTtlSeconds =
            opts?.defaultTtlSeconds ??
            (Number.isFinite(ttlFromEnv) && ttlFromEnv > 0 ? ttlFromEnv : 86_400);

        if (!this.hmacSecret) {
            this.warnNoSecret();
        }

        // Touch parent dir
        const parent = dirname(this.statePath);
        if (!existsSync(parent)) {
            mkdirSync(parent, { recursive: true });
        }

        // Eagerly verify integrity if file exists — refuse to load on tamper.
        if (existsSync(this.statePath)) {
            const integrity = this.verifyStateIntegrity();
            if (!integrity.valid && integrity.reason !== "hmac not configured") {
                throw new Error(
                    `canary-state HMAC mismatch — file tampered or wrong key (${integrity.reason})`,
                );
            }
        }
    }

    // --- Public API ---

    issueToken(opts?: IssueCanaryOptions): IssueCanaryResult {
        const token = randomUUID();
        const watchHandle = this.computeWatchHandle(token);
        const now = Date.now();
        const ttl = opts?.ttlSeconds ?? this.defaultTtlSeconds;
        const expiresAt = new Date(now + ttl * 1000).toISOString();
        const deployedAt = new Date(now).toISOString();

        const entry: CanaryToken = {
            token,
            watchHandle,
            context: opts?.context,
            deployedAt,
            expiresAt,
        };

        const state = this.loadState();
        const pruned = this.pruneExpired(state.tokens);
        pruned.push(entry);
        this.saveState(pruned);

        return {
            token,
            watchHandle,
            expiresAt,
            context: opts?.context,
        };
    }

    checkEcho(content: string, watchHandle?: string): CheckEchoResult {
        const state = this.loadState();
        const active = this.pruneExpired(state.tokens);

        // If pruning dropped tokens, persist the trimmed state. Best-effort —
        // a write failure here shouldn't fail the check itself.
        if (active.length !== state.tokens.length) {
            try {
                this.saveState(active);
            } catch (err) {
                console.error("[CanaryService] Failed to persist pruned state:", err);
            }
        }

        const candidates = watchHandle
            ? active.filter((t) => t.watchHandle === watchHandle)
            : active;

        const matches: CheckEchoMatch[] = [];
        for (const t of candidates) {
            if (content.includes(t.token)) {
                matches.push({
                    token: t.token,
                    watchHandle: t.watchHandle,
                    context: t.context,
                    deployedAt: t.deployedAt,
                });
            }
        }

        return {
            echoDetected: matches.length > 0,
            matches,
            severity: matches.length > 0 ? "critical" : "safe",
        };
    }

    list(): CanaryToken[] {
        const state = this.loadState();
        return this.pruneExpired(state.tokens);
    }

    revoke(watchHandle: string): boolean {
        const state = this.loadState();
        const before = state.tokens.length;
        const remaining = state.tokens.filter((t) => t.watchHandle !== watchHandle);
        if (remaining.length === before) {
            return false;
        }
        this.saveState(remaining);
        return true;
    }

    verifyStateIntegrity(): { valid: boolean; reason?: string } {
        if (!existsSync(this.statePath)) {
            return { valid: true, reason: "no state file" };
        }

        let parsed: CanaryStateFile;
        try {
            parsed = JSON.parse(readFileSync(this.statePath, "utf-8"));
        } catch (err) {
            return { valid: false, reason: `parse error: ${(err as Error).message}` };
        }

        if (!this.hmacSecret) {
            return { valid: true, reason: "hmac not configured" };
        }

        if (!parsed.hmac) {
            // File exists, secret configured, but no signature stored — treat
            // as tampered.
            return { valid: false, reason: "missing hmac signature" };
        }

        const expected = this.computeHmac(parsed.version, parsed.tokens);
        if (expected !== parsed.hmac) {
            return { valid: false, reason: "hmac mismatch" };
        }

        return { valid: true };
    }

    // --- Private helpers ---

    private computeWatchHandle(token: string): string {
        return createHash("sha256").update(token).digest("hex").slice(0, 12);
    }

    private computeHmac(version: number, tokens: CanaryToken[]): string {
        if (!this.hmacSecret) return "";
        const payload = JSON.stringify({ version, tokens });
        return createHmac("sha256", this.hmacSecret).update(payload).digest("hex");
    }

    private loadState(): CanaryStateFile {
        if (!existsSync(this.statePath)) {
            return { version: STATE_VERSION, tokens: [], hmac: "" };
        }

        try {
            const raw = readFileSync(this.statePath, "utf-8");
            const parsed = JSON.parse(raw) as CanaryStateFile;
            if (!Array.isArray(parsed.tokens)) {
                return { version: STATE_VERSION, tokens: [], hmac: "" };
            }
            return parsed;
        } catch (err) {
            console.error("[CanaryService] Failed to read state file:", err);
            return { version: STATE_VERSION, tokens: [], hmac: "" };
        }
    }

    private saveState(tokens: CanaryToken[]): void {
        const hmac = this.computeHmac(STATE_VERSION, tokens);
        const state: CanaryStateFile = {
            version: STATE_VERSION,
            tokens,
            hmac,
        };
        const content = JSON.stringify(state, null, 2);
        const tmp = this.statePath + ".tmp";
        writeFileSync(tmp, content, "utf-8");
        renameSync(tmp, this.statePath);
    }

    private pruneExpired(tokens: CanaryToken[]): CanaryToken[] {
        const now = Date.now();
        return tokens.filter((t) => Date.parse(t.expiresAt) > now);
    }

    private warnNoSecret(): void {
        if (this.warnedNoSecret) return;
        this.warnedNoSecret = true;
        console.error(
            "[CanaryService] WARNING: no CANARY_HMAC_SECRET / PATTERN_INTEGRITY_SECRET set. Canary state will be stored unsigned.",
        );
    }
}
