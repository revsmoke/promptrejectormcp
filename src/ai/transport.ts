import type { CallContext, FailureCode } from "./contracts.js";

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
export type TransportResult =
    | { status: "ok"; value: unknown; attempts: number; reservationIds: string[]; elapsedMs: number }
    | { status: "unavailable"; code: FailureCode; attempts: number; reservationIds: string[]; elapsedMs: number };
export interface JsonRequest {
    url: string;
    headers: Record<string, string>;
    body: string;
    timeoutMs: number;
    maxResponseBytes?: number;
    estimatedUsd?: number | null;
    retry?: boolean;
}
class TransportFailure extends Error {
    constructor(readonly code: FailureCode) { super(code); }
}

/** Timer scheduling and Date.now need not cross a millisecond boundary together.
 * Recheck the absolute deadline so an early callback cannot cancel valid work. */
export function deadlineTimer(deadlineMs: number, abort: () => void): () => void {
    const check = () => {
        const remainingMs = deadlineMs - Date.now();
        if (remainingMs <= 0) abort();
        else timer = setTimeout(check, remainingMs);
    };
    let timer = setTimeout(check, Math.max(0, deadlineMs - Date.now()));
    return () => clearTimeout(timer);
}

/** Abortable wait used for the whole operation, including queue and response
 * body. Unlike Promise.race-only timeouts, callers also abort native fetch. */
export function untilAborted<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
    if (signal.aborted) { void work.catch(() => {}); return Promise.reject(new TransportFailure("cancelled")); }
    return new Promise<T>((resolve, reject) => {
        const abort = () => reject(new TransportFailure("cancelled"));
        signal.addEventListener("abort", abort, { once: true });
        work.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
    });
}
export async function withDeadline<T>(work: (signal: AbortSignal) => Promise<T>, deadlineMs: number, external?: AbortSignal): Promise<T> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    external?.addEventListener("abort", abort, { once: true });
    if (external?.aborted || Date.now() >= deadlineMs) controller.abort();
    const clearDeadline = deadlineTimer(deadlineMs, abort);
    try {
        if (controller.signal.aborted) throw new TransportFailure("cancelled");
        const result = await untilAborted(Promise.resolve().then(() => {
            if (controller.signal.aborted) throw new TransportFailure("cancelled");
            return work(controller.signal);
        }), controller.signal);
        if (controller.signal.aborted || Date.now() >= deadlineMs) { controller.abort(); throw new TransportFailure("timeout"); }
        return result;
    }
    catch (error) {
        if (controller.signal.aborted) throw new TransportFailure(external?.aborted ? "cancelled" : "timeout");
        throw error;
    }
    finally { clearDeadline(); external?.removeEventListener("abort", abort); }
}

interface Waiter { optional: boolean; accept(): void; reject(code: FailureCode): void }
export class NativeTransport {
    private active = 0;
    private queue: Waiter[] = [];
    private readonly fetcher: FetchLike;
    private readonly maxConcurrent: number;
    private readonly maxQueue: number;
    constructor(options: { fetch?: FetchLike; maxConcurrent?: number; maxQueue?: number } = {}) {
        // Resolve the global lazily so later test mocks and fetch replacement
        // work. Production bootstrap may inject an explicit stable fetch.
        this.fetcher = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
        this.maxConcurrent = options.maxConcurrent ?? 2;
        this.maxQueue = options.maxQueue ?? 32;
        if (!Number.isInteger(this.maxConcurrent) || this.maxConcurrent < 1 || !Number.isInteger(this.maxQueue) || this.maxQueue < 0) throw new Error("Invalid transport capacity");
    }
    private acquire(signal: AbortSignal, optional: boolean): Promise<() => void> {
        if (signal.aborted) return Promise.reject(new TransportFailure("cancelled"));
        if (this.active < this.maxConcurrent && this.queue.length === 0) {
            this.active++;
            return Promise.resolve(() => this.release());
        }
        // Optional work is shed instead of competing with queued required work.
        if (optional || this.queue.length >= this.maxQueue) return Promise.reject(new TransportFailure("budget_exceeded"));
        return new Promise((resolve, reject) => {
            const abort = () => {
                this.queue = this.queue.filter((item) => item !== waiter);
                waiter.reject("cancelled");
            };
            const waiter: Waiter = {
                optional,
                accept: () => { signal.removeEventListener("abort", abort); this.active++; resolve(() => this.release()); },
                reject: (code) => { signal.removeEventListener("abort", abort); reject(new TransportFailure(code)); },
            };
            this.queue.push(waiter);
            signal.addEventListener("abort", abort, { once: true });
        });
    }
    private release(): void {
        this.active--;
        this.queue.shift()?.accept();
    }
    async postJson(request: JsonRequest, call: CallContext): Promise<TransportResult> {
        const start = Date.now();
        const deadline = Math.min(call.deadlineMs, call.budget.deadlineMs, start + request.timeoutMs);
        const controller = new AbortController();
        const abort = () => controller.abort();
        call.signal?.addEventListener("abort", abort, { once: true });
        if (call.signal?.aborted || Date.now() >= deadline) controller.abort();
        const clearDeadline = deadlineTimer(deadline, abort);
        let attempts = 0;
        const reservationIds: string[] = [];
        const unavailable = (code: FailureCode): TransportResult => ({ status: "unavailable", code, attempts, reservationIds, elapsedMs: Date.now() - start });
        let release: (() => void) | undefined;
        try {
            release = await this.acquire(controller.signal, call.optional ?? false);
            for (let retry = 0; retry < (request.retry === false ? 1 : 2); retry++) {
                if (controller.signal.aborted) throw new TransportFailure("cancelled");
                if (Date.now() >= deadline) throw new TransportFailure("timeout");
                const reservation = call.budget.reserveAttempt({ optional: call.optional, estimatedUsd: request.estimatedUsd });
                if (!reservation.ok) throw new TransportFailure(reservation.code);
                reservationIds.push(reservation.id);
                attempts++;
                call.onAttempt?.();
                let response: Response;
                try {
                    response = await untilAborted(this.fetcher(request.url, {
                        method: "POST", headers: { "content-type": "application/json", ...request.headers },
                        body: request.body, redirect: "error", signal: controller.signal,
                    }), controller.signal);
                } catch {
                    if (controller.signal.aborted) throw new TransportFailure("cancelled");
                    if (retry === 0 && request.retry !== false && deadline - Date.now() > 100) {
                        await this.delay(100, controller.signal); continue;
                    }
                    throw new TransportFailure("transport");
                }
                if (Date.now() >= deadline) { void response.body?.cancel().catch(() => {}); controller.abort(); throw new TransportFailure("timeout"); }
                if (!response.ok) {
                    // Never read or expose a provider error body: it can echo
                    // credentials or untrusted input. Cancel even on redirects.
                    void response.body?.cancel().catch(() => {});
                    const transient = response.status === 429 || [500, 502, 503, 504, 529].includes(response.status);
                    const code: FailureCode = response.status === 401 || response.status === 403 ? "authentication" : response.status === 429 ? "rate_limited" : response.status === 413 ? "context_limit" : [400, 404, 422].includes(response.status) ? "unsupported" : "transport";
                    const delay = retryDelay(response.headers.get("retry-after"));
                    if (transient && retry === 0 && request.retry !== false && delay < deadline - Date.now()) {
                        await this.delay(delay, controller.signal); continue;
                    }
                    throw new TransportFailure(code);
                }
                if (response.redirected) { void response.body?.cancel().catch(() => {}); throw new TransportFailure("transport"); }
                const value = await this.readJson(response, request.maxResponseBytes ?? 1_048_576, controller.signal, deadline);
                if (Date.now() >= deadline) { controller.abort(); throw new TransportFailure("timeout"); }
                return { status: "ok", value, attempts, reservationIds, elapsedMs: Date.now() - start };
            }
            return unavailable("transport");
        } catch (error) {
            if (controller.signal.aborted) return unavailable(call.signal?.aborted ? "cancelled" : "timeout");
            return unavailable(error instanceof TransportFailure ? error.code : "transport");
        } finally {
            clearDeadline();
            call.signal?.removeEventListener("abort", abort);
            release?.();
        }
    }
    private async readJson(response: Response, maxBytes: number, signal: AbortSignal, deadlineMs: number): Promise<unknown> {
        const declared = response.headers.get("content-length");
        if (declared && Number(declared) > maxBytes) { void response.body?.cancel().catch(() => {}); throw new TransportFailure("invalid_response"); }
        if (!response.body) throw new TransportFailure("invalid_response");
        const reader = response.body.getReader();
        const chunks: Uint8Array[] = [];
        let bytes = 0;
        try {
            for (;;) {
                if (Date.now() >= deadlineMs) throw new TransportFailure("timeout");
                const next = await untilAborted(reader.read(), signal);
                if (next.done) break;
                bytes += next.value.byteLength;
                if (bytes > maxBytes) throw new TransportFailure("invalid_response");
                chunks.push(next.value);
            }
            const data = new Uint8Array(bytes);
            let offset = 0;
            for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.byteLength; }
            try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(data)); }
            catch { throw new TransportFailure("invalid_response"); }
        } finally { void reader.cancel().catch(() => {}); }
    }
    private async delay(ms: number, signal: AbortSignal): Promise<void> {
        let timer: ReturnType<typeof setTimeout> | undefined;
        try { await untilAborted(new Promise<void>((resolve) => { timer = setTimeout(resolve, ms); }), signal); }
        finally { if (timer) clearTimeout(timer); }
    }
}
function retryDelay(value: string | null): number {
    if (value !== null) {
        const seconds = Number(value);
        if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
        const date = Date.parse(value);
        if (Number.isFinite(date)) return Math.max(0, date - Date.now());
    }
    return 100;
}
