// Lightweight fetch mock helper used by VulnFeedService Pass 6 tests.
// We replace globalThis.fetch for the duration of fn(), then always restore —
// even on throw — so a failing test can't poison later suites.

export type FetchHandler = (url: string, init?: RequestInit) => Promise<Response>;

export async function withMockedFetch(handler: FetchHandler, fn: () => Promise<void>): Promise<void> {
    const original = globalThis.fetch;
    globalThis.fetch = handler as any;
    try {
        await fn();
    } finally {
        globalThis.fetch = original;
    }
}

// Build a JSON Response with sensible defaults.
export function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
    });
}
