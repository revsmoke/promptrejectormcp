export interface CanaryToken {
    token: string;
    watchHandle: string;
    expiresAt: string;
}

export interface CanaryIssueOptions {
    context?: string;
    ttlSeconds?: number;
}

export interface CanaryEchoResult {
    echoDetected: boolean;
    matches: string[];
    severity: "safe" | "critical";
}

export class CanaryService {
    // Stub: real token issuance + state persistence lands in Pass 10
    issueToken(opts?: CanaryIssueOptions): CanaryToken {
        void opts;
        const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
        return {
            token: "00000000-0000-0000-0000-000000000000",
            watchHandle: "stub-handle",
            expiresAt,
        };
    }

    checkEcho(content: string): CanaryEchoResult {
        void content;
        return { echoDetected: false, matches: [], severity: "safe" };
    }
}
