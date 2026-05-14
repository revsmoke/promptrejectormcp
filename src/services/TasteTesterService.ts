export interface TasteTesterInput {
    prompt: string;
    mode?: "fast" | "thorough";
    context?: string;
}

export interface TasteTesterIntent {
    action: string;
    target: string;
    severity: "safe" | "medium" | "high" | "critical";
    atlasTechniques: string[];
}

export interface TasteTesterBehaviorReport {
    intents: TasteTesterIntent[];
    monitorVerdict: "clean" | "suspicious" | "malicious";
    monitorRationale: string;
    severity: "safe" | "medium" | "high" | "critical";
}

export interface TasterTurn {
    role: string;
    content: string;
}

export interface TasteTesterResult {
    available: boolean;
    behaviorReport: TasteTesterBehaviorReport;
    tasterTranscript: TasterTurn[];
}

export class TasteTesterService {
    // Stub: real dual-agent sandbox lands in Pass 11
    async run(input: TasteTesterInput): Promise<TasteTesterResult> {
        void input;
        return {
            available: process.env.TASTE_TESTER_ENABLED === "true",
            behaviorReport: {
                intents: [],
                monitorVerdict: "clean",
                monitorRationale: "stub",
                severity: "safe",
            },
            tasterTranscript: [],
        };
    }
}
