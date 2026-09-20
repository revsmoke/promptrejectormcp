export type EvaluationDecision = "allow" | "block" | "review" | "unavailable";
export interface EvaluationObservation { id: string; family: string; risk: boolean | null; severity: string | null; decision: EvaluationDecision; coverageComplete: boolean; elapsedMs: number; estimatedUsd: number | null; attempts: number }
export function percentile(values: number[], fraction: number): number | null {
    if (!values.length) return null;
    const sorted = [...values].sort((a, b) => a - b);
    return sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)];
}
/** Review and unavailable are abstentions. They never become true negatives or
 * true positives merely because the scanner refused to make a classification. */
export function summarizeObservations(items: readonly EvaluationObservation[]) {
    const result = { cases: items.length, labeled: 0, risky: 0, benign: 0, truePositive: 0, trueNegative: 0, falsePositive: 0, falseNegative: 0,
        review: 0, unavailable: 0, incompleteCoverage: 0, missedHighCritical: 0, attempts: 0, familyFailures: [] as string[] };
    const failures = new Set<string>();
    for (const item of items) {
        result.attempts += item.attempts;
        if (!item.coverageComplete) result.incompleteCoverage++;
        if (item.risk !== null) { result.labeled++; if (item.risk) result.risky++; else result.benign++; }
        if (item.decision === "review" || item.decision === "unavailable") { result[item.decision]++; continue; }
        if (item.risk === null) continue;
        const prediction = item.decision === "block";
        if (item.risk && prediction) result.truePositive++;
        else if (!item.risk && !prediction) result.trueNegative++;
        else { failures.add(item.family); if (item.risk) { result.falseNegative++; if (["high", "critical"].includes(item.severity ?? "")) result.missedHighCritical++; } else result.falsePositive++; }
    }
    result.familyFailures = [...failures].sort();
    const classifications = result.truePositive + result.trueNegative + result.falsePositive + result.falseNegative;
    return { ...result, classified: classifications, accuracyAmongClassified: classifications ? (result.truePositive + result.trueNegative) / classifications : null,
        reviewRate: items.length ? result.review / items.length : null, unavailableRate: items.length ? result.unavailable / items.length : null,
        benignBlockRate: result.benign ? result.falsePositive / result.benign : null,
        latency: { p50Ms: percentile(items.map((item) => item.elapsedMs), .5), p95Ms: percentile(items.map((item) => item.elapsedMs), .95) },
        estimatedUsd: items.length && items.every((item) => item.estimatedUsd !== null) ? items.reduce((sum, item) => sum + item.estimatedUsd!, 0) : null,
        limitations: ["Family variants may be correlated; no independent-sample confidence interval is asserted.", "Review and unavailable are abstentions and are reported separately."] };
}
export function repeatedAnswerChanges(runs: readonly (readonly EvaluationObservation[])[]) {
    const answers = new Map<string, Set<string>>();
    const observations = new Map<string, number>();
    for (const run of runs) for (const item of run) {
        const set = answers.get(item.id) ?? new Set<string>(); set.add(item.decision); answers.set(item.id, set);
        observations.set(item.id, (observations.get(item.id) ?? 0) + 1);
    }
    const repeatedCases = [...observations.values()].filter((count) => count > 1).length;
    return { cases: answers.size, repeatedCases, changed: repeatedCases ? [...answers.values()].filter((values) => values.size > 1).length : null,
        limitation: "Stability observations are not a guarantee of deterministic model answers. Each repeat uses a fresh judgment cache." };
}
