export interface ModelReferenceCandidate { id: string; repository: string; start: number; end: number; text: string; kind: "model" | "dataset" | "space" | "other-url" | "unresolved" }
export interface ModelReferenceExtraction { incumbentIds: string[]; baselineIds: string[]; candidates: ModelReferenceCandidate[]; candidateOverflow: boolean; candidateCount: number; parserCorrections: Array<{ source: string; kind: string; repository: string | null }> }
interface Span { repository: string; start: number; end: number }
interface URLSpan extends Span { kind: ModelReferenceCandidate["kind"]; source: string }
const keyword = /\b(model|pretrained|huggingface|hf_hub|transformers|from_pretrained)\b/i;
function looksLikeIncumbentId(value: string): boolean {
    if (value.split("/").length !== 2 || /\.(json|md|txt|js|ts|py|html|css|png|jpe?g|gif|svg|yaml|yml|toml|lock|sh|cfg|ini)$/i.test(value)) return false;
    const [owner, name] = value.split("/");
    return !(/^\d+$/.test(owner) && /^\d+$/.test(name)) && owner.length >= 2 && name.length >= 2 && !/^[a-z0-9-]+\.(co|com|org|io|net|ai|app|dev|gg|me)$/i.test(owner);
}
function bareSpans(text: string): Span[] {
    return [...text.matchAll(/\b([A-Za-z0-9_.][A-Za-z0-9_.-]*\/[A-Za-z0-9_.][A-Za-z0-9_.-]*)\b/g)]
        .map((match) => ({ repository: match[1], start: match.index!, end: match.index! + match[1].length }));
}
function incumbentSpans(text: string): Span[] {
    const urls = [...text.matchAll(/huggingface\.co\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)/g)]
        .filter((match) => looksLikeIncumbentId(match[1]))
        .map((match) => ({ repository: match[1], start: match.index!, end: match.index! + match[0].length }));
    return [...urls, ...bareSpans(text).filter((span) => looksLikeIncumbentId(span.repository) && keyword.test(text.slice(Math.max(0, span.start - 80), Math.min(text.length, span.end + 80))))];
}
/** Preserve the exact pre-rollout extraction as a separately measured ablation. */
export function extractIncumbentModelIds(text: string): string[] { return [...new Set(incumbentSpans(text).map((span) => span.repository))]; }
function urlSpans(text: string): URLSpan[] {
    // Find every start independently before consuming a token. Adjacent URLs
    // separated by uncommon punctuation must not hide the second repository.
    const starts = [...text.matchAll(/https?:\/\/[^/\s<>"'`()\[\],;|\\、]+(?=\/)|\b(?:www\.)?huggingface\.co(?=\/)/gi)];
    return starts.map((match, index) => {
        const segment = text.slice(match.index!, starts[index + 1]?.index ?? text.length);
        const source = segment.match(/^[^\s<>"'`()\[\],;|\\、]+/)?.[0] ?? match[0];
        const trimmed = source.replace(/[.,;:!?)\]}]+$/, "");
        const span: URLSpan = { repository: "", start: match.index!, end: match.index! + source.length, source, kind: "other-url" };
        try {
            const url = new URL(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
            if (!["huggingface.co", "www.huggingface.co"].includes(url.hostname) || url.username || url.password) return span;
            span.kind = "unresolved";
            const parts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
            const prefix = parts[0];
            const kind = prefix === "datasets" ? "dataset" : prefix === "spaces" ? "space" : "model";
            if (["docs", "api", "blog", "organizations", "settings", "join", "login", "kernels", "buckets"].includes(prefix)) { span.kind = "other-url"; return span; }
            if (kind !== "model") parts.shift();
            if (parts.length < 2 || !parts.slice(0, 2).every((part) => /^[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?$/.test(part))) return span;
            span.repository = parts.slice(0, 2).join("/"); span.kind = kind;
        } catch { /* Malformed URLs cannot establish an exact repository. */ }
        return span;
    });
}
/** Parse exact URL resources first, then retain all remaining incumbent bare
 * IDs. Semantic candidates are an additive diagnostic set, never a filter on
 * this authoritative baseline. Off/shadow callers audit baselineIds only. */
export function extractModelReferences(text: string, maxCandidates = 64): ModelReferenceExtraction {
    if (!Number.isSafeInteger(maxCandidates) || maxCandidates < 1 || maxCandidates > 256) throw new Error("Invalid candidate limit");
    const urls = urlSpans(text);
    const containingUrl = (offset: number): URLSpan | undefined => {
        let low = 0, high = urls.length - 1;
        while (low <= high) {
            const middle = (low + high) >>> 1;
            const url = urls[middle];
            if (offset < url.start) high = middle - 1;
            else if (offset >= url.end) low = middle + 1;
            else return url;
        }
        return undefined;
    };
    const incumbent = incumbentSpans(text);
    const baseline = new Set<string>();
    const corrections: ModelReferenceExtraction["parserCorrections"] = [];
    for (const span of incumbent) {
        const exact = containingUrl(span.start);
        if (!exact || exact.kind === "unresolved") baseline.add(span.repository);
        else if (exact.kind === "model") baseline.add(exact.repository);
        if (exact && exact.kind !== "unresolved" && (exact.kind !== "model" || exact.repository !== span.repository)) corrections.push({ source: exact.source, kind: exact.kind, repository: exact.repository || null });
    }
    for (const url of urls) if (url.kind === "model") baseline.add(url.repository);
    const candidates = [
        ...urls.filter((url) => url.repository).map((url) => ({ repository: url.repository, start: url.start, end: url.end, kind: url.kind })),
        ...bareSpans(text).filter((span) => { const url = containingUrl(span.start); return !url || url.kind === "unresolved"; }).map((span) => ({ ...span, kind: "unresolved" as const })),
    ].sort((left, right) => left.start - right.start);
    const seenCorrections = new Set<string>();
    return { incumbentIds: [...new Set(incumbent.map((span) => span.repository))], baselineIds: [...baseline], candidateCount: candidates.length, candidateOverflow: candidates.length > maxCandidates,
        candidates: candidates.slice(0, maxCandidates).map((candidate, index) => ({ ...candidate, id: `c${index}`, text: text.slice(candidate.start, candidate.end) })),
        parserCorrections: corrections.filter((item) => { const key = `${item.kind}:${item.source}`; if (seenCorrections.has(key)) return false; seenCorrections.add(key); return true; }),
    };
}
