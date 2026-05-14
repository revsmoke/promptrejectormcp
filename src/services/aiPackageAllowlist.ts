// Allowlist of AI / agent / ML packages whose vulnerabilities are relevant to
// prompt-injection-adjacent risk. Used by OsvFeedService.query() and as a
// post-filter for GhsaGraphQLService.query() to keep only AI-ecosystem advisories.

export type EcosystemPackage = {
    // OSV-style ecosystem names. GHSA GraphQL uses different identifiers
    // ("PIP", "NPM") — see ECOSYSTEMS_FOR_GHSA below for that mapping.
    ecosystem: "PyPI" | "npm" | "Go" | "Maven";
    name: string;
};

export const AI_PACKAGE_ALLOWLIST: EcosystemPackage[] = [
    // Python — agent frameworks
    { ecosystem: "PyPI", name: "langchain" },
    { ecosystem: "PyPI", name: "langchain-core" },
    { ecosystem: "PyPI", name: "langchain-community" },
    { ecosystem: "PyPI", name: "langgraph" },
    { ecosystem: "PyPI", name: "llama-index" },
    { ecosystem: "PyPI", name: "autogen" },
    { ecosystem: "PyPI", name: "crewai" },
    { ecosystem: "PyPI", name: "transformers" },
    { ecosystem: "PyPI", name: "vllm" },
    { ecosystem: "PyPI", name: "sglang" },
    { ecosystem: "PyPI", name: "litellm" },
    { ecosystem: "PyPI", name: "mlflow" },
    { ecosystem: "PyPI", name: "ollama" },
    { ecosystem: "PyPI", name: "openai" },
    { ecosystem: "PyPI", name: "anthropic" },
    // JS — agent frameworks
    { ecosystem: "npm", name: "@langchain/core" },
    { ecosystem: "npm", name: "@langchain/community" },
    { ecosystem: "npm", name: "langchain" },
    { ecosystem: "npm", name: "@huggingface/transformers" },
    { ecosystem: "npm", name: "@anthropic-ai/sdk" },
    { ecosystem: "npm", name: "openai" },
    { ecosystem: "npm", name: "ollama" },
    { ecosystem: "npm", name: "llamaindex" },
];

// GHSA GraphQL ecosystem enum values we scan. OSV "PyPI" -> GHSA "PIP", OSV "npm" -> GHSA "NPM".
export const ECOSYSTEMS_FOR_GHSA = ["PIP", "NPM"] as const;
export type GhsaEcosystem = (typeof ECOSYSTEMS_FOR_GHSA)[number];

// Build a fast lookup set: lowercase "<ghsa-ecosystem>:<name>" for post-filter.
const _ghsaAllowlistKeys = new Set<string>(
    AI_PACKAGE_ALLOWLIST.map((p) => {
        const ghsaEco = p.ecosystem === "PyPI" ? "PIP" : p.ecosystem === "npm" ? "NPM" : p.ecosystem.toUpperCase();
        return `${ghsaEco}:${p.name.toLowerCase()}`;
    }),
);

export function isAllowedGhsaPackage(ghsaEcosystem: string, packageName: string): boolean {
    return _ghsaAllowlistKeys.has(`${ghsaEcosystem.toUpperCase()}:${packageName.toLowerCase()}`);
}
