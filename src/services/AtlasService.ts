export interface AtlasTechnique {
    id: string;
    name: string;
    tactic: string;
}

export class AtlasService {
    private stubEntries: Record<string, AtlasTechnique> = {
        "AML.T0051": {
            id: "AML.T0051",
            name: "LLM Prompt Injection",
            tactic: "Initial Access",
        },
    };

    lookup(techniqueId: string): AtlasTechnique | null {
        return this.stubEntries[techniqueId] || null;
    }
}
