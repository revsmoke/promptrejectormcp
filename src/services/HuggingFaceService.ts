export interface HuggingFaceFlagResult {
    flags: string[];
}

export class HuggingFaceService {
    // Stub: real implementation in Pass 8 will query HF Hub security signals
    async checkModel(modelId: string): Promise<HuggingFaceFlagResult> {
        void modelId;
        return { flags: [] };
    }
}
