export interface GhsaAdvisory {
    ghsaId: string;
    cveId: string | null;
    summary: string;
    ecosystem: string;
    severity: string;
    publishedAt: string;
}

export class GhsaGraphQLService {
    // Stub: real implementation in Pass 6 will query GitHub GraphQL securityVulnerabilities
    async query(ecosystem: string, limit: number = 50): Promise<GhsaAdvisory[]> {
        void ecosystem;
        void limit;
        return [];
    }
}
