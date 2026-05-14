export interface OsvVuln {
    id: string;
    summary: string;
    ecosystem: string;
    packageName: string;
    aliases: string[];
    severity: string;
}

export interface OsvPackageQuery {
    ecosystem: string;
    name: string;
}

export class OsvFeedService {
    // Stub: real implementation in Pass 6 will hit /v1/querybatch
    async query(packages: OsvPackageQuery[]): Promise<OsvVuln[]> {
        void packages;
        return [];
    }
}
