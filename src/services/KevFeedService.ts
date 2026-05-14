export class KevFeedService {
    private kevSet: Set<string> = new Set();

    // Stub: real implementation in Pass 7 will fetch CISA KEV catalog JSON
    async refresh(): Promise<{ count: number }> {
        return { count: this.kevSet.size };
    }

    isInKev(cveId: string): boolean {
        return this.kevSet.has(cveId);
    }
}
