import { createHash } from "crypto";

export interface McpToolScanInput {
    tool: object;
    priorHash?: string;
}

export interface McpToolScanResult {
    hash: string;
    drift: boolean;
    findings: any[];
    severity: "safe";
}

export class McpToolScanner {
    // Stub: lint + drift detection lands in Pass 4
    scan(input: McpToolScanInput): McpToolScanResult {
        const serialized = JSON.stringify(input.tool);
        const hash = createHash("sha256").update(serialized).digest("hex");
        return {
            hash,
            drift: false,
            findings: [],
            severity: "safe",
        };
    }
}
