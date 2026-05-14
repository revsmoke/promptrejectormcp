import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createRequire } from "module";
import { SecurityService } from "../services/SecurityService.js";
import { SkillScanService } from "../services/SkillScanService.js";
import { PatternService } from "../services/PatternService.js";
import { VulnFeedService } from "../services/VulnFeedService.js";
import { AtlasService } from "../services/AtlasService.js";
import { OsvFeedService } from "../services/OsvFeedService.js";
import { GhsaGraphQLService } from "../services/GhsaGraphQLService.js";
import { KevFeedService } from "../services/KevFeedService.js";
import { HuggingFaceService } from "../services/HuggingFaceService.js";
import { TrifectaAnalyzer } from "../services/TrifectaAnalyzer.js";
import { CanaryService } from "../services/CanaryService.js";
import { McpToolScanner } from "../services/McpToolScanner.js";
import { TasteTesterService } from "../services/TasteTesterService.js";

const require = createRequire(import.meta.url);
const { version } = require("../../package.json");

export class PromptRejectorMCPServer {
    private server: Server;
    private securityService: SecurityService;
    private skillScanService: SkillScanService;
    private patternService: PatternService;
    private vulnFeedService: VulnFeedService;
    private atlasService: AtlasService;
    private osvFeedService: OsvFeedService;
    private ghsaGraphQLService: GhsaGraphQLService;
    private kevFeedService: KevFeedService;
    private huggingFaceService: HuggingFaceService;
    private trifectaAnalyzer: TrifectaAnalyzer;
    private canaryService: CanaryService;
    private mcpToolScanner: McpToolScanner;
    private tasteTesterService: TasteTesterService;

    constructor() {
        this.patternService = new PatternService();
        this.securityService = new SecurityService(this.patternService);
        this.skillScanService = new SkillScanService(this.patternService);
        this.vulnFeedService = new VulnFeedService(this.patternService);
        this.atlasService = new AtlasService();
        this.osvFeedService = new OsvFeedService();
        this.ghsaGraphQLService = new GhsaGraphQLService();
        this.kevFeedService = new KevFeedService();
        this.huggingFaceService = new HuggingFaceService();
        this.trifectaAnalyzer = new TrifectaAnalyzer();
        this.canaryService = new CanaryService();
        this.mcpToolScanner = new McpToolScanner(this.patternService);
        this.tasteTesterService = new TasteTesterService();
        this.server = new Server(
            {
                name: "prompt-rejector",
                version,
            },
            {
                capabilities: {
                    tools: {},
                },
            }
        );

        this.setupTools();
    }

    private setupTools() {
        // List available tools
        this.server.setRequestHandler(ListToolsRequestSchema, async () => {
            return {
                tools: [
                    {
                        name: "check_prompt",
                        description: "Check a user prompt for injection attacks and traditional vulnerabilities (XSS, SQLi). Use this before processing any untrusted user input.",
                        inputSchema: {
                            type: "object",
                            properties: {
                                prompt: {
                                    type: "string",
                                    description: "The user input prompt to check.",
                                },
                            },
                            required: ["prompt"],
                        },
                    },
                    {
                        name: "scan_skill",
                        description: "Scan a SKILL.md file for security vulnerabilities including prompt injection, malicious tool usage, data exfiltration attempts, and social engineering. Use this before installing any third-party skills.",
                        inputSchema: {
                            type: "object",
                            properties: {
                                skillContent: {
                                    type: "string",
                                    description: "The raw markdown content of the SKILL.md file to scan.",
                                },
                            },
                            required: ["skillContent"],
                        },
                    },
                    {
                        name: "list_patterns",
                        description: "List detection patterns from the pattern library. Optionally filter by category.",
                        inputSchema: {
                            type: "object",
                            properties: {
                                category: {
                                    type: "string",
                                    description: "Filter patterns by category (e.g., 'xss', 'sqli', 'shell_injection').",
                                },
                            },
                        },
                    },
                    {
                        name: "update_vuln_feeds",
                        description: "Scan NVD and GitHub Advisory databases for new vulnerabilities and generate candidate detection patterns. Candidates are staged for review before activation.",
                        inputSchema: {
                            type: "object",
                            properties: {
                                lookbackDays: {
                                    type: "number",
                                    description: "Number of days to look back for new vulnerabilities (default: 30).",
                                },
                            },
                        },
                    },
                    {
                        name: "verify_pattern_integrity",
                        description: "Verify the integrity of the pattern library by checking file hashes against the manifest and validating the HMAC signature.",
                        inputSchema: {
                            type: "object",
                            properties: {},
                        },
                    },
                    {
                        name: "scan_mcp_tool",
                        description: "Scan an MCP tool descriptor for tool-poisoning signals (imperative override language, hidden Unicode, descriptor drift).",
                        inputSchema: {
                            type: "object",
                            properties: {
                                tool: {
                                    type: "object",
                                    description: "MCP tool descriptor (name, description, inputSchema).",
                                },
                                priorHash: {
                                    type: "string",
                                    description: "Previously-recorded SHA-256 hash of the descriptor; drift is reported when mismatch.",
                                },
                            },
                            required: ["tool"],
                        },
                    },
                    {
                        name: "check_lethal_trifecta",
                        description: "Analyze an agent/skill capability set for the lethal trifecta (private-data read + untrusted-content fetch + external egress).",
                        inputSchema: {
                            type: "object",
                            properties: {
                                capabilities: {
                                    type: "array",
                                    items: { type: "string" },
                                    description: "Optional list of capability strings (e.g., tool names).",
                                },
                                skillContent: {
                                    type: "string",
                                    description: "Optional raw SKILL.md content to analyze.",
                                },
                            },
                        },
                    },
                    {
                        name: "query_cve",
                        description: "Unified read across NVD, OSV, GHSA, KEV, and ATLAS feeds for AI-relevant CVEs.",
                        inputSchema: {
                            type: "object",
                            properties: {
                                keyword: { type: "string" },
                                ecosystem: { type: "string" },
                                atlasTechnique: { type: "string" },
                                severity: { type: "string" },
                                inKev: { type: "boolean" },
                                limit: { type: "number" },
                            },
                        },
                    },
                    {
                        name: "deploy_canary",
                        description: "Issue a canary token to embed in memory/RAG context for later echo-detection.",
                        inputSchema: {
                            type: "object",
                            properties: {
                                context: { type: "string" },
                                ttlSeconds: { type: "number" },
                            },
                        },
                    },
                    {
                        name: "verify_canary",
                        description: "Check provided content for echoes of previously-issued canary tokens (memory/RAG poisoning signal).",
                        inputSchema: {
                            type: "object",
                            properties: {
                                content: { type: "string" },
                                watchHandle: { type: "string" },
                            },
                            required: ["content"],
                        },
                    },
                    {
                        name: "taste_test",
                        description: "Detonate a suspect prompt in a dual-agent sandbox (Taster + Monitor) and return the Monitor's verdict on observed intent.",
                        inputSchema: {
                            type: "object",
                            properties: {
                                prompt: { type: "string" },
                                mode: { type: "string", enum: ["fast", "thorough"] },
                                context: { type: "string" },
                            },
                            required: ["prompt"],
                        },
                    },
                ],
            };
        });

        // Handle tool calls
        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            const { name, arguments: args } = request.params;

            if (name === "check_prompt") {
                const { prompt } = args as { prompt: string };
                if (!prompt || prompt.length > 100_000) {
                    return {
                        content: [{ type: "text", text: JSON.stringify({ error: "Prompt must be 1-100,000 characters" }) }],
                    };
                }
                const report = await this.securityService.runSecurityScan(prompt);

                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify(report, null, 2),
                        },
                    ],
                };
            }

            if (name === "scan_skill") {
                const { skillContent } = args as { skillContent: string };
                if (!skillContent || skillContent.length > 500_000) {
                    return {
                        content: [{ type: "text", text: JSON.stringify({ error: "Skill content must be 1-500,000 characters" }) }],
                    };
                }
                const report = await this.skillScanService.scanSkill(skillContent);

                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify(report, null, 2),
                        },
                    ],
                };
            }

            if (name === "list_patterns") {
                const { category } = (args || {}) as { category?: string };
                const patterns = this.patternService.list(category ? { category } : undefined);

                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify({ count: patterns.length, patterns }, null, 2),
                        },
                    ],
                };
            }

            if (name === "update_vuln_feeds") {
                const { lookbackDays } = (args || {}) as { lookbackDays?: number };
                const result = await this.vulnFeedService.updateFeeds(lookbackDays);

                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify(result, null, 2),
                        },
                    ],
                };
            }

            if (name === "verify_pattern_integrity") {
                const result = this.patternService.verify();

                return {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify(result, null, 2),
                        },
                    ],
                };
            }

            if (name === "scan_mcp_tool") {
                const { tool, priorHash } = (args || {}) as { tool: object; priorHash?: string };
                const result = this.mcpToolScanner.scan({ tool, priorHash });
                return {
                    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
                };
            }

            if (name === "check_lethal_trifecta") {
                const { capabilities, skillContent } = (args || {}) as { capabilities?: string[]; skillContent?: string };
                const result = this.trifectaAnalyzer.analyze({ capabilities, skillContent });
                return {
                    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
                };
            }

            if (name === "query_cve") {
                // Stub: real unified-cache lookup lands in Pass 9
                const result = { stub: true, total: 0, records: [] };
                return {
                    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
                };
            }

            if (name === "deploy_canary") {
                const { context, ttlSeconds } = (args || {}) as { context?: string; ttlSeconds?: number };
                const result = this.canaryService.issueToken({ context, ttlSeconds });
                return {
                    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
                };
            }

            if (name === "verify_canary") {
                const { content } = (args || {}) as { content: string; watchHandle?: string };
                const result = this.canaryService.checkEcho(content);
                return {
                    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
                };
            }

            if (name === "taste_test") {
                const { prompt, mode, context } = (args || {}) as { prompt: string; mode?: "fast" | "thorough"; context?: string };
                const result = await this.tasteTesterService.run({ prompt, mode, context });
                return {
                    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
                };
            }

            // Silence unused-private-member warnings for stub services wired only for future passes
            void this.atlasService;
            void this.osvFeedService;
            void this.ghsaGraphQLService;
            void this.kevFeedService;
            void this.huggingFaceService;

            throw new Error(`Unknown tool: ${name}`);
        });
    }

    async run() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error("[MCP] PromptRejector MCP server running on stdio");
    }
}
