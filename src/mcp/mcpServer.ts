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

const require = createRequire(import.meta.url);
const { version } = require("../../package.json");

export class PromptRejectorMCPServer {
    private server: Server;
    private securityService: SecurityService;
    private skillScanService: SkillScanService;
    private patternService: PatternService;
    private vulnFeedService: VulnFeedService;

    constructor() {
        this.patternService = new PatternService();
        this.securityService = new SecurityService(this.patternService);
        this.skillScanService = new SkillScanService(this.patternService);
        this.vulnFeedService = new VulnFeedService(this.patternService);
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

            throw new Error(`Unknown tool: ${name}`);
        });
    }

    async run() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error("[MCP] PromptRejector MCP server running on stdio");
    }
}
