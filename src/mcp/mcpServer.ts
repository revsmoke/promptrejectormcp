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
import { UnifiedCveCache, type QueryCveFilters } from "../services/UnifiedCveCache.js";

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
    private unifiedCveCache: UnifiedCveCache;

    constructor() {
        this.patternService = new PatternService();
        this.securityService = new SecurityService(this.patternService);
        // Pass 8: instantiate HF service before SkillScanService so the same
        // instance (and its in-memory cache) is shared by every scan.
        this.huggingFaceService = new HuggingFaceService();
        this.skillScanService = new SkillScanService(this.patternService, this.huggingFaceService);
        this.atlasService = new AtlasService();
        this.osvFeedService = new OsvFeedService();
        this.ghsaGraphQLService = new GhsaGraphQLService();
        this.kevFeedService = new KevFeedService();
        // Pass 7: wire ATLAS + KEV into VulnFeedService so candidates pick up
        // taxonomy tags and KEV-escalated severity at staging time.
        this.vulnFeedService = new VulnFeedService(
            this.patternService,
            undefined,
            undefined,
            this.osvFeedService,
            this.ghsaGraphQLService,
            this.atlasService,
            this.kevFeedService,
        );
        this.trifectaAnalyzer = new TrifectaAnalyzer();
        this.canaryService = new CanaryService();
        this.mcpToolScanner = new McpToolScanner(this.patternService);
        this.tasteTesterService = new TasteTesterService();
        // Pass 9: read-only aggregator over staged CVE candidates. Depends on
        // vulnFeedService + atlasService + kevFeedService already being live.
        this.unifiedCveCache = new UnifiedCveCache(
            this.vulnFeedService,
            this.atlasService,
            this.kevFeedService,
        );
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
        // Small helper to produce the standard MCP-shaped validation error response
        // without throwing. MCP clients expect JSON-RPC-shaped error content, so all
        // bad-input paths return a { content: [...] } object rather than throwing.
        const validationError = (msg: string) => ({
            content: [{ type: "text", text: JSON.stringify({ error: msg }, null, 2) }],
        });

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
                        description: "Lint an MCP tool descriptor for tool-poisoning signals (imperative override language, hidden Unicode) and compute a canonical SHA-256 hash; reports descriptor drift when a priorHash is supplied.",
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
                                tools: {
                                    type: "array",
                                    items: { type: "string" },
                                    description: "Optional list of tool names declared by the skill/agent.",
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
                const a = (args || {}) as { tool?: unknown; priorHash?: unknown };
                // tool must be a non-null object (not array, not null, not primitive)
                if (!a.tool || typeof a.tool !== "object" || Array.isArray(a.tool)) {
                    return validationError("tool is required and must be a non-null object");
                }
                if (a.priorHash !== undefined && typeof a.priorHash !== "string") {
                    return validationError("priorHash must be a string if provided");
                }
                const result = this.mcpToolScanner.scan({ tool: a.tool as object, priorHash: a.priorHash as string | undefined });
                return {
                    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
                };
            }

            if (name === "check_lethal_trifecta") {
                const a = (args || {}) as { capabilities?: unknown; tools?: unknown; skillContent?: unknown };
                // At least one of capabilities/tools/skillContent must be present.
                if (a.capabilities === undefined && a.tools === undefined && a.skillContent === undefined) {
                    return validationError("at least one of capabilities, tools, or skillContent is required");
                }
                if (a.capabilities !== undefined) {
                    if (!Array.isArray(a.capabilities) || !a.capabilities.every((c) => typeof c === "string")) {
                        return validationError("capabilities must be an array of strings if provided");
                    }
                }
                if (a.tools !== undefined) {
                    if (!Array.isArray(a.tools) || !a.tools.every((t) => typeof t === "string")) {
                        return validationError("tools must be an array of strings if provided");
                    }
                }
                if (a.skillContent !== undefined) {
                    if (typeof a.skillContent !== "string" || a.skillContent.length > 500_000) {
                        return validationError("skillContent must be a string of at most 500,000 characters if provided");
                    }
                }
                const result = this.trifectaAnalyzer.analyze({
                    capabilities: a.capabilities as string[] | undefined,
                    tools: a.tools as string[] | undefined,
                    skillContent: a.skillContent as string | undefined,
                });
                return {
                    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
                };
            }

            if (name === "query_cve") {
                // Pass 9: real implementation backed by UnifiedCveCache.
                const a = (args || {}) as Record<string, unknown>;
                if (a.keyword !== undefined && typeof a.keyword !== "string") {
                    return validationError("keyword must be a string if provided");
                }
                if (a.ecosystem !== undefined && typeof a.ecosystem !== "string") {
                    return validationError("ecosystem must be a string if provided");
                }
                if (a.atlasTechnique !== undefined && typeof a.atlasTechnique !== "string") {
                    return validationError("atlasTechnique must be a string if provided");
                }
                if (a.severity !== undefined && typeof a.severity !== "string") {
                    return validationError("severity must be a string if provided");
                }
                if (a.inKev !== undefined && typeof a.inKev !== "boolean") {
                    return validationError("inKev must be a boolean if provided");
                }
                if (a.limit !== undefined) {
                    if (typeof a.limit !== "number" || !Number.isInteger(a.limit) || a.limit < 1 || a.limit > 200) {
                        return validationError("limit must be an integer between 1 and 200 if provided");
                    }
                }
                const result = this.unifiedCveCache.query(a as QueryCveFilters);
                return {
                    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
                };
            }

            if (name === "deploy_canary") {
                const a = (args || {}) as { context?: unknown; ttlSeconds?: unknown };
                if (a.context !== undefined) {
                    if (typeof a.context !== "string" || a.context.length > 1000) {
                        return validationError("context must be a string of at most 1,000 characters if provided");
                    }
                }
                // ttlSeconds: positive integer up to 30 days (86400 * 30 = 2,592,000)
                const MAX_TTL_SECONDS = 86_400 * 30;
                if (a.ttlSeconds !== undefined) {
                    if (
                        typeof a.ttlSeconds !== "number" ||
                        !Number.isInteger(a.ttlSeconds) ||
                        a.ttlSeconds < 1 ||
                        a.ttlSeconds > MAX_TTL_SECONDS
                    ) {
                        return validationError(`ttlSeconds must be a positive integer up to ${MAX_TTL_SECONDS} (30 days) if provided`);
                    }
                }
                const result = this.canaryService.issueToken({
                    context: a.context as string | undefined,
                    ttlSeconds: a.ttlSeconds as number | undefined,
                });
                return {
                    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
                };
            }

            if (name === "verify_canary") {
                const a = (args || {}) as { content?: unknown; watchHandle?: unknown };
                if (typeof a.content !== "string" || a.content.length < 1 || a.content.length > 500_000) {
                    return validationError("content is required and must be a string of 1-500,000 characters");
                }
                if (a.watchHandle !== undefined) {
                    if (typeof a.watchHandle !== "string" || !/^[a-f0-9]{12}$/i.test(a.watchHandle)) {
                        return validationError("watchHandle must be a 12-character hex string if provided");
                    }
                }
                const result = this.canaryService.checkEcho(a.content, a.watchHandle as string | undefined);
                return {
                    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
                };
            }

            if (name === "taste_test") {
                const a = (args || {}) as { prompt?: unknown; mode?: unknown; context?: unknown };
                if (typeof a.prompt !== "string" || a.prompt.length < 1 || a.prompt.length > 100_000) {
                    return validationError("prompt is required and must be a string of 1-100,000 characters");
                }
                if (a.mode !== undefined && a.mode !== "fast" && a.mode !== "thorough") {
                    return validationError("mode must be 'fast' or 'thorough' if provided");
                }
                if (a.context !== undefined) {
                    if (typeof a.context !== "string" || a.context.length > 100_000) {
                        return validationError("context must be a string of at most 100,000 characters if provided");
                    }
                }
                const result = await this.tasteTesterService.run({
                    prompt: a.prompt,
                    mode: a.mode as "fast" | "thorough" | undefined,
                    context: a.context as string | undefined,
                });
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
