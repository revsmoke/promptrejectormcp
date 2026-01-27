import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { SecurityService } from "../services/SecurityService.js";
import { z } from "zod";

export class PromptRejectorMCPServer {
    private server: Server;
    private securityService: SecurityService;

    constructor() {
        this.securityService = new SecurityService();
        this.server = new Server(
            {
                name: "prompt-rejector",
                version: "1.0.0",
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
                ],
            };
        });

        // Handle tool calls
        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            const { name, arguments: args } = request.params;

            if (name === "check_prompt") {
                const { prompt } = args as { prompt: string };
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

            throw new Error(`Unknown tool: ${name}`);
        });
    }

    async run() {
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        console.error("[MCP] PromptRejector MCP server running on stdio");
    }
}
