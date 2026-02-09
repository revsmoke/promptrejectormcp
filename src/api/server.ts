import express from "express";
import cors from "cors";
import { createRequire } from "module";
import { SecurityService } from "../services/SecurityService.js";
import { SkillScanService } from "../services/SkillScanService.js";
import { PatternService } from "../services/PatternService.js";
import { VulnFeedService } from "../services/VulnFeedService.js";
import { z } from "zod";

const require = createRequire(import.meta.url);
const { version } = require("../../package.json");

const app = express();
const port = process.env.PORT || 3000;

const patternService = new PatternService();
const securityService = new SecurityService(patternService);
const skillScanService = new SkillScanService(patternService);
const vulnFeedService = new VulnFeedService(patternService);

const corsOrigin = process.env.CORS_ORIGIN || "*";
app.use(cors({ origin: corsOrigin === "*" ? true : corsOrigin.split(",") }));
app.use(express.json());

// Validation schemas
const CheckPromptSchema = z.object({
    prompt: z.string().min(1, "Prompt cannot be empty").max(100_000, "Prompt exceeds 100,000 character limit"),
});

const ScanSkillSchema = z.object({
    skillContent: z.string().min(1, "Skill content cannot be empty").max(500_000, "Skill content exceeds 500,000 character limit"),
});

const UpdateFeedsSchema = z.object({
    lookbackDays: z.number().int().min(1).max(365).optional(),
}).optional();

const ListPatternsQuerySchema = z.object({
    category: z.string().optional(),
    scope: z.enum(["general", "skill"]).optional(),
    enabled: z.enum(["true", "false"]).optional(),
});

// Primary Endpoint - Check Prompt
app.post("/v1/check-prompt", async (req, res) => {
    try {
        const validatedBody = CheckPromptSchema.parse(req.body);
        const report = await securityService.runSecurityScan(validatedBody.prompt);

        res.json(report);
    } catch (error) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request body", details: error.issues });
        }
        console.error("API Error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Skill Scanning Endpoint
app.post("/v1/scan-skill", async (req, res) => {
    try {
        const validatedBody = ScanSkillSchema.parse(req.body);
        const report = await skillScanService.scanSkill(validatedBody.skillContent);

        res.json(report);
    } catch (error) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request body", details: error.issues });
        }
        console.error("API Error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Pattern Library Endpoints
app.get("/v1/patterns", (req, res) => {
    try {
        const query = ListPatternsQuerySchema.parse(req.query);
        const filters: any = {};
        if (query.category) filters.category = query.category;
        if (query.scope) filters.scope = query.scope;
        if (query.enabled !== undefined) filters.enabled = query.enabled === "true";

        const patterns = patternService.list(filters);
        res.json({ count: patterns.length, patterns });
    } catch (error) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid query parameters", details: error.issues });
        }
        console.error("API Error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/v1/patterns/update-feeds", async (req, res) => {
    try {
        const body = UpdateFeedsSchema.parse(req.body);
        const result = await vulnFeedService.updateFeeds(body?.lookbackDays);
        res.json(result);
    } catch (error) {
        if (error instanceof z.ZodError) {
            return res.status(400).json({ error: "Invalid request body", details: error.issues });
        }
        console.error("API Error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/v1/patterns/verify", (req, res) => {
    try {
        const result = patternService.verify();
        res.json(result);
    } catch (error) {
        console.error("API Error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Health check
app.get("/health", (req, res) => {
    res.json({ status: "ok", version });
});

export function startApiServer() {
    app.listen(port, () => {
        console.error(`[API] PromptRejector API running at http://localhost:${port}`);
    });
}

export default app;
