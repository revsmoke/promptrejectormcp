import { qualificationStatus } from "../ai/qualification.js";
import express from "express";
import cors from "cors";
import { createRequire } from "module";
import type { Services } from "../bootstrap.js";
import { promptInputSchema, skillInputSchema, isSizeError } from "../ai/schemas.js";
import { ReportVersionRequiredError } from "../services/SecurityService.js";
import { scanPromptReport, scanSkillReport } from "./reportSerializers.js";
import { z } from "zod";

const require = createRequire(import.meta.url);
const { version } = require("../../package.json");

export function createApiApp(services: Services) {
    const app = express();
    const { patternService, vulnFeedService } = services;

    const corsOrigin = process.env.CORS_ORIGIN || "*";
    app.use(cors({ origin: corsOrigin === "*" ? true : corsOrigin.split(",") }));
    app.use(express.json({ limit: "4mb" }));

    // Validation schemas
    const UpdateFeedsSchema = z.object({
        lookbackDays: z.number().int().min(1).max(365).optional(),
    }).optional();

    const ListPatternsQuerySchema = z.object({
        category: z.string().optional(),
        scope: z.enum(["general", "skill"]).optional(),
        enabled: z.enum(["true", "false"]).optional(),
    });

    // Primary Endpoint - Check Prompt
    for (const reportVersion of [1, 2] as const) {
        app.post(`/v${reportVersion}/check-prompt`, async (req, res) => {
            const validatedBody = promptInputSchema.safeParse(req.body);
            if (!validatedBody.success) return res.status(isSizeError(validatedBody.error) ? 413 : 400).json({ error: isSizeError(validatedBody.error) ? "input_too_large" : "invalid_input" });
            const controller = new AbortController();
            const cancel = () => { if (!res.writableEnded) controller.abort(); };
            req.on("aborted", cancel); res.on("close", cancel);
            try {
                const report = await scanPromptReport(services, validatedBody.data.prompt, reportVersion, controller.signal);

                res.json(report);
            } catch (error) {
                if (error instanceof ReportVersionRequiredError) return res.status(409).json({ error: error.code, route: "/v2/check-prompt" });
                console.error("API scan failed: internal_error");
                res.status(500).json({ error: "Internal server error" });
            } finally { req.off("aborted", cancel); res.off("close", cancel); }
        });

        // Skill Scanning Endpoint
        app.post(`/v${reportVersion}/scan-skill`, async (req, res) => {
            const validatedBody = skillInputSchema.safeParse(req.body);
            if (!validatedBody.success) return res.status(isSizeError(validatedBody.error) ? 413 : 400).json({ error: isSizeError(validatedBody.error) ? "input_too_large" : "invalid_input" });
            const controller = new AbortController();
            const cancel = () => { if (!res.writableEnded) controller.abort(); };
            req.on("aborted", cancel); res.on("close", cancel);
            try {
                const report = await scanSkillReport(services, validatedBody.data.skillContent, reportVersion, controller.signal);

                res.json(report);
            } catch (error) {
                if (error instanceof ReportVersionRequiredError) return res.status(409).json({ error: error.code, route: "/v2/scan-skill" });
                console.error("API scan failed: internal_error");
                res.status(500).json({ error: "Internal server error" });
            } finally { req.off("aborted", cancel); res.off("close", cancel); }
        });
    }

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
        const roles = Object.fromEntries(Object.entries(services.snapshot.config.roles).map(([role, setting]) => {
            const profile = services.snapshot.config.profiles[setting.primary];
            const enabled = !["taster", "monitor"].includes(role) || services.tasterEnabled;
            const configured = services.configuredProviders[profile.provider];
            const fallback = setting.fallback ? services.snapshot.config.profiles[setting.fallback] : undefined;
            return [role, { provider: profile.provider, model: profile.model, configured, enabled,
                readiness: !enabled ? "disabled" : configured && (!fallback || services.configuredProviders[fallback.provider]) ? "ready" : "degraded",
                fallback: fallback ? { provider: fallback.provider, model: fallback.model, configured: services.configuredProviders[fallback.provider] } : null }];
        }));
        const { model, ...modes } = services.snapshot.config.typesafe;
        const enabled = Object.values(modes).some((mode) => mode !== "off");
        res.json({ status: "ok", version, configHash: services.snapshot.hash, roles,
            typesafe: { model, modes, configured: services.configuredProviders.typesafe, readiness: !enabled ? "disabled" : services.configuredProviders.typesafe ? "ready" : "degraded" },
            qualificationPolicy: services.snapshot.config.qualificationPolicy, qualificationStatus: qualificationStatus(services.snapshot), mcpDefaultReportVersion: services.snapshot.config.mcpDefaultReportVersion,
            qualification: services.snapshot.qualification ?? { tasks: {} }, readinessMeaning: "local_configuration_and_credentials_only; account_access_and_quality_not_probed",
            reports: { prompt: [1, 2], skill: [1, 2], enforcementScope: "v2_only", legacyDescriptorCapability: "local_only", legacySemanticCompatible: services.semantic.supportsV1, legacyTasterCompatible: services.tasteTesterService.supportsV1 } });
    });
    app.use((error: { type?: string }, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
        if (error.type === "entity.too.large") return res.status(413).json({ error: "input_too_large" });
        if (error.type === "entity.parse.failed") return res.status(400).json({ error: "invalid_json" });
        return res.status(500).json({ error: "internal_error" });
    });
    return app;
}
export function startApiServer(services: Services, port = process.env.PORT || 3000) {
    return createApiApp(services).listen(port, () => {
        console.error(`[API] PromptRejector API running at http://localhost:${port}`);
    });
}

export default createApiApp;
