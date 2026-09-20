import { qualificationStatus } from "../ai/qualification.js";
import express from "express";
import cors from "cors";
import { createRequire } from "module";
import { readFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { Services } from "../bootstrap.js";
import { promptInputSchema, skillInputSchema, isSizeError } from "../ai/schemas.js";
import { scanPromptReport, scanSkillReport } from "./reportSerializers.js";
import { z } from "zod";

const require = createRequire(import.meta.url);
const { version } = require("../../package.json");

export function createApiApp(services: Services) {
    const app = express();
    const { patternService, vulnFeedService } = services;

    // Retired requests stop before body parsing or any scanner/feed operation.
    app.use("/v1", (req, res) => res.status(410).json({ error: "api_version_retired", route: `/v2${req.path === "/" ? "" : req.path}` }));
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
    app.post("/v2/check-prompt", async (req, res) => {
        const validatedBody = promptInputSchema.safeParse(req.body);
        if (!validatedBody.success) return res.status(isSizeError(validatedBody.error) ? 413 : 400).json({ error: isSizeError(validatedBody.error) ? "input_too_large" : "invalid_input" });
        const controller = new AbortController();
        const cancel = () => { if (!res.writableEnded) controller.abort(); };
        req.on("aborted", cancel); res.on("close", cancel);
        try {
            const report = await scanPromptReport(services, validatedBody.data.prompt, controller.signal);

            res.json(report);
        } catch (error) {
            console.error("API scan failed: internal_error");
            res.status(500).json({ error: "Internal server error" });
        } finally { req.off("aborted", cancel); res.off("close", cancel); }
    });

    // Skill Scanning Endpoint
    app.post("/v2/scan-skill", async (req, res) => {
        const validatedBody = skillInputSchema.safeParse(req.body);
        if (!validatedBody.success) return res.status(isSizeError(validatedBody.error) ? 413 : 400).json({ error: isSizeError(validatedBody.error) ? "input_too_large" : "invalid_input" });
        const controller = new AbortController();
        const cancel = () => { if (!res.writableEnded) controller.abort(); };
        req.on("aborted", cancel); res.on("close", cancel);
        try {
            const report = await scanSkillReport(services, validatedBody.data.skillContent, controller.signal);

            res.json(report);
        } catch (error) {
            console.error("API scan failed: internal_error");
            res.status(500).json({ error: "Internal server error" });
        } finally { req.off("aborted", cancel); res.off("close", cancel); }
    });

    // Pattern Library Endpoints
    app.get("/v2/patterns", (req, res) => {
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

    app.post("/v2/patterns/update-feeds", async (req, res) => {
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

    app.post("/v2/patterns/verify", (req, res) => {
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
            qualificationPolicy: services.snapshot.config.qualificationPolicy, qualificationStatus: qualificationStatus(services.snapshot),
            qualification: services.snapshot.qualification ?? { tasks: {} }, readinessMeaning: "local_configuration_and_credentials_only; account_access_and_quality_not_probed",
            reports: { schemaVersion: 2, restPrefix: "/v2" } });
    });
    app.use((error: { type?: string }, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
        if (error.type === "entity.too.large") return res.status(413).json({ error: "input_too_large" });
        if (error.type === "entity.parse.failed") return res.status(400).json({ error: "invalid_json" });
        return res.status(500).json({ error: "internal_error" });
    });
    return app;
}
export async function startApiServer(services: Services, port = Number(process.env.PORT || 3001), host = process.env.HOST || "127.0.0.1") {
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid API port");
    const protocol = process.env.API_PROTOCOL || "https";
    if (!["https", "http"].includes(protocol)) throw new Error("Invalid API protocol");
    const app = createApiApp(services);
    if (protocol === "https" && (!process.env.TLS_CERT_FILE || !process.env.TLS_KEY_FILE)) throw new Error("HTTPS requires TLS certificate and key files");
    const server = protocol === "https"
        ? createHttpsServer({ cert: readFileSync(process.env.TLS_CERT_FILE!), key: readFileSync(process.env.TLS_KEY_FILE!), minVersion: "TLSv1.2" }, app)
        : createHttpServer(app);
    await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.once("listening", () => { server.off("error", reject); resolve(); });
        server.listen(port, host);
    });
    console.error(`[API] PromptRejector API running at ${protocol}://${host}:${port}`);
    return server;
}

export default createApiApp;
