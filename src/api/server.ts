import express from "express";
import cors from "cors";
import { SecurityService } from "../services/SecurityService.js";
import { z } from "zod";

const app = express();
const port = process.env.PORT || 3000;
const securityService = new SecurityService();

app.use(cors());
app.use(express.json());

// Validation schema
const CheckPromptSchema = z.object({
    prompt: z.string().min(1, "Prompt cannot be empty"),
});

// Primary Endpoint
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

// Health check
app.get("/health", (req, res) => {
    res.json({ status: "ok", version: "1.0.0" });
});

export function startApiServer() {
    app.listen(port, () => {
        console.error(`[API] PromptRejector API running at http://localhost:${port}`);
    });
}

export default app;
