// scripts/listModels.ts
//
// Probes Google Generative AI to discover which Gemini model IDs are
// currently reachable with the configured API key. Iterates a hard-coded
// list of candidate IDs (gemini-1.5-flash, gemini-3-flash-preview, etc.) and
// issues a one-token generateContent call against each, printing AVAILABLE
// or UNAVAILABLE per model. Useful when picking / migrating GEMINI_MODEL.
//
// Required env vars:
//   GEMINI_API_KEY  Mandatory. Loaded via dotenv from .env in cwd. Without
//                   it the script prints "No API key" and returns (no error
//                   thrown — exit code stays 0).
//
// Run with:
//   npx tsx scripts/listModels.ts
//
// Exit codes:
//   0  Always (per-model failures are reported inline, not thrown).
import { GoogleGenerativeAI } from "@google/generative-ai";
import dotenv from "dotenv";

dotenv.config();

async function listModels() {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
        console.error("No API key");
        return;
    }
    const genAI = new GoogleGenerativeAI(apiKey);
    try {
        // There is no direct listModels in the standard SDK client sometimes,
        // but we can try to fetch them via the REST API or see if there's a helper.
        // Actually, let's just try the common ones.
        const models = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash-exp", "gemini-2.0-flash-preview", "gemini-3-flash-preview", "gemini-3-pro-preview"];
        for (const modelId of models) {
            try {
                const model = genAI.getGenerativeModel({ model: modelId });
                await model.generateContent("test");
                console.log(`Model [${modelId}] is AVAILABLE`);
            } catch (e: any) {
                console.log(`Model [${modelId}] is UNAVAILABLE: ${e.message}`);
            }
        }
    } catch (err) {
        console.error(err);
    }
}

listModels();
