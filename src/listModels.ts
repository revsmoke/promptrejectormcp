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
