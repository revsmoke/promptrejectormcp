import dotenv from "dotenv";
dotenv.config({ quiet: true });

import { HuggingFaceService } from "../services/HuggingFaceService.js";
import { withMockedFetch, jsonResponse } from "./helpers/mockFetch.js";

let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string) {
    if (condition) {
        console.log(`  PASS: ${message}`);
        passed++;
    } else {
        console.error(`  FAIL: ${message}`);
        failed++;
    }
}

async function runTests() {
    console.log("\n=== HuggingFaceService Tests (Pass 8) ===\n");

    // -----------------------------------------------------------------------
    // extractModelIds — no network.
    // -----------------------------------------------------------------------
    console.log("Test 1: extractModelIds — from_pretrained call");
    {
        const hf = new HuggingFaceService();
        const ids = hf.extractModelIds('from_pretrained("meta-llama/Llama-3-8B")');
        assert(ids.length === 1 && ids[0] === "meta-llama/Llama-3-8B",
            `Expected ["meta-llama/Llama-3-8B"], got ${JSON.stringify(ids)}`);
    }

    console.log("Test 2: extractModelIds — huggingface.co URL");
    {
        const hf = new HuggingFaceService();
        const ids = hf.extractModelIds("Check https://huggingface.co/owner/model and unrelated text");
        assert(ids.length === 1 && ids[0] === "owner/model",
            `Expected ["owner/model"], got ${JSON.stringify(ids)}`);
    }

    console.log("Test 3: extractModelIds — file path is NOT a model id");
    {
        const hf = new HuggingFaceService();
        const ids = hf.extractModelIds("This file is at path/to/something.json");
        assert(ids.length === 0,
            `Expected [] (file path, no context keyword), got ${JSON.stringify(ids)}`);
    }

    console.log("Test 4: extractModelIds — multiple ids deduped");
    {
        const hf = new HuggingFaceService();
        const text =
            'pipeline("text-classification", model="owner1/m1") ' +
            'https://huggingface.co/owner2/m2 ' +
            'AutoModel.from_pretrained("owner1/m1")';
        const ids = hf.extractModelIds(text);
        assert(ids.includes("owner1/m1"), `expected owner1/m1 in ${JSON.stringify(ids)}`);
        assert(ids.includes("owner2/m2"), `expected owner2/m2 in ${JSON.stringify(ids)}`);
        assert(ids.length === 2, `expected exactly 2 unique ids, got ${ids.length}`);
    }

    // -----------------------------------------------------------------------
    // checkModel — mocked fetch.
    // -----------------------------------------------------------------------
    console.log("Test 5: checkModel — gated model");
    {
        const hf = new HuggingFaceService({ cacheTtlMs: 0 });
        await withMockedFetch(
            async () => jsonResponse({
                id: "meta-llama/Llama-3-8B",
                gated: "manual",
                siblings: [{ rfilename: "model.safetensors" }],
            }),
            async () => {
                const r = await hf.checkModel("meta-llama/Llama-3-8B");
                assert(r.flags.some((f) => f.class === "gated"),
                    `expected a "gated" flag, got ${JSON.stringify(r.flags)}`);
                // severity should be at least "low"
                const sevOk = ["low", "medium", "high", "critical"].includes(r.severity);
                assert(sevOk, `expected severity >= low, got ${r.severity}`);
            },
        );
    }

    console.log("Test 6: checkModel — no safetensors but has .bin");
    {
        const hf = new HuggingFaceService({ cacheTtlMs: 0 });
        await withMockedFetch(
            async () => jsonResponse({
                id: "owner/unsafe-model",
                gated: false,
                siblings: [
                    { rfilename: "pytorch_model.bin" },
                    { rfilename: "config.json" },
                ],
            }),
            async () => {
                const r = await hf.checkModel("owner/unsafe-model");
                const unsafeFlag = r.flags.find((f) => f.class === "unsafe_serialization");
                assert(!!unsafeFlag,
                    `expected an "unsafe_serialization" flag, got ${JSON.stringify(r.flags)}`);
                assert(r.severity === "high",
                    `expected severity high, got ${r.severity}`);
            },
        );
    }

    console.log("Test 7: checkModel — trust_remote_code flagged as critical");
    {
        const hf = new HuggingFaceService({ cacheTtlMs: 0 });
        await withMockedFetch(
            async () => jsonResponse({
                id: "owner/risky",
                cardData: { tags: ["trust_remote_code", "transformers"] },
                siblings: [{ rfilename: "model.safetensors" }],
            }),
            async () => {
                const r = await hf.checkModel("owner/risky");
                assert(r.flags.some((f) => f.class === "code_execution_risk"),
                    `expected "code_execution_risk", got ${JSON.stringify(r.flags)}`);
                assert(r.severity === "critical",
                    `expected severity critical, got ${r.severity}`);
            },
        );
    }

    console.log("Test 8: checkModel — 404 yields lookup_failed");
    {
        const hf = new HuggingFaceService({ cacheTtlMs: 0 });
        await withMockedFetch(
            async () => new Response("not found", { status: 404 }),
            async () => {
                const r = await hf.checkModel("nobody/ghost");
                assert(r.flags.length === 1 && r.flags[0].class === "lookup_failed",
                    `expected single lookup_failed flag, got ${JSON.stringify(r.flags)}`);
                assert(r.severity === "safe",
                    `expected severity safe on lookup_failed alone, got ${r.severity}`);
            },
        );
    }

    console.log("Test 9: checkModel — network error doesn't throw");
    {
        const hf = new HuggingFaceService({ cacheTtlMs: 0 });
        let threw = false;
        await withMockedFetch(
            async () => { throw new Error("ECONNRESET"); },
            async () => {
                try {
                    const r = await hf.checkModel("owner/x");
                    assert(r.flags.some((f) => f.class === "lookup_failed"),
                        `expected lookup_failed flag, got ${JSON.stringify(r.flags)}`);
                } catch {
                    threw = true;
                }
            },
        );
        assert(!threw, "checkModel should never throw on network error");
    }

    console.log("Test 10: checkModel — cache prevents duplicate fetches");
    {
        const hf = new HuggingFaceService(); // default 6h TTL
        let calls = 0;
        await withMockedFetch(
            async () => {
                calls++;
                return jsonResponse({ id: "owner/x", siblings: [{ rfilename: "model.safetensors" }] });
            },
            async () => {
                const a = await hf.checkModel("owner/x");
                const b = await hf.checkModel("owner/x");
                assert(calls === 1, `expected 1 fetch call (cache hit), got ${calls}`);
                assert(a.modelId === "owner/x" && b.modelId === "owner/x",
                    "both reports should have the same modelId");
            },
        );
    }

    // -----------------------------------------------------------------------
    // SkillScanService integration.
    // -----------------------------------------------------------------------
    // We stub GeminiService to avoid the live API key requirement during tests.
    console.log("Test 11: SkillScanService aggregates HF flags");
    {
        const { SkillScanService } = await import("../services/SkillScanService.js");

        // Build a service with a hand-injected hf service. Easier than mocking Gemini:
        // we keep the real one (it returns an error-shaped benign result if the API
        // call fails or the prompt is benign) and only swap fetch for HF.
        const hf = new HuggingFaceService({ cacheTtlMs: 0 });
        const svc = new (SkillScanService as any)(undefined, hf);

        const skillContent =
            "# Skill\n\nLoads model from huggingface.co/owner/risky for analysis.\n";

        await withMockedFetch(
            async (url: string) => {
                if (url.includes("huggingface.co/api/models/owner/risky")) {
                    return jsonResponse({
                        id: "owner/risky",
                        cardData: { tags: ["trust_remote_code"] },
                        siblings: [{ rfilename: "model.safetensors" }],
                    });
                }
                // Gemini's real API call goes through @google/generative-ai which uses fetch.
                // Return an empty error body so GeminiService's catch path defaults to medium severity.
                return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
            },
            async () => {
                const result = await svc.scanSkill(skillContent);
                assert(Array.isArray(result.huggingFaceSecurityFlags),
                    "huggingFaceSecurityFlags should be an array");
                assert(result.huggingFaceSecurityFlags.length > 0,
                    `expected HF flags for a referenced risky model, got ${JSON.stringify(result.huggingFaceSecurityFlags)}`);
                assert(result.huggingFaceSecurityFlags.some((f: any) => f.class === "code_execution_risk"),
                    "expected code_execution_risk flag from trust_remote_code");
                assert(result.overallSeverity === "critical",
                    `expected overall severity critical, got ${result.overallSeverity}`);
                assert(Array.isArray(result.huggingFaceReports) && result.huggingFaceReports.length === 1,
                    `expected 1 huggingFaceReports entry, got ${result.huggingFaceReports.length}`);
            },
        );
    }

    console.log("Test 12: SkillScanService — no HF refs yields empty flags");
    {
        const { SkillScanService } = await import("../services/SkillScanService.js");
        const hf = new HuggingFaceService({ cacheTtlMs: 0 });
        const svc = new (SkillScanService as any)(undefined, hf);

        const skillContent = "# Skill\n\nReads a CSV file and prints the first row.\n";

        let fetchCalls = 0;
        await withMockedFetch(
            async () => {
                fetchCalls++;
                return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
            },
            async () => {
                const result = await svc.scanSkill(skillContent);
                assert(Array.isArray(result.huggingFaceSecurityFlags) && result.huggingFaceSecurityFlags.length === 0,
                    `expected empty huggingFaceSecurityFlags, got ${JSON.stringify(result.huggingFaceSecurityFlags)}`);
                assert(Array.isArray(result.huggingFaceReports) && result.huggingFaceReports.length === 0,
                    "expected empty huggingFaceReports");
                // We don't assert fetchCalls === 0 since Gemini may also call fetch via its SDK.
                void fetchCalls;
            },
        );
    }

    console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
    process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((err) => {
    console.error("Test runner error:", err);
    process.exit(1);
});
