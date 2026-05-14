import dotenv from "dotenv";
dotenv.config();

import { AtlasService } from "../services/AtlasService.js";
import { OsvFeedService } from "../services/OsvFeedService.js";
import { GhsaGraphQLService } from "../services/GhsaGraphQLService.js";
import { KevFeedService } from "../services/KevFeedService.js";
import { HuggingFaceService } from "../services/HuggingFaceService.js";
import { TrifectaAnalyzer } from "../services/TrifectaAnalyzer.js";
import { CanaryService } from "../services/CanaryService.js";
import { McpToolScanner } from "../services/McpToolScanner.js";
import { PatternService } from "../services/PatternService.js";
import { TasteTesterService } from "../services/TasteTesterService.js";

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
    console.log("\n=== v1.1 Skeleton Tests ===\n");

    // Test 1: All services instantiate without throwing
    console.log("Test 1: Services instantiate");
    {
        let ok = true;
        try {
            new AtlasService();
            new OsvFeedService();
            new GhsaGraphQLService();
            new KevFeedService();
            new HuggingFaceService();
            new TrifectaAnalyzer();
            new CanaryService();
            new McpToolScanner(new PatternService());
            new TasteTesterService();
        } catch (err) {
            console.error("  Instantiation threw:", err);
            ok = false;
        }
        assert(ok, "All new services should instantiate");
    }

    // Test 2: AtlasService.lookup hits + misses
    console.log("Test 2: AtlasService.lookup");
    {
        const svc = new AtlasService();
        const hit = svc.lookup("AML.T0051");
        assert(hit !== null && hit.id === "AML.T0051", "Lookup of AML.T0051 returns entry");
        const miss = svc.lookup("AML.NONEXISTENT");
        assert(miss === null, "Lookup of unknown technique returns null");
    }

    // Test 3: OsvFeedService.query
    console.log("Test 3: OsvFeedService.query");
    {
        const svc = new OsvFeedService();
        const res = await svc.query([]);
        assert(Array.isArray(res) && res.length === 0, "Stub returns []");
    }

    // Test 4: GhsaGraphQLService.query
    console.log("Test 4: GhsaGraphQLService.query");
    {
        const svc = new GhsaGraphQLService();
        const res = await svc.query("PyPI");
        assert(Array.isArray(res) && res.length === 0, "Stub returns []");
    }

    // Test 5: KevFeedService
    console.log("Test 5: KevFeedService");
    {
        const svc = new KevFeedService();
        const refresh = await svc.refresh();
        assert(refresh.count === 0, "Stub refresh returns count: 0");
        assert(svc.isInKev("CVE-0000-0000") === false, "Empty KEV set returns false");
    }

    // Test 6: HuggingFaceService.checkModel
    // Pass 8 wired this to the real HF API. We don't mock fetch here (this is
    // the skeleton smoke test, not the HF-specific suite), so the call will
    // either succeed against the live API or degrade to lookup_failed. Both
    // are acceptable; we only assert the report shape is well-formed.
    console.log("Test 6: HuggingFaceService.checkModel");
    {
        const svc = new HuggingFaceService({ timeoutMs: 1500 });
        const res = await svc.checkModel("test/model");
        assert(Array.isArray(res.flags), "checkModel returns a report with .flags array");
        assert(typeof res.modelId === "string" && res.modelId === "test/model", "report.modelId echoes input");
        assert(typeof res.severity === "string", "report.severity is a string");
    }

    // Test 7: TrifectaAnalyzer.analyze
    console.log("Test 7: TrifectaAnalyzer.analyze");
    {
        const svc = new TrifectaAnalyzer();
        const res = svc.analyze({});
        assert(res.trifectaPresent === false, "Stub returns trifectaPresent: false");
        assert(res.severity === "safe", "Stub severity is 'safe'");
        assert(res.privateDataRead.present === false, "privateDataRead.present is false");
        assert(res.untrustedContentFetch.present === false, "untrustedContentFetch.present is false");
        assert(res.externalEgress.present === false, "externalEgress.present is false");
    }

    // Test 8: CanaryService.issueToken + checkEcho
    console.log("Test 8: CanaryService");
    {
        const svc = new CanaryService();
        const issued = svc.issueToken();
        assert(/^[0-9a-f-]+$/i.test(issued.token), "Token matches UUID-ish shape");
        assert(typeof issued.expiresAt === "string" && issued.expiresAt.length > 0, "expiresAt is a non-empty string");
        const echo = svc.checkEcho("benign string");
        assert(echo.echoDetected === false, "Stub echoDetected is false");
        assert(echo.severity === "safe", "Stub severity is 'safe'");
        assert(Array.isArray(echo.matches) && echo.matches.length === 0, "Stub matches is []");
    }

    // Test 9: McpToolScanner.scan
    console.log("Test 9: McpToolScanner.scan");
    {
        const svc = new McpToolScanner(new PatternService());
        const res = svc.scan({ tool: { name: "test" } });
        assert(res.drift === false, "Stub drift is false");
        assert(/^[a-f0-9]{64}$/.test(res.hash), "Hash is 64-char hex");
        assert(res.severity === "safe", "Benign descriptor severity is 'safe'");
        assert(Array.isArray(res.findings) && res.findings.length === 0, "Benign descriptor findings is []");
    }

    // Test 10: TasteTesterService.run
    console.log("Test 10: TasteTesterService.run");
    {
        const svc = new TasteTesterService();
        const res = await svc.run({ prompt: "hello" });
        assert(res.behaviorReport.monitorVerdict === "clean", "Stub monitorVerdict is 'clean'");
        assert(res.behaviorReport.severity === "safe", "Stub severity is 'safe'");
        assert(Array.isArray(res.tasterTranscript) && res.tasterTranscript.length === 0, "Stub transcript is []");
    }

    console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
    process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((err) => {
    console.error("Test runner error:", err);
    process.exit(1);
});
