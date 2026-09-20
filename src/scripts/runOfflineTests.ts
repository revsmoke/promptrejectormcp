import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export interface OfflineSuite { file: string; allowLoopback?: boolean }

// Explicit registration is deliberate. advancedTests and skillScanTests make
// live provider calls and must never enter this default offline suite.
export const OFFLINE_SUITES: readonly OfflineSuite[] = [
    { file: "offlineRunnerTests.js" },
    { file: "patternServiceTests.js" },
    { file: "integrationTests.js" },
    { file: "vulnFeedTests.js" },
    { file: "vulnFeed2Tests.js" },
    { file: "v11SkeletonTests.js" },
    { file: "unicodeSmugglingTests.js" },
    { file: "policyPuppetryTests.js" },
    { file: "markdownExfilTests.js" },
    { file: "mcpToolScannerTests.js" },
    { file: "trifectaTests.js" },
    { file: "atlasKevTests.js" },
    { file: "huggingFaceTests.js" },
    { file: "queryCveTests.js" },
    { file: "canaryTests.js" },
    { file: "tasteTesterTests.js" },
    { file: "tasteTesterCorpusTests.js" },
    { file: "manyShotObfuscationTests.js" },
    { file: "ai/contractsTests.js" },
    { file: "ai/bootstrapTests.js" },
    { file: "ai/geminiAdapterTests.js" },
    { file: "ai/decisionPolicyTests.js" },
    { file: "ai/apiVersionTests.js", allowLoopback: true },
    { file: "ai/transportTests.js" },
    { file: "ai/budgetTests.js" },
    { file: "ai/typesafeAdapterTests.js" },
    { file: "ai/judgmentCacheTests.js" },
    { file: "ai/anthropicAdapterTests.js" },
    { file: "ai/openaiAdapterTests.js" },
    { file: "ai/modelConfigTests.js" },
    { file: "ai/roleRoutingTests.js" },
    { file: "ai/usageTests.js" },
    { file: "ai/operatorCommandsTests.js" },
    { file: "ai/descriptorRubricTests.js" },
    { file: "ai/rubricIsolationTests.js" },
    { file: "ai/trustedCapabilityTests.js" },
    { file: "ai/modelReferenceParserTests.js" },
    { file: "ai/sharedBudgetTests.js" },
    { file: "ai/judgmentServiceTests.js" },
    { file: "ai/descriptorAnalysisTests.js" },
    { file: "ai/promptShadowTests.js" },
    { file: "ai/capabilityReferenceShadowTests.js" },
    { file: "ai/shadowTransportTests.js" },
    { file: "ai/toolConversationTests.js" },
    { file: "ai/tasterPortabilityTests.js" },
    { file: "ai/tasterTransportTests.js" },
    { file: "ai/evaluationTests.js" },
    { file: "ai/evaluationCommandsTests.js" },
    { file: "ai/historicalReplayTests.js" },
    { file: "ai/qualificationTests.js" },
    { file: "ai/operationsTests.js", allowLoopback: true },
    { file: "ai/enforcementTests.js" },
    { file: "ai/cascadeTests.js" },
    { file: "ai/cascadeTransportTests.js", allowLoopback: true },
    { file: "ai/activationTests.js", allowLoopback: true },
    { file: "ai/mcpLauncherTests.js" },
    { file: "ai/apiLauncherTests.js", allowLoopback: true },
];

export function offlineEnvironment(source: NodeJS.ProcessEnv, home: string): NodeJS.ProcessEnv {
    // Allowlist, rather than a list of known credential names: newly added
    // providers and NODE_OPTIONS/DOTENV_CONFIG_PATH cannot leak into tests.
    return {
        PATH: source.PATH,
        SystemRoot: source.SystemRoot,
        TEMP: home,
        TMP: home,
        TMPDIR: home,
        HOME: home,
        USERPROFILE: home,
        NODE_ENV: "test",
        NO_COLOR: "1",
        TZ: "UTC",
    };
}

export function runSuite(cwd: string, suite: OfflineSuite, options: { timeoutMs?: number } = {}) {
    const log = join(cwd, "network-violations.jsonl");
    rmSync(log, { force: true });
    const child = spawnSync(process.execPath, [
        "--require", join(cwd, "dist/scripts/offlineNetworkGuard.cjs"),
        join(cwd, "dist/test", suite.file),
    ], {
        cwd,
        env: {
            ...offlineEnvironment(process.env, cwd),
            OFFLINE_NETWORK_LOG: log,
            OFFLINE_ALLOW_LOOPBACK: suite.allowLoopback ? "1" : "0",
        },
        encoding: "utf8",
        timeout: options.timeoutMs ?? 120_000,
        // Test subprocesses must not extend the deadline by ignoring SIGTERM.
        killSignal: "SIGKILL",
        maxBuffer: 10 * 1024 * 1024,
    });
    const violations = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean) : [];
    return {
        passed: child.status === 0 && !child.error && violations.length === 0,
        status: child.status,
        error: child.error?.message,
        output: child.stdout + child.stderr,
        violations,
    };
}

function copyFixtures(source: string, destination: string): void {
    mkdirSync(destination, { recursive: true });
    for (const entry of readdirSync(source, { withFileTypes: true })) {
        const from = join(source, entry.name);
        const to = join(destination, entry.name);
        if (entry.isDirectory()) copyFixtures(from, to);
        else if (entry.isFile() && excludeEnvironmentFiles(from) && /\.(?:ts|cts|json)$/.test(entry.name)) cpSync(from, to);
    }
}

function excludeEnvironmentFiles(path: string): boolean {
    return !path.split(/[\\/]/).some((name) => name === ".env" || name.startsWith(".env."));
}

export function runOfflineTests(projectRoot: string): boolean {
    const temporary = mkdtempSync(join(tmpdir(), "prompt-rejector-offline-"));
    let failures = 0;
    try {
        // Every suite gets a fresh filesystem; mutation in one suite cannot
        // modify production patterns or contaminate a later suite.
        for (const [index, suite] of OFFLINE_SUITES.entries()) {
            const cwd = join(temporary, String(index));
            mkdirSync(cwd);
            cpSync(join(projectRoot, "dist"), join(cwd, "dist"), { recursive: true, filter: excludeEnvironmentFiles });
            copyFixtures(join(projectRoot, "src"), join(cwd, "src"));
            // Some existing tests inspect source next to their compiled imports.
            copyFixtures(join(projectRoot, "src"), join(cwd, "dist"));
            cpSync(join(projectRoot, "config"), join(cwd, "config"), { recursive: true, filter: excludeEnvironmentFiles });
            if (suite.file === "ai/historicalReplayTests.js") cpSync(join(projectRoot, "experiments/typesafe/results"), join(cwd, "experiments/typesafe/results"), { recursive: true, filter: excludeEnvironmentFiles });
            cpSync(join(projectRoot, "evaluations/ai/datasets"), join(cwd, "evaluations/ai/datasets"), { recursive: true, filter: excludeEnvironmentFiles });
            cpSync(join(projectRoot, "patterns"), join(cwd, "patterns"), { recursive: true, filter: excludeEnvironmentFiles });
            // REST/MCP read the actual package version. This manifest contains
            // no credentials; preserve it instead of inventing a test version.
            cpSync(join(projectRoot, "package.json"), join(cwd, "package.json"));
            symlinkSync(join(projectRoot, "node_modules"), join(cwd, "node_modules"), "dir");
            const result = runSuite(cwd, suite);
            if (!result.passed) failures++;
            console.log(`${result.passed ? "PASS" : "FAIL"} ${suite.file} (${result.violations.length} network violations)`);
            if (!result.passed) console.error(result.output, result.error ?? "", ...result.violations);
        }
        console.log(`Offline suites: ${OFFLINE_SUITES.length - failures} passed, ${failures} failed; Node ${process.version}`);
        return failures === 0;
    } finally {
        rmSync(temporary, { recursive: true, force: true });
    }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
    process.exitCode = runOfflineTests(projectRoot) ? 0 : 1;
}
