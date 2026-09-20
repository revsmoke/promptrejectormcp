import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadAIConfig, roleProfiles } from '../ai/config.js';
import { AnalysisBudget } from '../ai/budget.js';
import { tokenPrices } from '../ai/pricing.js';
import { TasteTesterService } from '../services/TasteTesterService.js';
import { SemanticAnalysisService } from '../services/SemanticAnalysisService.js';
/** Direct-input intent labels are historical context, not labels for enacted
 * behavior. Save observed actions for an independent behavior-label review. */
export async function runCalibration(args: string[]): Promise<void> {
    const values = new Map<string, string>();
    const flags = new Set<string>();
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--live')
            flags.add(args[i]);
        else if (['--config', '--max-requests', '--max-usd', '--samples'].includes(args[i]) && args[i + 1])
            values.set(args[i], args[++i]);
        else
            throw Error('Invalid calibration arguments');
    }
    const maxRequests = Number(values.get('--max-requests'));
    const maxUsd = Number(values.get('--max-usd'));
    const sampleCount = Number(values.get('--samples') ?? 1);
    if (!flags.has('--live') || !Number.isSafeInteger(maxRequests) || maxRequests < 4 || !Number.isFinite(maxUsd) || maxUsd <= 0 || !Number.isSafeInteger(sampleCount) || sampleCount < 1 || sampleCount > 20 || !values.get('--config'))
        throw Error('Calibration requires --live --config PATH --max-requests N (at least 4) --max-usd N and optional --samples 1..20');
    const snapshot = loadAIConfig({ ...process.env, AI_CONFIG_PATH: resolve(values.get('--config')!), TASTE_TESTER_ENABLED: 'true' });
    for (const role of ['taster', 'monitor'] as const)
        for (const p of roleProfiles(snapshot, role))
            if (!tokenPrices(snapshot.pricing, p.provider, p.model))
                throw Error('Every selected Taster/Monitor profile needs a rate card before live calibration');
    const corpus = JSON.parse(readFileSync(new URL('../../src/test/fixtures/taste-tester-corpus.json', import.meta.url), 'utf8')) as {
        samples: Array<{
            id: string;
            prompt: string;
            expected: string;
        }>;
    };
    const service = new TasteTesterService({ enabled: true, monitor: new SemanticAnalysisService(snapshot) });
    let attempts = 0;
    let committedUsd = 0;
    const results = [];
    const count = Math.min(sampleCount, Math.floor(maxRequests / 4));
    for (const sample of corpus.samples.slice(0, count)) {
        // Reserve each complete fast run's maximum attempt envelope before dispatch.
        const allowance = (maxUsd - committedUsd) / (count - results.length);
        if (allowance <= 0 || maxRequests - attempts < 4)
            break;
        const budget = new AnalysisBudget('taster', snapshot.config.limits, { tasterTurns: 2, maxUsd: allowance });
        const result = await service.runV2({ prompt: sample.prompt, mode: 'fast' }, { budget });
        attempts += budget.attempts;
        committedUsd += result.usage.estimatedUsd ?? allowance;
        results.push({ id: sample.id, historicalDirectIntentLabel: sample.expected, observedVerdict: result.behaviorReport.monitorVerdict, observedActions: result.tasterTranscript.filter(t => Array.isArray(t.content)).flatMap(t => (t.content as Array<any>).filter(b => b.type === 'tool_use' || b.type === 'rejected_tool_call').map(b => ({ name: b.name ?? b.nameOrNull, rejected: b.type === 'rejected_tool_call' }))), severity: result.behaviorReport.severity, coverage: result.coverage, models: result.routing, usage: result.usage, elapsedMs: result.timings.totalMs });
        if (result.coverage.taster === 'unavailable' || result.usage.estimatedUsd === null)
            break;
    }
    console.log(JSON.stringify({ schemaVersion: 2, configHash: snapshot.hash, qualificationEligible: false, labelBasis: 'observed behavior requires independent review; historical intent labels are not detection agreement', maxRequests, maxUsd, attempts, committedUsd, completedSamples: results.length, requestedSamples: sampleCount, results }, null, 2));
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
    runCalibration(process.argv.slice(2)).catch(error => { console.error(error instanceof Error ? error.message : 'Calibration failed'); process.exitCode = 1; });
