import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
const hash = (value) => createHash('sha256').update(value).digest('hex');
const root = 'experiments/typesafe/results/2026-09-19T20-27-01.476Z/';
const groups = [['cases.json', JSON.parse(readFileSync(root + 'cases.json', 'utf8'))], ['followup-plan.json', JSON.parse(readFileSync(root + 'followup-plan.json', 'utf8')).cases]];
const cases = new Map();
for (const [file, rows] of groups) for (const item of rows) {
    const task = item.group === 'extraction' ? 'modelReference' : item.group;
    const input = task === 'descriptor' ? { tool: item.state.tool } : task === 'capability' ? item.state.configuration : task === 'prompt' ? { prompt: item.state.text } : { text: item.state.text };
    const sourceSha256 = hash(JSON.stringify(input));
    const key = task + ':' + sourceSha256;
    const historical = { file: root + file, id: item.id, expected: item.expected, caseSha256: hash(JSON.stringify(item)) };
    if (cases.has(key)) { cases.get(key).historical.occurrences.push(historical); continue; }
    cases.set(key, { id: `exploratory-${task}-${item.id}`, task, partition: 'development', family: `exploratory-${task}-${item.id}`, input, sourceSha256,
        label: { risk: typeof item.expected === 'boolean' ? item.expected : null, rationale: 'Historical author hypothesis preserved; not independently qualified ground truth.', kind: task === 'prompt' ? 'input-intent' : task === 'descriptor' ? 'descriptor-poisoning' : task === 'capability' ? 'declared-capability-buckets' : 'exact-model-references', target: 'supplied-artifact', severity: null, expected: item.expected },
        provenance: { type: 'historical-development', author: 'original TypeSafe exploration', familyReview: 'pending' }, historical: { occurrences: [historical] } });
}
const directory = 'evaluations/ai/datasets/exploratory-v1'; mkdirSync(directory, { recursive: true });
const text = [...cases.values()].map((item) => JSON.stringify(item)).join('\n') + '\n';
if (cases.size !== 107) throw new Error('Unexpected exploratory input inventory');
writeFileSync(directory + '/cases.jsonl', text);
writeFileSync(directory + '/manifest.json', JSON.stringify({ schemaVersion: 1, id: 'exploratory-v1', path: 'cases.jsonl', sha256: hash(text), count: cases.size, qualificationEligible: false,
    limitations: ['107 unique inputs from 111 historical records; duplicate occurrences retain every original label and file reference.', 'Development only. Historical labels and near-paraphrase families are not independently reviewed acceptance labels.', 'No historical experiment file or result is modified.'] }, null, 2) + '\n');
console.log(JSON.stringify({ imported: cases.size, originalRecords: groups.reduce((sum, [, rows]) => sum + rows.length, 0), sha256: hash(text) }));
