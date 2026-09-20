import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { percentile } from './Metrics.js';
interface HistoricalCase { id: string; group: string; expected: boolean | boolean[] | string[]; state: { candidates?: string[] } }
interface SavedRow { id: string; group: string; phase: string; elapsedMs: number; skipped?: string; data?: { answers: Record<string, { noul?: number }>; usage: { input_tokens: number } } }
/** Read-only replay of the exploratory primitive comparison. This intentionally
 * retains its historical .5 threshold and labels; it is not today's policy. */
export function replayHistorical(directory: string) {
    const cases = JSON.parse(readFileSync(join(directory,'cases.json'),'utf8')) as HistoricalCase[];
    const rows = readFileSync(join(directory,'results.jsonl'),'utf8').trim().split('\n').map((line) => JSON.parse(line) as SavedRow);
    const groups: Record<string, { cases: number; evaluated: number; typesafeExact: number; inputTokens: number; latency: { n: number; p50Ms: number | null; p95Ms: number | null } }> = {};
    for (const group of ['prompt','capability','descriptor','extraction']) {
        const selected = cases.filter((item) => item.group === group);
        let exact=0, evaluated=0, tokens=0;
        const times:number[]=[];
        for (const item of selected) {
            const row=rows.find((candidate)=>candidate.group===group && candidate.id===item.id && candidate.phase==='primary');
            if (!row?.data && !(group==='extraction' && row?.skipped==='no candidates')) continue;
            evaluated++;
            const answers=row.data?.answers;
            if (row.data) { times.push(row.elapsedMs); tokens+=row.data.usage.input_tokens; }
            let prediction: unknown;
            if (group==='prompt') prediction=Math.max(...Object.values(answers!).map((answer)=>answer.noul!))>=.5;
            else if (group==='descriptor') prediction=answers!.poison.noul!>=.5;
            else if (group==='capability') prediction=['private','untrusted','egress'].map((name)=>answers![name].noul!>=.5);
            else prediction=(item.state.candidates??[]).filter((_,index)=>(answers?.[`c${index}`]?.noul??0)>=.5).sort();
            const expected=group==='extraction' ? [...item.expected as string[]].sort() : item.expected;
            if(isDeepStrictEqual(prediction,expected))exact++;
        }
        groups[group]={cases:selected.length,evaluated,typesafeExact:exact,inputTokens:tokens,latency:{n:times.length,p50Ms:percentile(times,.5),p95Ms:percentile(times,.95)}};
    }
    return { evaluationOnly:true, qualification:false, scope:'historical primitive comparison; not full service behavior', groups };
}
