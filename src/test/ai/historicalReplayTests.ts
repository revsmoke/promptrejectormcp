import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { replayHistorical } from '../../evaluation/HistoricalReplay.js';
const path='experiments/typesafe/results/2026-09-19T20-27-01.476Z';
const stored=JSON.parse(readFileSync(`${path}/summary.json`,'utf8'));
const replay=replayHistorical(path);
for (const [name,group] of Object.entries(replay.groups)) for (const [key,value] of Object.entries(group)) assert.deepEqual(value,stored.groups[name][key],`${name}.${key}`);
assert.equal(replay.qualification,false);
assert.equal(replay.groups.prompt.typesafeExact,39);
assert.equal(replay.groups.descriptor.typesafeExact,12);
console.log('PASS read-only historical primitive replay reproduces saved counts and latency');
const temporary=mkdtempSync(join(tmpdir(),'historical-missing-'));
try {
  const groups=['prompt','descriptor','capability','extraction'];
  writeFileSync(join(temporary,'cases.json'),JSON.stringify(groups.map(group=>({id:group,group,expected:group==='extraction'?[]:false,state:{candidates:[]}}))));
  writeFileSync(join(temporary,'results.jsonl'),groups.map(group=>JSON.stringify({id:group,group,phase:'primary',elapsedMs:0,skipped:'no candidates'})).join('\n'));
  const missing=replayHistorical(temporary);
  for(const group of groups) assert.equal(missing.groups[group].evaluated,group==='extraction'?1:0,'only extraction can be evaluated without model data');
  assert.equal(missing.groups.extraction.typesafeExact,1);assert.equal(missing.groups.extraction.latency.n,0);
} finally {rmSync(temporary,{recursive:true,force:true});}
