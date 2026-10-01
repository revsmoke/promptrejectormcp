import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const temporary = mkdtempSync(join(tmpdir(), 'prompt-rejector-npm-'));
const npm = process.env.npm_execpath;
assert.ok(npm, 'Run through npm run test:cli-package');
function command(executable, args, options = {}) {
    const child = spawnSync(executable, args, { cwd: temporary, encoding: 'utf8', timeout: 180000, maxBuffer: 10 * 1024 * 1024, ...options });
    assert.equal(child.status, 0, child.stderr + child.stdout);
    return child.stdout;
}
try {
    // The script builds first. Packing with scripts disabled avoids a duplicate build.
    const packed = JSON.parse(command(process.execPath, [npm, 'pack', '--json', '--ignore-scripts', '--pack-destination', temporary], { cwd: root }))[0];
    const files = packed.files.map(file => file.path);
    for (const path of ['dist/cli/main.js', 'dist/client/index.js', 'dist/client/index.d.ts', 'config/ai.active.json', 'patterns/manifest.json', 'docs/cli.md']) assert.ok(files.includes(path), path);
    assert.ok(!files.some(path => /(^|\/)(\.env(?:\.|$)|\.certs|canary-state\.json|feed-cache\/|staging\/|test\/)/.test(path)));
    command(process.execPath, [npm, 'install', '--global', '--prefix', temporary, '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', join(temporary, packed.filename)]);
    const installed = join(temporary, process.platform === 'win32' ? 'node_modules/prompt-rejector' : 'lib/node_modules/prompt-rejector');
    const manifest = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'));
    const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, HOME: temporary };
    const binary = process.platform === 'win32' ? process.execPath : join(temporary, 'bin/prompt-rejector');
    const prefix = process.platform === 'win32' ? [join(installed, manifest.bin['prompt-rejector'])] : [];
    assert.equal(command(binary, [...prefix, '--version'], { env }).trim(), manifest.version);
    assert.equal(JSON.parse(command(binary, [...prefix, 'verify-pattern-integrity'], { env })).valid, true);
    const consumerDirectory = process.platform === 'win32' ? temporary : join(temporary, 'lib');
    const sdkScript = `const cwd=process.cwd(); const sdk=await import('prompt-rejector'); if(cwd!==process.cwd())throw new Error('cwd changed'); const report=await sdk.createPromptRejector().run('verify-pattern-integrity',{}); if(!report.valid)throw new Error('invalid patterns');`;
    writeFileSync(join(consumerDirectory, 'consumer.mjs'), sdkScript);
    assert.equal(command(process.execPath, [join(consumerDirectory, 'consumer.mjs')], { env }), '');
    // Resolve the package declarations as an external TypeScript consumer.
    writeFileSync(join(consumerDirectory, 'consumer.mts'), `import {createPromptRejector, type CommandResult} from 'prompt-rejector';\nconst client=createPromptRejector();\nconst result: CommandResult<'check-prompt'>=await client.run('check-prompt',{prompt:'synthetic'});\nconst decision: string=result.decision;\n// @ts-expect-error wrong field\nclient.run('check-prompt',{skillContent:'synthetic'});\n`);
    command(process.execPath, [resolve(root, 'node_modules/typescript/bin/tsc'), '--noEmit', '--strict', '--module', 'NodeNext', '--moduleResolution', 'NodeNext', '--target', 'es2020', join(consumerDirectory, 'consumer.mts')]);
    console.log('PASS packed CLI executable, external SDK import/types, relocated configuration and private-state exclusions');
} finally { rmSync(temporary, { recursive: true, force: true }); }
