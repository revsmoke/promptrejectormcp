import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { unzipSync } from 'fflate';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const temporary = mkdtempSync(join(tmpdir(), 'prompt rejector plugin test '));
const secret = 'synthetic-plugin-key-not-for-inference';
const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, PROMPT_REJECTOR_SETTINGS: join(temporary, 'settings.json'), PROMPT_REJECTOR_DATA_DIR: join(temporary, 'data') };
const invoke = (path, args = [], options = {}) => spawnSync(process.execPath, [path, ...args], { cwd: temporary, env, encoding: 'utf8', timeout: 30000, ...options });
const source = join(temporary, 'source plugin');
cpSync(join(root, 'plugins/prompt-rejector'), source, { recursive: true });
const envFile = join(temporary, 'private.env');
writeFileSync(envFile, `TYPESAFE_API_KEY=${secret}\nGEMINI_API_KEY=${secret}\n`, { mode: 0o600 });
const message = (id, method, params) => JSON.stringify({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) });
const initialize = message(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'plugin-test', version: '1' } });
function request(plugin, call = message(2, 'tools/list'), extraEnv = {}) {
  const result = invoke(join(plugin, 'scripts/launch.mjs'), [], { env: { ...env, ...extraEnv }, input: `${initialize}\n${call}\n` });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(!`${result.stdout}${result.stderr}`.includes(secret));
  const messages = result.stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.ok(messages.find(m => m.id === 1)?.result.serverInfo);
  return messages.find(m => m.id === 2)?.result;
}
function extract(path, target) {
  const archive = unzipSync(readFileSync(path));
  for (const [name, content] of Object.entries(archive)) {
    assert.ok(!name.startsWith('/') && !name.split('/').includes('..'));
    if (name.endsWith('/')) { mkdirSync(join(target, name), { recursive: true }); continue; }
    mkdirSync(dirname(join(target, name)), { recursive: true });
    writeFileSync(join(target, name), content);
  }
  return archive;
}

test('plugin installation, portable archives and isolation', async t => {
  try {
    await t.test('copied source plugin fails helpfully until configured', () => {
      const missing = invoke(join(source, 'scripts/launch.mjs'));
      assert.notEqual(missing.status, 0);
      assert.equal(missing.stdout, '');
      assert.match(missing.stderr, /needs setup/);
    });
    await t.test('setup uses explicit credentials without persisting or printing keys', () => {
      const setup = invoke(join(source, 'scripts/setup.mjs'), ['--installation', root, '--env-file', envFile]);
      assert.equal(setup.status, 0, setup.stderr);
      assert.ok(!`${setup.stdout}${setup.stderr}`.includes(secret));
      const settings = JSON.parse(readFileSync(env.PROMPT_REJECTOR_SETTINGS, 'utf8'));
      assert.deepEqual(settings, { installationPath: root, envFile, configFile: join(root, 'config/ai.active.json') });
      assert.ok(!JSON.stringify(settings).includes(secret));
      const tools = request(source).tools;
      assert.equal(tools.length, 11);
      assert.equal(tools.find(t => t.name === 'update_vuln_feeds').annotations.readOnlyHint, false);
      const doctor = invoke(join(source, 'scripts/doctor.mjs'));
      assert.equal(doctor.status, 0, doctor.stderr);
      assert.equal(JSON.parse(doctor.stdout).inferencePerformed, false);
    });
    await t.test('missing credentials and unavailable explicit configuration fail without replacing settings', () => {
      const before = readFileSync(env.PROMPT_REJECTOR_SETTINGS, 'utf8');
      const empty = join(temporary, 'empty.env'); writeFileSync(empty, '');
      const setup = invoke(join(source, 'scripts/setup.mjs'), ['--installation', root, '--env-file', empty]);
      assert.notEqual(setup.status, 0);
      assert.match(setup.stderr, /TYPESAFE_API_KEY/);
      assert.equal(readFileSync(env.PROMPT_REJECTOR_SETTINGS, 'utf8'), before);
      const bad = invoke(join(source, 'scripts/launch.mjs'), [], { env: { ...env, PROMPT_REJECTOR_ENV_FILE: join(temporary, 'missing.env') } });
      assert.notEqual(bad.status, 0); assert.equal(bad.stdout, '');
    });
    const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
    const bundleRoot = join(temporary, 'bundle');
    await t.test('archives include app dependencies and omit secrets, tests and mutable state', () => {
      for (const name of [`prompt-rejector-${version}-local.zip`, `prompt-rejector-${version}.mcpb`, 'prompt-rejector-skill.zip']) {
        const bytes = readFileSync(join(root, 'artifacts/plugins', name));
        const archive = unzipSync(bytes);
        const names = Object.keys(archive);
        for (const file of names) assert.ok(!/(^|\/)(\.env(?:\.|$)|\.certs|\.git\/|canary-state\.json|feed-cache\/|staging\/)/.test(file), file);
        if (name.endsWith('.mcpb')) {
          const manifest = JSON.parse(Buffer.from(archive['manifest.json']).toString());
          assert.equal(manifest.server.entry_point, 'scripts/launch.mjs');
          assert.ok(archive['runtime/dist/scripts/startMcpHttp.js']);
          assert.ok(archive['runtime/node_modules/jose/package.json']);
          assert.ok(!names.some(n => n.startsWith('runtime/dist/test/')));
          assert.ok(!archive['runtime/node_modules/typescript/package.json']);
          assert.ok(manifest.user_config.typesafe_api_key.sensitive);
        }
      }
      extract(join(root, 'artifacts/plugins', `prompt-rejector-${version}-local.zip`), bundleRoot);
    });
    await t.test('relocated bundle works without source checkout settings and preserves writable state', () => {
      const plugin = join(bundleRoot, 'prompt-rejector');
      const bundledEnv = { PROMPT_REJECTOR_BUNDLED_ONLY: 'true', TYPESAFE_API_KEY: secret, GEMINI_API_KEY: secret };
      assert.equal(request(plugin, undefined, bundledEnv).tools.length, 11);
      const first = request(plugin, message(2, 'tools/call', { name: 'deploy_canary', arguments: { context: 'package-test' } }), bundledEnv);
      const issued = JSON.parse(first.content[0].text);
      const second = request(plugin, message(2, 'tools/call', { name: 'verify_canary', arguments: { content: issued.token, watchHandle: issued.watchHandle } }), bundledEnv);
      assert.equal(JSON.parse(second.content[0].text).echoDetected, true);
      const identities = readdirSync(join(env.PROMPT_REJECTOR_DATA_DIR, 'runtimes'));
      assert.equal(identities.length, 1);
      assert.ok(existsSync(join(env.PROMPT_REJECTOR_DATA_DIR, 'runtimes', identities[0], 'patterns/canary-state.json')));
      assert.ok(!existsSync(join(plugin, 'runtime/patterns/canary-state.json')));
    });
    await t.test('remote generator uses the supplied endpoint and removes local executable wiring', () => {
      const output = join(temporary, 'remote.zip');
      const result = invoke(join(root, 'scripts/create-remote-plugin.mjs'), ['https://real-operator.example/mcp', output]);
      assert.equal(result.status, 0, result.stderr);
      const archive = unzipSync(readFileSync(output));
      const config = JSON.parse(Buffer.from(archive['prompt-rejector/mcp.json']).toString());
      assert.equal(config.mcpServers['prompt-rejector'].url, 'https://real-operator.example/mcp');
      assert.equal(config.mcpServers['prompt-rejector'].type, 'streamable-http');
      assert.ok(!archive['prompt-rejector/scripts/launch.mjs']);
      assert.notEqual(invoke(join(root, 'scripts/create-remote-plugin.mjs'), ['http://unsafe.example/mcp', output]).status, 0);
    });
    await t.test('Desktop manifest launches its extracted bundle using host substitutions', () => {
      const desktop = join(temporary, 'desktop extension');
      extract(join(root, 'artifacts/plugins', `prompt-rejector-${version}.mcpb`), desktop);
      const manifest = JSON.parse(readFileSync(join(desktop, 'manifest.json'), 'utf8'));
      const substitute = value => value.replaceAll('${__dirname}', desktop).replace(/\$\{user_config\.([a-z_]+)\}/g, (_, key) => key.endsWith('_api_key') ? secret : '');
      const configuration = manifest.server.mcp_config;
      assert.equal(configuration.command, 'node');
      const result = invoke(substitute(configuration.args[0]), [], { env: { ...env, ...Object.fromEntries(Object.entries(configuration.env).map(([key, value]) => [key, substitute(value)])) }, input: `${initialize}\n${message(2, 'tools/list')}\n` });
      assert.equal(result.status, 0, result.stderr);
      const messages = result.stdout.trim().split('\n').map(line => JSON.parse(line));
      assert.equal(messages.find(m => m.id === 2).result.tools.length, 11);
      assert.ok(!`${result.stdout}${result.stderr}`.includes(secret));
    });
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});
