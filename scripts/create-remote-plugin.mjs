import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { zipSync } from 'fflate';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
let temporary;
try {
  if (process.argv.length !== 4) throw new Error('Usage: node scripts/create-remote-plugin.mjs https://your-real-host/mcp /absolute/output.zip');
  const url = new URL(process.argv[2]);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/mcp') throw new Error('Use the real HTTPS /mcp URL without credentials, query or fragment.');
  temporary = mkdtempSync(join(tmpdir(), 'prompt-rejector-remote-plugin-'));
  const plugin = join(temporary, 'prompt-rejector');
  cpSync(join(root, 'plugins/prompt-rejector'), plugin, { recursive: true });
  rmSync(join(plugin, 'scripts'), { recursive: true });
  const write = (name, value) => writeFileSync(join(plugin, name), JSON.stringify(value, null, 2) + '\n');
  write('mcp.json', { $schema: 'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json', mcpServers: { 'prompt-rejector': { type: 'streamable-http', url: url.href } } });
  write('.mcp.json', { mcpServers: { 'prompt-rejector': { type: 'http', url: url.href } } });
  const compatibility = JSON.parse(readFileSync(join(plugin, '.codex-plugin/plugin.json'), 'utf8'));
  compatibility.mcpServers = { 'prompt-rejector': { url: url.href } };
  write('.codex-plugin/plugin.json', compatibility);
  writeFileSync(join(plugin, 'CONNECTION.md'), `This package connects to ${url.href}. It contains skills and connection metadata, not a hosted server or credentials. The operator must configure OAuth and verify the client connection. Do not install alongside the local plugin with the same name.\n`);
  const files = {};
  function collect(dir, prefix = '') {
    for (const item of readdirSync(dir, { withFileTypes: true })) {
      const name = `${prefix}${item.name}`;
      if (item.isDirectory()) collect(join(dir, item.name), `${name}/`);
      else if (item.isFile()) files[name] = readFileSync(join(dir, item.name));
      else throw new Error('Unexpected non-file in plugin');
    }
  }
  collect(temporary);
  writeFileSync(resolve(process.argv[3]), zipSync(files));
  console.log('Remote plugin archive created. Hosting and client OAuth verification are separate steps.');
} catch (error) { console.error(error.message); process.exitCode = 1; }
finally { if (temporary) rmSync(temporary, { recursive: true, force: true }); }
