import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { zipSync } from 'fflate';
import Ajv from 'ajv';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const destination = join(root, 'artifacts/plugins');
const temporary = mkdtempSync(join(tmpdir(), 'prompt-rejector-package-'));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const json = path => JSON.parse(readFileSync(path, 'utf8'));
const writeJson = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n');

function files(directory, prefix = '') {
  return readdirSync(directory).sort().flatMap(name => {
    const path = join(directory, name), rel = prefix + name, stat = lstatSync(path);
    // npm creates .bin links; executable shims are unnecessary for this Node entry point.
    if (stat.isSymbolicLink()) {
      if (prefix.includes('node_modules/') && prefix.endsWith('.bin/')) return [];
      throw new Error(`Symlink cannot be packaged: ${rel}`);
    }
    if (/^(?:\.env(?:\..*)?|\.certs|\.git|\.DS_Store)$/.test(name) || /\.(pem|key|p12|pfx)$/.test(name)) throw new Error(`Private file cannot be packaged: ${rel}`);
    return stat.isDirectory() ? files(path, rel + '/') : [[rel, readFileSync(path)]];
  });
}
function zip(directory, output) {
  writeFileSync(output, zipSync(Object.fromEntries(files(directory).map(([path, data]) => [path, [data, { mtime: new Date('2020-01-01T00:00:00Z') }]])), { level: 6 }));
}
try {
  const version = json(join(root, 'package.json')).version;
  const plugin = join(temporary, 'prompt-rejector');
  cpSync(join(root, 'plugins/prompt-rejector'), plugin, { recursive: true });
  const portableValidator = addFormats(new Ajv2020({ strict: false, allErrors: true }));
  for (const [file, schema] of [['plugin.json', 'agent-plugins-1.0.0.schema.json'], ['mcp.json', 'agent-plugins-mcp-1.0.0.schema.json']]) {
    const valid = portableValidator.compile(json(join(root, 'packaging/schemas', schema)));
    if (!valid(json(join(plugin, file)))) throw new Error(`Invalid ${file}: ${JSON.stringify(valid.errors)}`);
  }
  for (const manifest of ['plugin.json', '.codex-plugin/plugin.json', '.claude-plugin/plugin.json'])
    if (json(join(plugin, manifest)).version !== version) throw new Error(`Version mismatch: ${manifest}`);
  const runtime = join(plugin, 'runtime');
  mkdirSync(runtime);
  for (const name of ['package.json', 'package-lock.json', 'LICENSE']) cpSync(join(root, name), join(runtime, name));
  cpSync(join(root, 'dist'), join(runtime, 'dist'), { recursive: true, filter: path => !relative(join(root, 'dist'), path).split(/[\\/]/).includes('test') && !/\.(map|ts)$/.test(path) });
  mkdirSync(join(runtime, 'config'));
  for (const name of ['ai.active.json', 'ai.example.json', 'model-capabilities.json', 'ai-pricing.example.json']) cpSync(join(root, 'config', name), join(runtime, 'config', name));
  mkdirSync(join(runtime, 'patterns'));
  const manifest = json(join(root, 'patterns/manifest.json'));
  for (const name of ['manifest.json', ...Object.keys(manifest.files)]) {
    if (!/^[A-Za-z0-9_-]+\.json$/.test(name)) throw new Error('Invalid pattern manifest filename');
    const bytes = readFileSync(join(root, 'patterns', name));
    if (name !== 'manifest.json' && sha(bytes) !== manifest.files[name].sha256) throw new Error(`Pattern integrity failed: ${name}`);
    writeFileSync(join(runtime, 'patterns', name), bytes);
  }
  const npmArgs = ['ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'];
  const npmCli = process.env.npm_execpath;
  if (process.platform === 'win32' && !npmCli) throw new Error('Build through npm run plugin:build on Windows.');
  const install = spawnSync(npmCli ? process.execPath : 'npm', npmCli ? [npmCli, ...npmArgs] : npmArgs, { cwd: runtime, encoding: 'utf8', timeout: 180000 });
  if (install.status !== 0) throw new Error('Production dependency installation failed during packaging.');
  // No development tools, private env, caches, canary state or certificates enter the bundle.
  rmSync(join(runtime, 'node_modules/.bin'), { recursive: true, force: true });
  const runtimeFiles = files(runtime);
  const runtimeHash = sha(runtimeFiles.map(([name, bytes]) => `${name}\0${sha(bytes)}\n`).join(''));
  writeJson(join(plugin, 'runtime.json'), { version, sha256: runtimeHash, files: runtimeFiles.length });
  cpSync(join(root, 'LICENSE'), join(plugin, 'LICENSE'));
  mkdirSync(destination, { recursive: true });
  const localName = `prompt-rejector-${version}-local.zip`;
  zip(temporary, join(destination, localName));
  const skillRoot = join(temporary, 'skill-only');
  mkdirSync(skillRoot);
  cpSync(join(plugin, 'skills/prompt-rejector'), join(skillRoot, 'prompt-rejector'), { recursive: true });
  zip(skillRoot, join(destination, 'prompt-rejector-skill.zip'));
  cpSync(join(root, 'packaging/desktop/manifest.json'), join(plugin, 'manifest.json'));
  if (json(join(plugin, 'manifest.json')).version !== version) throw new Error('Desktop manifest version mismatch');
  const desktopName = `prompt-rejector-${version}.mcpb`;
  const validateDesktop = addFormats(new Ajv({ strict: false, allErrors: true })).compile(json(join(root, 'packaging/schemas/mcpb-manifest-v0.3.schema.json')));
  if (!validateDesktop(json(join(plugin, 'manifest.json')))) throw new Error(`Invalid Desktop manifest: ${JSON.stringify(validateDesktop.errors)}`);
  // MCPB is a ZIP with manifest.json at its root. Validate against the official
  // schema without shipping the CLI's interactive editor dependency tree.
  zip(plugin, join(destination, desktopName));
  const outputNames = [localName, desktopName, 'prompt-rejector-skill.zip'];
  writeFileSync(join(destination, 'SHA256SUMS'), outputNames.map(name => `${sha(readFileSync(join(destination, name)))}  ${name}`).join('\n') + '\n');
  writeJson(join(destination, 'build.json'), { version, runtimeHash, runtimeFiles: runtimeFiles.length, artifacts: outputNames.map(name => ({ name, bytes: readFileSync(join(destination, name)).length })) });
  console.log(`Built ${outputNames.join(', ')} in ${destination}`);
} finally { rmSync(temporary, { recursive: true, force: true }); }
