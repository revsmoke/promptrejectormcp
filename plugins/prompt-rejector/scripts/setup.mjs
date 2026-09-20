import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { pluginRoot, settingsPath } from './runtime.mjs';

try {
  const args = process.argv.slice(2);
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index], value = args[index + 1];
    if (!['--installation', '--env-file', '--config'].includes(name) || options[name] || !value || value.startsWith('--'))
      throw new Error('Usage: setup.mjs [--installation /absolute/repo] [--env-file /absolute/.env] [--config /absolute/config.json]');
    options[name] = resolve(value);
  }
  const root = options['--installation'] || resolve(pluginRoot, '../..');
  if (!existsSync(join(root, 'dist/scripts/startMcp.js')) || JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).name !== 'prompt-rejector')
    throw new Error('Build Prompt Rejector first: npm ci, then npm run build.');
  const envFile = options['--env-file'] || join(root, '.env');
  if (!existsSync(envFile)) throw new Error('Create a private .env with TYPESAFE_API_KEY and your reasoning-provider key, then rerun setup.');
  const configFile = options['--config'] || join(root, 'config/ai.active.json');
  if (!existsSync(configFile)) throw new Error('AI configuration file is unavailable.');
  // Check the real configuration without echoing credentials or performing inference.
  const moduleUrl = path => JSON.stringify(pathToFileURL(join(root, path)).href);
  const code = `import dotenv from ${moduleUrl('node_modules/dotenv/lib/main.js')};
    dotenv.config({path:${JSON.stringify(envFile)},quiet:true});
    process.env.AI_CONFIG_PATH=${JSON.stringify(configFile)};
    const {loadAIConfig}=await import(${moduleUrl('dist/ai/config.js')});
    const {describeAiConfig}=await import(${moduleUrl('dist/scripts/checkAiConfig.js')});
    console.log(JSON.stringify(describeAiConfig(loadAIConfig(),process.env)));`;
  const probe = spawnSync(process.execPath, ['--input-type=module', '--eval', code], { cwd: root, encoding: 'utf8' });
  if (probe.status !== 0) throw new Error('Configuration check failed. Check the selected environment and AI configuration.');
  const { missingCredentialEnvironmentVariables: missing } = JSON.parse(probe.stdout);
  if (missing.length) throw new Error(`Add the required keys to your private environment file: ${missing.join(', ')}`);
  const settings = { installationPath: root, envFile, configFile };
  const path = settingsPath();
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  writeFileSync(temporary, JSON.stringify(settings, null, 2) + '\n', { mode: 0o600 });
  renameSync(temporary, path); chmodSync(path, 0o600);
  console.log(`Plugin configured. Paths only, no keys, saved to ${path}`);
  console.log('Next: npm run plugin:doctor. Reconnect the plugin in a new client session.');
} catch (error) {
  console.error(error instanceof SyntaxError ? 'Invalid configuration JSON.' : error.message);
  process.exitCode = 1;
}
