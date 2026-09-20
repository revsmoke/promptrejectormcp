import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const pluginRoot = fileURLToPath(new URL('../', import.meta.url));
export const settingsPath = () => process.env.PROMPT_REJECTOR_SETTINGS || join(homedir(), '.config', 'prompt-rejector', 'plugin.json');
export function readSettings() {
  if (process.env.PROMPT_REJECTOR_BUNDLED_ONLY === 'true') return {};
  const path = settingsPath();
  if (!existsSync(path)) return {};
  const settings = JSON.parse(readFileSync(path, 'utf8'));
  if (!settings || Array.isArray(settings) || typeof settings !== 'object') throw new Error('Invalid plugin settings; rerun plugin:setup.');
  for (const [key, value] of Object.entries(settings)) {
    if (!['installationPath', 'envFile', 'configFile'].includes(key) || typeof value !== 'string' || !isAbsolute(value))
      throw new Error('Plugin settings accept only absolute installationPath, envFile and configFile paths.');
  }
  return settings;
}

function validInstallation(root) {
  try {
    return JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).name === 'prompt-rejector'
      && existsSync(join(root, 'dist/scripts/startMcp.js')) && existsSync(join(root, 'node_modules'));
  } catch { return false; }
}

export function resolveRuntime(settings = readSettings()) {
  if (settings.installationPath) {
    if (!validInstallation(settings.installationPath)) throw new Error('Configured installation is unavailable. Build it or rerun plugin:setup.');
    return settings.installationPath;
  }
  const bundled = join(pluginRoot, 'runtime');
  if (existsSync(bundled)) {
    const { sha256 } = JSON.parse(readFileSync(join(pluginRoot, 'runtime.json'), 'utf8'));
    if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error('Invalid runtime bundle identity.');
    // State belongs outside an immutable plugin cache and survives client restarts.
    const data = process.env.PROMPT_REJECTOR_DATA_DIR || join(homedir(), '.local', 'share', 'prompt-rejector');
    const target = join(data, 'runtimes', sha256);
    if (!existsSync(target)) {
      mkdirSync(dirname(target), { recursive: true });
      const temporary = mkdtempSync(join(dirname(target), '.install-'));
      try {
        cpSync(bundled, temporary, { recursive: true, dereference: false });
        try { renameSync(temporary, target); }
        catch (error) { if (!existsSync(target)) throw error; }
      } finally { rmSync(temporary, { recursive: true, force: true }); }
    }
    if (!validInstallation(target)) throw new Error('Incomplete bundled runtime; reinstall the plugin.');
    return target;
  }
  const checkout = resolve(pluginRoot, '../..');
  if (validInstallation(checkout)) return checkout;
  throw new Error('Prompt Rejector needs setup. Use the prompt-rejector skill to clone/build the repository and run npm run plugin:setup.');
}

export function launchOptions() {
  const settings = readSettings();
  const root = resolveRuntime(settings);
  const args = [join(root, 'dist/scripts/startMcp.js')];
  const envFile = process.env.PROMPT_REJECTOR_ENV_FILE || settings.envFile;
  const configFile = process.env.PROMPT_REJECTOR_AI_CONFIG || settings.configFile;
  for (const [flag, value] of [['--env-file', envFile], ['--config', configFile]]) {
    if (value) {
      if (!isAbsolute(value) || !existsSync(value)) throw new Error(`${flag} must name an existing absolute file path.`);
      args.push(flag, value);
    }
  }
  return { root, args };
}
