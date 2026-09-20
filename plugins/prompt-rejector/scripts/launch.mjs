import { spawn } from 'node:child_process';
import { launchOptions } from './runtime.mjs';

try {
  const { root, args } = launchOptions();
  // No shell and no npm: stdout is exclusively MCP JSON-RPC.
  const child = spawn(process.execPath, args, { cwd: root, env: process.env, stdio: 'inherit' });
  child.on('error', () => { console.error('Prompt Rejector could not start. Run plugin:doctor from the installation.'); process.exitCode = 1; });
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => child.kill(signal));
  child.on('exit', (code, signal) => { process.exitCode = code ?? (signal ? 1 : 0); });
} catch (error) {
  console.error(error instanceof SyntaxError ? 'Invalid plugin settings JSON; rerun plugin:setup.' : error.message);
  process.exitCode = 1;
}
