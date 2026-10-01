#!/usr/bin/env node
import type { Writable } from "node:stream";

// This executable owns stdout. Importing the SDK never changes console or signal handlers.
console.log = (...args) => console.error(...args);
const controller = new AbortController();
let timer: ReturnType<typeof setTimeout> | undefined;
let stopping = false;
const write = (stream: Writable, text: string) => new Promise<void>((resolve, reject) => stream.write(text, error => error ? reject(error) : resolve()));
async function stop(code: number, error: string) {
    if (stopping) return;
    stopping = true;
    controller.abort();
    try { await write(process.stderr, JSON.stringify({ error }) + "\n"); }
    finally { process.exit(code); }
}
process.once("SIGINT", () => { void stop(130, "cancelled"); });
process.once("SIGTERM", () => { void stop(143, "cancelled"); });
// A closed consumer is an operational failure, never an allow decision.
process.stdout.on("error", () => process.exit(3));
process.stderr.on("error", () => process.exit(3));

try {
    const { runCli } = await import("./run.js");
    const code = await runCli(process.argv.slice(2), {
        stdout: text => write(process.stdout, text), stderr: text => write(process.stderr, text), signal: controller.signal,
        setDeadline: milliseconds => { timer = setTimeout(() => { void stop(124, "timeout"); }, milliseconds); },
    });
    if (timer) clearTimeout(timer);
    if (!stopping) process.exit(code);
} catch { await stop(3, "internal_error"); }
