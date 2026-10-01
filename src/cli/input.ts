import { createReadStream } from "node:fs";
import type { Readable } from "node:stream";
import { PromptRejectorError } from "../client/errors.js";

export const MAX_INPUT_BYTES = 4 * 1024 * 1024;

export function inputStream(file: string | undefined): Readable {
    return file && file !== "-" ? createReadStream(file) : process.stdin;
}

export async function readInput(stream: Readable): Promise<string> {
    const chunks: Buffer[] = [];
    let size = 0;
    try {
        for await (const chunk of stream) {
            const buffer = Buffer.from(chunk);
            size += buffer.length;
            if (size > MAX_INPUT_BYTES) throw new PromptRejectorError("input_too_large");
            chunks.push(buffer);
        }
    } catch (error) { throw error instanceof PromptRejectorError ? error : new PromptRejectorError("io_error"); }
    return Buffer.concat(chunks).toString("utf8");
}

/** Bound each line before decoding/parsing; keep only the current line in memory. */
export async function* readLines(stream: Readable): AsyncGenerator<string> {
    let pending = Buffer.alloc(0);
    try {
        for await (const chunk of stream) {
            const buffer = Buffer.from(chunk);
            let start = 0;
            for (let end = buffer.indexOf(10); end !== -1; end = buffer.indexOf(10, start)) {
                if (pending.length + end - start > MAX_INPUT_BYTES) throw new PromptRejectorError("input_too_large");
                yield Buffer.concat([pending, buffer.subarray(start, end)]).toString("utf8").replace(/\r$/, "");
                pending = Buffer.alloc(0);
                start = end + 1;
            }
            if (pending.length + buffer.length - start > MAX_INPUT_BYTES) throw new PromptRejectorError("input_too_large");
            pending = Buffer.concat([pending, buffer.subarray(start)]);
        }
        if (pending.length) yield pending.toString("utf8");
    } catch (error) { throw error instanceof PromptRejectorError ? error : new PromptRejectorError("io_error"); }
}

export function parseJson(text: string): unknown {
    if (Buffer.byteLength(text) > MAX_INPUT_BYTES) throw new PromptRejectorError("input_too_large");
    try { return JSON.parse(text); } catch { throw new PromptRejectorError("invalid_json"); }
}
