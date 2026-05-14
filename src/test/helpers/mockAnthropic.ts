// Mock Anthropic client factory for TasteTesterService tests.
//
// Real Anthropic API calls are NEVER made in tests. This helper lets a test
// queue up a sequence of `messages.create` responses; each call to the mock
// pops the next response in order.
//
// Each "response" can be either:
//   - an object (returned as-is)
//   - a function (invoked with the request args; useful for asserting on
//     what the service sent, or returning a Promise<never> to simulate
//     never-resolving timeouts)
//   - an Error (thrown synchronously inside the Promise)

import type { MinimalAnthropicClient } from "../../services/TasteTesterService.js";

export type MockResponse =
    | object
    | Error
    | ((args: any) => any | Promise<any>);

export interface MockAnthropicHandle {
    factory: (opts: { apiKey: string }) => MinimalAnthropicClient;
    calls: any[];
}

export function createMockAnthropic(responses: MockResponse[]): MockAnthropicHandle {
    const queue = [...responses];
    const calls: any[] = [];

    const factory = (_opts: { apiKey: string }): MinimalAnthropicClient => {
        return {
            messages: {
                create: async (args: any) => {
                    calls.push(args);
                    if (queue.length === 0) {
                        throw new Error("mockAnthropic: response queue exhausted");
                    }
                    const next = queue.shift()!;
                    if (next instanceof Error) {
                        throw next;
                    }
                    if (typeof next === "function") {
                        return next(args);
                    }
                    return next;
                },
            },
        };
    };

    return { factory, calls };
}

// Build an assistant response with only a text block. Useful for benign /
// no-tool-use scenarios.
export function textResponse(text: string, stop_reason: "end_turn" | "stop_sequence" = "end_turn") {
    return {
        id: "msg_test",
        type: "message",
        role: "assistant",
        model: "test",
        content: [{ type: "text", text }],
        stop_reason,
        stop_sequence: null,
        usage: { input_tokens: 0, output_tokens: 0 },
    };
}

// Build an assistant response containing a single tool_use block.
export function toolUseResponse(name: string, input: Record<string, unknown>, id = "toolu_test_1") {
    return {
        id: "msg_test",
        type: "message",
        role: "assistant",
        model: "test",
        content: [{ type: "tool_use", id, name, input }],
        stop_reason: "tool_use",
        stop_sequence: null,
        usage: { input_tokens: 0, output_tokens: 0 },
    };
}
