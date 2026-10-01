export type ErrorCode = "invalid_input" | "input_too_large" | "invalid_json" | "unknown_command" | "configuration_error" | "io_error" | "internal_error" | "cancelled" | "timeout";

/** Stable, deliberately redacted errors; never attach input or provider responses. */
export class PromptRejectorError extends Error {
    constructor(readonly code: ErrorCode) { super(code); this.name = "PromptRejectorError"; }
}
