import { deepFreeze, validateConfiguration, type ConfigParseOptions, type ConfigSnapshot } from "../ai/configValidation.js";
import { hashConfiguration } from "../ai/modelProfiles.js";

/** Local evaluator only. This function validates every ordinary config/profile
 * constraint but cannot produce a serving snapshot or start a public listener.
 * No config, environment, REST, or MCP flag selects this construction path. */
export function createCandidateSnapshot(input: unknown, options: ConfigParseOptions = {}): ConfigSnapshot {
    const snapshot = validateConfiguration(input, false, options);
    return deepFreeze({ ...snapshot, evaluationOnly: true, hash: hashConfiguration({ config: snapshot.config, capabilities: snapshot.capabilities, pricing: snapshot.pricing ?? null, evaluationOnly: true }) });
}
