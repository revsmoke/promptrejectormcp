import { deepFreeze, validateConfiguration, type ConfigParseOptions, type ConfigSnapshot } from "../ai/configValidation.js";
import { PatternService } from "../services/PatternService.js";
import { hashConfiguration } from "../ai/modelProfiles.js";

/** Local evaluator only. This function validates every ordinary config/profile
 * constraint but cannot produce a serving snapshot or start a public listener.
 * No config, environment, REST, or MCP flag selects this construction path. */
export function createCandidateSnapshot(input: unknown, options: ConfigParseOptions = {}): ConfigSnapshot {
    const snapshot = validateConfiguration(input, false, options);
    const enforced = Object.values(snapshot.config.typesafe).some((value) => value === "enforce" || value === "cascade");
    const evaluationPatternsSha256 = enforced ? hashConfiguration((options.patternService ?? new PatternService()).getQualificationState()) : undefined;
    return deepFreeze({ ...snapshot, evaluationOnly: true, evaluationPatternsSha256, hash: hashConfiguration({ config: snapshot.config, capabilities: snapshot.capabilities, pricing: snapshot.pricing ?? null, evaluationOnly: true, evaluationPatternsSha256: evaluationPatternsSha256 ?? null }) });
}
