import dotenv from "dotenv";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { keyNames, loadAIConfig, type ConfigSnapshot } from "../ai/config.js";
import { modelCapabilities, profileHash } from "../ai/modelProfiles.js";
import { tokenPrices } from "../ai/pricing.js";
export function describeAiConfig(snapshot: ConfigSnapshot, env: NodeJS.ProcessEnv) {
    return { inferencePerformed: false, configHash: snapshot.hash, legacy: snapshot.legacy,
        profiles: Object.entries(snapshot.config.profiles).map(([name, profile]) => ({ name, provider: profile.provider, model: profile.model,
            profileHash: profileHash(profile), credentialPresent: !!env[keyNames[profile.provider]],
            capabilitiesDeclared: !!modelCapabilities(profile, snapshot.capabilities), priced: !!tokenPrices(snapshot.pricing, profile.provider, profile.model),
            readiness: env[keyNames[profile.provider]] ? "declared; live conformance and quality qualification remain separate" : "credential_missing" })),
        roles: snapshot.config.roles, typesafe: { ...snapshot.config.typesafe, credentialPresent: !!env.TYPESAFE_API_KEY },
        limits: snapshot.config.limits,
    };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    dotenv.config({ quiet: true });
    try { console.log(JSON.stringify(describeAiConfig(loadAIConfig(), process.env), null, 2)); }
    catch { console.error("AI configuration is invalid. Check referenced profiles, capability options and configuration files."); process.exitCode = 1; }
}
