import dotenv from "dotenv";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { keyNames, loadAIConfig, type ConfigSnapshot } from "../ai/config.js";
import { modelCapabilities, profileHash } from "../ai/modelProfiles.js";
import { tokenPrices } from "../ai/pricing.js";
export function describeAiConfig(snapshot: ConfigSnapshot, env: NodeJS.ProcessEnv) {
    const tasterEnabled = env.TASTE_TESTER_ENABLED === "true";
    const profiles = Object.entries(snapshot.config.profiles).map(([name, profile]) => {
        const referencedBy = Object.entries(snapshot.config.roles).flatMap(([role, setting]) =>
            (["primary", "fallback"] as const).filter((selection) => setting[selection] === name).map((selection) => ({
                role, selection, enabled: !["taster", "monitor"].includes(role) || tasterEnabled,
            })));
        const enabledRoles = [...new Set(referencedBy.filter((reference) => reference.enabled).map((reference) => reference.role))];
        const credentialEnvironmentVariable = keyNames[profile.provider];
        const credentialPresent = !!env[credentialEnvironmentVariable];
        return { name, provider: profile.provider, model: profile.model, profileHash: profileHash(profile), referencedBy, enabledRoles,
            credentialEnvironmentVariable, credentialPresent, credentialRequired: enabledRoles.length > 0,
            capabilitiesDeclared: !!modelCapabilities(profile, snapshot.capabilities), priced: !!tokenPrices(snapshot.pricing, profile.provider, profile.model),
            readiness: !enabledRoles.length ? "unused_or_disabled" : credentialPresent ? "declared; live conformance and quality qualification remain separate" : "credential_missing",
        };
    });
    const judgmentEnabled = Object.entries(snapshot.config.typesafe).some(([task, mode]) => task !== "model" && mode !== "off");
    return { inferencePerformed: false, configHash: snapshot.hash, legacy: snapshot.legacy, profiles,
        missingCredentialEnvironmentVariables: [...new Set(profiles.filter((profile) => profile.credentialRequired && !profile.credentialPresent).map((profile) => profile.credentialEnvironmentVariable)), ...(judgmentEnabled && !env.TYPESAFE_API_KEY ? [keyNames.typesafe] : [])],
        roles: snapshot.config.roles, typesafe: { ...snapshot.config.typesafe, credentialEnvironmentVariable: keyNames.typesafe, credentialPresent: !!env.TYPESAFE_API_KEY, credentialRequired: judgmentEnabled },
        limits: snapshot.config.limits, qualification: snapshot.qualification ?? { tasks: {} },
        reportScope: { enforcement: "v2_only", legacyDescriptorCapability: "local_only" },
    };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    dotenv.config({ quiet: true });
    try { console.log(JSON.stringify(describeAiConfig(loadAIConfig(), process.env), null, 2)); }
    catch { console.error("AI configuration is invalid. Check referenced profiles, capability options and configuration files."); process.exitCode = 1; }
}
