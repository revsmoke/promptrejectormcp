import { createRequire } from "node:module";
import { qualificationStatus } from "../ai/qualification.js";
import type { Services } from "../bootstrap.js";
const { version } = createRequire(import.meta.url)("../../package.json");

/** Shared local readiness; performs no inference or account probe. */
export function serviceHealth(services: Services) {
    const roles = Object.fromEntries(Object.entries(services.snapshot.config.roles).map(([role, setting]) => {
        const profile = services.snapshot.config.profiles[setting.primary];
        const enabled = !["taster", "monitor"].includes(role) || services.tasterEnabled;
        const configured = services.configuredProviders[profile.provider];
        const fallback = setting.fallback ? services.snapshot.config.profiles[setting.fallback] : undefined;
        return [role, { provider: profile.provider, model: profile.model, configured, enabled,
            readiness: !enabled ? "disabled" : configured && (!fallback || services.configuredProviders[fallback.provider]) ? "ready" : "degraded",
            fallback: fallback ? { provider: fallback.provider, model: fallback.model, configured: services.configuredProviders[fallback.provider] } : null }];
    }));
    const { model, ...modes } = services.snapshot.config.typesafe;
    const enabled = Object.values(modes).some((mode) => mode !== "off");
    return { status: "ok", version, configHash: services.snapshot.hash, roles,
        typesafe: { model, modes, configured: services.configuredProviders.typesafe, readiness: !enabled ? "disabled" : services.configuredProviders.typesafe ? "ready" : "degraded" },
        qualificationPolicy: services.snapshot.config.qualificationPolicy, qualificationStatus: qualificationStatus(services.snapshot),
        qualification: services.snapshot.qualification ?? { tasks: {} }, readinessMeaning: "local_configuration_and_credentials_only; account_access_and_quality_not_probed",
        reports: { schemaVersion: 2, restPrefix: "/v2" } };
}
