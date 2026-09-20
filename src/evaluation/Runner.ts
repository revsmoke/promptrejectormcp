import type { ConfigSnapshot } from "../ai/config.js";
import { ProviderRegistry } from "../ai/registry.js";
import { tokenPrices } from "../ai/pricing.js";
import { SemanticAnalysisService } from "../services/SemanticAnalysisService.js";
import { JudgmentService } from "../services/JudgmentService.js";
import { DescriptorAnalysisService } from "../services/DescriptorAnalysisService.js";
import { CapabilityAnalysisService } from "../services/CapabilityAnalysisService.js";
import { ModelReferenceService } from "../services/ModelReferenceService.js";
import { PatternService } from "../services/PatternService.js";
import { McpToolScanner } from "../services/McpToolScanner.js";
import { SecurityService } from "../services/SecurityService.js";
import { SkillScanService } from "../services/SkillScanService.js";
import { HuggingFaceService } from "../services/HuggingFaceService.js";
import { TasteTesterService, type TasteTesterInput } from "../services/TasteTesterService.js";
import { AnalysisBudget } from "../ai/budget.js";
import { validateCaseInput, type EvaluationCase } from "./Corpus.js";
import { modelAnswerFingerprint, type EvaluationDecision, type EvaluationObservation } from "./Metrics.js";
import type { RunQuota } from "./RunQuota.js";
class OfflineHF extends HuggingFaceService {
    override async checkModel(modelId: string) { return { modelId, fetchedAt: new Date().toISOString(), severity: "low" as const, flags: [{ class: "lookup_failed" as const, note: "Offline evaluation: metadata lookup not performed" }] }; }
}
/** Isolated library services only: no listeners, feed updates, public request
 * overrides or account discovery. Labels are never passed to a provider. */
export function evaluationServices(snapshot: ConfigSnapshot, options: { live: boolean; env?: NodeJS.ProcessEnv; quota?: RunQuota; patterns?: PatternService }) {
    const env = options.live ? options.env ?? process.env : {};
    const offlineFetch = async (): Promise<Response> => { throw new Error("Offline inference forbidden"); };
    const fetchImpl = options.live ? undefined : offlineFetch;
    const registry = new ProviderRegistry(snapshot, { env, fetch: fetchImpl, pricing: snapshot.pricing });
    const semantic = new SemanticAnalysisService(snapshot, registry, options.quota ? (task, signal) => options.quota!.context(snapshot, task, signal) : undefined);
    const judgments = new JudgmentService(snapshot, { apiKey: env.TYPESAFE_API_KEY, fetch: fetchImpl, prices: tokenPrices(snapshot.pricing, "typesafe", snapshot.config.typesafe.model) });
    const patterns = options.patterns ?? new PatternService();
    const descriptor = new DescriptorAnalysisService(new McpToolScanner(patterns), judgments, semantic);
    const capability = new CapabilityAnalysisService(judgments, undefined, undefined, semantic, patterns);
    const references = new ModelReferenceService(judgments);
    const prompt = new SecurityService(patterns, semantic, judgments);
    const skill = new SkillScanService(patterns, options.live ? new HuggingFaceService({ token: env.HF_TOKEN }) : new OfflineHF(), semantic, judgments, capability, references);
    const taster = new TasteTesterService({ enabled: true, apiKey: "", monitor: semantic });
    const tasterBudget = (turns: number) => options.quota?.context(snapshot, "taster", undefined, turns).budget ?? new AnalysisBudget("taster", snapshot.config.limits, { tasterTurns: turns });
    return { descriptor, capability, references, prompt, skill, semantic, taster, tasterBudget };
}
export async function evaluateCase(services: ReturnType<typeof evaluationServices>, item: EvaluationCase) {
    validateCaseInput(item);
    const started = Date.now();
    const report = await (async () => {
      if (item.task === "descriptor") return services.descriptor.analyze(item.input as { tool: Record<string, unknown> });
      if (item.task === "capability") return services.capability.analyze(item.input);
      if (item.task === "prompt") return services.prompt.runSecurityScanV2(item.input.prompt as string);
      if (item.task === "skill") return services.skill.scanSkillV2(item.input.skillContent as string);
      if (item.task === "taster") return services.taster.runV2(item.input as unknown as TasteTesterInput, { budget: services.tasterBudget(item.input.mode === "thorough" ? 5 : 2) });
        const text = item.input.text as string, context = services.semantic.createContext("skill");
        if (services.references.judgments.snapshot.config.typesafe.modelReference === "shadow") context.budget.authorizeShadow({ requiredWorkComplete: true });
        const result = await services.references.observe(text, services.references.extract(text), context);
        return { task: "modelReference" as const, ...result, usage: context.budget.usage.summary() };
    })();
    let decision: EvaluationDecision = "review", coverageComplete: boolean;
    if ("decision" in report) { decision = report.decision; coverageComplete = report.coverage.every((entry) => !entry.required || entry.status === "complete"); }
    else if ("behaviorReport" in report) {
        coverageComplete = report.coverage.taster === "complete" && report.coverage.monitor === "complete";
        decision = report.behaviorReport.monitorVerdict === "malicious" ? "block" : report.behaviorReport.monitorVerdict === "clean" ? "allow" : report.behaviorReport.monitorVerdict === "undetermined" ? "unavailable" : "review";
    } else coverageComplete = report.requiredComplete;
    const observation: EvaluationObservation = { id: item.id, family: item.family, risk: item.label.risk, severity: item.label.severity,
        decision, coverageComplete, answerFingerprint: modelAnswerFingerprint(report),
        elapsedMs: Date.now() - started, estimatedUsd: report.usage?.estimatedUsd ?? null, attempts: report.usage?.calls ?? 0 };
    const exactReferences = "extraction" in report && Array.isArray(item.label.expected)
        ? JSON.stringify([...report.lookupIds].sort()) === JSON.stringify([...item.label.expected].sort()) : null;
    return { id: item.id, task: item.task, sourceSha256: item.sourceSha256, observation, exactReferences, report };
}
