import { loadAIConfig, keyNames, type ConfigSnapshot } from "./ai/config.js";
import { ProviderRegistry } from "./ai/registry.js";
import type { FetchLike } from "./ai/transport.js";
import { SemanticAnalysisService } from "./services/SemanticAnalysisService.js";
import { GeminiService } from "./services/GeminiService.js";
import { SecurityService } from "./services/SecurityService.js";
import { SkillScanService } from "./services/SkillScanService.js";
import { PatternService } from "./services/PatternService.js";
import { VulnFeedService } from "./services/VulnFeedService.js";
import { AtlasService } from "./services/AtlasService.js";
import { OsvFeedService } from "./services/OsvFeedService.js";
import { GhsaGraphQLService } from "./services/GhsaGraphQLService.js";
import { KevFeedService } from "./services/KevFeedService.js";
import { HuggingFaceService } from "./services/HuggingFaceService.js";
import { TrifectaAnalyzer } from "./services/TrifectaAnalyzer.js";
import { CanaryService } from "./services/CanaryService.js";
import { McpToolScanner } from "./services/McpToolScanner.js";
import { TasteTesterService } from "./services/TasteTesterService.js";
import { UnifiedCveCache } from "./services/UnifiedCveCache.js";
import { JudgmentService } from "./services/JudgmentService.js";
import { DescriptorAnalysisService } from "./services/DescriptorAnalysisService.js";
import { CapabilityAnalysisService } from "./services/CapabilityAnalysisService.js";
import { ModelReferenceService } from "./services/ModelReferenceService.js";
import { tokenPrices } from "./ai/pricing.js";
import { assertServingSnapshot } from "./ai/qualification.js";

export interface ServiceDependencies {
    env?: NodeJS.ProcessEnv;
    fetch?: FetchLike;
    registry?: ProviderRegistry;
    semantic?: SemanticAnalysisService;
    patternService?: PatternService;
    huggingFaceService?: HuggingFaceService;
    tasteTesterService?: TasteTesterService;
    judgmentService?: JudgmentService;
}
/** One process graph, constructed only after dotenv. Importing this module
 * performs neither service construction nor provider/account discovery. */
export function createServices(snapshot: ConfigSnapshot = loadAIConfig(), deps: ServiceDependencies = {}) {
    assertServingSnapshot(snapshot);
    const env = deps.env ?? process.env;
    const configuredProviders = Object.fromEntries(Object.entries(keyNames).map(([provider, key]) => [provider, !!env[key]]));
    const registry = deps.registry ?? new ProviderRegistry(snapshot, { env, fetch: deps.fetch });
    const semantic = deps.semantic ?? new SemanticAnalysisService(snapshot, registry);
    const patternService = deps.patternService ?? new PatternService();
    const huggingFaceService = deps.huggingFaceService ?? new HuggingFaceService({ token: env.HF_TOKEN });
    const judgmentService = deps.judgmentService ?? new JudgmentService(snapshot, { apiKey: env.TYPESAFE_API_KEY, fetch: deps.fetch, prices: tokenPrices(snapshot.pricing, "typesafe", snapshot.config.typesafe.model) });
    const capabilityAnalysis = new CapabilityAnalysisService(judgmentService, undefined, undefined, semantic);
    const modelReferenceService = new ModelReferenceService(judgmentService);
    const securityService = new SecurityService(patternService, semantic, judgmentService);
    const skillScanService = new SkillScanService(patternService, huggingFaceService, semantic, judgmentService, capabilityAnalysis, modelReferenceService);
    const atlasService = new AtlasService();
    const osvFeedService = new OsvFeedService();
    const ghsaGraphQLService = new GhsaGraphQLService();
    const kevFeedService = new KevFeedService();
    const geminiService = new GeminiService(semantic);
    const vulnFeedService = new VulnFeedService(patternService, semantic, undefined, osvFeedService, ghsaGraphQLService, atlasService, kevFeedService);
    const trifectaAnalyzer = new TrifectaAnalyzer();
    const canaryService = new CanaryService();
    const mcpToolScanner = new McpToolScanner(patternService);
    const descriptorAnalysis = new DescriptorAnalysisService(mcpToolScanner, judgmentService, semantic);
    const tasteTesterService = deps.tasteTesterService ?? new TasteTesterService({ monitor: semantic, apiKey: env.ANTHROPIC_API_KEY ?? "", maxTurns: Number(env.TASTE_TESTER_MAX_TURNS) || 5, maxTokens: Number(env.TASTE_TESTER_MAX_TOKENS) || 4096, timeoutMs: Number(env.TASTE_TESTER_TIMEOUT_MS) || 30000, enabled: env.TASTE_TESTER_ENABLED === "true" });
    const unifiedCveCache = new UnifiedCveCache(vulnFeedService, atlasService, kevFeedService);
    return { snapshot, registry, semantic, configuredProviders, tasterEnabled: env.TASTE_TESTER_ENABLED === "true", patternService, securityService, skillScanService, huggingFaceService,
        atlasService, osvFeedService, ghsaGraphQLService, kevFeedService, geminiService, vulnFeedService,
        trifectaAnalyzer, canaryService, mcpToolScanner, tasteTesterService, unifiedCveCache, judgmentService, descriptorAnalysis, capabilityAnalysis, modelReferenceService };
}
export type Services = ReturnType<typeof createServices>;
