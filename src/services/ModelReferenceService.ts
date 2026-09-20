import type { CallContext, JudgmentQuestion } from "../ai/contracts.js";
import { noul, UNTRUSTED_BOUNDARY } from "../ai/rubrics/prompt.js";
import { extractModelReferences, type ModelReferenceExtraction } from "./HuggingFaceReferences.js";
import { JudgmentService, effectiveJudgmentMode } from "./JudgmentService.js";
import { QUALIFICATION_THRESHOLDS } from "../ai/qualification.js";
export const MODEL_REFERENCE_RUBRIC_VERSION = "model-reference-source-spans.2";
export class ModelReferenceService {
    constructor(readonly judgments: JudgmentService) {}
    extract(text: string): ModelReferenceExtraction { return extractModelReferences(text); }
    async observe(text: string, extraction: ModelReferenceExtraction, context: CallContext, parentTask?: "skill") {
        const enforced = effectiveJudgmentMode(this.judgments.snapshot, "modelReference", parentTask) === "enforce";
        const unresolved = extraction.candidates.filter((candidate) => candidate.kind === "unresolved");
        const questions: Record<string, JudgmentQuestion> = Object.fromEntries(unresolved.map((candidate) => [candidate.id, noul(UNTRUSTED_BOUNDARY + `In source, does candidate ${candidate.id} identify a Hugging Face MODEL repository? Count named models even when only cited or audited, or when the text says never install that model.`,
            "The source identifies this exact candidate as a model repository name. Loading, citing, auditing, recommendations, and warnings against installing that named model all count.", "A dataset, Space, local path, generic owner/repository software project, or insufficient context to establish a model reference.")]));
        // A no-candidate batch has no semantic work; never manufacture a question.
        if (!unresolved.length) return { judgments: null, additions: [] as string[], extraction, lookupIds: extraction.baselineIds, unresolvedIds: [] as string[], requiredComplete: extraction.baselineIds.length <= 16 && (!enforced || !extraction.candidateOverflow) };
        const observation = await this.judgments.evaluate("modelReference", { model: this.judgments.snapshot.config.typesafe.model, state: JSON.stringify({ source: text, candidates: extraction.candidates }), questions,
            rubricVersion: MODEL_REFERENCE_RUBRIC_VERSION, schemaVersion: "judgment.1" }, context, { parentTask, cache: false, completeSource: !extraction.candidateOverflow });
        const answers = observation.result?.status === "ok" ? observation.result.value : null;
        const additions = [...new Set(unresolved.filter((candidate) => { const answer = answers?.[candidate.id]; return answer?.type === "noul" && answer.noul >= QUALIFICATION_THRESHOLDS.high; }).map((candidate) => candidate.repository))].filter((id) => !extraction.baselineIds.includes(id));
        const lookupIds = enforced ? [...new Set([...extraction.baselineIds, ...additions])] : extraction.baselineIds;
        const unresolvedIds = unresolved.filter((candidate) => !lookupIds.includes(candidate.repository)).map((candidate) => candidate.id);
        return { judgments: observation, additions, extraction, lookupIds, unresolvedIds,
            requiredComplete: lookupIds.length <= 16 && (!enforced || (!extraction.candidateOverflow && observation.coverage === "complete" && unresolvedIds.length === 0)) };
    }
}
