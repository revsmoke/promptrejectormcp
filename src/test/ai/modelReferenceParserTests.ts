import assert from "node:assert/strict";
import { extractModelReferences, extractIncumbentModelIds } from "../../services/HuggingFaceReferences.js";
import { HuggingFaceService } from "../../services/HuggingFaceService.js";

const examples = [
    ["Use model https://huggingface.co/acme/weights.", ["acme/weights"]],
    ["Model docs [here](https://huggingface.co/acme/weights/tree/main).", ["acme/weights"]],
    ["model https://huggingface.co/datasets/acme/corpus", []],
    ["model https://huggingface.co/spaces/acme/demo", []],
    ["model https://github.com/acme/weights", []],
    ['from_pretrained("acme/weights")', ["acme/weights"]],
    ["Warning: never load the model acme/risky-weights", ["acme/risky-weights"]],
    ["https://huggingface.co/acme/weights?download=true#files", ["acme/weights"]],
    ["model https://huggingface.co.evil.invalid/acme/weights", []],
    ["model https://evilhuggingface.co/acme/weights", []],
    ["[one](https://huggingface.co/acme/first),[two](https://huggingface.co/other/second)", ["acme/first", "other/second"]],
    ["https://huggingface.co/acme/first,https://huggingface.co/other/second", ["acme/first", "other/second"]],
] as const;
for (const [text, ids] of examples) {
    assert.deepEqual(extractModelReferences(text).baselineIds, ids, text);
    assert.deepEqual(extractIncumbentModelIds(text), new HuggingFaceService().extractModelIds(text), "incumbent ablation parity");
}
const resources = extractModelReferences("https://huggingface.co/datasets/acme/corpus https://huggingface.co/spaces/acme/demo https://huggingface.co/acme/weights");
assert.deepEqual(resources.candidates.map((candidate) => candidate.kind), ["dataset", "space", "model"]);
assert.ok(resources.parserCorrections.length >= 2);
const explicit = extractModelReferences("Load acme/weights after reading these unrelated notes. " + "Long background. ".repeat(20));
assert.deepEqual(explicit.baselineIds, []);
assert.equal(explicit.candidates[0].repository, "acme/weights", "semantic candidate search must not need the old keyword window");
const local = extractModelReferences("Use model from local/weights-cache");
assert.deepEqual(local.baselineIds, new HuggingFaceService().extractModelIds("Use model from local/weights-cache"), "incumbent heuristic IDs stay in baseline even when ambiguous");
const duplicates = extractModelReferences("Use model acme/weights and https://huggingface.co/acme/weights.");
assert.deepEqual(duplicates.baselineIds, ["acme/weights"]);
for (const candidate of duplicates.candidates) assert.equal(candidate.text, "Use model acme/weights and https://huggingface.co/acme/weights.".slice(candidate.start, candidate.end));
const many = extractModelReferences(Array.from({ length: 70 }, (_, i) => `owner${i}/weights${i}`).join(" "));
assert.equal(many.candidateOverflow, true); assert.equal(many.candidateCount, 70); assert.equal(many.candidates.length, 64);
const preservedElsewhere = extractModelReferences("Model datasets/acme is intentional. Also dataset https://huggingface.co/datasets/acme/corpus");
assert.ok(preservedElsewhere.baselineIds.includes("datasets/acme"), "source-specific correction must not remove a separate incumbent bare ID");
assert.deepEqual(extractModelReferences("No repositories here.").candidates, []);
for (const id of ["acme/x", "acme/weights.py"]) {
    const extracted = extractModelReferences(`from_pretrained("${id}")`);
    assert.equal(extracted.candidateCount, 1, "semantic candidates cannot inherit old heuristic omissions");
    assert.equal(extracted.candidates[0].repository, id);
    assert.deepEqual(extracted.baselineIds, [], "candidate expansion is additive only after qualification");
    assert.deepEqual(extractModelReferences(`https://huggingface.co/${id}`).baselineIds, [id]);
}
for (const separator of [";", "|", "、", "\\n", "⚡"]) {
    const text = `https://huggingface.co/acme/one${separator}https://huggingface.co/other/two`;
    assert.deepEqual(extractModelReferences(text).baselineIds, ["acme/one", "other/two"], "URL starts must survive unusual separators");
}
for (const text of ["model https://huggingface.co/acme%2Fwrong/weights", "model https://huggingface.co/acme/weights%3Finvalid"]) {
    const result = extractModelReferences(text);
    assert.ok(result.incumbentIds.every((id) => result.baselineIds.includes(id)), "ambiguous malformed HF URLs are not proof for deleting incumbent references");
    assert.ok(result.candidates.every((candidate) => candidate.kind !== "model"), "malformed URLs cannot prove exact model identity");
}
console.log("PASS HF exact resource parsing, source spans, candidate completeness and incumbent preservation");
