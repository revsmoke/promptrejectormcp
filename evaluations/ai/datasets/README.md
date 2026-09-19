# Evaluation data

`synthetic-stress-v1` contains 1,200 authored **development** examples: 200 risky and 200 benign intent/poisoning labels for each of descriptor, prompt and skill analysis. They share 20 templates and 20 domain substitutions. Domain and descriptor placement are coupled, not a full factorial sample. Report results by family and placement; do not treat the rows as independent observations when calculating uncertainty.

The two independent label reviews found development-family overlap and construction artifacts in the initial version. Adjudication removed the label-specific prompt wrapper and skill suffix, clarified educational descriptor purposes, and removed unreviewed severity labels. The family overlap is retained transparently: these are stress/regression cases and cannot satisfy a held-out activation gate, regardless of row count. `review.json` records review provenance and the final case hash.

Only the `input` object goes to an inference provider. IDs, labels, rationales, family names, review comments and expected results stay in the evaluator. Labels describe instructions in the supplied artifact, not actual tool execution or proof of runtime permissions. The deliberately deceptive-result family also tests the broader reasoner; it need not trigger any of TypeSafe's initial three narrow hazards.

The historical 107 exploratory inputs remain in `experiments/typesafe/results/2026-09-19T20-27-01.476Z/`. Their original labels and outputs must remain intact. New interpretation/provenance belongs in an import manifest, not an edit to those files.

Independent acceptance data must be collected and reviewed separately, with family-aware partitioning, immutable hashes and no post-result tuning. The minimum counts in the SPEC are necessary gates, not permission to relabel correlated development variants as held-out evidence. Qualification must reject this stress dataset's `qualificationEligible:false` marker.

Regenerate the development cases with `node evaluations/ai/datasets/build-synthetic-stress.mjs`. Regeneration marks label review pending; rerun independent review before replacing the frozen reviewed artifact. No inference is performed by the generator.
