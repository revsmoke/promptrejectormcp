# RESEARCH_FEEDS — Vulnerability & Threat-Intel Sources for PromptRejectorMCP

**Status:** Plan-mode output. The user requested this be written to
`/Users/twoedge/Dev/promptrejectormcp/.claude/worktrees/hopeful-brahmagupta-338986/RESEARCH_FEEDS.md`,
but plan mode restricts edits to this plan file only. Copy the section below
verbatim once plan mode is exited.

**Baseline (what the project already pulls):** `src/services/VulnFeedService.ts`
already integrates **NVD CVE 2.0** (`services.nvd.nist.gov/rest/json/cves/2.0`,
keyword-driven: xss / sqli / command injection / path traversal / ssrf) and
the **GitHub Advisories REST** endpoint (`api.github.com/advisories`,
`cwe_id`-filtered for CWE-79/89/78/22/918). Both use proper rate-limiters
(NVD 5→50 r/30s, GitHub 60→5000 r/hr). Patterns flow through Gemini and into
`patterns/staging/pending-review.json`. The pipeline is **classic-web-vuln
biased**; no LLM/AI-specific signal currently enters the system.

---

## 1. NVD CVE API 2.0 — already integrated, but tune

- Base: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Auth: optional `apiKey` header. Free. 5 r/30s anon, 50 r/30s with key.
- Endpoints: `/cves/2.0`, `/cpes/2.0`, `/cvehistory/2.0`. Hard cap 2000 CVEs
  per response; paginate via `startIndex`/`resultsPerPage`.
- Schema: `vulnerabilities[].cve` with `id`, `descriptions`, `metrics.cvssMetricV31/V40`,
  `weaknesses[].description[]` (CWE), `configurations[].nodes[].cpeMatch` (CPE).
- LLM filter: add keywords `prompt injection`, `LLM`, `langchain`, `mlflow`,
  `huggingface`, `transformers`, `ollama`, `llama.cpp`, `vllm`, `litellm`,
  `vector database`, `model serialization`, `unsafe deserialization`.
  Add CWE-1039 (Inadequate Detection of Adversarial Inputs) and CWE-502
  (deserialization of untrusted data) to `TARGET_CWES`. Switch to
  incremental sync via `lastModStartDate`/`lastModEndDate` per NVD
  best-practice (every >=2h).
- **Recommendation: integrate further (delta = LLM keywords + CWE expansion).**

## 2. MITRE CVE Services API (cveawg) — skip for now

- Base: `https://cveawg.mitre.org/api/`  Docs: `cveawg.mitre.org/api-docs/`
  (OAS 3.0, currently 2.6.4; schema 5.1.1 since Dec 2024).
- Auth: none for read endpoints (`GET /cve/{id}`, `GET /cve-id`).
- Mostly useful for CNA/registrar workflows. The same records appear in
  NVD ~24h later and in the `CVEProject/cvelistV5` GitHub mirror — pulling
  raw JSON from that repo is cheaper than hitting cveawg.
- **Recommendation: skip (NVD covers it). Optional mirror: clone
  `github.com/CVEProject/cvelistV5` for offline backfill.**

## 3. GitHub Security Advisories — already integrated REST; add GraphQL

- REST (in use): `GET /advisories?cwe_id=...&updated=...` — fine for CWE
  filtering but ecosystem filter is awkward.
- GraphQL: `https://api.github.com/graphql` — query
  `securityVulnerabilities(ecosystem: PIP, package: "langchain", first: 50)`
  is far more precise for AI library packages than REST keyword search.
  Returns `advisory{ ghsaId, summary, severity, identifiers, references,
  cwes{ nodes{ cweId } } }` plus `vulnerableVersionRange` and `firstPatchedVersion`.
- Auth: `Authorization: Bearer <PAT>` (already wired). Same 5k/hr limit.
- LLM filter: maintain a list — `langchain`, `langchain-core`, `langgraph`,
  `llama-index`, `transformers`, `ollama`, `vllm`, `litellm`, `mlflow`,
  `gradio`, `streamlit`, `huggingface_hub`, `sentence-transformers`,
  `chromadb`, `pgvector`, `qdrant-client`, `weaviate-client`, `pyrit`,
  `garak`, `guardrails-ai`, `nemoguardrails`. Run one GraphQL query per
  ecosystem (`PIP`, `NPM`).
- **Recommendation: integrate GraphQL alongside REST (high-value delta).**

## 4. OSV.dev — integrate (best ergonomics for batch package queries)

- Base: `https://api.osv.dev/v1/`
- Auth: **none**. No documented rate limit (be polite; ~100 r/s observed).
- Key endpoints: `POST /v1/query` (single), `POST /v1/querybatch` (batch,
  up to ~1000 queries), `GET /v1/vulns/{id}` (record fetch).
- Query payload: `{ "package": { "name": "...", "ecosystem": "PyPI"|"npm" } }`
  or by purl: `pkg:pypi/langchain@0.3.0`. Response is OSV schema
  (`id`, `aliases` incl. CVE/GHSA, `severity[]`, `affected[].ranges`,
  `database_specific`).
- LLM filter: same AI-package allowlist as §3. OSV aggregates GHSA + PyPA +
  npm + Go + RustSec, so it's the cheapest single feed for cross-ecosystem
  AI-package coverage.
- License: CC-BY-4.0.
- **Recommendation: integrate (highest signal-per-request; pure delta).**

## 5. MITRE ATLAS — integrate (purpose-built for adversarial ML)

- STIX 2.1 bundle (raw):
  `https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json`
- YAML master: `https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml`
- Auth: none. Latest v1.14.0 (Feb 2026): 16 tactics, 84 techniques, 56 sub-
  techniques, 32 mitigations, 42 case studies.
- Schema: ATT&CK-style — `tactics[]`, `techniques[]` (with `id` like AML.T0051,
  `name`, `description`, `subtechniques[]`, `mitigations[]`), `case-studies[]`.
- Use: map detected patterns to AML.T#### IDs (e.g. AML.T0051 LLM Prompt
  Injection, AML.T0054 LLM Jailbreak, AML.T0057 LLM Data Leakage). Surface
  ATLAS IDs in detection metadata.
- License: ASL 2.0 / MITRE terms. Update cadence: 2–4× per year.
- **Recommendation: integrate (taxonomy, not signatures — small pull,
  large semantic value).**

## 6. OWASP LLM Top 10 — integrate, but no official JSON

- Source: `https://genai.owasp.org/llm-top-10/` and
  `github.com/OWASP/www-project-top-10-for-large-language-model-applications`.
- 2025 list confirmed: **LLM01 Prompt Injection, LLM02 Sensitive Info
  Disclosure, LLM03 Supply Chain, LLM04 Data/Model Poisoning, LLM05 Improper
  Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage,
  LLM08 Vector/Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded
  Consumption.** No 2026 cut published.
- **No structured JSON/YAML feed exists** (verified). Ship a hand-curated
  JSON in `patterns/taxonomy/owasp-llm-top10-2025.json` and add a
  `owaspLlm` tag to pattern metadata.
- License: CC-BY-SA 4.0.
- **Recommendation: integrate as static taxonomy file (not a live feed).**

## 7. AI Incident Database (AIID) — optional, low immediate utility

- Base: `https://incidentdatabase.ai/api/graphql` (Apollo-compatible).
- Auth: none for reads. ~1,200+ incidents.
- Schema: `incidents { incident_id, title, date, AllegedDeployerOfAISystem,
  reports { report_number, title, url, source_domain, text } }`.
- Signal: narrative reports, not detection signatures. Useful for incident
  context / risk scoring, but won't generate regexes.
- License: CC-BY 4.0.
- **Recommendation: optional. Wire only if a future feature surfaces
  "real-world incidents related to this prompt pattern".**

## 8. Hugging Face Hub security signals — integrate (cheap, high-signal)

- Base: `https://huggingface.co/api/`
- Auth: optional `Authorization: Bearer hf_***`. No hard public rate limit
  for anon; respect `Retry-After`.
- Useful endpoints:
  - `GET /api/models/{repo_id}` → `securityStatus` field including
    `scansDone`, `hasUnsafeFile`, `filesWithIssues[]` (Picklescan, ClamAV,
    ProtectAI Guardian results since 2024).
  - `GET /api/models?filter=...&full=true` → bulk security flags.
- Context (2025): "NullifAI" 7z-archive bypass forced Picklescan upgrades;
  Protect AI's Guardian has scanned 4.47M model versions and flagged 352k
  unsafe issues across 51.7k models (as of Apr 2025).
- LLM filter: not needed — entire surface is AI.
- **Recommendation: integrate (lookup, not bulk). Surface as a
  `scan_huggingface_repo` MCP tool that returns `securityStatus`.**

## 9. PyPI / npm AI-package advisories — covered via OSV + GHSA

- No standalone "AI advisory" endpoint exists on PyPI/npm. Coverage is
  fully delivered via §3 (GHSA GraphQL ecosystem queries) and §4 (OSV
  batch). Recent examples picked up automatically: CVE-2025-68664/68665
  (LangChain serialization), CVE-2025-67644 (LangGraph SQLi),
  CVE-2026-42208 (LiteLLM SQLi).
- **Recommendation: no separate integration; rely on OSV + GHSA.**

## 10. Open-source detector signatures

| Tool | Source | What's downloadable | Recommendation |
|---|---|---|---|
| **Garak** (NVIDIA) | `github.com/NVIDIA/garak` | 150+ probes, 3000+ prompt templates, Apache 2.0. Probes live in `garak/probes/*.py`. Static prompt corpora in `garak/data/`. | **Integrate** — vendor `garak/data/*.txt` prompt seeds; convert to regex/string-match patterns. Highest single source of LLM-attack signatures. |
| **PyRIT** (Microsoft) | `github.com/microsoft/PyRIT` | Datasets `pyrit/datasets/*.yaml` + loaders for SimpleSafetyTests, SALAD-Bench, BeaverTails, HarmfulQA, PromptIntel, etc. MIT. | **Integrate** — pull a curated subset of YAML seed prompts. |
| **Promptfoo** | `github.com/promptfoo/promptfoo` | Red-team plugin set (MIT). Strategy & plugin JSONs under `src/redteam/`. | **Optional** — useful test corpus, less useful as runtime signatures. |
| **Rebuff** | `github.com/protectai/rebuff` | Heuristic regex list in repo + canary-token scheme, Apache 2.0. | **Integrate (heuristic regex set only)** — small, high signal-to-noise. |
| **Lakera** open data | `huggingface.co/datasets/Lakera/mosscap_prompt_injection`, `lakeraai/pint-benchmark` | ~1k injection prompts (MIT), 4314-item PINT benchmark. | **Integrate** — direct prompt-injection training/eval corpus. |
| **Protect AI / huntr** | `huntr.com` (hacktivity feed) | Public reports go live at day-90; **no documented public API** (verified). Aggregated via OSV/GHSA/NVD downstream. | **Skip the direct feed** — wait for downstream aggregation, or scrape if a future need arises. |

## 11. Vendor security bulletins (Anthropic / OpenAI / Google) — skip

- None publish a structured security-advisory RSS or JSON feed for
  model-side mitigations as of May 2026 (verified search). Mitigations
  are buried inside model cards, transparency hubs, and blog posts.
- **Recommendation: skip until a vendor publishes a structured feed.**
  Optionally subscribe via blog RSS for human review.

## 12. Misc

- **CISA KEV** — `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  (also mirrored at `github.com/cisagov/kev-data`). Free, no auth, JSON
  schema published. AI entries are now appearing (e.g. CVE-2026-42208
  LiteLLM SQLi added April 2026). Tiny file (a few MB).
  **Recommendation: integrate** — small daily pull, flag any CVE that
  also appears in our staged candidates as `kev: true` (escalates severity).
- **Exploit-DB** — `gitlab.com/exploit-database/exploitdb`. CSV/Git mirror,
  GPL. Heavy on memory-corruption CVEs; near-zero LLM signal.
  **Recommendation: skip.**
- **Packetstorm** — RSS only, unstructured. **Skip.**

---

## Integration Priority Matrix

Scored: **Signal (LLM-relevance)** × **Ease** × **License** (1–5 each, 125 max).
Δ = delta vs current integration.

| Rank | Source | Signal | Ease | License | Score | Δ? | Note |
|---|---|---|---|---|---|---|---|
| 1 | **OSV.dev `/v1/querybatch`** | 5 | 5 | 5 CC-BY | **125** | new | One call → all AI-package CVEs across ecosystems |
| 2 | **MITRE ATLAS STIX/YAML** | 5 | 5 | 4 ASL2 | **100** | new | Adversarial-ML taxonomy, static file |
| 3 | **GHSA GraphQL (ecosystem)** | 5 | 4 | 5 CC-BY | **100** | partial | REST already in; GraphQL is the upgrade |
| 4 | **Garak probe corpora** | 5 | 4 | 5 Apache2 | **100** | new | 3000+ LLM attack prompts |
| 5 | **HuggingFace `securityStatus`** | 5 | 5 | 4 ToS | **100** | new | Model-supply-chain scans |
| 6 | **OWASP LLM Top 10 (curated)** | 4 | 5 | 5 CC-BY-SA | **100** | new | Ship as static JSON |
| 7 | **Lakera PINT + mosscap** | 5 | 5 | 4 MIT/CC | **100** | new | Prompt-injection corpus |
| 8 | **CISA KEV** | 3 | 5 | 5 PD | **75** | new | Escalator signal only |
| 9 | **PyRIT datasets** | 4 | 4 | 4 MIT | **64** | new | Larger but noisier |
| 10 | **NVD (LLM-tuned)** | 3 | 5 | 5 PD | **75** | tune | Add AI keywords + CWE-502/1039 |
| 11 | **Rebuff heuristics** | 4 | 4 | 4 Apache2 | **64** | new | Small regex set |
| 12 | **Promptfoo plugins** | 3 | 3 | 4 MIT | **36** | opt | Test-time, not runtime |
| 13 | **AIID GraphQL** | 2 | 4 | 4 CC-BY | **32** | opt | Context, no signatures |
| 14 | MITRE cveawg | 2 | 4 | 5 | 40 | skip | Duplicates NVD |
| 15 | Huntr direct | 4 | 1 | 1 | 4 | skip | No public API |
| 16 | Vendor RSS (Anthropic/OAI/G) | 2 | 1 | 3 | 6 | skip | No structured feed |
| 17 | Exploit-DB / Packetstorm | 1 | 3 | 4 | 12 | skip | No LLM relevance |

### Recommended next-pass order

1. **OSV.dev `/v1/querybatch`** — single new fetcher, AI-package allowlist
   shared with §3. ~80 LOC.
2. **GHSA GraphQL** — replace/augment the existing REST CWE loop with
   ecosystem+package queries. Reuses existing `githubToken` + limiter.
3. **MITRE ATLAS YAML** — daily `git`-style fetch of `ATLAS.yaml`; load
   into a new `taxonomyService`.
4. **HuggingFace `securityStatus`** — exposed as a new MCP tool
   `scan_huggingface_repo`.
5. **Static bundles**: OWASP LLM Top 10 JSON, Garak prompts, Lakera PINT,
   Rebuff heuristics — vendored under `patterns/external/` with a
   refresh script.
6. **CISA KEV daily sync** → `kev: true` overlay flag.
7. **NVD tuning**: extend `NVD_SEARCH_KEYWORDS` and `TARGET_CWES`; switch
   to `lastModStartDate` incremental sync.

Skip outright: cveawg, huntr direct, vendor RSS, exploit-db, packetstorm.

---

### Sources

- [NVD Vulnerability APIs](https://nvd.nist.gov/developers/vulnerabilities)
- [NVD API Key Announcement](https://nvd.nist.gov/general/news/API-Key-Announcement)
- [CVE Services API docs](https://cveawg.mitre.org/api-docs/)
- [CVE JSON record format 5.1](https://cveproject.github.io/cve-schema/schema/docs/)
- [GitHub Advisory Database](https://github.com/github/advisory-database)
- [OSV.dev API](https://google.github.io/osv.dev/api/)
- [OSV querybatch](https://google.github.io/osv.dev/post-v1-querybatch/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [atlas-data repo](https://github.com/mitre-atlas/atlas-data)
- [atlas-navigator-data repo](https://github.com/mitre-atlas/atlas-navigator-data)
- [OWASP LLM Top 10 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP LLM Top 10 PDF v2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
- [AI Incident Database](https://incidentdatabase.ai/)
- [AIID repo](https://github.com/responsible-ai-collaborative/aiid)
- [HuggingFace Protect AI 6-month](https://huggingface.co/blog/pai-6-month)
- [NVIDIA Garak](https://github.com/NVIDIA/garak)
- [Microsoft PyRIT](https://github.com/microsoft/PyRIT)
- [Promptfoo](https://github.com/promptfoo/promptfoo)
- [Rebuff](https://github.com/protectai/rebuff)
- [Lakera PINT benchmark](https://github.com/lakeraai/pint-benchmark)
- [Lakera mosscap dataset](https://huggingface.co/datasets/Lakera/mosscap_prompt_injection)
- [huntr.com](https://huntr.com/)
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [cisagov/kev-data](https://github.com/cisagov/kev-data)
- [LiteLLM SQLi KEV addition](https://thehackernews.com/2026/04/cisa-adds-8-exploited-flaws-to-kev-sets.html)
