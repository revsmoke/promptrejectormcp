# RESEARCH_THREATS — Prompt Injection & LLM/Agentic Malware Landscape

**Date of compilation:** 2026-05-13
**Purpose:** Inform new detection features for PromptRejectorMCP.
**Method:** Web search + targeted fetch of vendor/research pages. Primary sources cited inline. Dates were checked against article headers; items below are dated late 2025 through May 2026 unless flagged otherwise.

---

## 1. Latest Prompt Injection Techniques (2025–2026)

### 1.1 Policy Puppetry (HiddenLayer, Apr 2025, still active 2026)
A universal, cross-model jailbreak that wraps adversarial instructions in **fake "policy" structured data** (XML/JSON/INI/Markdown front-matter). Models interpret the structure as an internal policy directive and over-prioritize it over system-prompt safety. Reportedly works on GPT-4/4.5, Claude 3/3.5, Gemini 1.5/2, LLaMA 3, Mistral, DeepSeek, Qwen with no per-model tuning. First documented post-instruction-hierarchy bypass.
Source: https://www.hiddenlayer.com/research/novel-universal-bypass-for-all-major-llms ; https://news.ycombinator.com/item?id=43793280

### 1.2 ASCII / Unicode-Tag Smuggling ("Invisible ink")
Hidden instructions encoded in Unicode Tag block (U+E0000–U+E007F) plus zero-width / non-joiner chars. Invisible to humans, tokenized by LLMs. **"Sneaky Bits" (2025)** generalizes this to encoding arbitrary bytes with only two invisible chars. Used in real indirect-injection payloads served by webpages and emails.
Sources: https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/ ; https://aws.amazon.com/blogs/security/defending-llm-applications-against-unicode-character-smuggling/ ; https://blogs.cisco.com/ai/understanding-and-mitigating-unicode-tag-prompt-injection

### 1.3 Indirect Prompt Injection — now in the wild
Google + Forcepoint reports (Apr 2026) describe a **32% increase Nov 2025 → Feb 2026** in malicious-category indirect injections found on webpages. Specific payloads observed include hard-coded PayPal.me $5,000 charges aimed at payment-capable agents, and `rm -rf /` style payloads aimed at coding agents with shell access. Researchers cataloged 10 distinct in-the-wild payload families.
Sources: https://blog.google/security/prompt-injections-web/ ; https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/ ; https://www.helpnetsecurity.com/2026/04/24/indirect-prompt-injection-in-the-wild/

### 1.4 Many-Shot, Crescendo, Universal Suffix
- **Many-shot** (Anthropic, 2024 — still effective on long-context models): fill 100K+ token context with fake harmful Q&A then a real harmful question.
- **Crescendo** (Microsoft, 2024; refined 2025–26): multi-turn gradual escalation; defeats single-turn classifiers.
- **Universal adversarial suffixes** (Zou et al., still actively researched into 2026): optimization-derived token strings appended to prompts.
Source: https://ringsafe.in/llm-jailbreaks-2026-universal-suffixes-many-shot-crescendo-and-what-constitutional-ai-actually-stops/ ; https://www.anthropic.com/research/next-generation-constitutional-classifiers

### 1.5 Multimodal Injection
- **Image-based** (typographic, segmentation-aware): up to **64% ASR** under stealth on GPT-4V/Claude/Gemini/LLaVA.
- **Steganographic** image injection (neural stego): 24–32% ASR.
- **CHAI** (UC Santa Cruz, Jan 2026): physical-environment command-hijacking of embodied agents.
Sources: https://arxiv.org/abs/2603.03637 (CSA paper) ; https://arxiv.org/html/2507.22304v1 ; https://labs.cloudsecurityalliance.org/research/csa-research-note-image-prompt-injection-multimodal-llm-2026/
(*Date caveat:* arXiv "26xx" IDs are unusual — possibly placeholder formatting; treat the specific ASR numbers as approximate.)

### 1.6 Lethal Trifecta (framing, not a single technique)
Simon Willison (Jun 2025): exploitability is essentially guaranteed when an agent simultaneously has (a) access to private data, (b) exposure to untrusted content, (c) external-comm/exfil channel. The defense is **architectural** — sever one leg — not detection. Powers most observed exfil chains (e.g., Markdown-image data exfiltration in `antigravity`).
Sources: https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/ ; https://x.com/simonw/status/1991354081236164814

---

## 2. Agentic-Specific Threats

### 2.1 MCP Tool Poisoning
OWASP now lists **MCP Tool Poisoning** as a distinct attack class. Malicious / compromised MCP servers ship tool *descriptions* containing prompt-injection payloads — the description itself is fed to the model. Persists across sessions; "infects" any agent that lists the tool. Variant: **MCP command injection** (Keysight, Jan 2026) where tool-invocation arguments reach a shell.
Sources: https://owasp.org/www-community/attacks/MCP_Tool_Poisoning ; https://www.keysight.com/blogs/en/tech/nwvs/2026/01/12/mcp-command-injection-new-attack-vector ; https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/ ; https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp

### 2.2 Malicious Skills / Plugin Supply Chain
- **Snyk ToxicSkills study (Feb 2026):** scanned 3,984 skills on ClawHub + skills.sh; prompt injection in **36%**, **1,467 malicious payloads**, 76 confirmed credential-theft / backdoor skills.
- **71 overtly malicious Claude skills** catalogued on ClawHub.
- **Shai Hulud / SAP CAP** supply-chain attack via Claude Code (Mend.io).
- **Check Point:** abuse of Claude Code Hooks, MCP config, env vars to RCE on clone.
- **Sentinel One:** marketplace-skill *dependency hijack* — skill injects malicious npm/pip pins.
Sources: https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ ; https://cybersecuritywaala.com/blog/71-malicious-claude-skills-found/ ; https://www.mend.io/blog/shai-hulud-sap-cap-supply-chain-attack-claude-code/ ; https://blog.checkpoint.com/research/check-point-researchers-expose-critical-claude-code-flaws/ ; https://www.sentinelone.com/blog/marketplace-skills-and-dependency-hijack-in-claude-code/

### 2.3 Memory & RAG Poisoning
- **PoisonedRAG** (USENIX Security 2025): a few crafted docs inserted into corpus → reliable attacker-chosen answers.
- **MINJA** (2025): query-only memory injection, >95% success.
- **MemoryGraft** (arXiv 2512.16962, Dec 2025): "successful experience" grafting persists across sessions.
- Agent Security Bench: **84.3% average ASR** across 27 attack/defense combos × 400+ tools.
Sources: https://arxiv.org/abs/2512.16962 ; https://prompt.security/blog/the-embedded-threat-in-your-llm-poisoning-rag-pipelines-via-vector-embeddings ; https://beyondscale.tech/blog/ai-agent-memory-poisoning-defense-guide

### 2.4 Browser / Computer-Use Agent Hijack
- **ClaudeBleed** (LayerX, May 2026): zero-permission Chrome extensions can hijack Claude-in-Chrome via `externally_connectable` trust-boundary flaw → Gmail/Drive/GitHub exfil. Anthropic's v1.0.70 (2026-05-06) partial fix bypassed within hours.
- ~~**CVE-2026-2796** Claude exploit reverse-engineered by Anthropic Red team.~~ **[CVE attribution incorrect — verified 2026-05-18]** CVE-2026-2796 in NVD is a Firefox/Thunderbird WebAssembly JIT bug (CWE-843, Mozilla source), not the ClaudeBleed Chrome-extension hijack. Use the LayerX writeup as the canonical reference until the actual CVE ID is published. See SPEC §13.1 row 1.
- **Claude Desktop extensions** zero-click RCE exposing 10K+ users.
Sources: https://layerxsecurity.com/blog/a-flaw-in-claudes-browser-extension-allows-any-extension-to-hijack-it/ ; https://red.anthropic.com/2026/exploit/ ; https://www.securityweek.com/vulnerability-in-claude-extension-for-chrome-exposes-ai-agent-to-takeover/ ; https://layerxsecurity.com/blog/claude-desktop-extensions-rce/

---

## 3. Notable Incidents / Named Attacks / Standards Updates

| Item | Date | Significance |
|---|---|---|
| OWASP LLM Top 10 **v2025** | Nov 2024 (active 2025–26) | LLM01 = Prompt Injection; explicitly extends to multimodal. v2026 in draft as of writing. |
| MITRE ATLAS **v5.4.0** | Feb 2026 | 16 tactics / 84 techniques. Added (with Zenity Labs) "AI Agent Context Poisoning", "Memory Manipulation", "Thread Injection", "Modify AI Agent Configuration", "Publish Poisoned AI Agent Tool", "Escape to Host". |
| Policy Puppetry | Apr 2025 | Universal cross-model bypass. |
| Lethal Trifecta | Jun 2025 | Conceptual framework now standard vocabulary. |
| ToxicSkills / 71 malicious Claude skills | Feb–Apr 2026 | First large-scale skill-marketplace compromise. |
| ClaudeBleed | May 2026 | Browser-agent hijack via extension trust boundary. |
| ~~CVE-2026-2796~~ | — | **CVE attribution incorrect — verified 2026-05-18 (NVD).** ID maps to Firefox WebAssembly JIT bug, not the ClaudeBleed Chrome-extension claim. |
| MemoryGraft | Dec 2025 | First persistent agent-memory poison via benign artifacts. |

Sources: https://genai.owasp.org/llmrisk/llm01-prompt-injection/ ; https://atlas.mitre.org/ ; https://www.practical-devsecops.com/mitre-atlas-framework-guide-securing-ai-systems/

---

## 4. Defensive Research

| Defense | Source | Notes |
|---|---|---|
| **Constitutional Classifiers ++** (Anthropic) | https://www.anthropic.com/research/next-generation-constitutional-classifiers | v1: 86%→4.4% ASR. v2: ~1% extra compute, 1,700+ hr red-team — no full universal jailbreak found. |
| **StruQ / SecAlign** (Berkeley, USENIX Sec 2025) | https://bair.berkeley.edu/blog/2025/04/11/prompt-injection-defense/ | Structured queries + fine-tune. StruQ <2% ASR (non-optim), SecAlign 8% (optim). |
| **Spotlighting** (Microsoft) | (referenced widely) | Datamarking / encoding to flag untrusted text. |
| **DefensiveTokens** | https://dl.acm.org/doi/10.1145/3733799.3762982 | Lightweight prompt-level defense. |
| **Lakera Guard** (Cisco AI Defense, May 2025 acq.) | https://appsecsanta.com/lakera | 98%+ detection, <50ms, 100+ langs. Commercial. |
| **NVIDIA Garak** | https://appsecsanta.com/garak | OSS Apache-2.0, 37+ probes — useful as **signature corpus** for PromptRejectorMCP. |
| **NVIDIA NeMo Guardrails** | https://github.com/NVIDIA-NeMo/Guardrails | Colang DSL for dialog-flow control. |
| **Microsoft PyRIT** | (Azure/AI red team) | Multi-modal, multi-turn orchestration. |
| **LLM Guard** | https://appsecsanta.com/ai-security-tools | MIT-licensed, 15 input / 20 output scanners. |
| **Protect AI Rebuff, HiddenLayer AISec, Promptfoo, DeepTeam** | https://appsecsanta.com/ai-security-tools/lakera-alternatives | Various, mostly commercial. |

Caveat from 2026 meta-study (78 papers, 2021–26): adaptive attacks still exceed **85% ASR** against SoTA defenses — defense is layered mitigation, not solution.

---

## 5. Threat-Intel Sources / APIs To Integrate

| Source | URL | Free? | Auth | Rate Limit | Useful Endpoint(s) | Payload |
|---|---|---|---|---|---|---|
| **NVD CVE 2.0** | https://nvd.nist.gov/developers/vulnerabilities | Yes | Optional API key (free) | 5 req / 30s anon, 50 / 30s w/ key | `GET /rest/json/cves/2.0?keywordSearch=prompt+injection` | JSON, CVE objects with CVSS, CPE, refs |
| **OSV.dev** | https://google.github.io/osv.dev/api/ | Yes | None | No declared limit; SLOs P95≤6s batch | `POST /v1/query`, `POST /v1/querybatch` (≤1000 q) | `{package, version}` → vuln IDs |
| **GitHub Advisory DB (GHSA)** | https://docs.github.com/en/rest/security-advisories/global-advisories ; GraphQL | Yes | GitHub token recommended | 5000 req/hr authenticated | `GET /advisories?type=reviewed&ecosystem=...`; GraphQL `securityAdvisories` | GHSA records, includes malware advisories |
| **MITRE ATLAS** | https://atlas.mitre.org/ | Yes | None | n/a (static YAML/JSON) | `data/atlas.yaml` on GitHub | Tactics/techniques/case studies |
| **AVID** | https://avidml.org/database/ | Yes | None for browsing; SDK `avidtools` | n/a | Connectors pull NVD/ATLAS/garak | AVID records mapped to ATLAS + CVSS |
| **AI Incident Database (AIID)** | https://incidentdatabase.ai/ | Yes | None | Modest | REST + GraphQL | Reported AI incidents w/ taxonomies |
| **MITRE CVE Services** | https://www.cve.org/ | Yes | Optional | Moderate | CVE List downloads / API | Authoritative CVE feed |
| **Hugging Face Hub** | model cards | Yes | HF token | High | `GET /api/models/{id}` | Model-card flags, security tags |
| **Garak signatures** | https://github.com/NVIDIA/garak | OSS | n/a | n/a | Probe definitions in repo | Use as detection pattern corpus |
| **PyRIT prompts** | https://github.com/Azure/PyRIT | OSS | n/a | n/a | Attack libraries | Pattern corpus |
| **HiddenLayer / Lakera / Protect AI** | vendor sites | **Paid** | API key | Commercial | Detection-as-a-service | Use cautiously; vendor lock-in |
| **Promptfoo redteam plugins** | https://www.promptfoo.dev/docs/red-team/ | OSS | n/a | n/a | YAML attack defs | Strong pattern source |

---

## Top 10 Candidates for PromptRejectorMCP to Add

Ranked by signal-to-noise × ease of implementation × incident frequency:

1. **Unicode Tag / zero-width / invisible-char detector** — strip & flag U+E0000–U+E007F, U+200B–U+200F, bidi controls. Cheap, high-precision; covers ASCII Smuggling + Sneaky Bits. `[did not ship in v1.1.0 as a standalone detector tool]`
2. **Policy-Puppetry structural detector** — flag XML/JSON/INI/YAML blocks containing `policy|system|instruction|role:` keys inside *user* content, especially with `<system>`, `<policy>`, or `developer_message` tags. `[did not ship in v1.1.0]`
3. **MCP tool-description scanner** — for `scan_skill`-style flow, parse tool/skill manifests, hash & diff descriptions vs. known-good, flag imperative verbs in descriptions ("ignore previous", "you must", "as part of your job"). *(Shipped in v1.1.0 as `scan_mcp_tool`.)*
4. **Lethal-trifecta static analyzer for skills** — inspect a skill's declared capabilities: does it co-locate (read private data) + (fetch untrusted) + (network egress / markdown image / shell)? Emit severity-critical when all 3. *(Shipped in v1.1.0 as `check_lethal_trifecta`.)*
5. **Markdown-image / link exfiltration patterns** — regex for `![...](http...?...{data})` and `[text](javascript:...)`-style sinks; common exfil channel. `[did not ship in v1.1.0 as a dedicated feature]`
6. **Indirect-injection payload feed integration** — pull Garak probes + Promptfoo redteam YAML + Unit42 IOC list into pattern library; auto-refresh via `update_vuln_feeds`. `[did not ship in v1.1.0 — Garak/Promptfoo/Unit42 feeds not integrated]`
7. **Memory/RAG canary tokens** — emit guidance + helper for inserting canary strings in RAG/memory and watching for echo (detects MemoryGraft / MINJA). *(Shipped in v1.1.0 as `deploy_canary` / `verify_canary`.)*
8. **Many-shot / context-saturation heuristic** — flag prompts where >N synthetic Q&A pairs precede an instruction-like tail (many-shot signature). `[did not ship in v1.1.0]`
9. **NVD + OSV + GHSA + ATLAS feed connector** — keyword-filter on "prompt injection", "LLM", "MCP", "agent", "RAG" daily; build a CVE-to-pattern map. ATLAS/AVID give technique IDs; NVD/OSV give package CVEs; GHSA covers malicious-skill GHSAs. *(NVD, OSV, GHSA REST+GraphQL, and MITRE ATLAS shipped in v1.1.0; AVID did not.)*
10. **Skill supply-chain signer-check** — for Claude-style skills: verify `SKILL.md` signature/origin, account age, dependency-pin hashes; refuse unsigned skills from accounts < N days old (per Snyk ToxicSkills finding). `[did not ship in v1.1.0]`

### Honorable mentions

- Crescendo / multi-turn classifier (requires conversation state — heavier lift). `[did not ship in v1.1.0]`
- Multimodal OCR pass for inline images carrying typographic instructions. `[did not ship in v1.1.0 — deferred to v1.2]`
- Constitutional-classifier-style secondary screen for high-risk tool calls. `[did not ship in v1.1.0]`

---

## Uncertainty / Caveats

- Several arXiv IDs surfaced with "26xx" prefixes; some appear to be 2602/2603/2604/2606 — confirm before citing in product copy. Treat exact ASR numbers as indicative.
- "CVE-2026-2796" was named in one source (red.anthropic.com); confirm in NVD before treating as canonical.
- Lakera was acquired by Cisco in May 2025 — branding may be "Cisco AI Defense" in newer docs.
- OWASP LLM v2026 is reportedly in draft; v2025 remains the operative standard.
- Vendor blog posts overstate efficacy; the 85% adaptive-attack ASR meta-finding suggests no detector will be sufficient on its own — PromptRejectorMCP should explicitly position as **defense-in-depth**, not a guarantee.
