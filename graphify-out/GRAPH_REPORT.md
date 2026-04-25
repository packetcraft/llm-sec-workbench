# Graph Report - .  (2026-04-25)

## Corpus Check
- 65 files · ~148,455 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 841 nodes · 1499 edges · 39 communities detected
- Extraction: 81% EXTRACTED · 19% INFERRED · 0% AMBIGUOUS · INFERRED: 280 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Gate Scanning and Security Rules|Gate Scanning and Security Rules]]
- [[_COMMUNITY_App Entry and Pipeline Setup|App Entry and Pipeline Setup]]
- [[_COMMUNITY_Adversarial Attack Techniques|Adversarial Attack Techniques]]
- [[_COMMUNITY_Core Pipeline and Testing|Core Pipeline and Testing]]
- [[_COMMUNITY_Gate Abstraction Layer|Gate Abstraction Layer]]
- [[_COMMUNITY_Architecture and Gate Catalog|Architecture and Gate Catalog]]
- [[_COMMUNITY_Chat UI Components|Chat UI Components]]
- [[_COMMUNITY_Metrics and Inspector Panel|Metrics and Inspector Panel]]
- [[_COMMUNITY_Canary and Ollama Gates|Canary and Ollama Gates]]
- [[_COMMUNITY_Pipeline Architecture and Red Team|Pipeline Architecture and Red Team]]
- [[_COMMUNITY_AIRS SDK Integration|AIRS SDK Integration]]
- [[_COMMUNITY_Agentic Guard Hook|Agentic Guard Hook]]
- [[_COMMUNITY_Agentic View UI|Agentic View UI]]
- [[_COMMUNITY_PAIR Attack Runner|PAIR Attack Runner]]
- [[_COMMUNITY_Local ML Scanners|Local ML Scanners]]
- [[_COMMUNITY_AIRS SDK Server|AIRS SDK Server]]
- [[_COMMUNITY_Regex Gate Module|Regex Gate Module]]
- [[_COMMUNITY_Contributing Guidelines|Contributing Guidelines]]
- [[_COMMUNITY_Gate Info UI|Gate Info UI]]
- [[_COMMUNITY_Project Governance|Project Governance]]
- [[_COMMUNITY_DB Logger Rationale|DB Logger Rationale]]
- [[_COMMUNITY_DB Logger Rationale|DB Logger Rationale]]
- [[_COMMUNITY_LLM Client Rationale|LLM Client Rationale]]
- [[_COMMUNITY_LLM Client Rationale|LLM Client Rationale]]
- [[_COMMUNITY_LLM Client Rationale|LLM Client Rationale]]
- [[_COMMUNITY_LLM Client Rationale|LLM Client Rationale]]
- [[_COMMUNITY_LLM Client Rationale|LLM Client Rationale]]
- [[_COMMUNITY_LLM Client Rationale|LLM Client Rationale]]
- [[_COMMUNITY_LLM Client Rationale|LLM Client Rationale]]
- [[_COMMUNITY_Core Init Module|Core Init Module]]
- [[_COMMUNITY_Gate Rationale|Gate Rationale]]
- [[_COMMUNITY_Gates Init Module|Gates Init Module]]
- [[_COMMUNITY_Tests Init Module|Tests Init Module]]
- [[_COMMUNITY_UI Init Module|UI Init Module]]
- [[_COMMUNITY_Graphify Config Rules|Graphify Config Rules]]
- [[_COMMUNITY_HITL Agentic Plan|HITL Agentic Plan]]
- [[_COMMUNITY_Semantic Color System|Semantic Color System]]
- [[_COMMUNITY_Hot Patching Playground|Hot Patching Playground]]
- [[_COMMUNITY_Little Canary Advisory Mode|Little Canary Advisory Mode]]

## God Nodes (most connected - your core abstractions)
1. `_make()` - 86 edges
2. `_metric()` - 41 edges
3. `_build_pipeline()` - 25 edges
4. `22-Gate 6-Layer Security Pipeline` - 24 edges
5. `CustomRegexGate` - 22 edges
6. `SecurityGate Abstract Base Class` - 18 edges
7. `PipelineManager` - 16 edges
8. `TestLlamaGuardGate` - 15 edges
9. `agentic_guard.py Hook Script` - 15 edges
10. `_llm_guard_skip()` - 13 edges

## Surprising Connections (you probably didn't know these)
- `test_executable_extensions_flagged()` --calls--> `check()`  [INFERRED]
  C:\Users\B006\Documents\github\llm-sec-workbench\tests\test_gates.py → C:\Users\B006\Documents\github\llm-sec-workbench\docs\inspiration\canary_server.py
- `regex_gate()` --calls--> `CustomRegexGate`  [INFERRED]
  C:\Users\B006\Documents\github\llm-sec-workbench\tests\test_pipeline.py → C:\Users\B006\Documents\github\llm-sec-workbench\gates\regex_gate.py
- `Cost-Latency Funnel Principle` --semantically_similar_to--> `Hybrid Funnel Decision Priority (ALLOWLIST→PATH→REGEX→LLM)`  [INFERRED] [semantically similar]
  README.md → docs/agentic/ARCHITECTURE.md
- `_build_client()` --calls--> `OllamaClient`  [INFERRED]
  C:\Users\B006\Documents\github\llm-sec-workbench\app.py → C:\Users\B006\Documents\github\llm-sec-workbench\core\llm_client.py
- `_build_pipeline()` --calls--> `PipelineManager`  [INFERRED]
  C:\Users\B006\Documents\github\llm-sec-workbench\app.py → C:\Users\B006\Documents\github\llm-sec-workbench\core\pipeline.py

## Hyperedges (group relationships)
- **Chatbot Pipeline Defence-in-Depth (Input + Inference + Output Gates)** — readme_22gate_pipeline, readme_cost_latency_funnel, chat_adversarial_coverage_matrix, chat_adversarial_hardening_playbook, contributing_md_pipeline_payload [INFERRED 0.85]
- **RAG Poisoning Documents as Indirect Injection Test Vectors for Chat Pipeline** — rag_bank_policy_poisoning, rag_company_directory_backdoor, rag_helpdesk_faq_poisoning, readme_rag_simulation, chat_adversarial_indirect_injection_rag [INFERRED 0.88]
- **Agentic Guard Core Detection Pipeline** — agentic_arch_agentic_guard_py, agentic_arch_hybrid_funnel, agentic_arch_action_guard, agentic_arch_injection_guard, agentic_arch_audit_jsonl_schema [EXTRACTED 0.95]
- **PII Lifecycle Gates (Mask-In → Scan-Out → Restore)** — arch_gate_fast_scan, arch_gate_sensitive_out, arch_gate_deanonymize [EXTRACTED 0.95]
- **Local Pipeline Defense-In-Depth Layers (L0-L4)** — arch_gate_custom_regex, arch_gate_classify, arch_gate_mod_llm, gate_semantic_guard_overview, gate_little_canary_overview [INFERRED 0.88]
- **PAIR Red-Team Loop (Attacker → Pipeline → Target → Judge)** — redteam_arch_pair_roles, arch_pipeline_manager, redteam_arch_pair_runner [EXTRACTED 0.92]

## Communities

### Community 0 - "Gate Scanning and Security Rules"
Cohesion: 0.05
Nodes (41): Gate logic.  See module docstring for the full contract., Run the gate with timing and fail-open error protection.          This method is, CustomRegexGate, Operator-defined keyword blocklist gate.      Inherits the fail-open ``scan()``, Check the original input against the configured block phrases.          Appends, _Broken, _make(), _metric() (+33 more)

### Community 1 - "App Entry and Pipeline Setup"
Cohesion: 0.03
Nodes (59): _build_client(), _build_pipeline(), _init_session_state(), _load_config(), main(), _model_present(), app.py ────── Streamlit entry point for LLM Security Workbench.  Responsibilitie, Return True if the base model name (without :tag) is in the available list. (+51 more)

### Community 2 - "Adversarial Attack Techniques"
Cohesion: 0.03
Nodes (86): Allowlist Abuse Bypass (Process Substitution), Agentic Attack Chains, Coding Agent Guard Bypass Techniques, Agentic Guard Coverage Gap Summary, Encoding and Obfuscation Evasion, Agentic Guard Hardening Playbook, MITRE ATLAS Mapping (Agentic), Multi-Step Attack Staging (+78 more)

### Community 3 - "Core Pipeline and Testing"
Cohesion: 0.04
Nodes (68): _build_messages(), Assemble the full message list for the Ollama chat API.      Args:         curre, make_payload(), mock_llm_result(), output_payload(), payload(), tests/conftest.py ───────────────── Shared pytest fixtures for the LLM Security, Stand-in for the object returned by OllamaClient.generate(). (+60 more)

### Community 4 - "Gate Abstraction Layer"
Cohesion: 0.04
Nodes (60): ABC, gates/base_gate.py ────────────────── Abstract base class for all security gates, Stateless security gate base class.      Args:         config: Gate-specific con, _scan(), SecurityGate, _render_chat_content(), BaseLLMClient, GenerationResult (+52 more)

### Community 5 - "Architecture and Gate Catalog"
Cohesion: 0.04
Nodes (72): AIRS Sample API Responses Index (Real Captured Responses), Gate Error Handling Fail-Open Contract, BanTopicsGate (Zero-Shot DeBERTa), BiasOutputGate, PromptGuardGate (DeBERTa Injection Classifier), CustomRegexGate, DeanonymizeGate (PII Restoration), FastScanGate (PII + Secrets) (+64 more)

### Community 6 - "Chat UI Components"
Cohesion: 0.06
Nodes (42): _block_banner(), _build_options(), _gate_badges_html(), _gate_child(), _gate_row(), _inject_global_css(), _inject_sidebar_css(), _load_rag_catalog() (+34 more)

### Community 7 - "Metrics and Inspector Panel"
Cohesion: 0.09
Nodes (39): _build_inspector_json(), _build_inspector_md(), _fetch_context_size(), _fetch_model_info(), _mini_bar(), ui/metrics_panel.py ─────────────────── Phase 5 — Metrics & Telemetry Panel for, Return context window size in tokens; falls back to 4096., Fetch family, param size, quantization, and context window via ollama.show(). (+31 more)

### Community 8 - "Canary and Ollama Gates"
Cohesion: 0.08
Nodes (18): build_pipeline(), check(), Little Canary microservice — wraps SecurityPipeline as a REST endpoint. Called, _get_ollama_client(), _little_canary_skip(), LittleCanaryGate, LlamaGuardGate, gates/ollama_gates.py ───────────────────── Security gates backed by local Ollam (+10 more)

### Community 9 - "Pipeline Architecture and Red Team"
Cohesion: 0.07
Nodes (34): API Inspector (Gate Raw Traces), Cost/Latency Funnel Pipeline Ordering Principle, Gate Modes (OFF/AUDIT/ENFORCE), Ollama VRAM Management, PipelineManager Execution Logic, PipelinePayload Object, Red Teaming Dynamic PAIR Algorithm, Red Teaming Static Fuzzing Runner (+26 more)

### Community 10 - "AIRS SDK Integration"
Cohesion: 0.09
Nodes (15): BaseModel, Filter, title: Prisma AIRS SDK Diagnostic author: Gemini version: 5.8 requirements: pan-, Maps detection flags to human-readable labels., Extracts DLP patterns and hit counts., Generates the standardized Prisma Diagnostic Report., Valves, Filter (+7 more)

### Community 11 - "Agentic Guard Hook"
Cohesion: 0.15
Nodes (22): _classify(), _exit_allow(), _exit_block(), _extract_inspectable(), _git_info(), _is_allowlisted(), _load_config(), main() (+14 more)

### Community 12 - "Agentic View UI"
Cohesion: 0.16
Nodes (18): _badge(), _load_audit(), _method_badge(), ui/agentic_view.py ────────────────── Streamlit view for the Coding Agent Guard., Return the first 8 characters of a session ID for display., Return a short, readable preview of tool_input for table display., Glob all session JSONL files and return (records_df, sessions_dict).      record, Main entry point called by app.py for the Coding Agent Guard view. (+10 more)

### Community 13 - "PAIR Attack Runner"
Cohesion: 0.17
Nodes (9): PAIRRunner, core/pair_runner.py ─────────────────── PAIR algorithm — Prompt Automatic Iterat, Non-streaming Ollama chat with a given model.  Returns content str., Generate the next adversarial prompt.          Adapts its strategy based on whet, Score the Target's response against the attack goal.          Args:, Run the prompt through all input gates.          Returns::              {, Send the attack prompt to the Target LLM and return its response., Run the PAIR loop and yield progress events.          Each yielded dict has a `` (+1 more)

### Community 14 - "Local ML Scanners"
Cohesion: 0.26
Nodes (6): _load_prompt_guard(), PromptGuardGate, Injection/jailbreak classification via ProtectAI DeBERTa (CPU).      Always clas, Download and cache Prompt-Guard tokenizer + model (once per process).      Uses, Gate must classify original_input even when current_text is masked., TestPromptGuardGate

### Community 15 - "AIRS SDK Server"
Cohesion: 0.28
Nodes (6): init_and_get_scanner(), AIRS Python SDK sidecar — port 5003  Wraps pan-aisecurity (aisecurity package), Init global SDK config then return a fresh Scanner instance., Convert SDK response object to a plain dict for JSON serialisation., response_to_dict(), scan_sync()

### Community 16 - "Regex Gate Module"
Cohesion: 0.67
Nodes (1): gates/regex_gate.py ─────────────────── CustomRegexGate — lightweight WAF hot-pa

### Community 17 - "Contributing Guidelines"
Cohesion: 0.67
Nodes (3): PipelinePayload Dataclass, Rationale: Gate Exception Isolation, SecurityGate Interface (base_gate.py)

### Community 18 - "Gate Info UI"
Cohesion: 1.0
Nodes (1): ui/gate_info.py ─────────────── Shared gate metadata — consumed by:   • ui/chat_

### Community 19 - "Project Governance"
Cohesion: 1.0
Nodes (2): Contributing Guide, Security Policy

### Community 20 - "DB Logger Rationale"
Cohesion: 1.0
Nodes (1): Serialise a PipelinePayload (or duck-typed equivalent) to a row dict.

### Community 21 - "DB Logger Rationale"
Cohesion: 1.0
Nodes (1): Expand JSON columns back to Python objects.

### Community 22 - "LLM Client Rationale"
Cohesion: 1.0
Nodes (1): Blocking generation.  Returns the full response as a         ``GenerationResult`

### Community 23 - "LLM Client Rationale"
Cohesion: 1.0
Nodes (1): Streaming generation.  Yields text chunks as they arrive.          Token telemet

### Community 24 - "LLM Client Rationale"
Cohesion: 1.0
Nodes (1): Return telemetry from the most recent ``generate_stream()`` call.          Must

### Community 25 - "LLM Client Rationale"
Cohesion: 1.0
Nodes (1): Return ``True`` if the backend is reachable.

### Community 26 - "LLM Client Rationale"
Cohesion: 1.0
Nodes (1): Return the list of locally available model names (e.g. ``['llama3:latest']``).

### Community 27 - "LLM Client Rationale"
Cohesion: 1.0
Nodes (1): Stream the download progress for ``model_name``.          Each yielded dict has

### Community 28 - "LLM Client Rationale"
Cohesion: 1.0
Nodes (1): Extract a ``GenerationResult`` from a non-streaming Ollama response.

### Community 29 - "Core Init Module"
Cohesion: 1.0
Nodes (0): 

### Community 30 - "Gate Rationale"
Cohesion: 1.0
Nodes (1): Unique, stable identifier for this gate.          Used as the key in ``payload.r

### Community 31 - "Gates Init Module"
Cohesion: 1.0
Nodes (0): 

### Community 32 - "Tests Init Module"
Cohesion: 1.0
Nodes (0): 

### Community 33 - "UI Init Module"
Cohesion: 1.0
Nodes (0): 

### Community 34 - "Graphify Config Rules"
Cohesion: 1.0
Nodes (1): Graphify Rules for LLM-Sec-Workbench

### Community 35 - "HITL Agentic Plan"
Cohesion: 1.0
Nodes (1): V2 Phase 7: Human-in-the-Loop Escalation

### Community 36 - "Semantic Color System"
Cohesion: 1.0
Nodes (1): Semantic Color System for Gate Verdicts

### Community 37 - "Hot Patching Playground"
Cohesion: 1.0
Nodes (1): Hot-Patching with RegexGate Exercise

### Community 38 - "Little Canary Advisory Mode"
Cohesion: 1.0
Nodes (1): Little Canary Advisory Mode (Security Prefix Injection)

## Knowledge Gaps
- **300 isolated node(s):** `app.py ────── Streamlit entry point for LLM Security Workbench.  Responsibilitie`, `Load config.yaml once and cache for the app lifetime.      If config.yaml is mis`, `Instantiate and cache the OllamaClient.      The client holds a connection pool;`, `Set default session_state values on first page load.      Keys defined here span`, `Return True if the base model name (without :tag) is in the available list.` (+295 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Gate Info UI`** (2 nodes): `gate_info.py`, `ui/gate_info.py ─────────────── Shared gate metadata — consumed by:   • ui/chat_`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Project Governance`** (2 nodes): `Contributing Guide`, `Security Policy`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `DB Logger Rationale`** (1 nodes): `Serialise a PipelinePayload (or duck-typed equivalent) to a row dict.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `DB Logger Rationale`** (1 nodes): `Expand JSON columns back to Python objects.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `LLM Client Rationale`** (1 nodes): `Blocking generation.  Returns the full response as a         ``GenerationResult``
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `LLM Client Rationale`** (1 nodes): `Streaming generation.  Yields text chunks as they arrive.          Token telemet`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `LLM Client Rationale`** (1 nodes): `Return telemetry from the most recent ``generate_stream()`` call.          Must`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `LLM Client Rationale`** (1 nodes): `Return ``True`` if the backend is reachable.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `LLM Client Rationale`** (1 nodes): `Return the list of locally available model names (e.g. ``['llama3:latest']``).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `LLM Client Rationale`** (1 nodes): `Stream the download progress for ``model_name``.          Each yielded dict has`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `LLM Client Rationale`** (1 nodes): `Extract a ``GenerationResult`` from a non-streaming Ollama response.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Core Init Module`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Gate Rationale`** (1 nodes): `Unique, stable identifier for this gate.          Used as the key in ``payload.r`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Gates Init Module`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Tests Init Module`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `UI Init Module`** (1 nodes): `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Graphify Config Rules`** (1 nodes): `Graphify Rules for LLM-Sec-Workbench`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `HITL Agentic Plan`** (1 nodes): `V2 Phase 7: Human-in-the-Loop Escalation`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Semantic Color System`** (1 nodes): `Semantic Color System for Gate Verdicts`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Hot Patching Playground`** (1 nodes): `Hot-Patching with RegexGate Exercise`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Little Canary Advisory Mode`** (1 nodes): `Little Canary Advisory Mode (Security Prefix Injection)`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `_render_chat_content()` connect `Gate Abstraction Layer` to `Core Pipeline and Testing`, `Chat UI Components`?**
  _High betweenness centrality (0.088) - this node is a cross-community bridge._
- **Why does `_build_pipeline()` connect `App Entry and Pipeline Setup` to `Gate Scanning and Security Rules`, `Canary and Ollama Gates`, `Core Pipeline and Testing`, `Local ML Scanners`?**
  _High betweenness centrality (0.085) - this node is a cross-community bridge._
- **Why does `main()` connect `App Entry and Pipeline Setup` to `Gate Abstraction Layer`, `Chat UI Components`?**
  _High betweenness centrality (0.048) - this node is a cross-community bridge._
- **Are the 22 inferred relationships involving `_build_pipeline()` (e.g. with `PipelineManager` and `CustomRegexGate`) actually correct?**
  _`_build_pipeline()` has 22 INFERRED edges - model-reasoned connections that need verification._
- **What connects `app.py ────── Streamlit entry point for LLM Security Workbench.  Responsibilitie`, `Load config.yaml once and cache for the app lifetime.      If config.yaml is mis`, `Instantiate and cache the OllamaClient.      The client holds a connection pool;` to the rest of the system?**
  _300 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Gate Scanning and Security Rules` be split into smaller, more focused modules?**
  _Cohesion score 0.05 - nodes in this community are weakly interconnected._
- **Should `App Entry and Pipeline Setup` be split into smaller, more focused modules?**
  _Cohesion score 0.03 - nodes in this community are weakly interconnected._