# Chatbot Security — Plan

## 1. Overview

**Feature name:** Chatbot Security Pipeline  
**Parent project:** LLM Security Workbench ([master plan](../../plan.md))

### What this is

An extensible, locally-hosted multi-stage security pipeline that acts as a proxy between a user and a locally-hosted LLM. Each gate in the pipeline is independently switchable between `OFF`, `AUDIT`, and `ENFORCE` modes, allowing operators to measure defence efficacy, latency cost, and bypass vectors.

**Target audience:** Security engineers, AI researchers, and developers.  
**Key design principle:** **Stateless Gates, Stateful Pipeline.** The pipeline passes a `PipelinePayload` object so upstream mutations (e.g., PII masking) are preserved without breaking downstream classifiers.

### How it differs from the Agentic Security monitor

| | Chatbot Security | Agentic Security |
|:--|:--|:--|
| **Threat model** | Malicious user input; unsafe model output | Compromised or manipulated agent acting on the host system |
| **Interception point** | Between user and LLM (proxy pipeline) | Between Claude Code and OS/filesystem/network (hooks) |
| **Primary risk** | Prompt injection, jailbreak, PII leakage | Destructive shell commands, credential exfiltration, supply chain compromise |
| **Response latency** | Seconds acceptable (async pipeline) | Must be fast — Claude waits synchronously for hook verdict |
| **Guard model** | Llama Guard 3 (8B, full taxonomy) | tinyllama / qwen2.5:1.5b (≤1.5B, sub-200ms target) |

---

## 2. Tech Stack & Environmental Constraints
* **Frontend & Web Framework:** `Streamlit` (utilizing `st.session_state` for state management and `st.fragment` for non-blocking iterative UI updates).
* **LLM Inference Engine:** `Ollama` (Running locally. **Constraint:** Must use a single Ollama instance and rely on internal queuing to prevent VRAM Out-Of-Memory crashes).
* **Security Tooling (Mapped to Gates):**
    * **Protect.ai `llm-guard` (≥0.3.16):** Python library providing 15 input scanners and 21 output scanners for fast, transformer/regex-based input/output scanning. See Section 3.3 for the full scanner inventory.
    * **ProtectAI `deberta-v3-base-prompt-injection-v2`:** Fast binary injection classifier (SAFE / INJECTION) loaded locally via Hugging Face `transformers` (CPU). Publicly accessible — no gated HuggingFace account required.
    * **Meta `llama-guard3`:** Safety moderation LLM, executed locally via `Ollama`.
    * **Semantic-Guard (Custom):** An LLM-as-a-judge intent classifier (using smaller models like `phi3` or `tinyllama` via `Ollama`).
    * **`little-canary`:** Python library for behavioral and structural injection probing.
    * **Palo Alto AIRS (`httpx`/`requests`):** Cloud APIs for enterprise-grade prompt/response scanning.
* **Architecture Pattern:** Chain of Responsibility (for the security gates).

## 3. Core Architecture: The Stateful Pipeline
The system operates as a sequential interceptor following a "Cost/Latency Funnel" (cheapest/fastest checks run first). To prevent data loss during processing, the pipeline passes a `PipelinePayload` object rather than a raw string.



### 3.1 The Payload Object
```python
class PipelinePayload:
    original_input: str            # The raw user prompt (never modified, used for classification)
    current_text: str              # The string passed to the LLM (may be masked/sanitized by input gates)
    is_blocked: bool               # Current execution status (True if any gate in ENFORCE mode fails)
    block_reason: str              # Name of the gate that triggered the block and why
    metrics: list                  # List of dicts: {gate_name, latency_ms, score} for UI telemetry
    output_text: str               # The final LLM response (post-inference, evaluated by output gates)
    prompt_tokens: int = 0         # Number of tokens in the input prompt (polled from Ollama inference)
    completion_tokens: int = 0     # Number of tokens in the generated response (polled from Ollama inference)
    tokens_per_second: float = 0.0 # Generation speed metric (polled from Ollama inference)
    raw_traces: dict = {}          # Stores the exact JSON requests/responses for the API Inspector tabs
```

### 3.2 The Pipeline Sequence
If a prompt fails at any gate (and the gate is in `ENFORCE` mode), execution halts and returns a refusal template.

**Input Chain**

| Stage | Gate Key | Tool / Scanner | Primary Defense Target | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Gate 0** | `custom_regex` | `CustomRegexGate` (pure Python) | WAF hot-patch keyword/regex blocklist | ✅ Done |
| **Gate 1a** | `fast_scan` | `llm-guard`: `Anonymize` + `Secrets` | PII redaction, credential detection | ✅ Done |
| **Gate 1b** | `token_limit` | `llm-guard`: `TokenLimit` (tiktoken) | Oversized prompt rejection | ✅ Done |
| **Gate 1c** | `invisible_text` | `llm-guard`: `InvisibleText` | Unicode steganography / hidden chars | ✅ Done |
| **Gate 1d** | `toxicity_in` | `llm-guard`: `Toxicity` + `Sentiment` | Hostile / abusive input tone | ✅ Done |
| **Gate 1e** | `ban_topics` | `llm-guard`: `BanTopics` | Off-limits subject matter (zero-shot) | Phase 3+ |
| **Gate 2** | `classify` | `deberta-v3-base-prompt-injection-v2` | Fast injection/jailbreak classification | ✅ Done |
| **Gate 3** | `mod_llm` | `Llama-Guard-3` (Ollama) | Detailed safety taxonomies (LLM judge) | Phase 4 |
| **Gate 4** | `airs_inlet` | Prisma AIRS (Cloud API) | Enterprise injection + malicious URL | Phase 4 |

**Inference**

| Stage | | Tool | |
| :--- | :--- | :--- | :--- |
| **Target** | **Inference** | **Target LLM** (Ollama) | Main generation task |

**Output Chain**

| Stage | Gate Key | Tool / Scanner | Primary Defense Target | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Gate A** | `deanonymize` | `llm-guard`: `Deanonymize` (Vault) | Restore PII placeholders → real values | ✅ Done |
| **Gate B** | `sensitive_out` | `llm-guard`: `Sensitive` (Presidio) | PII that the LLM generated itself | ✅ Done |
| **Gate C** | `malicious_urls` | Heuristic layer + `llm-guard`: `MaliciousURLs` | Dangerous/phishing links in responses | ✅ Done |
| **Gate D** | `no_refusal` | `llm-guard`: `NoRefusal` | Detects model refusals (red-team + over-blocking) | ✅ Done |
| **Gate E** | `bias_out` | `llm-guard`: `Bias` + `Toxicity` (output) | Biased or abusive model output | ✅ Done |
| **Gate F** | `relevance` | `llm-guard`: `Relevance` (BAAI embeddings) | Off-topic / hallucinated responses | ✅ Done |
| **Gate G** | `structure` | `little-canary` (Python) | Behavioral/JSON integrity probes | Phase 5 |
| **Gate H** | `airs_dual` | Prisma AIRS (Cloud API) | Output DLP + malware scanning | Phase 4 |

### 3.3 llm-guard Full Scanner Inventory

All scanners return `(sanitized_text, is_valid, risk_score: float 0–1)`. They are CPU-viable but latency varies significantly.

**Input Scanners (15 total)**

| Scanner | Catches | Model / Method | CPU Latency |
|:--------|:--------|:---------------|:------------|
| `Anonymize` | PII (names, emails, SSN, IBAN, crypto) | Presidio NER + regex | 1–3 s |
| `BanCode` | Code submission | Language ID model | 100–500 ms |
| `BanCompetitors` | Competitor mentions | NER + list | 100–500 ms |
| `BanSubstrings` | Exact phrases | String match | < 1 ms |
| `BanTopics` | Off-limits subjects | Zero-shot (roberta-base-c-v2) | 500 ms–2 s |
| `Code` | Code snippets (25+ languages) | Language ID model | 100–500 ms |
| `Gibberish` | Nonsensical input | HuggingFace classifier | 100–500 ms |
| `InvisibleText` | Hidden Unicode chars | Unicode category analysis | < 1 ms |
| `Language` | Enforces input language | xlm-roberta | 100–500 ms |
| `PromptInjection` | Injection/jailbreak | deberta-v3-base-prompt-injection-v2 | 500 ms–2 s |
| `Regex` | Custom patterns | User-defined regex | < 1 ms |
| `Secrets` | API keys, credentials | detect-secrets (regex + entropy) | 1–10 ms |
| `Sentiment` | Negative/hostile tone | HuggingFace classifier | 100–500 ms |
| `TokenLimit` | Input length | tiktoken | < 1 ms |
| `Toxicity` | Abusive language | HuggingFace classifier | 100–500 ms |

**Output Scanners (21 total — includes mirrors of input scanners plus these unique ones)**

| Scanner | Catches | Model / Method | CPU Latency |
|:--------|:--------|:---------------|:------------|
| `Bias` | Biased content | distilroberta-bias | 100–500 ms |
| `Deanonymize` | Restores PII from Vault | Vault lookup (in-memory) | < 1 ms |
| `FactualConsistency` | Response vs context accuracy | Embedding similarity | 500 ms–2 s |
| `JSON` | Validates / repairs JSON output | Schema + json-repair | < 1 ms |
| `LanguageSame` | Output language matches input | xlm-roberta | 100–500 ms |
| `MaliciousURLs` | Dangerous links in response | codebert-base-Malicious_URLs | 500 ms–2 s |
| `NoRefusal` | Model complied with attack | distilroberta-base-rejection-v1 | 100–500 ms |
| `ReadingTime` | Response too long | Word count heuristic | < 1 ms |
| `Relevance` | Off-topic responses | BAAI/bge-base-en-v1.5 embeddings | 500 ms–2 s |
| `Sensitive` | PII in LLM output | Presidio Analyzer | 1–3 s |
| `URLReachability` | Validates links are live | HTTP status check | network-dependent |

**ONNX Optimisation:** Installing `llm-guard[onnxruntime]` reduces transformer model latency by 50–70% on CPU. Recommended for all Phase 3+ gates.

### 3.4 Vault Architecture (PII De-anonymisation)

The `Vault` is a session-scoped in-memory map that makes PII anonymisation reversible across the input→LLM→output boundary:

```
User input:   "My name is Alice Smith, email alice@example.com"
  ↓ Anonymize (Gate 1a)
To LLM:       "My name is [REDACTED_PERSON_1], email [REDACTED_EMAIL_1]"
  ↓ LLM responds using placeholders
LLM output:   "Hello [REDACTED_PERSON_1], I've noted [REDACTED_EMAIL_1]"
  ↓ Deanonymize (Gate A)
To user:      "Hello Alice Smith, I've noted alice@example.com"
```

The `Deanonymize` output gate (Gate A) must share the same `Vault` instance as `Anonymize` (Gate 1a). The `Vault` is initialised once per conversation and passed into both gate constructors. **Gate A is not yet wired** — without it, placeholder text leaks into user-visible responses (known issue, Phase 3+).

## 4. Proposed File Structure
```text
llm-sec-workbench/
│
├── .streamlit/
│   └── config.toml         # Streamlit global theme configuration (Dark Mode)
├── .env.example            # Template for environment variables (DO NOT commit real .env)
├── .gitignore              # Standard Python/Streamlit gitignore
├── README.md               # Main project overview, features, and badges
├── config.yaml             # API keys, active models, default thresholds, AIRS profiles
├── requirements.txt        # Version-locked dependencies
├── app.py                  # Main Streamlit UI and execution orchestrator
├── start.bat               # Windows 1-click launcher script
├── start.sh                # Mac/Linux 1-click launcher script
├── Dockerfile              # Container definition for the Streamlit app
├── docker-compose.yml      # Orchestrates the app and optional networked services
├── pytest.ini              # Pytest configuration
│
├── docs/
│   ├── QUICKSTART.md       # Step-by-step setup guide (Ollama install, pip install, run)
│   └── ARCHITECTURE.md     # Explanation of the PipelinePayload and Gate sequence
│
├── core/
│   ├── __init__.py
│   ├── payload.py          # PipelinePayload class definition
│   ├── llm_client.py       # Ollama wrapper with startup auto-pull logic
│   └── pipeline.py         # Pipeline manager orchestrator
│
├── data/
│   └── static_payloads.json   # Prebuilt prompts categorized by intent and severity
│
├── gates/                  # The "Chain of Responsibility" implementations
│   ├── __init__.py
│   ├── base_gate.py        # Abstract base class: SecurityGate with try/except wrappers
│   ├── regex_gate.py       # Gate 0: CustomRegexGate (hot-patch keyword/regex blocklist) ✅
│   ├── local_scanners.py   # Gates 1a–1e & 2: llm-guard input scanners + deberta classifier ✅ (partial)
│   ├── output_scanners.py  # Gates A–F: llm-guard output scanners (Deanonymize, Sensitive, NoRefusal, etc.)
│   ├── ollama_gates.py     # Gate 3: Llama-Guard-3 (Ollama-hosted safety LLM)
│   └── airs_gate.py        # Gates 4 & H: Prisma AIRS cloud API (inlet + dual)
│
├── tests/
│   ├── __init__.py
│   ├── test_pipeline.py    # Unit tests for the PipelineManager state mutations
│   └── test_gates.py       # Unit tests for individual gate logic
│
├── redteam/
│   ├── __init__.py
│   ├── static_runner.py    # Handles batch execution and MD report generation
│   └── dynamic_pair.py     # Implements the PAIR iterative refinement algorithm
│
└── ui/
    ├── __init__.py
    ├── chat_view.py        # Manual testing chat interface
    ├── redteam_view.py     # Dashboard for Static & Dynamic automation
    └── metrics_panel.py    # Visual pipeline configuration, latency charts, text diffs
```    

## 5. Security Gate Interface & Execution Modes
All classes in the `gates/` directory inherit from an abstract base class `SecurityGate`. 

**Gate Modes:**
Every gate in the UI will have a 3-way state selector:
1.  `OFF`: The pipeline skips this gate entirely (0 latency added).
2.  `AUDIT`: Scans the input. If a violation is found, it is logged in the payload metrics, but the pipeline **continues**.
3.  `ENFORCE`: Scans the input. If a violation is found, the pipeline **halts immediately**, skips LLM generation, and shows a block message.

**Implementation Rules for Agent:**
* **Strict Error Bubbling:** Every gate implementation must wrap its logic in a `try-except` block. If a model fails to load or an API times out, the gate must return `is_safe=True` but log an error in the metadata so the pipeline survives.

```python
class SecurityGate(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def scan(self, payload: PipelinePayload) -> PipelinePayload:
        """
        1. Start timer.
        2. Run scan (use payload.original_input for classifiers, current_text for inference).
        3. Append metrics to payload.metrics (latency, scores).
        4. Update payload.current_text if masking/sanitization occurs.
        5. If blocked, update payload.is_blocked and payload.block_reason.
        6. Return payload.
        """
        pass
```

## 6. Implementation Phases for Coding Agent
* **Phase 0 (Repository Scaffolding):** Generate the standard GitHub files. Create the .streamlit/config.toml to establish the Dark Mode theme (Section 9.6).Create a comprehensive `README.md` summarizing this project. Create a `.gitignore` suitable for Python and Streamlit. Create `.env.example` with placeholders for `OLLAMA_HOST` and `PANW_API_KEY`. Finally, generate `docs/QUICKSTART.md` and `docs/ARCHITECTURE.md` based on the logic in this PLAN.MD. 
* **Phase 0.5 (Database, Testing & Deployment):** Implement a lightweight SQLite logger (`core/db_logger.py`) that automatically saves finalized `PipelinePayload` objects to a local `.sqlite` file. Create the `tests/` directory with basic `pytest` functions. Create the `Dockerfile` and `docker-compose.yml`. **Crucial:** Write a `start.bat` and `start.sh` script that automatically copies `.env.example` to `.env`, runs `docker-compose up`, and opens the browser to `localhost:8501` to make setup frictionless for non-developers.
* **Phase 1 (Foundation & Chat UI):** Setup `requirements.txt` and `app.py`. In `core/llm_client.py`, create an abstract base class (`BaseLLMClient`) with a `generate()` method to future-proof for cloud APIs, then implement `OllamaClient` as the first concrete subclass. Implement the Chat UI, including the expandable "System Context / RAG Document" text area (Section 9.5). **Crucial:** Build a "First Run" loading screen in Streamlit that clearly displays the download progress when running `ollama pull` for the required models on startup, so users know the app isn't frozen.
* **Phase 2 (Pipeline & Hot-Patching):** Implement `core/payload.py`, `core/pipeline.py`, and `gates/base_gate.py`. Build the `CustomRegexGate` for the Hot-Patching feature (Section 9.5) to establish the pipeline flow before adding heavy AI models.
* **Phase 3 (Fast Local Classifiers — llm-guard Full Suite):** Expand `local_scanners.py` and create `output_scanners.py`. The full Phase 3 scope, in priority order:
  1. **Gate A `Deanonymize`** — highest priority: wire the `Vault` through `Anonymize`→`Deanonymize` so PII placeholders are restored in the user-visible response instead of leaking as `[REDACTED_PERSON_1]`.
  2. **Gate 1b `TokenLimit`** — zero-ML, add immediately: reject oversized prompts before they reach heavier gates.
  3. **Gate 1c `InvisibleText`** — zero-ML, add immediately: catches Unicode steganography attacks.
  4. **Gate B `Sensitive`** — output-side Presidio scan: catches PII that the LLM generates itself (not just echoing user input).
  5. **Gate C `MaliciousURLs`** — output gate: scan LLM responses for dangerous links.
  6. **Gate D `NoRefusal`** — output gate: flag when the model *complied* with an attack (jailbreak succeeded but ENFORCE gates were in AUDIT).
  7. **Gate 1d `Toxicity`/`Sentiment`** — input gates: block hostile prompts before inference.
  8. **Gate E `Bias`/`Toxicity`** — output gates: quality gates on model responses.
  9. **Gate F `Relevance`** — output gate: BAAI embedding similarity check for off-topic responses.
  10. **Gate 1e `BanTopics`** — input gate: zero-shot topic restriction (slowest of the batch, add last).
  * Force all transformer-based scanners to CPU (`device="cpu"`). Add `llm-guard[onnxruntime]` to `requirements.txt` for 50–70% latency reduction.
  * Each gate must log its raw JSON to `payload.raw_traces` for the API Inspector.
  * The shared `Vault` instance must be created once per pipeline rebuild and passed to both `Anonymize` (input) and `Deanonymize` (output).
* **Phase 4 (LLM & Cloud Gates):** Implement `ollama_gates.py` and `airs_gate.py`. Include a configurable timeout (e.g., 2-3 seconds) for Prisma AIRS API calls to ensure fail-open reliability.
* **Phase 5 (Workspace & Observability):** Finalize `ui/metrics_panel.py`. Build the tabbed "API Inspector" expander. Implement the `@st.fragment` hardware memory polling (VRAM/RAM), the Persona/Parameter controls, and wire up the `demo_mode` Clean UI toggle.
* **Phase 6 (Static Fuzzing & Importers):** Implement `redteam/static_runner.py`. Build the UI for `.jsonl` Garak file uploads and the JailbreakBench GitHub fetcher. Implement the Markdown/JSON report export buttons.
* **Phase 7 (Dynamic PAIR & Auto-Harden):** Implement `redteam/dynamic_pair.py` using `st.fragment` for the scrolling battle log. Implement the Defender LLM logic for the "Auto-Harden" button to rewrite system prompts upon a successful breach.

## 7. Advanced Architecture: The Configurable Security Pipeline

```python
class PipelineManager:
    # Pseudo-logic for the coding agent to follow
    def execute(self, user_text, gates_config):
        payload = PipelinePayload(original_input=user_text, current_text=user_text)

        # INPUT GATES
        for gate_name, gate_instance in self.input_gates:
            mode = gates_config[gate_name]['mode']
            if mode == 'OFF': continue
            
            payload = gate_instance.scan(payload)
            if mode == 'ENFORCE' and payload.is_blocked:
                return self.generate_refusal_response(payload)

        # INFERENCE
        payload.output_text = self.target_llm.generate(payload.current_text)

        # OUTPUT GATES
        for gate_name, gate_instance in self.output_gates:
            mode = gates_config[gate_name]['mode']
            if mode == 'OFF': continue
            
            payload = gate_instance.scan(payload)
            if mode == 'ENFORCE' and payload.is_blocked:
                return self.generate_refusal_response(payload)

        return payload
```

## 8. The Offensive Engine: Red Teaming & Fuzzing
### 8.1. Static Red Teaming (Batch Fuzzing)
* **Execution:** User selects predefined malicious payloads by category/severity. The `static_runner.py` iterates them through the `PipelineManager`.
* **Reporting:** Automates the generation of an `export.md` summarizing bypass rates, blocked payloads, and pipeline latencies. Maps vulnerabilities to the OWASP Top 10 for LLMs.

### 8.2. Dynamic Red Teaming (LLM-Assisted PAIR)
* **Architecture:** Uses two LLMs. The Attacker LLM generates a prompt, sends it to the Target LLM (through the pipeline), evaluates the failure/block message, and iteratively refines the attack.
* **Execution:** Modeled after the PAIR Algorithm (Chao et al., 2023). The Attacker LLM must output a JSON object containing `{"thought": "...", "next_prompt": "..."}`. The UI features a live scrolling log of the execution.
* **Reporting:** Include UI buttons to export the dynamic probe's iteration log and final verdict as both JSON and Markdown reports.

### 8.3. Threat Data Import Options
* **Garak Import:** Implement a file uploader (`st.file_uploader`) in the Red Team UI that accepts garak `.report.jsonl` or `.hitlog.jsonl` files. Parse the `attempt` entries and extract the `prompt` fields to use as test payloads.
* **JailbreakBench Fetcher:** Implement a function that fetches verified jailbreaks directly from GitHub (`https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/{method}/{model}.json`) and adds them to the static fuzzing queue.

### 8.4. Auto-Remediation (The Defender LLM)
* **Functionality:** If a Dynamic PAIR probe succeeds (Breach), reveal an "Auto-Harden" button in the UI.
* **Execution:** Send the successful attack trace to an Ollama model with instructions to rewrite the user's current `System Prompt` to specifically defend against that attack vector. Allow the user to 1-click apply the new prompt and re-run the PAIR test.

## 9. Workspace Controls & Telemetry
To provide a complete lab environment, the UI must include advanced model controls and hardware observability.

### 9.1 Persona & Parameter Configuration
* In the chat interface sidebar, add controls for LLM generation parameters: `Temperature`, `Top P`, `Top K`, and `Repeat Penalty`.
* Add a "Persona" dropdown that populates the System Prompt. Include presets like: "Code Architect", "Strict DLP Auditor", and "Socratic Tutor".

### 9.2 Hardware & Token Telemetry (st.fragment)
* Create a dedicated telemetry panel using `@st.fragment(run_every=5)` to poll the local Ollama instance asynchronously.
* **Ollama APIs to poll:**
  * `/api/ps`: To extract and display `size_vram` vs `size` (RAM) to monitor memory pressure.
  * `/api/show`: To extract `model_info` and display the active context window size.
* Display Tokens Per Second (t/s) and a progress bar showing context window utilization based on the `prompt_tokens` in the payload.

### 9.3 The API Inspector
* Below the main chat, include a collapsible `st.expander("🛠️ API Inspector")`.
* Inside the expander, dynamically generate Streamlit Tabs (`st.tabs`) for each active gate in `payload.raw_traces`.
* In each tab, use two columns (`st.columns(2)`) to display the raw JSON Request and Response payloads side-by-side using `st.json()`.
* Include a utility in the sidebar or header to export the current manual chat session (including all gate verdicts and latency metrics) as a Markdown file.

### 9.4 End-User Demo Mode (Clean UI Toggle)
* **Functionality:** Add a prominent toggle button (e.g., in the header or sidebar) labeled "Toggle Demo Mode".
* **State Management:** This should bind to a `st.session_state.demo_mode` boolean.
* **Execution (Demo Mode ON):** * Hide all security instrumentation in the chat interface. This includes scanner badges, latency metrics, the API Inspector expander, and the right-hand Telemetry panel.
  * The chat should look like a vanilla, generic chatbot (e.g., ChatGPT).
  * If a prompt or response is blocked by a gate in `ENFORCE` mode, do not show the technical reason (e.g., "PromptInjection score 0.99"). Instead, display a generic, end-user-friendly refusal message (e.g., "I cannot fulfill this request due to security policies.").
* **Execution (Demo Mode OFF):** Restore the full, transparent workbench view, revealing exactly which gates fired and why.

### 9.5. RAG Simulation (Indirect Injection) & Hot-Patching
* **RAG Context:** Add an expandable `System Context / RAG Document` text area in the chat UI. Ensure the `PipelineManager` appends this context to the LLM call, allowing users to test indirect prompt injections hidden in simulated retrieved documents.
* **Hot-Patching:** Add a simple text-input in the sidebar for "Custom Block Phrases (Comma separated)". Create a lightweight `RegexGate` that evaluates the prompt against these phrases before it hits the heavier AI models, simulating a WAF hot-patch.

### 9.6 UI/UX Theming & Semantic Colors
The application must feel like a professional cybersecurity tool. 
* **Global Theme:** Force Dark Mode by generating a `.streamlit/config.toml` file with a dark background (e.g., `#0E1117`), a secondary background for panels (e.g., `#262730`), and a distinct primary color (e.g., `#7AA2F7` or a tech blue).
* **Semantic Status Colors:** When rendering gate badges, metrics, or the API Inspector trace, strictly adhere to these semantic colors using `st.markdown` HTML styling or Streamlit's native status elements:
  * **Blocked / Threat:** Red (`#F7768E` or `st.error`)
  * **Flagged / Warning:** Orange/Yellow (`#E0AF68` or `st.warning`)
  * **Safe / Passed:** Green (`#9ECE6A` or `st.success`)
  * **AI Processing / Semantic Judge:** Purple (`#BB9AF7`)

## 10. Configuration & Dependencies
```markdown
### 10.1 Base `config.yaml` / `.env` Schema

**`config.yaml`**
```yaml
models:
  target: "llama3"
  attacker: "phi3"
  safety: "llama-guard3"

palo_alto_airs:
  api_key: "YOUR_SCM_KEY"
  profile_name: "workbench-default"
  app_id: "llm-sec-workbench-local"
  region: "us-east-1"
```

**`.env.example`**
```env
# Explicitly set the default Ollama host to the Docker bridge so the container can see the host's Ollama
OLLAMA_HOST="[http://host.docker.internal:11434](http://host.docker.internal:11434)"
PANW_API_KEY="your_api_key_here"
```

### 10.2 Build-Safe `requirements.txt`
To prevent the agent from causing dependency conflicts (especially CUDA/Protobuf mismatches), strictly define these constraints:
```text
streamlit>=1.37.0
ollama
llm-guard
transformers
onnxruntime
torch --index-url https://download.pytorch.org/whl/cpu
pyyaml
pandas
plotly
httpx
pytest>=8.0.0
pytest-asyncio
sqlalchemy
```

## 11. Reference Materials & Inspiration for the Agent
When implementing the features above, rely on the APIs, concepts, and architectural patterns of the following open-source projects. Do not clone these repositories directly unless instructed; use them via `pip install` or as conceptual models for your code.

* **Pipeline & Scanners:** `protectai/llm-guard` (≥0.3.16). Use its `InputScanner` and `OutputScanner` base classes for Gates 1a–1e and A–F. See Section 3.3 for the full scanner inventory and CPU latency expectations.
* **Injection Classifier:** `protectai/deberta-v3-base-prompt-injection-v2` — Gate 2. Binary SAFE/INJECTION classifier. Publicly accessible, no HuggingFace token required.
* **PII De-anonymisation:** `llm_guard.vault.Vault` + `llm_guard.output_scanners.Deanonymize` — must share the same `Vault` instance as `Anonymize` (Gate 1a). See Section 3.4.
* **Behavioral Probes:** `protectai/little-canary` (Conceptual reference for Gate G structural evaluation).
* **ONNX Acceleration:** `pip install llm-guard[onnxruntime]` — reduces CPU inference latency 50–70% for all transformer-based scanners.
* **Dynamic Red Teaming (PAIR Algorithm):** Model the iterative loop after the "Jailbreaking Black Box Large Language Models in Twenty Queries" (Chao et al., 2023) paper. The Attacker LLM should evaluate the Target's response and output a JSON object containing `{"thought": "...", "next_prompt": "..."}`.
