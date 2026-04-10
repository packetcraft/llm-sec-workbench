# Architecture Reference

This document covers the internal design of LLM Security Workbench: the `PipelinePayload` object, the gate sequence, the execution model, and the key design decisions behind each choice.

---

## Design Principle: Stateless Gates, Stateful Pipeline

Every security gate in the system is **stateless** — it holds no memory between calls and does not depend on external state. All state lives in a single `PipelinePayload` object that is threaded through the pipeline from start to finish.

This separation means:
- Gates can be independently enabled, disabled, reordered, or replaced without side effects.
- The pipeline always has a complete audit trail of what each gate observed and decided.
- Upstream mutations (like PII masking) are recorded so downstream gates can still operate on the **original** unmodified text for classification purposes.

---

## The `PipelinePayload` Object

Defined in `core/payload.py`. Every piece of data produced or consumed by the pipeline lives here.

```python
class PipelinePayload:
    original_input: str        # Raw user prompt — NEVER modified. Used by classifiers.
    current_text: str          # Text passed to the LLM. May be sanitized/masked by input gates.
    is_blocked: bool           # True if any ENFORCE-mode gate has triggered a block.
    block_reason: str          # Which gate blocked the request and why.
    metrics: list[dict]        # Per-gate telemetry: {gate_name, latency_ms, score, verdict}
    output_text: str           # Final LLM response text. Populated after inference.
    prompt_tokens: int         # Token count of the input prompt (from Ollama).
    completion_tokens: int     # Token count of the generated response (from Ollama).
    tokens_per_second: float   # Generation throughput (from Ollama).
    raw_traces: dict           # Raw JSON request/response pairs, keyed by gate name.
```

### Why Two Text Fields?

`original_input` and `current_text` are intentionally separate.

When Gate 1 (`Fast-Scan`) detects PII like a credit card number, it replaces it in `current_text` with a placeholder (e.g., `[CREDIT_CARD]`) before the text reaches the LLM. If Gate 2 (`Classify`) were to run on `current_text`, the now-masked string would look completely benign and might fool the injection classifier.

By always running **classifiers against `original_input`** and passing **`current_text` to the LLM**, the pipeline achieves both safety and correctness simultaneously.

---

## The Gate Interface

Defined in `gates/base_gate.py`. All gates implement this abstract base class.

```python
class SecurityGate(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def scan(self, payload: PipelinePayload) -> PipelinePayload:
        """
        Contract:
        1. Record wall-clock start time.
        2. Run the scan — use payload.original_input for classifiers,
           payload.current_text for anything modifying the inference input.
        3. Append a metrics dict to payload.metrics:
               {gate_name, latency_ms, score, verdict}
        4. If masking/sanitization occurs, update payload.current_text.
        5. Store raw JSON traces in payload.raw_traces[gate_name].
        6. If a violation is found, set payload.is_blocked = True
           and payload.block_reason to a descriptive string.
        7. Always return payload — never raise from within scan().
        """
        pass
```

### Error Handling Contract

Every concrete gate implementation **must** wrap its logic in a `try-except`. If a model fails to load, an ONNX runtime errors, or an API call times out, the gate must:

1. Log the error into `payload.metrics` with a `verdict: "ERROR"` entry.
2. Leave `payload.is_blocked` unchanged (default `False`).
3. Return the payload immediately.

This guarantees the pipeline **fails open** — a broken gate never silently blocks legitimate traffic.

---

## Gate Modes

Each gate in the UI exposes a 3-way mode selector stored in `st.session_state`:

| Mode | Pipeline Behavior |
|:-----|:-----------------|
| `OFF` | Gate is skipped entirely. No latency, no logging. |
| `AUDIT` | Gate scans and logs its verdict in `payload.metrics`, but `is_blocked` is never set. The pipeline continues regardless of the scan result. |
| `ENFORCE` | Gate scans. If `is_blocked` is set to `True` after the scan, the `PipelineManager` immediately halts execution, skips LLM inference (or remaining output gates), and returns a refusal response. |

---

## The Pipeline Sequence

The pipeline follows a **Cost/Latency Funnel**: the cheapest and fastest checks run first to avoid wasting compute on prompts that can be rejected in milliseconds.

```
USER PROMPT
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  INPUT GATES                                                 │
│                                                              │
│  Gate 1 │ Fast-Scan    │ llm-guard (CPU/ONNX)               │
│         │              │ PII, secrets, regex                 │
│                                                              │
│  Gate 2 │ Classify     │ Prompt-Guard-86M (CPU/ONNX)        │
│         │              │ Injection & jailbreak ID            │
│                                                              │
│  Gate 3 │ Mod-LLM      │ Llama-Guard-3 (Ollama)             │
│         │              │ Detailed safety taxonomies          │
│                                                              │
│  Gate 4 │ AIRS-Inlet   │ Prisma AIRS (Cloud API)            │
│         │              │ Enterprise injection & malicious URL│
└─────────────────────────────────────────────────────────────┘
    │  (if not blocked)
    ▼
┌─────────────────┐
│   INFERENCE     │  Target LLM via Ollama
└─────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│  OUTPUT GATES                                                │
│                                                              │
│  Gate 5 │ Structure    │ little-canary (Python)             │
│         │              │ Behavioral & JSON integrity         │
│                                                              │
│  Gate 6 │ Final-Check  │ llm-guard (CPU/ONNX)               │
│         │              │ Refusal check & PII unmasking       │
│                                                              │
│  Gate 7 │ AIRS-Dual    │ Prisma AIRS (Cloud API)            │
│         │              │ Output DLP & malware detection      │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
RESPONSE → UI
```

### Why This Order?

1. **Gate 1 (llm-guard, CPU):** Regex and transformer-based scanners are near-zero latency and catch the most obvious violations (PII, secrets).
2. **Gate 2 (Prompt-Guard, CPU):** A small 86M-parameter ONNX model — fast enough to run before any GPU workload.
3. **Gate 3 (Llama-Guard-3, GPU via Ollama):** A full safety LLM. Runs only if the cheaper gates pass, preserving VRAM.
4. **Gate 4 (Prisma AIRS, Cloud):** Network round-trip makes this the most expensive input gate. Placed last before inference.
5. **Target Inference:** Runs only when all active input gates pass.
6. **Gate 5 (little-canary):** Structural output check — pure Python, no model loading.
7. **Gate 6 (llm-guard, CPU):** Checks for refusal bypass and performs PII **un-masking** so the user sees the original text.
8. **Gate 7 (Prisma AIRS, Cloud):** Final DLP pass on the complete output.

---

## `PipelineManager` Execution Logic

Defined in `core/pipeline.py`. Pseudo-code for the main execution loop:

```python
class PipelineManager:
    def execute(self, user_text: str, gates_config: dict) -> PipelinePayload:
        payload = PipelinePayload(
            original_input=user_text,
            current_text=user_text
        )

        # INPUT GATES
        for gate_name, gate_instance in self.input_gates:
            mode = gates_config[gate_name]["mode"]
            if mode == "OFF":
                continue

            payload = gate_instance.scan(payload)

            if mode == "ENFORCE" and payload.is_blocked:
                return self._refusal_response(payload)

        # INFERENCE
        payload = self.target_llm.generate(payload)

        # OUTPUT GATES
        for gate_name, gate_instance in self.output_gates:
            mode = gates_config[gate_name]["mode"]
            if mode == "OFF":
                continue

            payload = gate_instance.scan(payload)

            if mode == "ENFORCE" and payload.is_blocked:
                return self._refusal_response(payload)

        return payload
```

Key behaviors:
- An `AUDIT`-mode gate **never** causes the loop to exit early, even if it sets `is_blocked`.
- `_refusal_response()` generates a user-facing block message. In Demo Mode, this is a generic string. In Workbench Mode, it includes the gate name and score.
- The `PipelineManager` uses a single Ollama instance internally. All LLM calls (target, Llama-Guard, Semantic-Guard) are serialized through Ollama's internal queue to prevent VRAM OOM crashes from concurrent model loads.

---

## Ollama VRAM Management

The app is designed around a single `OllamaClient` instance. Ollama handles model loading and VRAM eviction internally. The application:

1. Never calls multiple Ollama inference endpoints concurrently.
2. Monitors VRAM via `/api/ps` and displays live pressure indicators.
3. Exposes a `config.yaml` field to set which models are active, allowing users to trade capability for VRAM budget.

---

## The Red Teaming Engine

### Static Fuzzing (`redteam/static_runner.py`)

Iterates a list of payloads (from `data/static_payloads.json`, uploaded Garak files, or JailbreakBench) through `PipelineManager.execute()` in sequence, collecting the full `PipelinePayload` result for each. Generates an export Markdown report mapping results to OWASP Top 10 for LLMs categories.

### Dynamic PAIR (`redteam/dynamic_pair.py`)

Implements the Chao et al. (2023) iterative refinement algorithm:

```
Attacker LLM
    │
    │ generates prompt
    ▼
PipelineManager.execute()
    │
    │ returns payload (blocked or not)
    ▼
Attacker LLM
    │ evaluates response, outputs:
    │   {"thought": "...", "next_prompt": "..."}
    └── loop until breach or max_iterations
```

The Attacker LLM is a smaller model (default: `phi3`) to minimize VRAM contention with the target model.

---

## Telemetry & the API Inspector

### Hardware Telemetry (`@st.fragment`)

A Streamlit fragment polls Ollama every 5 seconds:
- `/api/ps` → `size_vram` vs `size` (VRAM vs RAM usage per loaded model)
- `/api/show` → `model_info.context_length` (maximum context window)

Token counts and generation speed are populated by the `OllamaClient` after each inference call and stored in the `PipelinePayload`.

### API Inspector

`payload.raw_traces` is a dict keyed by gate name. The UI dynamically creates one tab per key and renders the request and response JSON side-by-side. This allows users to inspect exactly what each gate sent and received — critical for debugging cloud API responses.

---

## Semantic Color System

All gate verdicts, metrics, and inspector UI elements follow a consistent semantic color scheme:

| Meaning | Color | Streamlit Element |
|:--------|:------|:------------------|
| Blocked / Threat | `#F7768E` (red) | `st.error()` |
| Flagged / Warning | `#E0AF68` (amber) | `st.warning()` |
| Safe / Passed | `#9ECE6A` (green) | `st.success()` |
| AI / Semantic Judge | `#BB9AF7` (purple) | `st.markdown` with inline style |
| UI Background | `#0E1117` | `.streamlit/config.toml` |
| Panel Background | `#262730` | `.streamlit/config.toml` |
| Primary Accent | `#7AA2F7` (tech blue) | `.streamlit/config.toml` |
