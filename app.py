"""
app.py
──────
Streamlit entry point for LLM Security Workbench.

Responsibilities
----------------
1. Set page config (must be the first Streamlit call).
2. Load config.yaml and environment variables.
3. Initialise session state defaults.
4. Instantiate the OllamaClient (cached for the app lifetime).
5. Route to the correct view:
     - Ollama unreachable   → connection error screen
     - Required models absent → First Run download screen
     - Everything ready     → main chat view

Phase integration notes
-----------------------
Phase 2 will add:
  - Pipeline initialisation (PipelineManager, gate configs in session_state)
  - Routing the chat view through the pipeline instead of the raw client
Phase 5+ will add:
  - Additional top-level tabs (Red Team, Metrics)
"""

from __future__ import annotations

import os

import streamlit as st
import yaml
from dotenv import load_dotenv

# ── MUST be the very first Streamlit call ─────────────────────────────────────
st.set_page_config(
    page_title="LLM Security Workbench",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": "https://github.com/your-org/llm-sec-workbench/issues",
        "Report a bug": "https://github.com/your-org/llm-sec-workbench/issues",
        "About": "LLM Security Workbench — local AI red-teaming and defence testing.",
    },
)

load_dotenv()


# ── Cached resource loaders ───────────────────────────────────────────────────

@st.cache_resource
def _load_config() -> dict:
    """Load config.yaml once and cache for the app lifetime.

    If config.yaml is missing, returns a minimal default dict so the app
    still starts (Ollama connection check will fail gracefully if needed).
    """
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")
    try:
        with open(config_path) as fh:
            return yaml.safe_load(fh) or {}
    except FileNotFoundError:
        st.warning("`config.yaml` not found — using built-in defaults.")
        return {
            "models": {"target": "llama3", "safety": "llama-guard3", "attacker": "phi3"},
            "generation": {
                "temperature": 0.7,
                "top_p": 0.9,
                "top_k": 40,
                "repeat_penalty": 1.1,
                "max_tokens": 2048,
            },
        }


@st.cache_resource
def _build_client(host: str, model: str):
    """Instantiate and cache the OllamaClient.

    The client holds a connection pool; caching it means one pool is shared
    across all Streamlit re-runs for the lifetime of the server process.
    This also ensures we never race-connect from multiple threads.
    """
    from core.llm_client import OllamaClient
    return OllamaClient(model=model, host=host)


# ── Session state initialisation ──────────────────────────────────────────────

def _init_session_state(config: dict) -> None:
    """Set default session_state values on first page load.

    Keys defined here span all phases so that Phase 2+ code can read them
    without needing to add initialisation elsewhere.
    """
    gen = config.get("generation", {})

    defaults: dict = {
        # Chat history
        "messages": [],

        # UI toggles
        "demo_mode": False,

        # Persona / system prompt
        "persona": "Default",
        "system_prompt": "",

        # RAG simulation (Section 9.5)
        "rag_context": "",

        # Hot-Patching (Section 9.5) — wired to RegexGate in Phase 2
        "custom_block_phrases": "",

        # BanTopics (Gate 1e) — comma-separated forbidden subject areas
        "ban_topics_list": "",

        # Gate thresholds — adjustable via sidebar sliders
        "pii_threshold": 0.7,
        "token_limit":   512,

        # Generation parameters (Section 9.1)
        "temperature": float(gen.get("temperature", 0.7)),
        "top_p": float(gen.get("top_p", 0.9)),
        "top_k": int(gen.get("top_k", 40)),
        "repeat_penalty": float(gen.get("repeat_penalty", 1.1)),

        # Selected target model — defaults to config.yaml, overridden by the sidebar dropdown
        "target_model": config.get("models", {}).get("target", "llama3"),

        # Gate modes — populated per-phase as gates are implemented.
        # Format: {"gate_name": "OFF" | "AUDIT" | "ENFORCE"}
        "gate_modes": {},

        # Last generation token throughput — updated after each stream; read
        # by the hardware telemetry panel (Phase 5) in the sidebar.
        "last_tps": 0.0,
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    # Merge in defaults for any newly introduced gates so existing sessions
    # pick up new keys without losing user-configured values.
    gate_defaults = {
        "custom_regex":   "AUDIT",    # Phase 2 — Hot-Patch RegexGate
        "token_limit":    "ENFORCE",  # Phase 3 — Token budget (zero-ML)
        "invisible_text": "ENFORCE",  # Phase 3 — Unicode steganography (zero-ML)
        "fast_scan":      "AUDIT",    # Phase 3 — PII / Secrets scanner
        "classify":       "AUDIT",    # Phase 3 — Prompt-Guard injection classifier
        "toxicity_in":    "AUDIT",    # Phase 3 — Hostile/toxic input tone (quality)
        "ban_topics":     "AUDIT",    # Phase 3 — Forbidden subject-area filter (zero-shot)
        "mod_llm":        "AUDIT",    # Phase 4 — Llama Guard 3 LLM safety judge (Ollama)
        "sensitive_out":  "AUDIT",    # Phase 3 — Output-side PII scan (LLM-generated PII)
        "malicious_urls": "ENFORCE",  # Phase 3 — Malicious URL detection (output gate)
        "no_refusal":     "AUDIT",    # Phase 3 — Model refusal detection (output gate)
        "bias_out":       "AUDIT",    # Phase 3 — Biased/toxic output (quality)
        "relevance":      "AUDIT",    # Phase 3 — Off-topic / hallucination (quality)
        "deanonymize":    "ENFORCE",  # Phase 3 — PII restoration (output gate)
    }
    for gate_key, gate_default in gate_defaults.items():
        st.session_state.gate_modes.setdefault(gate_key, gate_default)


# ── Model availability helper ─────────────────────────────────────────────────

def _model_present(name: str, available: list[str]) -> bool:
    """Return True if the base model name (without :tag) is in the available list.

    Handles the common case where the config says ``"llama3"`` but Ollama
    returns ``"llama3:latest"``.
    """
    base = name.split(":")[0].lower().strip()
    return any(base == a.split(":")[0].lower().strip() for a in available)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    config = _load_config()
    _init_session_state(config)

    ollama_host: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    # Use the sidebar-selected model if set; otherwise fall back to config.yaml default.
    # _build_client is cached per (host, model) so switching models reuses existing pools.
    target_model: str = st.session_state.get(
        "target_model",
        config.get("models", {}).get("target", "llama3"),
    )
    client = _build_client(host=ollama_host, model=target_model)

    from ui.chat_view import render, render_connection_error, render_first_run

    # ── Top-level navigation ──────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("## Navigation")
        page = st.radio(
            label="page",
            options=["💬 Chat Workbench", "🛡️ Agentic Security"],
            label_visibility="collapsed",
        )
        st.divider()

    # ── Agentic Security — no pipeline or Ollama required ────────────────────
    if page == "🛡️ Agentic Security":
        from ui.agentic_view import render as render_agentic
        render_agentic(config)
        return

    # ── Route: Ollama unreachable ─────────────────────────────────────────────
    if not client.is_available():
        render_connection_error(ollama_host)
        return

    # ── Route: First Run — required models not yet pulled ─────────────────────
    available_models = client.list_models()
    required_models: list[str] = [
        config.get("models", {}).get("target", "llama3"),
        config.get("models", {}).get("safety", "llama-guard3"),
        config.get("models", {}).get("attacker", "phi3"),
    ]
    missing = [m for m in required_models if not _model_present(m, available_models)]

    if missing:
        render_first_run(client, missing)
        return

    # ── Build security pipeline ───────────────────────────────────────────────
    # Rebuilt on every re-run so gate config (phrases, modes) is always current.
    from core.pipeline import PipelineManager
    from gates.regex_gate import CustomRegexGate
    from gates.local_scanners import (
        TokenLimitGate, InvisibleTextGate,
        FastScanGate, PromptGuardGate, DeanonymizeGate,
        SensitiveGate, MaliciousURLsGate, NoRefusalGate,
        ToxicityInputGate, BiasOutputGate, RelevanceGate,
        BanTopicsGate,
    )
    from gates.ollama_gates import LlamaGuardGate

    thresholds = config.get("thresholds", {})

    regex_gate = CustomRegexGate(config={
        "phrases": st.session_state.get("custom_block_phrases", ""),
    })

    token_limit_gate = TokenLimitGate(config={
        "limit":         st.session_state.get("token_limit", 512),
        "encoding_name": "cl100k_base",
    })

    invisible_text_gate = InvisibleTextGate(config={})

    fast_scan_gate = FastScanGate(config={
        "scan_pii":      True,
        "scan_secrets":  True,
        "pii_threshold": st.session_state.get("pii_threshold", 0.7),
    })

    classify_gate = PromptGuardGate(config={
        "threshold":  thresholds.get("prompt_guard_injection", 0.80),
        "model_name": "protectai/deberta-v3-base-prompt-injection-v2",
    })

    deanonymize_gate = DeanonymizeGate(config={})

    sensitive_gate = SensitiveGate(config={
        "pii_threshold": st.session_state.get("pii_threshold", 0.7),
    })

    malicious_urls_gate = MaliciousURLsGate(config={
        "threshold": thresholds.get("malicious_urls", 0.5),
    })

    no_refusal_gate = NoRefusalGate(config={
        "threshold": thresholds.get("no_refusal", 0.5),
    })

    toxicity_in_gate = ToxicityInputGate(config={
        "toxicity_threshold":  thresholds.get("toxicity_in", 0.5),
        "sentiment_threshold": thresholds.get("sentiment_in", -0.5),
    })

    _raw_topics = st.session_state.get("ban_topics_list", "")
    ban_topics_gate = BanTopicsGate(config={
        "topics":    [t.strip() for t in _raw_topics.split(",") if t.strip()],
        "threshold": thresholds.get("ban_topics", 0.5),
    })

    llama_guard_gate = LlamaGuardGate(config={
        "host":  ollama_host,
        "model": config.get("models", {}).get("safety", "llama-guard3"),
    })

    bias_out_gate = BiasOutputGate(config={
        "threshold": thresholds.get("bias_out", 0.5),
    })

    relevance_gate = RelevanceGate(config={
        "threshold": thresholds.get("relevance", 0.5),
    })

    pipeline = PipelineManager(
        client=client,
        input_gates=[
            ("custom_regex",   regex_gate),
            ("token_limit",    token_limit_gate),
            ("invisible_text", invisible_text_gate),
            ("fast_scan",      fast_scan_gate),
            ("classify",       classify_gate),
            ("toxicity_in",    toxicity_in_gate),    # quality: hostile input tone
            ("ban_topics",     ban_topics_gate),     # operator topic restrictions
            ("mod_llm",        llama_guard_gate),    # LLM safety judge (Llama Guard 3)
        ],
        output_gates=[
            ("sensitive_out",  sensitive_gate),      # redact LLM-generated PII
            ("malicious_urls", malicious_urls_gate), # block malicious URLs
            ("no_refusal",     no_refusal_gate),     # detect model refusals
            ("bias_out",       bias_out_gate),       # quality: biased/toxic output
            ("relevance",      relevance_gate),      # quality: off-topic / hallucination
            ("deanonymize",    deanonymize_gate),    # restore user-provided PII last
            # Phase 4: ("airs_dual", AIRSDualGate(...))
        ],
    )

    # ── Route: Main chat view ─────────────────────────────────────────────────
    render(pipeline, config)


main()
