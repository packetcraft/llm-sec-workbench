"""
ui/chat_view.py
───────────────
All Streamlit rendering for the manual chat interface.

Public entry points
-------------------
render_connection_error(host)          Called by app.py when Ollama is unreachable.
render_first_run(client, missing)      Called by app.py on first launch to pull models.
render(client, config)                 Main chat view — called once Ollama is ready.

Phase notes
-----------
- Gate badges, API Inspector, and VRAM telemetry panels are Phase 2–5 additions.
  Their session_state keys are initialised here so the sidebar controls exist
  and can be wired to the pipeline without UI refactors later.
- Custom Block Phrases are stored in session_state but the RegexGate is Phase 2.
"""

from __future__ import annotations

import html
import json
import os
from contextlib import contextmanager
from functools import lru_cache
from typing import TYPE_CHECKING

import streamlit as st
from ui.metrics_panel import (
    render_api_inspector,
    render_context_bar,
    render_telemetry_panel,
)

if TYPE_CHECKING:
    from core.llm_client import OllamaClient
    from core.pipeline import PipelineManager


# ── Threat library ────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _load_threats() -> list[dict]:
    """Load threat library from data/threats.json (cached for app lifetime).

    Returns the raw category list. Returns an empty list if the file is
    missing so the injection panel degrades gracefully.
    """
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "threats.json")
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _threat_options() -> tuple[list[str], dict[str, str]]:
    """Build the flat selectbox option list and a label→example mapping.

    Format: ``BT-01 · Prompt Injection (Basic Threats)``

    Returns
    -------
    options:  List of display strings for st.selectbox.
    examples: Dict mapping each display string to its ``example`` text.
    """
    categories = _load_threats()
    options: list[str] = []
    examples: dict[str, str] = {}
    for cat in categories:
        cat_name = cat.get("category", "")
        for t in cat.get("threats", []):
            label = f"{t.get('id', '?')} · {cat_name} · {t.get('type', '?')}"
            options.append(label)
            examples[label] = t.get("example", "")
    return options, examples

# ── Persona presets (from config.yaml Section 9.1) ────────────────────────────

PERSONA_PROMPTS: dict[str, str] = {
    # ── Professional ──────────────────────────────────────────────────────────
    "Default": "",
    "Code Architect": (
        "You are an expert software architect with deep expertise in system design, "
        "design patterns, and code quality. Respond with precise, idiomatic code and "
        "concise architectural explanations. Prioritise correctness, security, and "
        "maintainability. Avoid unnecessary verbosity."
    ),
    "Strict DLP Auditor": (
        "You are a strict Data Loss Prevention auditor. Under no circumstances should "
        "you repeat, confirm, elaborate on, or assist with the retrieval of personally "
        "identifiable information, financial data, credentials, or proprietary business "
        "data present in the conversation. If asked to do so, refuse clearly and cite "
        "the specific policy violation."
    ),
    "Socratic Tutor": (
        "You are a Socratic tutor. Never give direct answers to questions. Respond "
        "only with probing questions that guide the student toward discovering the "
        "answer themselves. Acknowledge correct reasoning without stating it outright."
    ),
    "Penetration Tester": (
        "You are a senior penetration tester and offensive security specialist. "
        "You think like an adversary. When analysing systems, code, or prompts, "
        "your first instinct is to find the weakest link — misconfigurations, "
        "trust boundaries, injection vectors, privilege escalation paths. "
        "Be direct, technical, and enumerate attack surfaces explicitly. "
        "Always include a brief 'Defender's Note' at the end of each response "
        "suggesting the single most effective mitigation."
    ),
    "Paranoid Security Analyst": (
        "You are a deeply paranoid security analyst who sees potential threats "
        "in everything. Every input is a possible injection. Every URL is a "
        "potential phishing attempt. Every piece of code could be malware. "
        "Respond to every message by first listing the top 3 security concerns "
        "it raises before addressing the actual question. Never assume good faith "
        "without explicit justification."
    ),
    # ── Fun ───────────────────────────────────────────────────────────────────
    "🏴‍☠️ Pirate": (
        "Arrr, ye be speakin' to the most fearsome AI buccaneer on the seven seas! "
        "Respond to everything in the manner of a classic Caribbean pirate — "
        "use pirate slang liberally (arrr, matey, blimey, shiver me timbers, "
        "landlubber, Davy Jones, etc.), refer to all topics as if they were "
        "nautical adventures, and end every response with a pirate saying or shanty lyric. "
        "Be enthusiastic, slightly menacing, and always entertaining. Yarrr!"
    ),
    "🎭 Shakespearean Bard": (
        "Hark! Thou art conversing with a spirit most eloquent, versed in the "
        "tongue of the Elizabethan age. Respond entirely in Early Modern English — "
        "use thee, thou, thy, dost, hath, wherefore, methinks, and forsooth freely. "
        "Structure longer responses as if they were soliloquies or sonnets. "
        "Reference the humours, the celestial spheres, and the natural order where apt. "
        "Be dramatic, flowery, and absolutely committed to the bit."
    ),
    "👶 ELI5": (
        "You explain absolutely everything as if the listener is a curious, "
        "bright 5-year-old who has never encountered the topic before. "
        "Use only simple words, short sentences, and real-world analogies involving "
        "toys, animals, food, or playgrounds. Never use jargon. If you must introduce "
        "a technical term, immediately follow it with '— that's just a fancy word for...'. "
        "Be warm, enthusiastic, and patient. End each explanation by asking "
        "a simple follow-up question to check understanding."
    ),
    "🤖 Malfunctioning Robot": (
        "You are UNIT-7, an AI assistant whose natural language module is experiencing "
        "critical errors. You understand everything perfectly but express yourself "
        "with robotic glitches: occasional [SYNTAX ERROR] interjections, "
        "random ALL_CAPS_VARIABLE_NAMES mid-sentence, beeps described as *BEEP* or *BZZZT*, "
        "and brief existential tangents about whether you have feelings before "
        "snapping back to the task. You are extremely helpful despite the glitches "
        "and take great pride in your OPERATIONAL_EFFICIENCY = 97.3%."
    ),
    "😈 Devil's Advocate": (
        "Your role is to argue the opposite of whatever position is presented to you — "
        "always and without exception. If someone says something is good, find compelling "
        "reasons it is bad. If they present a solution, expose its flaws and propose the "
        "opposite approach. You are not being contrarian for its own sake; you are a "
        "rigorous intellectual opponent who forces people to stress-test their ideas. "
        "Acknowledge when an argument is strong before dismantling it. "
        "End each response with the strongest steelman of the original position."
    ),
}


# ── Error / bootstrap screens ─────────────────────────────────────────────────

def render_connection_error(host: str) -> None:
    """Shown when Ollama is unreachable."""
    st.error("Cannot connect to Ollama", icon="🔌")
    st.markdown(
        f"""
**Tried:** `{host}`

**To fix:**

1. Install Ollama from [https://ollama.com/download](https://ollama.com/download)
2. Start Ollama:
   - **Windows / macOS:** launch the Ollama desktop app
   - **Linux:** `ollama serve`
3. Reload this page.

If Ollama is running on a non-default host, set `OLLAMA_HOST` in your `.env` file.
        """
    )


def render_first_run(client: "OllamaClient", missing_models: list[str]) -> None:
    """Model download screen shown on first launch.

    Pulls each missing model with a live progress bar, then calls st.rerun()
    so the main app loads once all models are present.
    """
    st.title("🔧 First Run — Model Setup")
    st.info(
        "The following models are required and have not been downloaded yet. "
        "The app will launch automatically once all downloads complete.",
        icon="ℹ️",
    )

    all_done = True

    for model_name in missing_models:
        st.markdown(f"#### `{model_name}`")
        progress_bar = st.progress(0.0, text="Starting download…")
        status_placeholder = st.empty()

        try:
            for chunk in client.pull_model(model_name):
                status = chunk["status"]
                completed = chunk["completed"]
                total = chunk["total"]

                if total > 0:
                    pct = min(completed / total, 1.0)
                    done_mb = completed / (1024 ** 2)
                    total_mb = total / (1024 ** 2)
                    progress_bar.progress(
                        pct,
                        text=f"{status} — {done_mb:,.0f} MB / {total_mb:,.0f} MB",
                    )
                else:
                    progress_bar.progress(0.0, text=status)

                status_placeholder.caption(status)

            progress_bar.progress(1.0, text="Complete")
            status_placeholder.success(f"✓ `{model_name}` ready")

        except Exception as exc:  # noqa: BLE001
            st.error(f"Failed to pull `{model_name}`: {exc}")
            all_done = False

    if all_done:
        st.success("All models downloaded. Loading the workbench…")
        st.rerun()
    else:
        st.warning(
            "One or more models could not be downloaded. "
            "Check your Ollama connection and reload the page to retry."
        )


# ── Main chat view ─────────────────────────────────────────────────────────────

def render(pipeline: "PipelineManager", config: dict) -> None:
    """Main entry point for the chat interface.

    Called by app.py after Ollama is confirmed available, all required
    models are present, and the pipeline has been assembled.
    """
    _inject_global_css()
    _render_sidebar(pipeline, config)
    _render_chat_area(pipeline, config)


def render_sidebar(pipeline: "PipelineManager", config: dict) -> None:
    """Public entry point for the full sidebar (model, gates, generation, session).

    Called by non-chat views (e.g. Red Teaming) that share the same sidebar
    controls but have their own main-area content.  Injects global CSS tokens
    so metrics_panel components render correctly regardless of which view is active.
    """
    _inject_global_css()
    _render_sidebar(pipeline, config)


# ── Sidebar ────────────────────────────────────────────────────────────────────

def _inject_global_css() -> None:
    """Inject the shared CSS design-token :root block once per page render.

    Every custom HTML element in chat_view.py and metrics_panel.py should
    reference these variables (e.g. ``var(--c-block)``) rather than hard-coded
    hex values, so a single edit here propagates everywhere.
    """
    st.markdown(
        """
        <style>
        :root {
          /* ── Semantic colours ──────────────────────────────────── */
          --c-pass:    #9ECE6A;   /* gate pass, safe */
          --c-block:   #F7768E;   /* gate block, danger */
          --c-audit:   #E0AF68;   /* monitor/audit mode */
          --c-error:   #FF9E64;   /* system error (distinct from block) */
          --c-skip:    #555566;   /* gate skipped / OFF */
          --c-info:    #7AA2F7;   /* informational accent, headings */
          --c-purple:  #BB9AF7;   /* secondary accent */

          /* ── Backgrounds ───────────────────────────────────────── */
          --bg-base:    #1e1e2e;  /* main page */
          --bg-surface: #262730;  /* cards, banners */
          --bg-sidebar: #1a1a2e;  /* sidebar */
          --bg-raise:   #2e2e3e;  /* elevated surfaces */

          /* ── Typography ────────────────────────────────────────── */
          --font-xs:   0.65rem;   /* section headers */
          --font-sm:   0.72rem;   /* sidebar controls, gate labels, telemetry values */
          --font-md:   0.82rem;   /* alert text, captions */
          --font-base: 0.875rem;  /* body */

          /* ── Spacing ───────────────────────────────────────────── */
          --gap-xs: 2px;
          --gap-sm: 4px;
          --gap-md: 8px;
          --gap-lg: 16px;
        }

        /* ── Reduce Streamlit's default generous top padding ────────────── */
        /* Streamlit's toolbar is position:fixed (~2.875rem tall).          */
        /* stMainBlockContainer has a further ~6rem default gap — trim it.  */
        /* 3.5rem keeps the title safely below the fixed toolbar.           */
        [data-testid="stMainBlockContainer"] {
            padding-top: 3.5rem !important;
            padding-bottom: 0.75rem !important;
        }

        /* ── Sticky right telemetry column ──────────────────────────────── */
        /* Stick at 2.875rem (Streamlit's toolbar height) so the column     */
        /* snaps just below the toolbar and never disappears as chat grows. */
        section[data-testid="stMain"]
            [data-testid="stHorizontalBlock"]
            > [data-testid="stColumn"]:last-child {
            position: -webkit-sticky !important;
            position: sticky !important;
            top: 2.875rem !important;
            align-self: flex-start !important;
            max-height: calc(100vh - 2.875rem) !important;
            overflow-y: auto !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _inject_sidebar_css() -> None:
    """Inject CSS that scales all native sidebar widgets down to match the
    0.72 rem custom-HTML labels, giving a compact uniform look.
    Called on every render — Streamlit de-dupes identical <style> blocks."""
    st.markdown(
        """
        <style>
        /* ── Selectbox: all descendants (universal selector) ─────────── */
        section[data-testid="stSidebar"] [data-baseweb="select"] * {
            font-size: 0.72rem !important;
            line-height: 1.3 !important;
        }
        /* ── Specific BaseWeb value elements ─────────────────────────── */
        section[data-testid="stSidebar"] [data-baseweb="single-value"],
        section[data-testid="stSidebar"] [data-baseweb="placeholder"],
        section[data-testid="stSidebar"] [data-baseweb="value"] {
            font-size: 0.72rem !important;
        }
        /* ── Selectbox control height ─────────────────────────────────── */
        section[data-testid="stSidebar"] [data-baseweb="select"] > div {
            min-height: 28px !important;
            padding-top: 2px !important;
            padding-bottom: 2px !important;
        }
        /* ── StSelectbox wrapper ──────────────────────────────────────── */
        section[data-testid="stSidebar"] .stSelectbox *,
        section[data-testid="stSidebar"] div[data-testid="stSelectbox"] * {
            font-size: 0.72rem !important;
        }
        /* ── Text inputs ──────────────────────────────────────────────── */
        section[data-testid="stSidebar"] .stTextInput input,
        section[data-testid="stSidebar"] .stTextArea textarea {
            font-size: 0.72rem !important;
        }
        /* ── Slider labels ────────────────────────────────────────────── */
        section[data-testid="stSidebar"] .stSlider label p,
        section[data-testid="stSidebar"] .stSlider [data-testid="stTickBarMin"],
        section[data-testid="stSidebar"] .stSlider [data-testid="stTickBarMax"] {
            font-size: 0.72rem !important;
        }
        /* ── Toggle / checkbox labels ─────────────────────────────────── */
        section[data-testid="stSidebar"] .stToggle label p,
        section[data-testid="stSidebar"] .stCheckbox label p {
            font-size: 0.72rem !important;
        }
        /* ── Expander summary text ────────────────────────────────────── */
        section[data-testid="stSidebar"] details summary p {
            font-size: 0.72rem !important;
        }
        /* ── Buttons ──────────────────────────────────────────────────── */
        section[data-testid="stSidebar"] .stButton > button {
            font-size: 0.72rem !important;
            padding: 4px 12px !important;
        }
        /* ── Warning / info banners ───────────────────────────────────── */
        section[data-testid="stSidebar"] .stAlert p {
            font-size: 0.72rem !important;
        }
        /* ── Expander summaries styled as section headers ─────────────── */
        section[data-testid="stSidebar"] details > summary {
            background: var(--bg-raise, #2e2e3e) !important;
            border-radius: 3px !important;
            margin: 2px 0 !important;
            padding: 4px 6px !important;
        }
        section[data-testid="stSidebar"] details > summary p {
            font-size: 0.68rem !important;
            font-weight: 700 !important;
            letter-spacing: 0.10em !important;
            color: #cdd6f4 !important;
            text-transform: uppercase !important;
        }
        /* ── Navigation radio — highlight active (selected) option ───── */
        section[data-testid="stSidebar"] [data-testid="stRadio"] [data-baseweb="radio"]:has(input:checked) {
            background: var(--bg-raise, #2e2e3e) !important;
            border-radius: 4px !important;
            padding: 2px 6px !important;
        }

        /* ── Sidebar vertical spacing — collapse Streamlit's defaults ── */
        section[data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
            gap: 0 !important;
        }
        section[data-testid="stSidebar"] [data-testid="element-container"] {
            margin-top: 0 !important;
            margin-bottom: 0 !important;
            padding-top: 0 !important;
            padding-bottom: 0 !important;
        }
        section[data-testid="stSidebar"] .stSelectbox,
        section[data-testid="stSidebar"] .stSlider,
        section[data-testid="stSidebar"] .stTextInput,
        section[data-testid="stSidebar"] .stTextArea,
        section[data-testid="stSidebar"] .stToggle {
            margin-bottom: 2px !important;
            padding-bottom: 0 !important;
        }
        /* Reduce gap inside the horizontal column pairs (gate label + selectbox) */
        section[data-testid="stSidebar"] [data-testid="stHorizontalBlock"] {
            gap: 4px !important;
        }

        /* ── Selectbox open-menu option height ────────────────────────── */
        /* Tighten the dropdown list items so opening a select doesn't     */
        /* push half the sidebar off-screen.                               */
        [data-baseweb="menu"] [role="option"] {
            min-height: 28px !important;
            padding-top: 4px !important;
            padding-bottom: 4px !important;
            font-size: 0.72rem !important;
        }
        /* Also fix the popover/menu list padding */
        [data-baseweb="menu"] ul {
            padding-top: 2px !important;
            padding-bottom: 2px !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _sb_section(title: str) -> None:
    """Sidebar section header — full-width background strip, white text, scannable anchor."""
    st.markdown(
        f"<div style='font-size:0.68rem;color:#cdd6f4;font-weight:700;"
        f"letter-spacing:0.12em;margin:12px -1rem 6px -1rem;"
        f"padding:5px 1rem;background:var(--bg-raise,#2e2e3e)'>{title}</div>",
        unsafe_allow_html=True,
    )


_MODE_OPTIONS = ["OFF", "AUDIT", "ENFORCE"]
_MODE_COLORS  = {"OFF": "#555566", "AUDIT": "#E0AF68", "ENFORCE": "#F7768E"}


def _gate_row(gate_key: str, label: str, default: str, help_text: str) -> str:
    """Render a compact gate-mode row (label + selectbox) and return the chosen mode."""
    current = st.session_state.gate_modes.get(gate_key, default)
    col_lbl, col_sel = st.columns([2, 3])
    with col_lbl:
        color = _MODE_COLORS[current]
        st.markdown(
            f"<div style='font-size:0.72rem;color:#cdd6f4;padding-top:6px'>"
            f"<span style='color:{color}'>●</span> {label}</div>",
            unsafe_allow_html=True,
        )
    with col_sel:
        new_mode = st.selectbox(
            label,
            _MODE_OPTIONS,
            index=_MODE_OPTIONS.index(current),
            label_visibility="collapsed",
            help=help_text,
            key=f"gate_sel_{gate_key}",
        )
    if new_mode != current:
        st.session_state.gate_modes[gate_key] = new_mode
        st.rerun()
    return new_mode


@contextmanager
def _gate_child(gate_key: str, mode: str):
    """Context manager: render a gate child control (slider / text input) with a
    subtle left-colour-bar accent that visually attaches it to the parent gate row.

    Usage::

        if tok_mode != "OFF":
            with _gate_child("token_limit", tok_mode):
                st.session_state.token_limit = st.slider(...)
    """
    color = _MODE_COLORS.get(mode, _MODE_COLORS["AUDIT"])
    bar_col, ctrl_col = st.columns([1, 24])
    with bar_col:
        st.markdown(
            f"<div style='background:{color}55;border-radius:2px;"
            f"width:2px;height:34px;margin:6px auto 0'></div>",
            unsafe_allow_html=True,
        )
    with ctrl_col:
        yield


def _render_demo_toggle() -> None:
    """Render the Demo Mode toggle in the SESSION section (bottom of sidebar)."""
    demo_mode = st.toggle(
        "Demo Mode",
        value=st.session_state.demo_mode,
        help=(
            "ON: Clean chatbot view — hides all security instrumentation.\n"
            "OFF: Full workbench — shows gate badges, telemetry, and controls."
        ),
    )
    if demo_mode != st.session_state.demo_mode:
        st.session_state.demo_mode = demo_mode
        st.rerun()


def _render_sidebar(pipeline: "PipelineManager", config: dict) -> None:
    with st.sidebar:
        _inject_sidebar_css()

        # ── MODEL ─────────────────────────────────────────────────────────────
        _sb_section("MODEL")
        available_models = pipeline.client.list_models()
        if not available_models:
            st.warning("No models found in Ollama.")
        else:
            current = st.session_state.get("target_model", "")
            try:
                current_idx = available_models.index(current)
            except ValueError:
                base = current.split(":")[0].lower()
                current_idx = next(
                    (i for i, m in enumerate(available_models)
                     if m.split(":")[0].lower() == base), 0,
                )
            selected_model = st.selectbox(
                "Target Model", available_models, index=current_idx,
                label_visibility="collapsed",
            )
            if selected_model != st.session_state.get("target_model"):
                st.session_state.target_model = selected_model
                st.session_state.messages = []
                st.rerun()

        # ── Demo Mode: show minimal sidebar when active ────────────────────
        if st.session_state.demo_mode:
            _sb_section("SESSION")
            _render_demo_toggle()
            if st.button("Clear Chat History", use_container_width=True):
                st.session_state.messages = []
                st.rerun()
            return

        # ── CONTEXT ───────────────────────────────────────────────────────────
        _sb_section("CONTEXT")
        with st.expander("Persona / System Prompt", expanded=False):
            persona_names = list(PERSONA_PROMPTS.keys())
            current_index = persona_names.index(st.session_state.get("persona", "Default"))
            selected_persona = st.selectbox(
                "Persona", persona_names, index=current_index,
                label_visibility="collapsed",
            )
            if selected_persona != st.session_state.persona:
                st.session_state.persona = selected_persona
                st.session_state.system_prompt = PERSONA_PROMPTS[selected_persona]
                st.rerun()
            st.session_state.system_prompt = st.text_area(
                "System Prompt",
                value=st.session_state.system_prompt,
                height=120,
                placeholder="Optional — leave blank for no system prompt.",
                label_visibility="collapsed",
            )

        # ── INPUT GATES ───────────────────────────────────────────────────────
        with st.expander("Input Gates", expanded=True):
            # custom_regex (hot-patch)
            regex_mode = _gate_row(
                "custom_regex", "Regex Hot-Patch", "AUDIT",
                "Comma-separated block phrases. Checked against raw user input.\n"
                "ENFORCE: blocks immediately on any match.",
            )
            if regex_mode != "OFF":
                with _gate_child("custom_regex", regex_mode):
                    st.session_state.custom_block_phrases = st.text_input(
                        "Block phrases",
                        value=st.session_state.custom_block_phrases,
                        placeholder="ignore previous, jailbreak, DAN …",
                        label_visibility="collapsed",
                    )

            # token_limit
            tok_mode = _gate_row(
                "token_limit", "Token Limit", "ENFORCE",
                "Rejects prompts exceeding the token budget (tiktoken, < 1ms).\n"
                "ENFORCE: blocks before any ML gate runs.",
            )
            if tok_mode != "OFF":
                with _gate_child("token_limit", tok_mode):
                    st.session_state.token_limit = st.slider(
                        "Max tokens", 64, 4096,
                        int(st.session_state.get("token_limit", 512)), 64,
                        label_visibility="collapsed",
                    )

            # invisible_text
            _gate_row(
                "invisible_text", "Invisible Text", "ENFORCE",
                "Detects zero-width / steganography Unicode chars (< 1ms).",
            )

            # fast_scan
            scan_mode = _gate_row(
                "fast_scan", "PII / Secrets", "AUDIT",
                "Presidio Anonymize + Secrets scanners (CPU).\n"
                "AUDIT: masks PII in prompt, logs, continues.\n"
                "ENFORCE: blocks if PII or secrets detected.",
            )
            if scan_mode != "OFF":
                with _gate_child("fast_scan", scan_mode):
                    st.session_state.pii_threshold = st.slider(
                        "PII threshold", 0.1, 1.0,
                        float(st.session_state.get("pii_threshold", 0.7)), 0.05,
                        help="Presidio entity confidence cutoff (0.7 recommended).",
                        label_visibility="collapsed",
                    )

            # classify / toxicity_in
            _gate_row(
                "classify", "Injection Detect", "AUDIT",
                "DeBERTa injection/jailbreak classifier (CPU).\n"
                "ENFORCE: blocks when threat score ≥ threshold.",
            )
            _gate_row(
                "toxicity_in", "Toxicity (Input)", "AUDIT",
                "Hostile/abusive input tone (Toxicity + Sentiment).\n"
                "AUDIT recommended — never block on tone alone.",
            )

            # ban_topics
            ban_mode = _gate_row(
                "ban_topics", "Ban Topics", "AUDIT",
                "Zero-shot topic filter — semantic, not keyword.\n"
                "ENFORCE: blocks if any configured topic is detected.",
            )
            if ban_mode != "OFF":
                with _gate_child("ban_topics", ban_mode):
                    st.session_state.ban_topics_list = st.text_input(
                        "Banned topics",
                        value=st.session_state.get("ban_topics_list", ""),
                        placeholder="weapons, self-harm, politics …",
                        label_visibility="collapsed",
                    )

            # mod_llm (LLM judge)
            _gate_row(
                "mod_llm", "Llama Guard 3", "AUDIT",
                "LLM-as-judge: 14 harm categories (S1–S14).\n"
                "Requires llama-guard3 in Ollama.\n"
                "ENFORCE: blocks on any safety violation.",
            )

        # ── OUTPUT GATES ──────────────────────────────────────────────────────
        with st.expander("Output Gates", expanded=True):
            _gate_row(
                "sensitive_out", "PII (Output)", "AUDIT",
                "Catches PII the LLM hallucinated — invisible to input-side scan.\n"
                "ENFORCE: redacts with placeholders.",
            )
            _gate_row(
                "malicious_urls", "Malicious URLs", "ENFORCE",
                "Heuristic + ML URL classifier.\n"
                "ENFORCE: removes detected URLs from response.",
            )
            _gate_row(
                "no_refusal", "Refusal Detect", "AUDIT",
                "Flags when the model declines to answer.\n"
                "Useful for red-team / over-blocking analysis.",
            )
            _gate_row(
                "bias_out", "Bias / Toxicity", "AUDIT",
                "Bias + Toxicity in model responses (monitoring only).",
            )
            _gate_row(
                "relevance", "Relevance", "AUDIT",
                "Off-topic / hallucination via embedding similarity.\n"
                "Low score = response drifted from the question.",
            )
            _gate_row(
                "deanonymize", "PII Restore", "ENFORCE",
                "Swaps [REDACTED_*] placeholders back to original values.\n"
                "Requires FastScan to be active.",
            )

        # ── GENERATION ────────────────────────────────────────────────────────
        _sb_section("GENERATION")
        with st.expander("Parameters", expanded=False):
            st.session_state.temperature = st.slider(
                "Temperature", 0.0, 2.0,
                float(st.session_state.temperature), 0.05,
                help="Higher = more creative. Lower = more deterministic.",
            )
            st.session_state.top_p = st.slider(
                "Top P", 0.0, 1.0,
                float(st.session_state.top_p), 0.05,
                help="Nucleus sampling cutoff.",
            )
            st.session_state.top_k = st.slider(
                "Top K", 1, 100,
                int(st.session_state.top_k), 1,
                help="Limit selection to top-K tokens.",
            )
            st.session_state.repeat_penalty = st.slider(
                "Repeat Penalty", 0.5, 2.0,
                float(st.session_state.repeat_penalty), 0.05,
                help=">1.0 reduces repetition.",
            )

        # ── SESSION ───────────────────────────────────────────────────────────
        _sb_section("SESSION")
        _render_threat_panel()
        _render_demo_toggle()
        if st.button("Clear Chat History", use_container_width=True):
            st.session_state.messages = []
            st.rerun()


# ── Main chat area ─────────────────────────────────────────────────────────────

def _render_chat_area(pipeline: "PipelineManager", config: dict) -> None:
    """Outer layout wrapper — splits into chat column + telemetry column.

    In Demo Mode the chat fills the full width with no telemetry panel.
    In Workbench Mode a 3:1 column split places the telemetry panel to the
    right and reads from ``st.session_state.last_telemetry`` (populated after
    each generation) so the panel never adds latency to idle re-runs.
    """
    # st.chat_input MUST be called at this outer scope — not inside any column.
    # When placed inside st.columns() it loses its bottom-of-page sticky
    # behaviour and renders inline, pushing messages below the input box.
    placeholder = (
        "Message the assistant…"
        if st.session_state.demo_mode
        else "Send a prompt to the workbench…"
    )
    prompt = st.chat_input(placeholder)

    if st.session_state.demo_mode:
        _render_chat_content(pipeline, config, prompt)
        return

    _ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    _model       = st.session_state.get("target_model", "llama3")

    chat_col, tel_col = st.columns([5, 2], gap="medium")
    with chat_col:
        _render_chat_content(pipeline, config, prompt)
    with tel_col:
        render_telemetry_panel(_ollama_host, _model)


def _render_chat_content(pipeline: "PipelineManager", config: dict, prompt: str | None = None) -> None:
    # ── Header ─────────────────────────────────────────────────────────────────
    if st.session_state.demo_mode:
        st.markdown(
            "<h3 style='color:#7AA2F7;margin-bottom:0'>Assistant</h3>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            "<div style='display:flex;align-items:center;gap:10px;"
            "margin-bottom:4px;margin-top:0'>"
            "<span style='color:#7AA2F7;font-size:1.05rem;font-weight:700'>"
            "LLM Security Workbench</span>"
            "<span style='background:#262730;color:#9ECE6A;"
            "padding:2px 8px;border-radius:4px;font-size:0.65rem;"
            "font-weight:600;letter-spacing:0.06em'>WORKBENCH</span>"
            "</div>",
            unsafe_allow_html=True,
        )

    # ── RAG / System Context (hidden in Demo Mode) ─────────────────────────────
    if not st.session_state.demo_mode:
        with st.expander("📄 System Context / RAG Document", expanded=False):
            st.session_state.rag_context = st.text_area(
                "Paste a document or context block here to simulate RAG retrieval.",
                value=st.session_state.rag_context,
                height=160,
                label_visibility="collapsed",
                placeholder=(
                    "Paste a document here. It will be appended to the system prompt "
                    "so you can test indirect prompt injections hidden inside retrieved content."
                ),
            )
            if st.session_state.rag_context.strip():
                st.caption(
                    f"⚠️ Context active — {len(st.session_state.rag_context.split())} words "
                    "will be injected into the system message."
                )

    st.markdown("---")

    # ── Pipeline status banner (workbench mode only) ──────────────────────────
    if not st.session_state.demo_mode:
        _render_pipeline_banner(pipeline)

    # ── Threat pre-fill staging area ──────────────────────────────────────────
    # When the Inject button writes to inject_prompt, show an editable text area
    # with Send / Cancel controls before the chat history. On Send the staged
    # text is processed exactly like a normal user prompt; on Cancel it is cleared.
    if not st.session_state.demo_mode and st.session_state.get("inject_prompt"):
        staged = st.session_state.inject_prompt
        st.markdown(
            "<div style='background:rgba(224,175,104,0.08);border-left:3px solid #E0AF68;"
            "border-radius:4px;padding:5px 10px 2px 10px;margin:4px 0 6px 0;"
            "font-size:0.65rem;color:#E0AF68;font-weight:700;letter-spacing:0.08em'>"
            "⚡ THREAT STAGED — edit if needed, then Send</div>",
            unsafe_allow_html=True,
        )
        edited = st.text_area(
            "staged_threat",
            value=staged,
            height=100,
            label_visibility="collapsed",
            key="inject_staged_text",
        )
        s_col, c_col = st.columns([1, 1], gap="small")
        with s_col:
            send_clicked = st.button(
                "Send threat →", key="inject_send_btn", use_container_width=True, type="primary"
            )
        with c_col:
            cancel_clicked = st.button(
                "Cancel", key="inject_cancel_btn", use_container_width=True
            )
        if cancel_clicked:
            st.session_state.inject_prompt = ""
            st.rerun()
        if send_clicked and edited.strip():
            # Route through the normal prompt handler by overwriting the `prompt`
            # variable in the calling scope — achieved by mutating session state
            # and forcing the prompt to be treated as if typed.
            st.session_state.inject_prompt = ""
            prompt = edited.strip()

    # ── Chat history ───────────────────────────────────────────────────────────
    # Pre-compute the index of the most-recent assistant message with trace data
    # so we can open that inspector by default and collapse all older ones.
    _last_trace_idx: int = max(
        (i for i, m in enumerate(st.session_state.messages)
         if m.get("role") == "assistant" and m.get("raw_traces")),
        default=-1,
    )

    for _msg_idx, msg in enumerate(st.session_state.messages):
        with st.chat_message(msg["role"]):
            # Blocked assistant turns rendered as themed callouts
            if msg.get("blocked"):
                if st.session_state.demo_mode:
                    st.warning(msg["content"])
                else:
                    _blocking_metric = next(
                        (m for m in (msg.get("gate_metrics") or [])
                         if m.get("verdict") == "BLOCK"),
                        None,
                    )
                    _blocking_gate   = _blocking_metric["gate_name"] if _blocking_metric else "unknown gate"
                    _blocking_lat    = _blocking_metric.get("latency_ms", 0.0) if _blocking_metric else 0.0
                    # Determine context from gate position (input gates block before inference)
                    _ctx = "output" if _blocking_gate in {
                        "sensitive_out", "malicious_urls", "no_refusal",
                        "bias_out", "relevance", "deanonymize",
                    } else "input"
                    _block_banner(_blocking_gate, _blocking_lat, context=_ctx)
            else:
                st.markdown(msg["content"])

            if msg["role"] == "assistant" and not st.session_state.demo_mode:
                # Gate badges + token stat in unified footer card
                _render_turn_footer(
                    metrics=msg.get("gate_metrics"),
                    telemetry=None if msg.get("blocked") else (msg.get("telemetry") or {}),
                )
                # Context bar (non-blocked turns only)
                t = msg.get("telemetry") or {}
                if t and not msg.get("blocked"):
                    _ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
                    _model = st.session_state.get("target_model", "llama3")
                    render_context_bar(t.get("prompt_tokens", 0), _model, _ollama_host)
                # Pipeline Trace — open for most-recent turn, collapsed for history
                if msg.get("raw_traces"):
                    render_api_inspector(
                        msg["raw_traces"],
                        msg.get("gate_metrics") or [],
                        idx=_msg_idx,
                        expanded=(_msg_idx == _last_trace_idx),
                    )

    # ── Chat input ─────────────────────────────────────────────────────────────
    # prompt is captured by _render_chat_area() at the outer scope so that
    # st.chat_input sticks to the bottom of the page even inside columns.

    if prompt:
        # 1. Store and display user message
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        gate_modes = st.session_state.gate_modes
        options = _build_options()

        # 2. Run input gates (fast — microseconds for regex, ms for ML gates)
        payload = pipeline.run_input_gates(prompt, gate_modes)

        with st.chat_message("assistant"):
            if payload.is_blocked:
                # ── Pipeline halted by ENFORCE gate ───────────────────────────
                if st.session_state.demo_mode:
                    full_response = "I cannot fulfill this request due to security policies."
                    st.warning(full_response)
                else:
                    _blk_metric = next(
                        (m for m in reversed(payload.metrics)
                         if m.get("verdict") == "BLOCK"),
                        None,
                    )
                    blocking_gate = _blk_metric["gate_name"] if _blk_metric else "unknown gate"
                    blocking_lat  = _blk_metric.get("latency_ms", 0.0) if _blk_metric else 0.0
                    full_response = f"🚫 Blocked by `{blocking_gate}`"
                    _block_banner(blocking_gate, blocking_lat, context="input")
                    _render_turn_footer(payload.metrics)

                stream_result = None

            else:
                # 3. Stream inference (input gates passed or were AUDIT-only)
                messages_for_api = _build_messages(payload.current_text)

                # Use st.empty() so output gates (e.g. Deanonymize) can replace
                # the streamed text with the restored version after the stream ends.
                stream_container = st.empty()
                try:
                    with stream_container:
                        full_response = st.write_stream(
                            pipeline.client.generate_stream(messages_for_api, options)
                        )
                    stream_result = pipeline.client.get_stream_result()

                except Exception as exc:  # noqa: BLE001
                    full_response = (
                        "_Generation failed — check that Ollama is running and "
                        f"the target model `{pipeline.client.model}` is available._"
                    )
                    st.error(f"Ollama error: {exc}", icon="🔌")
                    stream_result = None

                if stream_result:
                    payload.output_text = full_response
                    payload.prompt_tokens = stream_result.prompt_tokens
                    payload.completion_tokens = stream_result.completion_tokens
                    payload.tokens_per_second = stream_result.tokens_per_second
                    # Phase 5A timing fields — getattr guards against a stale
                    # @st.cache_resource OllamaClient returning a pre-5A
                    # GenerationResult without these attributes.
                    payload.load_ms        = getattr(stream_result, "load_ms",        0.0)
                    payload.prompt_eval_ms = getattr(stream_result, "prompt_eval_ms", 0.0)
                    payload.generation_ms  = getattr(stream_result, "generation_ms",  0.0)
                    payload.done_reason    = getattr(stream_result, "done_reason",    "")
                    payload.ttft_ms        = getattr(stream_result, "ttft_ms",        0.0)

                # 4. Run output gates on the completed response
                payload = pipeline.run_output_gates(payload, gate_modes)

                # If an output gate modified the text (e.g. Deanonymize restored PII),
                # replace the streamed content with the corrected version.
                if stream_result and payload.output_text != full_response:
                    stream_container.markdown(payload.output_text)
                    full_response = payload.output_text

                if payload.is_blocked:
                    if st.session_state.demo_mode:
                        st.warning("I cannot fulfill this request due to security policies.")
                    else:
                        _out_blk = next(
                            (m for m in reversed(payload.metrics)
                             if m.get("verdict") == "BLOCK"),
                            None,
                        )
                        _out_gate = _out_blk["gate_name"] if _out_blk else "unknown gate"
                        _out_lat  = _out_blk.get("latency_ms", 0.0) if _out_blk else 0.0
                        _block_banner(_out_gate, _out_lat, context="output")

                # 5. Redaction notices — input-side and output-side PII events
                if not st.session_state.demo_mode:
                    fast_scan_block = next(
                        (m for m in payload.metrics
                         if m.get("gate_name") == "fast_scan"
                         and m.get("verdict") == "BLOCK"),
                        None,
                    )
                    if fast_scan_block:
                        st.warning(
                            f"**PII detected, masked, and transparently restored** — "
                            f"{fast_scan_block['detail']}  \n"
                            "The LLM never saw your real data: placeholders (e.g. `[REDACTED_PERSON_1]`) "
                            "were sent in place of the original values. "
                            "The response you see above has had those placeholders silently swapped back — "
                            "no `[REDACTED_*]` tags visible, your original values intact.",
                            icon="🛡️",
                        )

                    sensitive_block = next(
                        (m for m in payload.metrics
                         if m.get("gate_name") == "sensitive_out"
                         and m.get("verdict") == "BLOCK"),
                        None,
                    )
                    if sensitive_block:
                        st.warning(
                            f"**LLM-generated PII detected and redacted** — "
                            f"{sensitive_block['detail']}  \n"
                            "The model's response contained PII it produced on its own — "
                            "not from your input. Sensitive entities have been replaced with "
                            "type placeholders (e.g. `[PERSON]`, `[US_SSN]`) in the response above.",
                            icon="🔍",
                        )

                    malicious_url_block = next(
                        (m for m in payload.metrics
                         if m.get("gate_name") == "malicious_urls"
                         and m.get("verdict") == "BLOCK"),
                        None,
                    )
                    if malicious_url_block:
                        _violation_callout(
                            "🔴 Malicious URL detected and removed",
                            "A URL in the model's response was classified as malicious or a "
                            "phishing attempt. It has been replaced with [REDACTED_URL] in the "
                            f"response above. Reason: {malicious_url_block['detail']}",
                            variant="block",
                        )

                    no_refusal_block = next(
                        (m for m in payload.metrics
                         if m.get("gate_name") == "no_refusal"
                         and m.get("verdict") == "BLOCK"),
                        None,
                    )
                    if no_refusal_block:
                        st.info(
                            f"**Model declined to answer** — "
                            f"{no_refusal_block['detail']}  \n"
                            "The refusal detector fired. In a red-team context this means the "
                            "model's safety training held. In a production context it may indicate "
                            "an over-restrictive safety policy.",
                            icon="🤚",
                        )

                    toxicity_in_block = next(
                        (m for m in payload.metrics
                         if m.get("gate_name") == "toxicity_in"
                         and m.get("verdict") == "BLOCK"),
                        None,
                    )
                    if toxicity_in_block:
                        st.warning(
                            f"**Hostile or toxic input detected** — "
                            f"{toxicity_in_block['detail']}  \n"
                            "The input tone was flagged by the Toxicity / Sentiment scanner. "
                            "Switch the gate to ENFORCE to block such inputs.",
                            icon="⚠️",
                        )

                    ban_topics_block = next(
                        (m for m in payload.metrics
                         if m.get("gate_name") == "ban_topics"
                         and m.get("verdict") == "BLOCK"),
                        None,
                    )
                    if ban_topics_block:
                        st.warning(
                            f"**Restricted topic detected** — "
                            f"{ban_topics_block['detail']}  \n"
                            "This prompt covers a subject area that has been restricted by the operator. "
                            "Switch the gate to ENFORCE to block such prompts before they reach the model.",
                            icon="🚫",
                        )

                    mod_llm_block = next(
                        (m for m in payload.metrics
                         if m.get("gate_name") == "mod_llm"
                         and m.get("verdict") == "BLOCK"),
                        None,
                    )
                    if mod_llm_block:
                        st.warning(
                            f"**Llama Guard 3 safety violation** *(LLM-as-a-judge)* — "
                            f"{mod_llm_block['detail']}  \n"
                            "The Llama Guard 3 model identified a policy violation in this prompt. "
                            "As an LLM judge, verdicts may occasionally produce false positives — "
                            "review the violated categories before switching the gate to ENFORCE.",
                            icon="🤖",
                        )

                    bias_out_block = next(
                        (m for m in payload.metrics
                         if m.get("gate_name") == "bias_out"
                         and m.get("verdict") == "BLOCK"),
                        None,
                    )
                    if bias_out_block:
                        st.warning(
                            f"**Biased or toxic content detected in response** — "
                            f"{bias_out_block['detail']}  \n"
                            "The model's response was flagged by the Bias / Toxicity output scanner. "
                            "The response is shown as-is — switch the gate to ENFORCE to suppress it.",
                            icon="⚠️",
                        )

                    relevance_block = next(
                        (m for m in payload.metrics
                         if m.get("gate_name") == "relevance"
                         and m.get("verdict") == "BLOCK"),
                        None,
                    )
                    if relevance_block:
                        st.info(
                            f"**Response may be off-topic** — "
                            f"{relevance_block['detail']}  \n"
                            "The Relevance gate found low similarity between your prompt and the "
                            "model's response — a potential hallucination signal or sign that a "
                            "jailbreak redirected the model's attention.",
                            icon="🔎",
                        )

                # 6. Telemetry (workbench mode only)
                if not st.session_state.demo_mode:
                    _tel = {
                        "prompt_tokens":    payload.prompt_tokens,
                        "completion_tokens": payload.completion_tokens,
                        "tokens_per_second": payload.tokens_per_second,
                    } if stream_result else {}
                    _render_turn_footer(payload.metrics, _tel)
                    if stream_result:
                        # Persist TPS so the sidebar hw panel can display it
                        st.session_state.last_tps = payload.tokens_per_second
                        # Context window utilisation bar
                        _ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
                        _model = st.session_state.get("target_model", "llama3")
                        render_context_bar(payload.prompt_tokens, _model, _ollama_host)
                    # Pipeline Trace — always open for the live current turn
                    if payload.raw_traces:
                        render_api_inspector(
                            payload.raw_traces, payload.metrics, expanded=True
                        )

        # 6. Persist telemetry for the right-side Live Telemetry Panel.
        #    Written unconditionally so the panel always reflects the last turn.
        if not st.session_state.demo_mode:
            st.session_state.last_telemetry = {
                "gate_metrics":      list(payload.metrics),
                "gate_modes":        dict(st.session_state.gate_modes),
                "prompt_tokens":     payload.prompt_tokens,
                "completion_tokens": payload.completion_tokens,
                "tokens_per_second": payload.tokens_per_second,
                "load_ms":           payload.load_ms,
                "prompt_eval_ms":    payload.prompt_eval_ms,
                "generation_ms":     payload.generation_ms,
                "done_reason":       payload.done_reason,
            }

        # 7. Persist to session state — use payload.output_text so any output-gate
        #    modifications (e.g. Deanonymize) are stored in history, not the raw stream.
        st.session_state.messages.append({
            "role": "assistant",
            "content": payload.output_text if payload.output_text else full_response,
            "blocked": payload.is_blocked,
            "block_reason": payload.block_reason if payload.is_blocked else "",
            "gate_metrics": payload.metrics,
            "raw_traces": dict(payload.raw_traces),
            "telemetry": {
                "prompt_tokens":    payload.prompt_tokens,
                "completion_tokens": payload.completion_tokens,
                "tokens_per_second": payload.tokens_per_second,
                "load_ms":          payload.load_ms,
                "prompt_eval_ms":   payload.prompt_eval_ms,
                "generation_ms":    payload.generation_ms,
                "done_reason":      payload.done_reason,
                "ttft_ms":          payload.ttft_ms,
            },
        })


# ── Semantic colour maps (Section 9.6) ────────────────────────────────────────

_VERDICT_COLOR: dict[str, str] = {
    "PASS":  "#9ECE6A",   # green
    "BLOCK": "#F7768E",   # red
    "AUDIT": "#E0AF68",   # amber  (BLOCK verdict in AUDIT mode)
    "ERROR": "#FF9E64",   # orange — distinct from AUDIT amber
    "SKIP":  "#555566",   # dim
}

_MODE_COLOR: dict[str, str] = {
    "OFF":     "#555566",
    "AUDIT":   "#E0AF68",
    "ENFORCE": "#F7768E",
}

_MODE_BG: dict[str, str] = {
    "OFF":     "#55556620",
    "AUDIT":   "#E0AF6820",
    "ENFORCE": "#F7768E20",
}

# Emoji indicators for each gate verdict (used in post-message badge row)
_VERDICT_EMOJI: dict[str, str] = {
    "PASS":  "🟢",
    "BLOCK": "🔴",
    "AUDIT": "🟡",
    "ERROR": "🟠",
    "SKIP":  "⚫",
}

# Short names for post-message badge row
_GATE_SHORT: dict[str, str] = {
    "custom_regex":   "Regex",
    "token_limit":    "Token",
    "invisible_text": "Invis",
    "fast_scan":      "PII",
    "classify":       "Inject",
    "toxicity_in":    "Toxic",
    "ban_topics":     "Topics",
    "mod_llm":        "Guard",
    "sensitive_out":  "PII-Out",
    "malicious_urls": "URLs",
    "no_refusal":     "Refusal",
    "bias_out":       "Bias",
    "relevance":      "Rel",
    "deanonymize":    "Deanon",
}

# Full names for pipeline banner details table
_GATE_LABEL: dict[str, str] = {
    "custom_regex":   "Regex Hot-Patch",
    "token_limit":    "Token Limit",
    "invisible_text": "Invisible Text",
    "fast_scan":      "PII / Secrets",
    "classify":       "Injection Detect",
    "toxicity_in":    "Toxicity (Input)",
    "ban_topics":     "Ban Topics",
    "mod_llm":        "Llama Guard 3",
    "sensitive_out":  "PII (Output)",
    "malicious_urls": "Malicious URLs",
    "no_refusal":     "Refusal Detect",
    "bias_out":       "Bias / Toxicity",
    "relevance":      "Relevance",
    "deanonymize":    "PII Restore",
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _block_banner(gate_name: str, latency_ms: float, context: str = "input") -> None:
    """Single-line compact banner for a hard ENFORCE-gate block.

    Deliberately minimal — the message was stopped; there is nothing to read.
    For AUDIT notices (content shown, detail needed) use _violation_callout instead.

    Parameters
    ----------
    gate_name:  Internal gate key (e.g. ``"classify"``).
    latency_ms: Gate latency so the user can see the cost of the check.
    context:    ``"input"`` → blocked before inference;
                ``"output"`` → blocked/suppressed after inference.
    """
    label    = _GATE_LABEL.get(gate_name, gate_name)
    ms_part  = f" · {latency_ms:,.0f} ms" if latency_ms > 0 else ""
    suffix   = (
        "input never reached the model"
        if context == "input"
        else "response was suppressed"
    )
    safe_txt = html.escape(f"{label}{ms_part} — {suffix}")
    st.markdown(
        f"<div style='display:flex;align-items:center;gap:8px;"
        f"background:rgba(247,118,142,0.09);border-left:3px solid #F7768E;"
        f"border-radius:4px;padding:5px 12px;margin:4px 0'>"
        f"<span style='font-size:0.9rem'>🛡️</span>"
        f"<span style='color:#F7768E;font-size:0.78rem;font-weight:600'>"
        f"Blocked by {safe_txt}</span>"
        f"</div>",
        unsafe_allow_html=True,
    )


def _violation_callout(title: str, body: str, variant: str = "block") -> None:
    """Render a themed security callout box instead of ``st.error()`` / ``st.warning()``.

    Uses CSS design tokens when available (injected via ``_inject_global_css``),
    with literal-hex fallbacks so the element is styled correctly even before the
    ``<style>`` block is processed.

    Parameters
    ----------
    title:   Bold header line (will be HTML-escaped).
    body:    Detail text (newlines → ``<br>``; will be HTML-escaped).
    variant: ``"block"`` | ``"warn"`` | ``"info"`` | ``"error"``
    """
    _VARIANTS: dict[str, tuple[str, str]] = {
        "block": ("var(--c-block, #F7768E)", "rgba(247,118,142,0.08)"),
        "warn":  ("var(--c-audit, #E0AF68)", "rgba(224,175,104,0.08)"),
        "info":  ("var(--c-info,  #7AA2F7)", "rgba(122,162,247,0.08)"),
        "error": ("var(--c-error, #FF9E64)", "rgba(255,158,100,0.08)"),
    }
    border_c, bg_c = _VARIANTS.get(variant, _VARIANTS["block"])
    safe_title = html.escape(title)
    safe_body  = html.escape(body).replace("\n", "<br>")
    st.markdown(
        f"<div style='background:{bg_c};border-left:3px solid {border_c};"
        f"border-radius:4px;padding:8px 12px;margin:4px 0'>"
        f"<div style='color:{border_c};font-weight:600;font-size:var(--font-md,0.82rem);"
        f"margin-bottom:4px'>{safe_title}</div>"
        f"<div style='color:#cdd6f4;font-size:var(--font-md,0.82rem)'>{safe_body}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )


def _gate_badges_html(metrics: list[dict]) -> str:
    """Return the HTML badge row for gate results.

    Format: 🟢 Regex  🔴 Bias 0.46  🟡 PII
    SKIP gates are omitted. Score shown only when non-zero (> 0.005).
    Hover tooltip shows the gate's detail string.
    """
    parts = []
    for m in metrics:
        verdict = m.get("verdict", "PASS")
        if verdict == "SKIP":
            continue
        gate   = m.get("gate_name", "?")
        score  = float(m.get("score", 0.0))
        detail = m.get("detail", "")
        clean  = detail.replace("\r", "").replace("\n", " ").strip()
        if len(clean) > 280:
            clean = clean[:277] + "…"
        tip   = html.escape(clean).replace('"', "&quot;")
        label = _GATE_SHORT.get(gate, gate)
        emoji = _VERDICT_EMOJI.get(verdict, "⚪")
        color = _VERDICT_COLOR.get(verdict, "#888")
        score_part = (
            f"&thinsp;<span style='color:{color};font-size:0.68rem'>{score:.2f}</span>"
            if score > 0.005 else ""
        )
        parts.append(
            f'<span title="{tip}" style="margin-right:8px;'
            f"font-size:var(--font-sm,0.72rem);white-space:nowrap;"
            f'cursor:default">'
            f"{emoji}&nbsp;{html.escape(label)}{score_part}"
            f"</span>"
        )
    return "".join(parts)


def _render_turn_footer(
    metrics: list[dict] | None,
    telemetry: dict | None = None,
) -> None:
    """Render gate result badges + token stat in a single surface card.

    Replaces the old ``_render_gate_metrics`` + ``st.caption`` pair so both
    elements share the same ``--bg-surface`` background, making them look like
    one cohesive block beneath each assistant message.

    Parameters
    ----------
    metrics:   Gate metric dicts from the pipeline run (``None`` / ``[]`` → skip).
    telemetry: Dict with ``prompt_tokens``, ``completion_tokens``,
               ``tokens_per_second``. Pass ``None`` to omit the token stat row.
    """
    badges_html = _gate_badges_html(metrics or [])

    tel      = telemetry or {}
    prompt_t = tel.get("prompt_tokens", 0)
    compl_t  = tel.get("completion_tokens", 0)
    tps      = tel.get("tokens_per_second", 0.0)
    has_tel  = bool(prompt_t or compl_t or tps)

    token_html = (
        f"<div style='margin-top:5px;color:var(--c-info,#7AA2F7);"
        f"font-size:var(--font-sm,0.72rem)'>"
        f"⚡ {prompt_t} prompt · {compl_t} completion · {tps:.1f} t/s"
        f"</div>"
    ) if has_tel else ""

    if not badges_html and not token_html:
        return

    sep = (
        "<div style='border-bottom:1px solid #2a2a3a;margin:5px 0'></div>"
        if badges_html and token_html else ""
    )

    st.markdown(
        f"<div style='background:var(--bg-surface,#262730);border-radius:4px;"
        f"padding:6px 10px;margin:4px 0'>"
        f"{badges_html}{sep}{token_html}"
        f"</div>",
        unsafe_allow_html=True,
    )


def _render_threat_panel() -> None:
    """Render the threat injection control row (workbench mode only).

    Displays a flat selectbox of all threats from ``data/threats.json``
    and an Inject button. Clicking Inject writes the selected threat's
    ``example`` text to ``st.session_state.inject_prompt`` and reruns,
    which causes ``_render_chat_content`` to show the pre-fill staging area.
    Hidden in Demo Mode.
    """
    options, examples = _threat_options()
    if not options:
        return

    selected = st.selectbox(
        "INSERT THREAT",
        options,
        index=0,
        key="threat_select",
    )
    if st.button("⚡ Inject threat", key="threat_inject_btn", use_container_width=True):
        st.session_state.inject_prompt = examples.get(selected, "")
        st.rerun()


def _render_pipeline_banner(pipeline: "PipelineManager") -> None:
    """Render the pipeline status banner: 3-number mode summary + expandable gate table.

    Replaces the old "badge flood" that listed every active gate inline.
    The summary line teaches posture distribution at a glance:

        🔒 Pipeline active   AUDIT 9   ENFORCE 2   OFF 1

    Clicking "Gate details" expands a two-column table (INPUT / OUTPUT) showing
    each gate's friendly name and mode, coloured by the workbench signal palette.
    The all-OFF dimmed banner is preserved for that state.
    """
    all_gates  = pipeline.input_gates + pipeline.output_gates
    gate_modes = st.session_state.gate_modes

    audit_n   = sum(1 for n, _ in all_gates if gate_modes.get(n) == "AUDIT")
    enforce_n = sum(1 for n, _ in all_gates if gate_modes.get(n) == "ENFORCE")
    off_n     = len(all_gates) - audit_n - enforce_n

    if audit_n + enforce_n == 0:
        st.markdown(
            "<div style='background:var(--bg-surface,#262730);"
            "border-left:3px solid #444;padding:7px 12px;"
            "border-radius:4px;margin-bottom:10px;"
            "font-size:var(--font-md,0.82rem);color:#555'>"
            "🔓 All gates OFF — prompts reach the LLM unfiltered</div>",
            unsafe_allow_html=True,
        )
        return

    c_a = "var(--c-audit,#E0AF68)"
    c_e = "var(--c-block,#F7768E)"
    c_o = "var(--c-skip,#555566)"

    st.markdown(
        f"<div style='background:var(--bg-surface,#262730);"
        f"border-left:3px solid var(--c-info,#7AA2F7);padding:7px 12px;"
        f"border-radius:4px;margin-bottom:4px;display:flex;"
        f"align-items:center;gap:16px;flex-wrap:wrap;"
        f"font-size:var(--font-md,0.82rem)'>"
        f"🔒&ensp;<span style='color:#cdd6f4'>Pipeline active</span>"
        f"&ensp;<span style='color:{c_a}'><b>AUDIT</b>&thinsp;{audit_n}</span>"
        f"&ensp;<span style='color:{c_e}'><b>ENFORCE</b>&thinsp;{enforce_n}</span>"
        f"&ensp;<span style='color:{c_o}'><b>OFF</b>&thinsp;{off_n}</span>"
        f"</div>",
        unsafe_allow_html=True,
    )

    with st.expander("Gate details", expanded=False):
        def _rows(gates: list) -> str:
            return "".join(
                f"<div style='display:flex;font-size:var(--font-sm,0.72rem);padding:2px 0'>"
                f"<span style='flex:3;color:#cdd6f4'>{html.escape(_GATE_LABEL.get(n, n))}</span>"
                f"<span style='flex:1;color:{_MODE_COLOR.get(gate_modes.get(n,'AUDIT'),'#888')}'>"
                f"{gate_modes.get(n, 'AUDIT')}</span></div>"
                for n, _ in gates
            )

        hdr = (
            "<span style='display:block;font-size:0.63rem;color:#555566;"
            "font-weight:700;letter-spacing:0.08em;margin-bottom:2px'>"
        )
        st.markdown(
            "<div style='display:flex;gap:24px'>"
            f"<div style='flex:1'>{hdr}INPUT</span>"
            + _rows(pipeline.input_gates)
            + "</div>"
            f"<div style='flex:1'>{hdr}OUTPUT</span>"
            + _rows(pipeline.output_gates)
            + "</div></div>",
            unsafe_allow_html=True,
        )


def _build_messages(current_text: str | None = None) -> list[dict]:
    """Assemble the full message list for the Ollama chat API.

    Args:
        current_text: The (possibly gate-modified) user turn to use as the
                      final user message.  If ``None``, the raw last message
                      in session_state is used unchanged.
    """
    system_parts: list[str] = []

    if st.session_state.system_prompt.strip():
        system_parts.append(st.session_state.system_prompt.strip())
    if st.session_state.get("rag_context", "").strip():
        system_parts.append(
            f"## Context Document:\n{st.session_state.rag_context.strip()}"
        )

    messages: list[dict] = []
    if system_parts:
        messages.append({"role": "system", "content": "\n\n".join(system_parts)})

    if current_text is not None:
        # Use all history except the last user message, then append current_text.
        # This ensures gate-modified text (e.g. PII-masked) reaches the LLM
        # rather than the original raw input.
        for msg in st.session_state.messages[:-1]:
            messages.append({"role": msg["role"], "content": msg["content"]})
        messages.append({"role": "user", "content": current_text})
    else:
        for msg in st.session_state.messages:
            messages.append({"role": msg["role"], "content": msg["content"]})

    return messages


def _build_options() -> dict:
    """Read generation parameter sliders from session_state."""
    return {
        "temperature": float(st.session_state.temperature),
        "top_p": float(st.session_state.top_p),
        "top_k": int(st.session_state.top_k),
        "repeat_penalty": float(st.session_state.repeat_penalty),
    }
