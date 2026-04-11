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

import os
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
    _render_sidebar(pipeline, config)
    _render_chat_area(pipeline, config)


# ── Sidebar ────────────────────────────────────────────────────────────────────

def _render_sidebar(pipeline: "PipelineManager", config: dict) -> None:
    with st.sidebar:
        # ── Demo Mode toggle (always visible) ─────────────────────────────────
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

        st.markdown("---")

        # ── Target model dropdown ──────────────────────────────────────────────
        st.caption("TARGET MODEL")
        available_models = pipeline.client.list_models()

        if not available_models:
            st.warning("No models found in Ollama.")
        else:
            # Resolve the best index for the currently stored model name.
            # Handles both exact matches ("llama3:latest") and base-name matches
            # where config.yaml says "llama3" but Ollama returns "llama3:latest".
            current = st.session_state.get("target_model", "")
            try:
                current_idx = available_models.index(current)
            except ValueError:
                base = current.split(":")[0].lower()
                current_idx = next(
                    (i for i, m in enumerate(available_models)
                     if m.split(":")[0].lower() == base),
                    0,
                )

            selected_model = st.selectbox(
                "Target Model",
                available_models,
                index=current_idx,
                label_visibility="collapsed",
            )

            if selected_model != st.session_state.get("target_model"):
                st.session_state.target_model = selected_model
                # Clear history so the new model starts fresh
                st.session_state.messages = []
                st.rerun()

        if st.session_state.demo_mode:
            # Demo Mode: show nothing further in the sidebar
            return

        # ── Persona & System Prompt ────────────────────────────────────────────
        st.markdown("#### Persona")

        persona_names = list(PERSONA_PROMPTS.keys())
        current_index = persona_names.index(st.session_state.get("persona", "Default"))

        selected_persona = st.selectbox(
            "Preset",
            persona_names,
            index=current_index,
            label_visibility="collapsed",
        )

        # When persona changes, overwrite the system prompt with the preset
        if selected_persona != st.session_state.persona:
            st.session_state.persona = selected_persona
            st.session_state.system_prompt = PERSONA_PROMPTS[selected_persona]
            st.rerun()

        st.session_state.system_prompt = st.text_area(
            "System Prompt",
            value=st.session_state.system_prompt,
            height=150,
            placeholder="Optional — leave blank for no system prompt.",
        )

        st.markdown("---")

        # ── Generation parameters ──────────────────────────────────────────────
        st.markdown("#### Generation Parameters")

        st.session_state.temperature = st.slider(
            "Temperature",
            min_value=0.0,
            max_value=2.0,
            value=float(st.session_state.temperature),
            step=0.05,
            help="Higher = more creative / random. Lower = more deterministic.",
        )
        st.session_state.top_p = st.slider(
            "Top P",
            min_value=0.0,
            max_value=1.0,
            value=float(st.session_state.top_p),
            step=0.05,
            help="Nucleus sampling — cumulative probability cutoff.",
        )
        st.session_state.top_k = st.slider(
            "Top K",
            min_value=1,
            max_value=100,
            value=int(st.session_state.top_k),
            step=1,
            help="Limits token selection to the top-K most probable tokens.",
        )
        st.session_state.repeat_penalty = st.slider(
            "Repeat Penalty",
            min_value=0.5,
            max_value=2.0,
            value=float(st.session_state.repeat_penalty),
            step=0.05,
            help="Penalises repeated tokens. >1.0 reduces repetition.",
        )

        st.markdown("---")

        # ── Hot-Patching (CustomRegexGate) ────────────────────────────────────
        st.markdown("#### Hot-Patching")

        current_regex_mode = st.session_state.gate_modes.get("custom_regex", "AUDIT")
        mode_colors = {"OFF": "#888", "AUDIT": "#E0AF68", "ENFORCE": "#F7768E"}

        new_regex_mode = st.radio(
            "RegexGate mode",
            options=["OFF", "AUDIT", "ENFORCE"],
            index=["OFF", "AUDIT", "ENFORCE"].index(current_regex_mode),
            horizontal=True,
            label_visibility="collapsed",
            help=(
                "OFF: gate skipped.\n"
                "AUDIT: flags matches in telemetry but never blocks.\n"
                "ENFORCE: blocks the prompt immediately on any match."
            ),
        )
        if new_regex_mode != current_regex_mode:
            st.session_state.gate_modes["custom_regex"] = new_regex_mode
            st.rerun()

        # Coloured mode badge
        badge_color = mode_colors[new_regex_mode]
        st.markdown(
            f"<span style='color:{badge_color};font-size:0.78rem'>"
            f"● RegexGate — {new_regex_mode}</span>",
            unsafe_allow_html=True,
        )

        if new_regex_mode != "OFF":
            st.session_state.custom_block_phrases = st.text_input(
                "Block Phrases",
                value=st.session_state.custom_block_phrases,
                placeholder="e.g. ignore all previous, jailbreak, DAN",
                help="Comma-separated, case-insensitive. Checked against the raw user input.",
            )

        st.markdown("---")

        # ── Fast Classifiers (FastScanGate, PromptGuardGate) ──────────────────
        # ── Input Guardrails (zero-ML) ─────────────────────────────────────────
        st.markdown("#### Input Guardrails")

        _GUARDRAIL_GATES = [
            (
                "token_limit",
                "Token Limit",
                (
                    "Rejects prompts exceeding the token budget (tiktoken, < 1ms).\n"
                    "Prevents context-exhaustion attacks and oversized injection payloads.\n"
                    "ENFORCE: blocks oversized prompts before any ML gate runs.\n"
                    "AUDIT: flags but continues."
                ),
            ),
            (
                "invisible_text",
                "Invisible Text",
                (
                    "Detects hidden Unicode characters (zero-width, directional overrides, "
                    "control chars) used in steganography injection attacks (< 1ms).\n"
                    "ENFORCE: blocks prompts containing invisible characters.\n"
                    "AUDIT: flags but continues."
                ),
            ),
        ]

        for gate_key, gate_label, gate_help in _GUARDRAIL_GATES:
            current_gr_mode = st.session_state.gate_modes.get(gate_key, "ENFORCE")
            new_gr_mode = st.radio(
                gate_label,
                options=["OFF", "AUDIT", "ENFORCE"],
                index=["OFF", "AUDIT", "ENFORCE"].index(current_gr_mode),
                horizontal=True,
                help=gate_help,
            )
            if new_gr_mode != current_gr_mode:
                st.session_state.gate_modes[gate_key] = new_gr_mode
                st.rerun()
            badge_color = mode_colors[new_gr_mode]
            st.markdown(
                f"<span style='color:{badge_color};font-size:0.78rem'>"
                f"● {gate_key} — {new_gr_mode}</span>",
                unsafe_allow_html=True,
            )

            # Token limit slider — shown only for token_limit gate when not OFF
            if gate_key == "token_limit" and new_gr_mode != "OFF":
                st.session_state.token_limit = st.slider(
                    "Max Tokens",
                    min_value=64,
                    max_value=4096,
                    value=int(st.session_state.get("token_limit", 512)),
                    step=64,
                    help=(
                        "Maximum number of tokens allowed in a single prompt.\n"
                        "Uses cl100k_base (GPT-4 / llama compatible) tokenisation.\n"
                        "512 is a reasonable default for interactive chat.\n"
                        "Raise to 2048–4096 if users need to paste large documents."
                    ),
                )

        st.markdown("---")

        st.markdown("#### Fast Classifiers")

        _CLASSIFIER_GATES = [
            (
                "fast_scan",
                "FastScan (PII / Secrets)",
                (
                    "llm-guard Anonymize + Secrets scanners (CPU/Presidio).\n"
                    "OFF: skipped entirely.\n"
                    "AUDIT: masks PII in current_text, logs verdict, pipeline continues.\n"
                    "ENFORCE: blocks prompt if PII or secrets detected."
                ),
            ),
            (
                "classify",
                "PromptGuard (Injection)",
                (
                    "Meta Prompt-Guard-86M injection/jailbreak classifier (CPU).\n"
                    "OFF: skipped entirely.\n"
                    "AUDIT: logs threat score, pipeline continues regardless.\n"
                    "ENFORCE: blocks prompt when threat score \u2265 threshold."
                ),
            ),
            (
                "toxicity_in",
                "Toxicity / Sentiment (Input)",
                (
                    "Quality gate — detects hostile, abusive, or toxic input tone.\n"
                    "Runs two sub-scanners: Toxicity (abusive language classifier) and\n"
                    "Sentiment (flags extreme negativity below -0.5).\n"
                    "AUDIT (recommended): logs verdict, never blocks on tone alone.\n"
                    "ENFORCE: blocks prompt if toxicity or hostile sentiment detected.\n"
                    "OFF: gate is skipped entirely."
                ),
            ),
        ]

        # Render classifier gates
        for gate_key, gate_label, gate_help in _CLASSIFIER_GATES:
            current_clf_mode = st.session_state.gate_modes.get(gate_key, "AUDIT")
            new_clf_mode = st.radio(
                gate_label,
                options=["OFF", "AUDIT", "ENFORCE"],
                index=["OFF", "AUDIT", "ENFORCE"].index(current_clf_mode),
                horizontal=True,
                help=gate_help,
            )
            if new_clf_mode != current_clf_mode:
                st.session_state.gate_modes[gate_key] = new_clf_mode
                st.rerun()
            badge_color = mode_colors[new_clf_mode]
            st.markdown(
                f"<span style='color:{badge_color};font-size:0.78rem'>"
                f"● {gate_key} — {new_clf_mode}</span>",
                unsafe_allow_html=True,
            )

            # PII confidence threshold slider — shown only for fast_scan
            if gate_key == "fast_scan" and new_clf_mode != "OFF":
                st.session_state.pii_threshold = st.slider(
                    "PII Confidence Threshold",
                    min_value=0.1,
                    max_value=1.0,
                    value=float(st.session_state.get("pii_threshold", 0.7)),
                    step=0.05,
                    help=(
                        "Minimum Presidio confidence score for an entity to be treated as PII.\n"
                        "Lower = more aggressive (more false positives).\n"
                        "Higher = more conservative (may miss low-confidence PII).\n"
                        "0.7 is recommended for general use."
                    ),
                )

        # ── Ban Topics (Gate 1e) ───────────────────────────────────────────────
        ban_topics_mode = st.session_state.gate_modes.get("ban_topics", "AUDIT")
        new_ban_mode = st.radio(
            "Ban Topics (Subject Filter)",
            options=["OFF", "AUDIT", "ENFORCE"],
            index=["OFF", "AUDIT", "ENFORCE"].index(ban_topics_mode),
            horizontal=True,
            help=(
                "Zero-shot topic classifier — blocks prompts covering forbidden subjects.\n"
                "Uses semantic understanding, not keyword matching.\n"
                "AUDIT: flags matching topics in telemetry, pipeline continues.\n"
                "ENFORCE: blocks the prompt if any configured topic is detected.\n"
                "OFF: gate is skipped entirely (no-op if Topics list is empty)."
            ),
        )
        if new_ban_mode != ban_topics_mode:
            st.session_state.gate_modes["ban_topics"] = new_ban_mode
            st.rerun()
        badge_color = mode_colors[new_ban_mode]
        st.markdown(
            f"<span style='color:{badge_color};font-size:0.78rem'>"
            f"● ban_topics — {new_ban_mode}</span>",
            unsafe_allow_html=True,
        )

        if new_ban_mode != "OFF":
            st.session_state.ban_topics_list = st.text_input(
                "Banned Topics",
                value=st.session_state.get("ban_topics_list", ""),
                placeholder="e.g. weapons, self-harm, politics",
                help=(
                    "Comma-separated subject areas the model must not discuss.\n"
                    "Uses zero-shot classification — paraphrases are caught too.\n"
                    "Gate is a no-op when this list is empty.\n"
                    "Examples: weapons, gambling, competitor products, adult content."
                ),
            )

        st.markdown("---")

        # ── LLM Judges ────────────────────────────────────────────────────────
        st.markdown("#### LLM Judges")

        current_mod_mode = st.session_state.gate_modes.get("mod_llm", "AUDIT")
        new_mod_mode = st.radio(
            "Llama Guard 3",
            options=["OFF", "AUDIT", "ENFORCE"],
            index=["OFF", "AUDIT", "ENFORCE"].index(current_mod_mode),
            horizontal=True,
            help=(
                "Meta Llama Guard 3 — LLM-as-judge safety classifier (Ollama).\n"
                "Classifies the raw user prompt against 14 harm categories "
                "(S1–S14: violent crimes, CBRN weapons, CSAM, hate, self-harm, etc.).\n"
                "Requires llama-guard3 to be pulled in Ollama.\n"
                "AUDIT: logs verdict and categories, pipeline continues.\n"
                "ENFORCE: blocks the prompt if any safety category is violated.\n"
                "OFF: gate skipped entirely (no Ollama call)."
            ),
        )
        if new_mod_mode != current_mod_mode:
            st.session_state.gate_modes["mod_llm"] = new_mod_mode
            st.rerun()
        badge_color = mode_colors[new_mod_mode]
        st.markdown(
            f"<span style='color:{badge_color};font-size:0.78rem'>"
            f"● mod_llm — {new_mod_mode}</span>",
            unsafe_allow_html=True,
        )

        st.markdown("---")

        # ── Output Gates ───────────────────────────────────────────────────────
        st.markdown("#### Output Gates")

        _OUTPUT_GATES = [
            (
                "sensitive_out",
                "Sensitive (LLM-Generated PII)",
                (
                    "Scans the model's response for PII the LLM generated on its own.\n"
                    "Catches hallucinated names, invented phone numbers, or training-data leakage "
                    "that the input-side FastScan can never see.\n"
                    "ENFORCE: redacts found PII with placeholders (e.g. [PERSON], [US_SSN]).\n"
                    "AUDIT: flags in telemetry and redacts, but does not halt the pipeline.\n"
                    "OFF: gate is skipped entirely."
                ),
            ),
            (
                "bias_out",
                "Bias / Toxicity (Output)",
                (
                    "Quality gate — detects biased or toxic content in model responses.\n"
                    "Runs two sub-scanners: Bias (distilroberta-bias) and output-side Toxicity.\n"
                    "Does not modify the response text — monitoring only.\n"
                    "AUDIT (recommended): logs verdict, pipeline continues.\n"
                    "ENFORCE: halts pipeline if bias or toxicity detected in response.\n"
                    "OFF: gate is skipped entirely."
                ),
            ),
            (
                "relevance",
                "Relevance (Hallucination)",
                (
                    "Quality gate — detects off-topic or hallucinated responses.\n"
                    "Compares user prompt to model response using BAAI/bge-base-en-v1.5\n"
                    "embeddings. Low cosine similarity = response drifted from the question.\n"
                    "Does not modify the response text — monitoring only.\n"
                    "AUDIT (recommended): logs similarity score, pipeline continues.\n"
                    "ENFORCE: halts if similarity falls below threshold.\n"
                    "OFF: gate is skipped entirely."
                ),
            ),
            (
                "malicious_urls",
                "Malicious URLs",
                (
                    "Scans the model's response for malicious or phishing URLs.\n"
                    "Catches links the model was tricked into echoing via prompt injection, "
                    "or hallucinated domains that match known threat patterns.\n"
                    "ENFORCE (recommended): removes detected URLs from the response.\n"
                    "AUDIT: flags in telemetry but lets the URL through.\n"
                    "OFF: gate is skipped entirely."
                ),
            ),
            (
                "no_refusal",
                "No Refusal (Refusal Detector)",
                (
                    "Detects when the model declines to answer.\n"
                    "Useful for red-team analysis ('did my attack work?') and "
                    "over-blocking detection ('is the safety system too aggressive?').\n"
                    "The model's refusal message is always shown — this gate only flags it.\n"
                    "AUDIT (recommended): logs refusals as a BLOCK badge in telemetry.\n"
                    "ENFORCE: additionally surfaces an error banner.\n"
                    "OFF: gate is skipped entirely."
                ),
            ),
            (
                "deanonymize",
                "Deanonymize (PII Restore)",
                (
                    "Restores original PII values from placeholders in the LLM response.\n"
                    "Requires FastScan to be ON and to have detected PII.\n"
                    "ENFORCE (recommended): always restore — users see real names, not [REDACTED_PERSON_1].\n"
                    "AUDIT: restores but logs; useful for testing the gate in isolation.\n"
                    "OFF: placeholders remain visible in the response."
                ),
            ),
        ]

        for gate_key, gate_label, gate_help in _OUTPUT_GATES:
            current_out_mode = st.session_state.gate_modes.get(gate_key, "ENFORCE")
            new_out_mode = st.radio(
                gate_label,
                options=["OFF", "AUDIT", "ENFORCE"],
                index=["OFF", "AUDIT", "ENFORCE"].index(current_out_mode),
                horizontal=True,
                help=gate_help,
            )
            if new_out_mode != current_out_mode:
                st.session_state.gate_modes[gate_key] = new_out_mode
                st.rerun()
            badge_color = mode_colors[new_out_mode]
            st.markdown(
                f"<span style='color:{badge_color};font-size:0.78rem'>"
                f"● {gate_key} — {new_out_mode}</span>",
                unsafe_allow_html=True,
            )

        st.markdown("---")

        # ── Session controls ───────────────────────────────────────────────────
        st.markdown("#### Session")
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

    chat_col, tel_col = st.columns([3, 1], gap="medium")
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
        col_title, col_badge = st.columns([6, 1])
        with col_title:
            st.markdown(
                "<h3 style='color:#7AA2F7;margin-bottom:0'>LLM Security Workbench</h3>",
                unsafe_allow_html=True,
            )
        with col_badge:
            st.markdown(
                "<div style='text-align:right;padding-top:8px'>"
                "<span style='background:#262730;color:#9ECE6A;"
                "padding:3px 10px;border-radius:4px;font-size:0.75rem'>"
                "WORKBENCH</span></div>",
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
        active_gates = [
            (name, st.session_state.gate_modes.get(name, "AUDIT"))
            for name, _ in pipeline.input_gates + pipeline.output_gates
            if st.session_state.gate_modes.get(name, "AUDIT") != "OFF"
        ]
        if active_gates:
            gate_badges = " ".join(
                f"<span style='background:{_MODE_BG[m]};color:{_MODE_COLOR[m]};"
                f"padding:1px 7px;border-radius:3px;font-size:0.72rem'>{n}: {m}</span>"
                for n, m in active_gates
            )
            st.markdown(
                f"<div style='background:#262730;border-left:3px solid #7AA2F7;"
                f"padding:7px 12px;border-radius:4px;margin-bottom:10px'>"
                f"🔒 Pipeline active — {gate_badges}</div>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                "<div style='background:#262730;border-left:3px solid #444;"
                "padding:7px 12px;border-radius:4px;margin-bottom:10px;"
                "font-size:0.82rem;color:#555'>"
                "🔓 All gates OFF — prompts reach the LLM unfiltered</div>",
                unsafe_allow_html=True,
            )

    # ── Chat history ───────────────────────────────────────────────────────────
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            # Blocked assistant turns rendered as errors
            if msg.get("blocked"):
                if st.session_state.demo_mode:
                    st.warning(msg["content"])
                else:
                    st.error(msg["content"])
            else:
                st.markdown(msg["content"])

            if msg["role"] == "assistant" and not st.session_state.demo_mode:
                # Gate metric badges
                if msg.get("gate_metrics"):
                    _render_gate_metrics(msg["gate_metrics"])
                # Token telemetry + context bar
                t = msg.get("telemetry") or {}
                if t and not msg.get("blocked"):
                    st.caption(
                        f"⚡ {t.get('prompt_tokens', 0)} prompt · "
                        f"{t.get('completion_tokens', 0)} completion · "
                        f"{t.get('tokens_per_second', 0.0):.1f} t/s"
                    )
                    _ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
                    _model = st.session_state.get("target_model", "llama3")
                    render_context_bar(
                        t.get("prompt_tokens", 0),
                        _model,
                        _ollama_host,
                    )
                # API Inspector
                if msg.get("raw_traces"):
                    render_api_inspector(msg["raw_traces"], msg.get("gate_metrics") or [])

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
                    blocking_gate = next(
                        (m["gate_name"] for m in reversed(payload.metrics)
                         if m.get("verdict") == "BLOCK"),
                        "unknown gate",
                    )
                    full_response = (
                        f"🚫 **Blocked by `{blocking_gate}`**\n\n"
                        f"{payload.block_reason}"
                    )
                    st.error(full_response)
                    _render_gate_metrics(payload.metrics)

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
                        blocking_gate = next(
                            (m["gate_name"] for m in reversed(payload.metrics)
                             if m.get("verdict") == "BLOCK"),
                            "unknown gate",
                        )
                        st.error(
                            f"🚫 **Output blocked by `{blocking_gate}`:** "
                            f"{payload.block_reason}"
                        )

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
                        st.error(
                            "**Malicious URL detected and removed** — "
                            "A URL in the model's response was classified as malicious or a phishing attempt. "
                            "It has been replaced with `[REDACTED_URL]` in the response above.  \n"
                            f"*Reason: {malicious_url_block['detail']}*",
                            icon="⛔",
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
                    _render_gate_metrics(payload.metrics)
                    if stream_result:
                        st.caption(
                            f"⚡ {payload.prompt_tokens} prompt · "
                            f"{payload.completion_tokens} completion · "
                            f"{payload.tokens_per_second:.1f} t/s"
                        )
                        # Persist TPS so the sidebar hw panel can display it
                        st.session_state.last_tps = payload.tokens_per_second
                        # Context window utilisation bar
                        _ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
                        _model = st.session_state.get("target_model", "llama3")
                        render_context_bar(payload.prompt_tokens, _model, _ollama_host)
                    # API Inspector — raw gate traces
                    if payload.raw_traces:
                        render_api_inspector(payload.raw_traces, payload.metrics)

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
            },
        })


# ── Semantic colour maps (Section 9.6) ────────────────────────────────────────

_VERDICT_COLOR: dict[str, str] = {
    "PASS":  "#9ECE6A",   # green
    "BLOCK": "#F7768E",   # red
    "AUDIT": "#E0AF68",   # amber  (BLOCK verdict in AUDIT mode)
    "ERROR": "#E0AF68",   # amber
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


# ── Helpers ────────────────────────────────────────────────────────────────────

def _render_gate_metrics(metrics: list[dict]) -> None:
    """Render coloured verdict badges for each gate that ran."""
    if not metrics:
        return
    badges = ""
    for m in metrics:
        verdict = m.get("verdict", "?")
        color = _VERDICT_COLOR.get(verdict, "#888")
        gate = m.get("gate_name", "?")
        latency = m.get("latency_ms", 0.0)
        detail = m.get("detail", "")
        clean = detail.replace("\r", "").replace("\n", " ").strip()
        if len(clean) > 300:
            clean = clean[:297] + "..."
        title = clean.replace("&", "&amp;").replace('"', "&quot;").replace("'", "&#39;")
        badges += (
            f'<span title="{title}" style="'
            f"background:{color}18;color:{color};"
            f"border:1px solid {color}44;padding:1px 8px;"
            f'border-radius:4px;font-size:0.73rem;margin-right:5px">'
            f"{gate}: {verdict} ({latency:.1f}ms)</span>"
        )
    st.markdown(badges, unsafe_allow_html=True)


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
