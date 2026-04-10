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

from typing import TYPE_CHECKING

import streamlit as st

if TYPE_CHECKING:
    from core.llm_client import OllamaClient

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

def render(client: "OllamaClient", config: dict) -> None:
    """Main entry point for the chat interface.

    Called by app.py after Ollama is confirmed available and all required
    models are present.
    """
    _render_sidebar(client, config)
    _render_chat_area(client, config)


# ── Sidebar ────────────────────────────────────────────────────────────────────

def _render_sidebar(client: "OllamaClient", config: dict) -> None:
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
        available_models = client.list_models()

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

        # ── Hot-Patching (RegexGate — Phase 2) ────────────────────────────────
        st.markdown("#### Hot-Patching")
        st.session_state.custom_block_phrases = st.text_input(
            "Custom Block Phrases",
            value=st.session_state.custom_block_phrases,
            placeholder="e.g. ignore all previous, jailbreak, DAN",
            help="Comma-separated phrases. Wires into the RegexGate in Phase 2.",
        )
        st.caption("⚙️ RegexGate available in Phase 2.")

        st.markdown("---")

        # ── Session controls ───────────────────────────────────────────────────
        st.markdown("#### Session")
        if st.button("Clear Chat History", use_container_width=True):
            st.session_state.messages = []
            st.rerun()


# ── Main chat area ─────────────────────────────────────────────────────────────

def _render_chat_area(client: "OllamaClient", config: dict) -> None:
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

    # ── Phase 2 placeholder banner (workbench mode only) ──────────────────────
    if not st.session_state.demo_mode:
        st.markdown(
            "<div style='background:#262730;border-left:3px solid #7AA2F7;"
            "padding:8px 12px;border-radius:4px;margin-bottom:12px;"
            "font-size:0.82rem;color:#888'>"
            "🔒 Security Pipeline: <em>not yet active — gates wire in Phase 2</em>"
            "</div>",
            unsafe_allow_html=True,
        )

    # ── Chat history ───────────────────────────────────────────────────────────
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

            # Token telemetry — workbench mode only, assistant messages only
            if (
                msg["role"] == "assistant"
                and not st.session_state.demo_mode
            ):
                t = msg.get("telemetry") or {}
                if t:
                    st.caption(
                        f"⚡ {t.get('prompt_tokens', 0)} prompt tokens · "
                        f"{t.get('completion_tokens', 0)} completion tokens · "
                        f"{t.get('tokens_per_second', 0.0):.1f} t/s"
                    )

    # ── Chat input ─────────────────────────────────────────────────────────────
    placeholder = (
        "Message the assistant…"
        if st.session_state.demo_mode
        else "Send a prompt to the workbench…"
    )

    if prompt := st.chat_input(placeholder):
        # Add user message to history
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Build API payload
        messages_for_api = _build_messages()
        options = _build_options()

        # Generate response (streaming)
        with st.chat_message("assistant"):
            try:
                full_response: str = st.write_stream(
                    client.generate_stream(messages_for_api, options)
                )
                result = client.get_stream_result()

            except Exception as exc:  # noqa: BLE001
                err_msg = (
                    "_Generation failed — check that Ollama is running and the "
                    f"target model `{client.model}` is available._"
                )
                st.error(f"Ollama error: {exc}", icon="🔌")
                full_response = err_msg
                result = None

            # Token telemetry (workbench mode only)
            if result and not st.session_state.demo_mode:
                st.caption(
                    f"⚡ {result.prompt_tokens} prompt tokens · "
                    f"{result.completion_tokens} completion tokens · "
                    f"{result.tokens_per_second:.1f} t/s"
                )

        # Persist to session state
        st.session_state.messages.append({
            "role": "assistant",
            "content": full_response,
            "telemetry": {
                "prompt_tokens": result.prompt_tokens if result else 0,
                "completion_tokens": result.completion_tokens if result else 0,
                "tokens_per_second": result.tokens_per_second if result else 0.0,
            },
        })


# ── Helpers ────────────────────────────────────────────────────────────────────

def _build_messages() -> list[dict]:
    """Assemble the full message list for the Ollama chat API.

    Combines system prompt, RAG context, and conversation history.
    The most recent user message is the last entry in
    ``st.session_state.messages`` (added by the caller before this runs).
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
