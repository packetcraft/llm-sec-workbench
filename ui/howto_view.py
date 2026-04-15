"""
ui/howto_view.py
────────────────
Pipeline Reference — first page shown on load.

Covers:
  0. Project intent — what the workbench is, the three modules, prerequisites
  1. Pipeline architecture diagram
  2. Detection method types (Static / ML / LLM)
  3. Gate reference table (all 14 gates)
  4. Gate mode semantics (OFF / AUDIT / ENFORCE)
  5. Cost / latency funnel

No Ollama or pipeline required — fully static, works before first-run setup.
"""

from __future__ import annotations

import streamlit as st
from ui.gate_info import (
    ALL_GATE_KEYS,
    GATE_INFO,
    INPUT_GATE_KEYS,
    METHOD_STYLES,
    OUTPUT_GATE_KEYS,
)

# Default modes (mirrors app.py gate_defaults)
_DEFAULT_MODES: dict[str, str] = {
    "custom_regex":   "AUDIT",
    "token_limit":    "ENFORCE",
    "invisible_text": "ENFORCE",
    "fast_scan":      "AUDIT",
    "classify":       "AUDIT",
    "toxicity_in":    "AUDIT",
    "ban_topics":     "AUDIT",
    "mod_llm":        "AUDIT",
    "sensitive_out":  "AUDIT",
    "malicious_urls": "ENFORCE",
    "no_refusal":     "AUDIT",
    "bias_out":       "AUDIT",
    "relevance":      "AUDIT",
    "deanonymize":    "ENFORCE",
}


# ── Public entry point ────────────────────────────────────────────────────────

def render() -> None:
    """Render the Pipeline Reference page."""

    st.markdown("## 🔧 Pipeline Reference")

    # ── 0. Project intent ─────────────────────────────────────────────────────
    st.info(
        "The **LLM Security Workbench** is a local-first research and testing environment "
        "for understanding, probing, and defending AI language model deployments. "
        "Every prompt and response passes through a configurable **14-gate security pipeline** "
        "— all processing stays on your machine, nothing leaves to external services."
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        with st.container(border=True):
            st.markdown("##### 💬 Chat Workbench")
            st.write(
                "Interact with a local Ollama model through the live security pipeline. "
                "Watch gates fire in real time, inspect scores, and tune gate modes "
                "to find the right balance of security and usability."
            )

    with c2:
        with st.container(border=True):
            st.markdown("##### 🛡️ Agentic Security")
            st.write(
                "Monitor and audit tool calls from **Claude Code** and **Gemini CLI** "
                "via hook interception. Every tool call is classified — ALLOWLIST, PATH, "
                "REGEX, or LLM — and written to a searchable audit log."
            )

    with c3:
        with st.container(border=True):
            st.markdown("##### ⚔️ Red Teaming")
            st.write(
                "Test the pipeline against 76 known attack patterns across 11 categories. "
                "Measure true/false positive rates in Batch mode, or run the **PAIR** "
                "algorithm to autonomously discover novel bypasses."
            )

    with c4:
        with st.container(border=True):
            st.markdown("##### 📦 Prerequisites")
            st.write(
                "Chat Workbench and Red Teaming require **Ollama** running locally with "
                "your target model and `llama-guard3` pulled. "
                "Agentic Security and this page work without Ollama."
            )
            st.caption("`ollama pull llama3`\n`ollama pull llama-guard3`")

    # ── 1. Pipeline architecture ──────────────────────────────────────────────
    st.divider()
    st.markdown("#### Pipeline Architecture")
    st.caption(
        f"Every prompt passes through {len(INPUT_GATE_KEYS)} input gates before the LLM "
        f"sees it, and every response passes through {len(OUTPUT_GATE_KEYS)} output gates "
        "before you see it. A single ENFORCE gate in BLOCK state halts the pipeline immediately."
    )

    pipeline_diagram = """
    graph LR
        A([User Prompt]) --> B[Input Gates x8]
        B -->|BLOCK| C([Pipeline Halted])
        B -->|all pass| D[LLM Inference]
        D --> E[Output Gates x6]
        E -->|BLOCK| F([Response Blocked])
        E -->|all pass| G([Response Delivered])
    """
    st.html(
        f"""
        <div class="mermaid" style="display:flex;justify-content:center;">
            {pipeline_diagram}
        </div>
        <script type="module">
            import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
            mermaid.initialize({{
                startOnLoad: true, theme: 'dark',
                flowchart: {{ useMaxWidth: true, htmlLabels: true, curve: 'basis' }}
            }});
        </script>
        """
    )

    # ── 2. Detection method types ─────────────────────────────────────────────
    st.divider()
    st.markdown("#### Detection Methods")

    method_descs = {
        "static": (
            "Pure Python — string operations, Unicode scans, token counting. "
            "No model loading, no GPU. Instant results regardless of hardware. "
            "Used for Regex Hot-Patch, Token Limit, Invisible Text, and PII Restore."
        ),
        "ml": (
            "Local Hugging Face and Presidio models running on CPU. "
            "First call loads the model into RAM; subsequent calls are fast. "
            "Used for PII/Secrets, Injection Detect, Toxicity, Ban Topics, and output gates."
        ),
        "llm": (
            "Full Ollama LLM inference. Requires `llama-guard3` to be pulled. "
            "Slowest but most contextually aware — evaluates 14 harm categories (S1–S14). "
            "Placed last in the input chain so it only runs when all cheaper gates pass."
        ),
    }

    d1, d2, d3 = st.columns(3)
    for col, (key, (label, color)) in zip([d1, d2, d3], METHOD_STYLES.items()):
        with col:
            with st.container(border=True):
                st.markdown(f"**{label}**")
                st.write(method_descs[key])

    # ── 3. Gate reference ─────────────────────────────────────────────────────
    st.divider()
    st.markdown("#### Gate Reference")
    st.caption(
        "Gates run in pipeline order. "
        "Default mode is what the app ships with — change any gate in the sidebar."
    )

    _TYPE_COLOR   = {"Input": "#9ECE6A", "Output": "#BB9AF7"}
    _METHOD_COLOR = {k: v for k, (_, v) in METHOD_STYLES.items()}
    _METHOD_LABEL = {k: lbl for k, (lbl, _) in METHOD_STYLES.items()}
    _MODE_COLOR   = {"ENFORCE": "#F7768E", "AUDIT": "#E0AF68", "OFF": "#555566"}

    def _badge(text: str, color: str) -> str:
        return (
            f"<span style='background:{color}22;color:{color};padding:2px 8px;"
            f"border-radius:4px;font-size:0.70rem;font-weight:700;"
            f"white-space:nowrap'>{text}</span>"
        )

    rows_html = ""
    for key in ALL_GATE_KEYS:
        info        = GATE_INFO[key]
        cat         = info["category"]
        method_key  = info["method"]
        default     = _DEFAULT_MODES.get(key, "AUDIT")

        # separator row before first output gate
        if key == "sensitive_out":
            rows_html += (
                "<tr><td colspan='6' style='padding:4px 12px 2px;border:none'>"
                "<div style='font-size:0.62rem;font-weight:700;letter-spacing:0.08em;"
                "text-transform:uppercase;color:#555566;border-top:1px solid #2a2a3a;"
                "padding-top:10px;margin-top:4px'>Output Gates</div></td></tr>"
            )

        rows_html += (
            "<tr style='border-bottom:1px solid #1e1e2e'>"
            f"<td style='padding:10px 12px;font-weight:700;color:#cdd6f4;white-space:nowrap'>"
            f"{info['label']}</td>"
            f"<td style='padding:10px 8px'>{_badge(cat, _TYPE_COLOR[cat])}</td>"
            f"<td style='padding:10px 8px'>"
            f"{_badge(_METHOD_LABEL[method_key], _METHOD_COLOR[method_key])}</td>"
            f"<td style='padding:10px 8px;font-family:monospace;font-size:0.72rem;"
            f"color:#7AA2F7;white-space:nowrap'>{info['latency']}</td>"
            f"<td style='padding:10px 8px'>{_badge(default, _MODE_COLOR[default])}</td>"
            f"<td style='padding:10px 12px;font-size:0.75rem;color:#aaa;"
            f"line-height:1.55'>{info['description']}</td>"
            "</tr>"
        )

    st.html(
        f"""
        <style>
          .gate-table {{ width:100%;border-collapse:collapse;font-size:0.78rem }}
          .gate-table th {{
            font-size:0.60rem;letter-spacing:0.09em;text-transform:uppercase;
            color:#555566;border-bottom:2px solid #2a2a3a;
            padding:8px 12px;text-align:left;white-space:nowrap
          }}
          .gate-table tr:hover td {{ background:rgba(122,162,247,0.04) }}
        </style>
        <div style='border:1px solid #2a2a3a;border-radius:8px;overflow:hidden'>
          <div style='font-size:0.62rem;font-weight:700;letter-spacing:0.08em;
                text-transform:uppercase;color:#9ECE6A;padding:8px 14px 4px;
                background:rgba(158,206,106,0.06)'>Input Gates</div>
          <table class='gate-table'>
            <thead><tr>
              <th>Gate</th><th>Type</th><th>Method</th>
              <th>Latency</th><th>Default</th><th>Description</th>
            </tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </div>
        """
    )

    # ── 4. Gate mode semantics ────────────────────────────────────────────────
    st.divider()
    st.markdown("#### Gate Mode Semantics")

    modes = [
        (
            "OFF",
            "Gate is completely skipped — zero latency overhead.",
            "No scan, no metrics entry. Use when a gate's detection category is "
            "irrelevant to your deployment — e.g. turn off Refusal Detect if you "
            "aren't running red-team sessions.",
            "Example: Relevance gate OFF on a creative writing chatbot where "
            "off-topic responses are expected.",
        ),
        (
            "AUDIT",
            "Gate scans and logs its verdict — but never stops the pipeline.",
            "A BLOCK verdict is recorded in the telemetry panel and Gate Trace, "
            "but the prompt continues to the LLM. Use AUDIT to monitor signals "
            "without impacting the user experience until you are confident in the "
            "gate's accuracy at your threshold.",
            "Example: Toxicity gate AUDIT — flag hostile inputs for later review "
            "without blocking users who are simply frustrated.",
        ),
        (
            "ENFORCE",
            "Gate scans and, on a BLOCK verdict, immediately halts the pipeline.",
            "For input gates the LLM never receives the prompt. For output gates "
            "the response is replaced with a rejection message. Subsequent gates "
            "do not run, saving latency. Use ENFORCE only when you are certain "
            "the gate's false-positive rate is acceptable.",
            "Example: Token Limit gate ENFORCE — oversized prompts can never reach "
            "the LLM regardless of content.",
        ),
    ]

    e1, e2, e3 = st.columns(3)
    for col, (mode, headline, body, example) in zip([e1, e2, e3], modes):
        with col:
            with st.container(border=True):
                st.markdown(f"**{mode}**")
                st.write(f"_{headline}_")
                st.write(body)
                st.caption(example)

    # ── 5. Cost / latency funnel ──────────────────────────────────────────────
    st.divider()
    st.markdown("#### Cost / Latency Funnel")
    st.caption(
        "Gates are ordered cheapest-first so that expensive ML and LLM calls only "
        "run when lighter checks pass. This minimises median latency while preserving "
        "deep analysis for ambiguous inputs."
    )

    funnel = [
        (
            "1 — Static / Rules",
            "< 1 ms each",
            "Regex Hot-Patch · Token Limit · Invisible Text · PII Restore",
            "Pure Python. Run first — eliminate obvious bad inputs before any model is loaded.",
        ),
        (
            "2 — ML Models (CPU)",
            "5 ms – 500 ms",
            "PII/Secrets · Injection Detect · Toxicity · Ban Topics · PII Out · Bad URLs · Refusal · Bias · Relevance",
            "Local Hugging Face / Presidio models. Run only if cheaper gates pass. "
            "First call warms the model; subsequent calls are significantly faster.",
        ),
        (
            "3 — LLM / Ollama",
            "1 s – 10 s",
            "Llama Guard 3",
            "Highest accuracy, highest cost. Runs last in the input chain so it only "
            "evaluates prompts that already cleared all cheaper gates.",
        ),
    ]

    for tier, latency, gates, note in funnel:
        with st.container(border=True):
            fc1, fc2 = st.columns([1, 4])
            with fc1:
                st.markdown(f"**{tier}**")
                st.caption(f"avg {latency}")
            with fc2:
                st.write(note)
                st.caption(gates)
