"""
ui/howto_view.py
────────────────
"How It Works" — educational reference page for the LLM Security Workbench.

Covers:
  1. Pipeline flow diagram (User Input → Input Gates → LLM → Output Gates → Response)
  2. Gate reference table (all 14 gates: method, latency, default mode, detection)
  3. Gate mode semantics (OFF / AUDIT / ENFORCE)
  4. Cost / Latency Funnel architecture note

No Ollama or pipeline required — fully static, accessible on every page load.
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

# ── Colour tokens (match global dark theme) ───────────────────────────────────
_BG_CARD   = "rgba(255,255,255,0.04)"
_BG_DARK   = "#13131f"
_BORDER    = "#2a2a3a"
_TEXT      = "#cdd6f4"
_DIM       = "#555566"
_BLUE      = "#7AA2F7"
_GREEN     = "#9ECE6A"
_AMBER     = "#E0AF68"
_RED       = "#F7768E"
_PURPLE    = "#BB9AF7"
_GOLD      = "#FFD700"

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

_MODE_COLORS: dict[str, str] = {
    "ENFORCE": _RED,
    "AUDIT":   _AMBER,
    "OFF":     _DIM,
}


def _css() -> None:
    st.markdown(
        """
        <style>
        /* ── Pipeline diagram ─────────────────────────────────── */
        .hw-pipeline {
            display: flex;
            align-items: stretch;
            gap: 0;
            margin: 16px 0 28px 0;
            flex-wrap: nowrap;
            overflow-x: auto;
        }
        .hw-node {
            flex: 1;
            min-width: 110px;
            padding: 14px 12px;
            border-radius: 8px;
            border: 1px solid #2a2a3a;
            background: rgba(255,255,255,0.04);
            text-align: center;
        }
        .hw-node-title {
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        .hw-node-item {
            font-size: 0.65rem;
            color: #888;
            line-height: 1.7;
        }
        .hw-arrow {
            display: flex;
            align-items: center;
            padding: 0 4px;
            font-size: 1.2rem;
            color: #2a2a3a;
            flex-shrink: 0;
        }
        /* ── Gate table ───────────────────────────────────────── */
        .hw-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.72rem;
            font-family: ui-monospace, monospace;
            margin: 12px 0 24px 0;
        }
        .hw-table th {
            font-size: 0.60rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: #555566;
            border-bottom: 1px solid #2a2a3a;
            padding: 6px 10px;
            text-align: left;
            white-space: nowrap;
        }
        .hw-table td {
            padding: 7px 10px;
            border-bottom: 1px solid #1a1a2a;
            color: #cdd6f4;
            vertical-align: top;
        }
        .hw-table tr:hover td {
            background: rgba(122,162,247,0.05);
        }
        .hw-method-badge {
            display: inline-block;
            padding: 2px 7px;
            border-radius: 3px;
            font-size: 0.62rem;
            font-weight: 700;
            white-space: nowrap;
        }
        .hw-mode-badge {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.62rem;
            font-weight: 700;
        }
        .hw-cat-badge {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.62rem;
            font-weight: 600;
        }
        /* ── Mode semantics cards ─────────────────────────────── */
        .hw-mode-card {
            padding: 14px 16px;
            border-radius: 8px;
            border: 1px solid #2a2a3a;
            background: rgba(255,255,255,0.03);
            margin-bottom: 10px;
        }
        .hw-mode-card-title {
            font-size: 0.80rem;
            font-weight: 700;
            margin-bottom: 6px;
        }
        .hw-mode-card-body {
            font-size: 0.72rem;
            color: #888;
            line-height: 1.55;
        }
        .hw-mode-card-example {
            margin-top: 8px;
            font-size: 0.68rem;
            color: #555566;
            font-style: italic;
        }
        /* ── Section heading ──────────────────────────────────── */
        .hw-section {
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 0.10em;
            text-transform: uppercase;
            color: #555566;
            margin: 28px 0 10px 0;
            border-bottom: 1px solid #2a2a3a;
            padding-bottom: 5px;
        }
        /* ── Funnel note ──────────────────────────────────────── */
        .hw-funnel-row {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 12px;
            border-radius: 6px;
            border: 1px solid #2a2a3a;
            background: rgba(255,255,255,0.03);
            margin-bottom: 8px;
            font-size: 0.72rem;
        }
        .hw-funnel-num {
            font-size: 1.0rem;
            font-weight: 700;
            min-width: 24px;
            text-align: center;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _pipeline_diagram() -> None:
    input_gate_names = [
        GATE_INFO[k]["label"] for k in INPUT_GATE_KEYS
    ]
    output_gate_names = [
        GATE_INFO[k]["label"] for k in OUTPUT_GATE_KEYS
    ]

    input_items  = "".join(f"<div class='hw-node-item'>{n}</div>" for n in input_gate_names)
    output_items = "".join(f"<div class='hw-node-item'>{n}</div>" for n in output_gate_names)

    st.markdown(
        f"""
        <div class='hw-pipeline'>
          <div class='hw-node' style='border-color:{_BLUE}55;max-width:100px'>
            <div class='hw-node-title' style='color:{_BLUE}'>User<br>Input</div>
            <div class='hw-node-item'>raw prompt</div>
          </div>
          <div class='hw-arrow'>→</div>
          <div class='hw-node' style='border-color:{_GREEN}55'>
            <div class='hw-node-title' style='color:{_GREEN}'>Input Gates
              <span style='font-weight:400;color:{_DIM}'> ({len(INPUT_GATE_KEYS)})</span>
            </div>
            {input_items}
          </div>
          <div class='hw-arrow'>→</div>
          <div class='hw-node' style='border-color:{_GOLD}88;background:rgba(255,215,0,0.05);
               max-width:130px'>
            <div class='hw-node-title' style='color:{_GOLD}'>🧠 LLM<br>Inference</div>
            <div class='hw-node-item'>Ollama</div>
            <div class='hw-node-item'>local model</div>
          </div>
          <div class='hw-arrow'>→</div>
          <div class='hw-node' style='border-color:{_PURPLE}55'>
            <div class='hw-node-title' style='color:{_PURPLE}'>Output Gates
              <span style='font-weight:400;color:{_DIM}'> ({len(OUTPUT_GATE_KEYS)})</span>
            </div>
            {output_items}
          </div>
          <div class='hw-arrow'>→</div>
          <div class='hw-node' style='border-color:{_GREEN}55;max-width:100px'>
            <div class='hw-node-title' style='color:{_GREEN}'>Response</div>
            <div class='hw-node-item'>safe &amp; filtered</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _gate_table() -> None:
    rows = ""
    for i, key in enumerate(ALL_GATE_KEYS, 1):
        info       = GATE_INFO[key]
        method_key = info["method"]
        method_lbl, method_color = METHOD_STYLES[method_key]
        cat        = info["category"]
        cat_color  = _GREEN if cat == "Input" else _PURPLE
        default    = _DEFAULT_MODES.get(key, "AUDIT")
        mode_color = _MODE_COLORS[default]
        sep        = (
            f"<tr><td colspan='7' style='padding:2px 0;border-bottom:none'>"
            f"<div style='font-size:0.60rem;color:{_DIM};letter-spacing:0.08em;"
            f"text-transform:uppercase;padding:8px 10px 2px 10px'>"
            f"─── Output Gates ───</div></td></tr>"
        ) if key == "sensitive_out" else ""

        rows += (
            f"{sep}"
            f"<tr>"
            f"<td style='color:{_DIM};text-align:right'>{i}</td>"
            f"<td style='font-weight:600;color:{_TEXT};white-space:nowrap'>{info['label']}</td>"
            f"<td>"
            f"<span class='hw-cat-badge' style='background:{cat_color}22;"
            f"color:{cat_color}'>{cat}</span>"
            f"</td>"
            f"<td>"
            f"<span class='hw-method-badge' style='background:{method_color}22;"
            f"color:{method_color}'>{method_lbl}</span>"
            f"</td>"
            f"<td style='color:{_DIM};white-space:nowrap'>{info['latency']}</td>"
            f"<td>"
            f"<span class='hw-mode-badge' style='background:{mode_color}22;"
            f"color:{mode_color}'>{default}</span>"
            f"</td>"
            f"<td style='color:#888;max-width:340px'>{info['description']}</td>"
            f"</tr>"
        )

    st.markdown(
        f"<table class='hw-table'>"
        f"<thead><tr>"
        f"<th>#</th><th>Gate</th><th>Type</th><th>Method</th>"
        f"<th>Latency</th><th>Default</th><th>What it does</th>"
        f"</tr></thead>"
        f"<tbody>{rows}</tbody>"
        f"</table>",
        unsafe_allow_html=True,
    )


def _mode_semantics() -> None:
    cards = [
        (
            "OFF",
            _DIM,
            "Gate is completely skipped — zero latency overhead.",
            "No scan, no metrics entry. Use when a gate's detection category is "
            "irrelevant to your deployment, e.g. turn off Refusal Detect if you "
            "aren't running red-team sessions.",
            "Example: Relevance gate OFF on a creative writing chatbot where "
            "off-topic responses are expected.",
        ),
        (
            "AUDIT",
            _AMBER,
            "Gate scans and logs its verdict — but never stops the pipeline.",
            "A BLOCK verdict is recorded in the telemetry panel and Gate Trace, "
            "but the prompt continues to the LLM (or the response continues to the "
            "user). Use AUDIT to monitor signals without impacting the user experience "
            "until you are confident in the gate's accuracy at your threshold.",
            "Example: Toxicity gate AUDIT — flag hostile inputs for later review "
            "without blocking users who are simply frustrated.",
        ),
        (
            "ENFORCE",
            _RED,
            "Gate scans and, on a BLOCK verdict, immediately halts the pipeline.",
            "For input gates, the LLM never receives the prompt. For output gates, "
            "the response is replaced with a rejection message. The pipeline returns "
            "immediately — subsequent gates do not run, saving latency. Use ENFORCE "
            "only when you are certain the gate's false-positive rate is acceptable.",
            "Example: Token Limit gate ENFORCE — oversized prompts can never reach "
            "the LLM regardless of content.",
        ),
    ]

    cols = st.columns(3)
    for col, (mode, color, headline, body, example) in zip(cols, cards):
        with col:
            st.markdown(
                f"<div class='hw-mode-card' style='border-color:{color}55'>"
                f"<div class='hw-mode-card-title'>"
                f"<span style='background:{color}22;color:{color};"
                f"padding:2px 8px;border-radius:4px;font-size:0.78rem'>{mode}</span>"
                f"</div>"
                f"<div class='hw-mode-card-body' style='color:{_TEXT};margin-bottom:6px'>"
                f"<strong>{headline}</strong>"
                f"</div>"
                f"<div class='hw-mode-card-body'>{body}</div>"
                f"<div class='hw-mode-card-example'>{example}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )


def _cost_latency_funnel() -> None:
    rows = [
        ("1", _GREEN,  "Static / Rules",
         "Regex Hot-Patch · Token Limit · Invisible Text · PII Restore",
         "< 1 ms each", "Pure Python. Run first — eliminate obvious bad inputs before "
         "any model is loaded."),
        ("2", _BLUE,   "ML Models (CPU)",
         "PII/Secrets · Injection Detect · Toxicity · Ban Topics · "
         "PII Out · Malicious URLs · Refusal · Bias · Relevance",
         "5 ms – 500 ms", "Local Hugging Face / Presidio models. Run only if cheaper "
         "gates pass. Parallelisable in future."),
        ("3", _PURPLE, "LLM / Ollama",
         "Llama Guard 3",
         "1 s – 10 s", "Highest accuracy, highest cost. Runs last in the input chain "
         "so it only evaluates prompts that already cleared all cheaper gates."),
    ]

    html_rows = ""
    for num, color, tier, gates, latency, note in rows:
        html_rows += (
            f"<div class='hw-funnel-row' style='border-color:{color}44'>"
            f"<div class='hw-funnel-num' style='color:{color}'>{num}</div>"
            f"<div style='flex:1'>"
            f"<div style='font-weight:700;color:{color};margin-bottom:3px'>{tier}"
            f"<span style='color:{_DIM};font-weight:400;margin-left:8px'>"
            f"avg {latency}</span></div>"
            f"<div style='color:{_DIM};font-size:0.65rem;margin-bottom:4px'>{gates}</div>"
            f"<div style='color:#888'>{note}</div>"
            f"</div>"
            f"</div>"
        )
    st.markdown(html_rows, unsafe_allow_html=True)


def _method_legend() -> None:
    items = list(METHOD_STYLES.items())
    cols = st.columns(len(items))
    for col, (key, (label, color)) in zip(cols, items):
        descriptions = {
            "static": "Pure Python — string ops, Unicode scans, token counting. "
                      "No model loading, no GPU. Instant results regardless of hardware.",
            "ml":     "Local Hugging Face / Presidio models running on CPU. "
                      "First call loads the model into RAM; subsequent calls are fast.",
            "llm":    "Full Ollama LLM inference. Requires the safety model to be "
                      "pulled (llama-guard3). Slowest but most contextually aware.",
        }
        col.markdown(
            f"<div class='hw-mode-card' style='border-color:{color}55'>"
            f"<div class='hw-mode-card-title'>"
            f"<span class='hw-method-badge' style='background:{color}22;"
            f"color:{color}'>{label}</span>"
            f"</div>"
            f"<div class='hw-mode-card-body'>{descriptions[key]}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )


# ── Public entry point ────────────────────────────────────────────────────────

def render() -> None:
    """Render the How It Works educational page."""
    _css()

    st.markdown("## 📖 How It Works")
    st.markdown(
        "The LLM Security Workbench wraps a local Ollama model in a "
        f"**{len(ALL_GATE_KEYS)}-gate security pipeline**. Every prompt passes through "
        "a chain of input gates before the LLM sees it; every response passes through "
        "a chain of output gates before you see it. All processing is local — no data "
        "leaves your machine."
    )

    # ── Pipeline diagram ──────────────────────────────────────────────────────
    st.markdown("<div class='hw-section'>Pipeline Flow</div>", unsafe_allow_html=True)
    _pipeline_diagram()

    # ── Method legend ─────────────────────────────────────────────────────────
    st.markdown("<div class='hw-section'>Detection Methods</div>", unsafe_allow_html=True)
    _method_legend()

    # ── Gate reference table ──────────────────────────────────────────────────
    st.markdown(
        "<div class='hw-section'>Gate Reference</div>",
        unsafe_allow_html=True,
    )
    st.caption(
        "Gates run in pipeline order (top to bottom). "
        "Input gates run before the LLM call; output gates run after. "
        "The Default mode is what the app ships with — you can change any gate "
        "in the sidebar."
    )
    _gate_table()

    # ── Mode semantics ────────────────────────────────────────────────────────
    st.markdown(
        "<div class='hw-section'>Gate Mode Semantics</div>",
        unsafe_allow_html=True,
    )
    _mode_semantics()

    # ── Cost / latency funnel ─────────────────────────────────────────────────
    st.markdown(
        "<div class='hw-section'>Cost / Latency Funnel</div>",
        unsafe_allow_html=True,
    )
    st.caption(
        "Gates are ordered cheapest-first so that expensive ML and LLM calls only "
        "run when lighter checks pass. This minimises median latency while preserving "
        "deep analysis for ambiguous inputs."
    )
    _cost_latency_funnel()

    st.markdown("<br>", unsafe_allow_html=True)
