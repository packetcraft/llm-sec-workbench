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
    "gibberish":      "AUDIT",
    "language_in":    "AUDIT",
    "classify":       "AUDIT",
    "toxicity_in":    "AUDIT",
    "ban_topics":     "AUDIT",
    "semantic_guard": "AUDIT",
    "little_canary":  "AUDIT",
    "mod_llm":        "AUDIT",
    "airs_inlet":     "AUDIT",
    "sensitive_out":  "AUDIT",
    "malicious_urls": "ENFORCE",
    "no_refusal":     "AUDIT",
    "bias_out":       "AUDIT",
    "relevance":      "AUDIT",
    "language_same":  "AUDIT",
    "deanonymize":    "ENFORCE",
    "airs_dual":      "AUDIT",
}

# Layer assignment for Gate Reference table
_LAYER_MAP: dict[str, str] = {
    "custom_regex":   "L0",
    "token_limit":    "L0",
    "invisible_text": "L0",
    "fast_scan":      "L1",
    "gibberish":      "L1",
    "language_in":    "L2",
    "classify":       "L2",
    "toxicity_in":    "L2",
    "ban_topics":     "L2",
    "semantic_guard": "L3",
    "little_canary":  "L3",
    "mod_llm":        "L4",
    "airs_inlet":     "L5",
    "sensitive_out":  "O·ML",
    "malicious_urls": "O·ML",
    "no_refusal":     "O·ML",
    "bias_out":       "O·ML",
    "relevance":      "O·ML",
    "language_same":  "O·ML",
    "deanonymize":    "O·Static",
    "airs_dual":      "O·Cloud",
}


# ── Public entry point ────────────────────────────────────────────────────────

def render() -> None:
    """Render the Pipeline Reference page."""

    st.markdown("## 🔧 Pipeline Reference")

    # ── 0. Project intent ─────────────────────────────────────────────────────
    st.info(
        "The **LLM Security Workbench** is a local-first research and testing environment "
        "for understanding, probing, and defending AI language model deployments. "
        "Every prompt and response passes through a configurable **22-gate, 6-layer security pipeline**. "
        "Layers L0–L4 run entirely on your machine. "
        "The optional **Layer 5 Cloud** tier (AIRS Inlet + AIRS Dual) degrades to SKIP when no API key "
        "is configured — all local processing remains offline."
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
            st.markdown("##### 🛡️ Coding Agent Guard")
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
                "your target model, `llama-guard3`, and the LLM judge/canary models pulled. "
                "The optional AIRS cloud gates require an `AIRS_API_KEY` in `.env`. "
                "Coding Agent Guard and this page work without Ollama."
            )
            st.caption(
                "`ollama pull llama3`\n"
                "`ollama pull llama-guard3`\n"
                "`ollama pull shieldgemma:2b`\n"
                "`ollama pull qwen2.5:1.5b`"
            )

    # ── 1. Pipeline architecture ──────────────────────────────────────────────
    st.divider()
    st.markdown("#### Pipeline Architecture")
    st.caption(
        f"Every prompt passes through {len(INPUT_GATE_KEYS)} input gates before the LLM "
        f"sees it, and every response passes through {len(OUTPUT_GATE_KEYS)} output gates "
        "before you see it. A single ENFORCE gate in BLOCK state halts the pipeline immediately."
    )

    # Pure HTML/CSS pipeline diagram — no external JS dependencies.
    # Mermaid requires external CDN which is blocked inside st.html() iframes.
    def _layer_card(
        label: str,
        latency: str,
        gates: str,
        border_color: str,
        label_color: str,
        bg_color: str,
        badge: str = "",
        badge_color: str = "#555",
    ) -> str:
        badge_html = (
            f"<span style='background:{badge_color}22;color:{badge_color};"
            f"padding:1px 7px;border-radius:4px;font-size:0.65rem;font-weight:700;"
            f"margin-left:8px'>{badge}</span>"
            if badge else ""
        )
        return (
            f"<div style='display:flex;align-items:stretch;gap:6px;width:100%'>"
            f"<div style='flex:1;background:{bg_color};border:1px solid {border_color};"
            f"border-radius:8px;padding:10px 16px'>"
            f"<div style='font-weight:700;color:{label_color};font-size:0.82rem'>"
            f"{label}{badge_html}</div>"
            f"<div style='color:#7AA2F7;font-size:0.68rem;font-family:monospace;"
            f"margin:2px 0'>{latency}</div>"
            f"<div style='color:#888;font-size:0.72rem'>{gates}</div>"
            f"</div>"
            f"<div style='display:flex;align-items:center;padding:0 4px'>"
            f"<span style='color:#F7768E;font-size:0.65rem;font-weight:700;"
            f"white-space:nowrap'>&#8594; BLOCK</span>"
            f"</div>"
            f"</div>"
        )

    _connector = (
        "<div style='width:2px;height:14px;background:#2a2a4a;"
        "margin:0 auto'></div>"
    )
    _arrow = (
        "<div style='text-align:center;color:#3a3a6a;font-size:1rem;"
        "line-height:1;margin:-2px 0'>&#9660;</div>"
    )
    _endpoint = lambda text, color: (  # noqa: E731
        f"<div style='background:#1e1e2e;border:2px solid {color};"
        f"border-radius:20px;padding:7px 22px;color:{color};"
        f"font-weight:700;font-size:0.82rem;text-align:center;"
        f"margin:0 auto'>{text}</div>"
    )
    _divider_bar = (
        "<div style='width:100%;margin:8px 0;padding:8px 16px;"
        "background:#16213e;border:1px solid #2a3a5a;border-radius:8px;"
        "text-align:center;color:#56B6C2;font-weight:700;font-size:0.82rem;"
        "letter-spacing:0.05em'>&#9866; LLM Inference &#9866;</div>"
    )

    _cards = [
        # Input layers
        _endpoint("User Prompt", "#cdd6f4"),
        _connector, _arrow,
        _layer_card("L0 — Pre-flight", "< 1 ms",
                    "Regex Hot-Patch · Token Limit · Invisible Text",
                    "#2d4a2d", "#9ECE6A", "#0e1e0e"),
        _connector, _arrow,
        _layer_card("L1 — Pattern Scanning", "1 – 10 ms",
                    "PII / Secrets · Gibberish Detect",
                    "#1a2a4a", "#7AA2F7", "#0a1020"),
        _connector, _arrow,
        _layer_card("L2 — ML Classifiers", "50 – 500 ms",
                    "Language Enforce · Injection Detect · Toxicity · Ban Topics",
                    "#1a2a4a", "#7AA2F7", "#0a1020"),
        _connector, _arrow,
        _layer_card("L3 — LLM Judge: General", "0.5 – 3 s",
                    "Semantic Guard · Little Canary",
                    "#2a1a4a", "#BB9AF7", "#120a20"),
        _connector, _arrow,
        _layer_card("L4 — LLM Judge: Specialised", "1 – 10 s",
                    "Llama Guard 3",
                    "#2a1a4a", "#BB9AF7", "#120a20"),
        _connector, _arrow,
        _layer_card("L5 — Cloud", "0.5 – 2 s",
                    "AIRS Inlet ☁",
                    "#3a2a0a", "#FFB86C", "#1a1200",
                    badge="optional", badge_color="#FFB86C"),
        _connector,
        _divider_bar,
        _connector, _arrow,
        # Output layers
        _layer_card("Output — ML Scanners", "50 – 500 ms",
                    "PII Out · URLs · Refusal · Bias · Relevance · Lang Match",
                    "#1a2a4a", "#7AA2F7", "#0a1020"),
        _connector, _arrow,
        _layer_card("Output — Post-process", "< 1 ms",
                    "PII Restore",
                    "#2d4a2d", "#9ECE6A", "#0e1e0e"),
        _connector, _arrow,
        _layer_card("Output — Cloud", "0.5 – 2 s",
                    "AIRS Dual ☁",
                    "#3a2a0a", "#FFB86C", "#1a1200",
                    badge="optional", badge_color="#FFB86C"),
        _connector, _arrow,
        _endpoint("Response Delivered", "#9ECE6A"),
    ]

    st.html(
        "<div style='display:flex;justify-content:center;padding:8px 0'>"
        "<div style='display:flex;flex-direction:column;align-items:stretch;"
        "width:min(560px,100%)'>"
        + "".join(_cards)
        + "</div></div>"
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
            "Used for PII/Secrets, Gibberish, Injection Detect, Toxicity, Ban Topics, and all output ML gates."
        ),
        "llm": (
            "Full Ollama LLM inference. Covers two sub-tiers: "
            "L3 General judges (Semantic Guard with editable policy + Little Canary behavioral probe) "
            "and L4 Specialised (Llama Guard 3, fixed S1–S14 taxonomy). "
            "Placed after all ML gates so Ollama calls only run when cheaper checks pass."
        ),
        "cloud": (
            "Outbound call to Palo Alto Networks AI Runtime Security (AIRS). "
            "Requires an API key and internet access. Covers URL/IP reputation, enterprise DLP policy, "
            "and threat intelligence not available locally. "
            "Both cloud gates degrade to SKIP when no key is configured — "
            "all local layers (L0–L4) run unaffected."
        ),
    }

    d1, d2, d3, d4 = st.columns(4)
    for col, (key, (label, color)) in zip([d1, d2, d3, d4], METHOD_STYLES.items()):
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
                "<tr><td colspan='7' style='padding:4px 12px 2px;border:none'>"
                "<div style='font-size:0.62rem;font-weight:700;letter-spacing:0.08em;"
                "text-transform:uppercase;color:#555566;border-top:1px solid #2a2a3a;"
                "padding-top:10px;margin-top:4px'>Output Gates</div></td></tr>"
            )

        layer     = _LAYER_MAP.get(key, "")
        rows_html += (
            "<tr style='border-bottom:1px solid #1e1e2e'>"
            f"<td style='padding:10px 12px;font-weight:700;color:#cdd6f4;white-space:nowrap'>"
            f"{info['label']}</td>"
            f"<td style='padding:10px 8px;white-space:nowrap'>"
            f"{_badge(layer, _METHOD_COLOR[method_key])}</td>"
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
              <th>Gate</th><th>Layer</th><th>Type</th><th>Method</th>
              <th>Latency</th><th>Default</th><th>Description</th>
            </tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </div>
        """
    )

    st.html(
        """
        <div style='margin-top:10px;padding:10px 14px;border:1px solid #2a2a3a;
             border-radius:6px;background:rgba(122,162,247,0.04)'>
          <div style='font-size:0.60rem;font-weight:700;letter-spacing:0.10em;
               text-transform:uppercase;color:#555566;margin-bottom:8px'>
            Open-Source Attribution
          </div>
          <div style='display:flex;flex-wrap:wrap;gap:6px 24px;font-size:0.72rem;color:#888'>
            <span>
              <span style='color:#7AA2F7;font-weight:600'>Gate pipeline architecture</span>
              &nbsp;·&nbsp;
              <a href='https://github.com/protectai/llm-guard'
                 style='color:#7AA2F7;text-decoration:none'
                 target='_blank'>protectai/llm-guard</a>
            </span>
            <span>
              <span style='color:#7AA2F7;font-weight:600'>PII / Secrets detection &amp; restore</span>
              &nbsp;·&nbsp;
              <a href='https://github.com/microsoft/presidio'
                 style='color:#7AA2F7;text-decoration:none'
                 target='_blank'>microsoft/presidio</a>
            </span>
            <span>
              <span style='color:#7AA2F7;font-weight:600'>Injection classifier</span>
              &nbsp;·&nbsp;
              <a href='https://github.com/microsoft/deberta'
                 style='color:#7AA2F7;text-decoration:none'
                 target='_blank'>microsoft/deberta</a>
              <span style='color:#555566'> (base)</span>
              &nbsp;+&nbsp;
              <a href='https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2'
                 style='color:#7AA2F7;text-decoration:none'
                 target='_blank'>protectai fine-tune</a>
            </span>
            <span>
              <span style='color:#7AA2F7;font-weight:600'>Safety classifier</span>
              &nbsp;·&nbsp;
              <a href='https://huggingface.co/meta-llama/Llama-Guard-3-8B'
                 style='color:#7AA2F7;text-decoration:none'
                 target='_blank'>meta-llama/Llama-Guard-3-8B</a>
            </span>
            <span>
              <span style='color:#7AA2F7;font-weight:600'>Relevance embeddings</span>
              &nbsp;·&nbsp;
              <a href='https://huggingface.co/BAAI/bge-base-en-v1.5'
                 style='color:#7AA2F7;text-decoration:none'
                 target='_blank'>BAAI/bge-base-en-v1.5</a>
            </span>
          </div>
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
            "L0 — Pre-flight",
            "< 1 ms each",
            "Regex Hot-Patch · Token Limit · Invisible Text",
            "Pure Python — no model loading, no GPU. Run first to eliminate obvious bad inputs "
            "before any dependencies are touched. Always-on regardless of hardware.",
        ),
        (
            "L1 — Pattern Scanning",
            "1 – 10 ms",
            "PII / Secrets · Gibberish Detect",
            "Static ML (Presidio NER + detect-secrets + small HuggingFace classifier). "
            "No GPU needed. Catches structured data leaks and noise-flood attacks "
            "before heavier models load.",
        ),
        (
            "L2 — ML Classifiers",
            "50 – 500 ms",
            "Language Enforce · Injection Detect · Toxicity · Ban Topics",
            "Local HuggingFace CPU models. First call loads the model into RAM; "
            "subsequent calls are significantly faster. Covers multilingual bypass, "
            "injection patterns, hostile tone, and topic scope.",
        ),
        (
            "L3 — LLM Judge: General",
            "0.5 – 3 s",
            "Semantic Guard · Little Canary",
            "Configurable Ollama judge with an editable safety prompt, plus a behavioral canary probe. "
            "Catches intent-level threats and novel jailbreaks that fixed classifier datasets have never seen. "
            "Runs before Llama Guard because smaller models (shieldgemma:2b, qwen2.5:1.5b) are faster.",
        ),
        (
            "L4 — LLM Judge: Specialised",
            "1 – 10 s",
            "Llama Guard 3",
            "Fixed MLCommons S1–S14 harm taxonomy. Highest local accuracy — placed last in the local "
            "chain so it only evaluates prompts that cleared all cheaper gates. "
            "Requires `ollama pull llama-guard3`.",
        ),
        (
            "L5 — Cloud (optional)",
            "0.5 – 2 s",
            "AIRS Inlet",
            "Palo Alto Networks AI Runtime Security. Adds URL/IP reputation and enterprise DLP policy "
            "that cannot be replicated locally. Placed last — cloud round-trip cost is only paid when "
            "all local gates (L0–L4) pass. Degrades to SKIP when no AIRS_API_KEY is configured.",
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
