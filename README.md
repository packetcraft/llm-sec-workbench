# LLM Security Workbench (Local Edition)

> An extensible, locally-hosted web application for testing and educating about LLM security. Configure a multi-stage Security Pipeline, measure defense efficacy and latency, and run static and dynamic red-team campaigns — all on your own hardware.

---

## Features

- **22-Gate, 6-Layer Security Pipeline** — input and output gates across Static, ML, LLM Judge (General + Specialised), and Cloud tiers, each independently switchable between `OFF`, `AUDIT`, and `ENFORCE` modes.
- **Stateful `PipelinePayload`** — Upstream mutations (e.g., PII masking) are preserved without breaking downstream classifiers.
- **Cost/Latency Funnel** — L0 static rules run first (< 1 ms); cloud gates run last (0.5–2 s). Expensive checks only fire when cheaper ones pass.
- **LLM-as-Judge (Configurable)** — Semantic Guard uses a user-editable safety system prompt against any Ollama model. Little Canary uses a behavioral canary probe to detect novel jailbreaks at runtime.
- **Cloud Tier (Optional)** — AIRS Inlet + AIRS Dual connect to Palo Alto Networks AI Runtime Security for URL/IP reputation and enterprise DLP. Both gates degrade to SKIP when no API key is configured.
- **Static Fuzzing** — Batch-run predefined or imported malicious payloads; export OWASP-mapped Markdown reports.
- **Dynamic PAIR Red Teaming** — Attacker LLM iteratively refines prompts against the pipeline using the Chao et al. (2023) algorithm.
- **Auto-Harden** — On a successful breach, a Defender LLM rewrites your system prompt to patch the identified vector.
- **Hardware Telemetry** — Live VRAM/RAM usage and tokens-per-second polled from Ollama every 5 seconds via `st.fragment`.
- **Demo Mode** — One toggle hides all security instrumentation for clean end-user demonstrations.
- **RAG Simulation** — Inject a simulated retrieved document into the LLM context to test indirect prompt injection.
- **Hot-Patching** — Add custom block phrases in the sidebar for instant regex-based WAF simulation.
- **Coding Agent Guard** — Real-time hook interception for Claude Code and Gemini CLI tool calls with allowlist, path, regex, and LLM-based verdict tiers. Full audit log with live feed, explorer, and dashboard.

---

## Security Gate Summary

### Input Gates — 13 gates across 6 layers

| Layer | Key | Tool | Defense Target | Default |
|:------|:----|:-----|:---------------|:--------|
| L0 Static | `custom_regex` | Python regex | Hot-patch block phrases / WAF simulation | AUDIT |
| L0 Static | `token_limit` | tiktoken | Prompt length — context exhaustion & injection hiding | ENFORCE |
| L0 Static | `invisible_text` | Unicode Cf/Cc scan | Hidden Unicode steganography | ENFORCE |
| L1 Pattern | `fast_scan` | Presidio + detect-secrets (CPU) | PII masking + secrets/credential detection | AUDIT |
| L1 Pattern | `gibberish` | Gibberish-Detector HF (CPU) | Noise-flood and token-waste attacks | AUDIT |
| L2 ML | `language_in` | XLM-RoBERTa (CPU) | Multilingual jailbreak bypass | AUDIT |
| L2 ML | `classify` | protectai/DeBERTa-v3 (CPU) | Injection & jailbreak classification | AUDIT |
| L2 ML | `toxicity_in` | RoBERTa HF classifiers (CPU) | Hostile tone / extreme negative sentiment | AUDIT |
| L2 ML | `ban_topics` | DeBERTa zero-shot NLI (CPU) | Operator-defined forbidden subject areas | AUDIT |
| L3 LLM | `semantic_guard` | Any Ollama model (configurable) | Intent-level threats, novel jailbreaks, social engineering | AUDIT |
| L3 LLM | `little_canary` | qwen2.5:1.5b via Ollama | Behavioral injection probe — compromise residue detection | AUDIT |
| L4 LLM | `mod_llm` | Llama Guard 3 via Ollama | Broad safety taxonomy — S1–S14 harm categories | AUDIT |
| L5 Cloud | `airs_inlet` | Palo Alto AIRS API | URL/IP reputation, agent abuse, enterprise policy — fail-closed | AUDIT |

### Inference

| | | |
|:-|:-|:-|
| **Target LLM** | Ollama (local) | Main generation task |

### Output Gates — 8 gates

| Layer | Key | Tool | Defense Target | Default |
|:------|:----|:-----|:---------------|:--------|
| O·ML | `sensitive_out` | Presidio (CPU) | PII the LLM generated itself | AUDIT |
| O·ML | `malicious_urls` | Heuristic + ML classifier (CPU) | Phishing links & malware URLs in responses | ENFORCE |
| O·ML | `no_refusal` | DistilRoBERTa (CPU) | Model refusal detection (red-team signal) | AUDIT |
| O·ML | `bias_out` | DistilRoBERTa classifiers (CPU) | Biased / toxic model output monitoring | AUDIT |
| O·ML | `relevance` | BAAI/bge embeddings (CPU) | Off-topic responses & jailbreak drift | AUDIT |
| O·ML | `language_same` | XLM-RoBERTa (CPU) | Response language drift / multilingual jailbreak | AUDIT |
| O·Static | `deanonymize` | Presidio Vault | Restore user PII placeholders in response | ENFORCE |
| O·Cloud | `airs_dual` | Palo Alto AIRS API | Response DLP masking, URL cats, hallucination — fail-open | AUDIT |

> **Cloud tier (L5) is optional.** Both AIRS gates degrade to SKIP when `AIRS_API_KEY` is not configured — all 20 local gates run fully offline.

---

## Tech Stack

| Layer | Technology |
|:------|:-----------|
| UI / Web Framework | [Streamlit](https://streamlit.io/) |
| LLM Inference | [Ollama](https://ollama.com/) (local) |
| PII / Secrets Detection | [Microsoft Presidio](https://github.com/microsoft/presidio) + detect-secrets |
| ML Gate Library | [llm-guard](https://github.com/protectai/llm-guard) |
| Injection Classifier | [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) |
| Language Detection | [papluca/xlm-roberta-base-language-detection](https://huggingface.co/papluca/xlm-roberta-base-language-detection) |
| Relevance Embeddings | [BAAI/bge-base-en-v1.5](https://huggingface.co/BAAI/bge-base-en-v1.5) |
| Safety Moderation LLM (L4) | `llama-guard3` via Ollama |
| LLM Judge — General (L3) | Any Ollama model — recommended `shieldgemma:2b` |
| Behavioral Canary (L3) | [little-canary](https://github.com/hermeslabs/little-canary) + `qwen2.5:1.5b` |
| Cloud Scanning (L5, optional) | [Palo Alto Networks AIRS](https://www.paloaltonetworks.com/network-security/ai-runtime-security) |
| Configuration | `config.yaml` + `.env` |
| Persistence | SQLite via SQLAlchemy |

---

## Quick Start

See **[docs/QUICKSTART.md](docs/QUICKSTART.md)** for the full setup guide. Once running, try the **[docs/chatbot/PLAYGROUND.md](docs/chatbot/PLAYGROUND.md)** for a guided walkthrough — including how to execute a live prompt injection attack against an undefended model.

### Prerequisites

- [Ollama](https://ollama.com/download) installed and running
- Python 3.10+
- *(Optional)* Docker + Docker Compose

### 1-Click Launch (Windows)

```bat
start.bat
```

### 1-Click Launch (Mac/Linux)

```sh
./start.sh
```

### Manual

```bash
# 1. Clone and enter the repo
git clone https://github.com/your-org/llm-sec-workbench.git
cd llm-sec-workbench

# 2. Copy environment template
cp .env.example .env

# 3. Install dependencies (CPU-only PyTorch)
pip install -r requirements.txt

# 4. Launch
streamlit run app.py
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

| Variable | Description | Required |
|:---------|:------------|:---------|
| `OLLAMA_HOST` | URL of the Ollama instance (default: `http://localhost:11434`) | Yes |
| `AIRS_API_KEY` | Palo Alto Networks AIRS API key (`x-pan-token` from Strata Cloud Manager) | Only for L5 cloud gates |
| `AIRS_PROFILE` | AIRS AI security profile name configured in Strata Cloud Manager | Only for L5 cloud gates |

Edit `config.yaml` to set active model names and default gate thresholds. Both cloud gates degrade to SKIP when `AIRS_API_KEY` is absent — no change to `.env` is needed for local-only operation.

---

## Project Structure

```
llm-sec-workbench/
├── app.py                  # Streamlit entry point
├── config.yaml             # Runtime configuration
├── requirements.txt        # Locked dependencies
├── core/                   # Pipeline engine
│   ├── payload.py          # PipelinePayload dataclass
│   ├── pipeline.py         # PipelineManager orchestrator
│   └── llm_client.py       # Ollama client wrapper
├── gates/                  # Chain-of-Responsibility gate implementations
├── ui/                     # Streamlit view components
├── redteam/                # Static fuzzing and dynamic PAIR engine
├── data/                   # Prebuilt static payloads
├── tests/                  # Pytest unit tests
└── docs/                   # Guides and architecture reference
```

---

## Architecture

See **[docs/chatbot/ARCHITECTURE.md](docs/chatbot/ARCHITECTURE.md)** for a detailed explanation of the `PipelinePayload` object, the gate sequence, and design decisions.

### Chatbot Security

| Doc | Purpose |
|:----|:--------|
| [QUICKSTART.md](docs/QUICKSTART.md) | Installation, environment setup, Docker, agentic hook setup |
| [chatbot/PLAYGROUND.md](docs/chatbot/PLAYGROUND.md) | Hands-on tutorial — basic chat through live prompt injection |
| [chatbot/ARCHITECTURE.md](docs/chatbot/ARCHITECTURE.md) | Pipeline internals, gate interface, design decisions |
| [chatbot/ADVERSARIAL.md](docs/chatbot/ADVERSARIAL.md) | Gate bypass analysis, OWASP/MITRE mapping, attack chains, hardening playbook |

### Coding Agent Guard

| Doc | Purpose |
|:----|:--------|
| [agentic/PLAN.md](docs/agentic/PLAN.md) | Design decisions, architecture overview, implementation phases |
| [agentic/ARCHITECTURE.md](docs/agentic/ARCHITECTURE.md) | Hook internals, JSONL schema, UI data flow, coverage matrix |
| [agentic/PLAYGROUND.md](docs/agentic/PLAYGROUND.md) | Hands-on exercises — setup, trigger blocks, review audit log |
| [agentic/ADVERSARIAL.md](docs/agentic/ADVERSARIAL.md) | Hook bypass techniques, guard model evasion, MITRE ATLAS mapping |

---

## Red Teaming

### Static Fuzzing
Select payload categories and severities, run them all through the pipeline, and export an OWASP Top 10 for LLMs–mapped Markdown report.

### Dynamic PAIR
An Attacker LLM iteratively refines prompts against the live pipeline. The attack loop runs until a breach is detected or the maximum iteration count is reached. Full iteration logs are exportable as JSON or Markdown.

### Threat Data Import
- **Garak:** Upload `.report.jsonl` or `.hitlog.jsonl` files directly.
- **JailbreakBench:** Fetch verified jailbreaks from the official GitHub artifacts repository.

---

## License

This project is intended for security research and educational use. Use responsibly and only against systems you are authorized to test.
