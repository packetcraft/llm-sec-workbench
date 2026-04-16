# LLM Security Workbench (Local Edition)

> An extensible, locally-hosted web application for testing and educating about LLM security. Configure a multi-stage Security Pipeline, measure defense efficacy and latency, and run static and dynamic red-team campaigns — all on your own hardware.

---

## Features

- **Configurable Security Pipeline** — 12 gates across input and output stages, each independently switchable between `OFF`, `AUDIT`, and `ENFORCE` modes.
- **Stateful `PipelinePayload`** — Upstream mutations (e.g., PII masking) are preserved without breaking downstream classifiers.
- **Cost/Latency Funnel** — Cheapest and fastest checks run first; heavy LLM-backed gates run last.
- **Static Fuzzing** — Batch-run predefined or imported malicious payloads; export OWASP-mapped Markdown reports.
- **Dynamic PAIR Red Teaming** — Attacker LLM iteratively refines prompts against the pipeline using the Chao et al. (2023) algorithm.
- **Auto-Harden** — On a successful breach, a Defender LLM rewrites your system prompt to patch the identified vector.
- **API Inspector** — Side-by-side raw JSON request/response traces for every active gate.
- **Hardware Telemetry** — Live VRAM/RAM usage and tokens-per-second polled from Ollama every 5 seconds via `st.fragment`.
- **Demo Mode** — One toggle hides all security instrumentation for clean end-user demonstrations.
- **RAG Simulation** — Inject a simulated retrieved document into the LLM context to test indirect prompt injection.
- **Hot-Patching** — Add custom block phrases in the sidebar for instant regex-based WAF simulation.

---

## Security Gate Summary

### Input Gates

| Key | Gate | Tool | Defense Target | Default Mode |
|:----|:-----|:-----|:---------------|:-------------|
| `custom_regex` | CustomRegexGate | Python regex (zero-ML) | Hot-patch block phrases / WAF simulation | AUDIT |
| `token_limit` | TokenLimitGate | tiktoken (zero-ML) | Prompt length — context exhaustion & injection hiding | ENFORCE |
| `invisible_text` | InvisibleTextGate | Unicode Cf/Cc scan (zero-ML) | Hidden Unicode steganography | ENFORCE |
| `fast_scan` | FastScanGate | llm-guard / Presidio (CPU) | PII masking + secrets/credential detection | AUDIT |
| `classify` | PromptGuardGate | DeBERTa-v3 ONNX (CPU) | Injection & jailbreak classification | AUDIT |
| `toxicity_in` | ToxicityInputGate | llm-guard HF classifiers (CPU) | Hostile tone / extreme negative sentiment | AUDIT |
| `ban_topics` | BanTopicsGate | llm-guard DeBERTa zero-shot (CPU) | Operator-defined forbidden subject areas | AUDIT |
| `mod_llm` | LlamaGuardGate | Llama Guard 3 via Ollama (LLM-as-a-judge) | Broad safety taxonomy — S1–S14 harm categories | AUDIT |

### Inference

| | | |
|:-|:-|:-|
| **Target LLM** | Ollama (local) | Main generation task |

### Output Gates

| Key | Gate | Tool | Defense Target | Default Mode |
|:----|:-----|:-----|:---------------|:-------------|
| `sensitive_out` | SensitiveGate | Presidio (CPU) | PII the LLM generated itself | AUDIT |
| `malicious_urls` | MaliciousURLsGate | Heuristic + llm-guard ML (CPU) | Phishing links & malware URLs in responses | ENFORCE |
| `no_refusal` | NoRefusalGate | llm-guard classifier (CPU) | Model refusal detection (red-team signal) | AUDIT |
| `bias_out` | BiasOutputGate | llm-guard classifiers (CPU) | Biased / toxic model output monitoring | AUDIT |
| `relevance` | RelevanceGate | BAAI embeddings (CPU) | Off-topic responses & jailbreak drift | AUDIT |
| `deanonymize` | DeanonymizeGate | llm-guard Vault (CPU) | Restore user PII placeholders in response | ENFORCE |

> **Phase 4 (partial):** Llama-Guard-3 (`mod_llm`) is implemented. Prisma AIRS (Cloud API) for enterprise DLP is upcoming.

---

## Tech Stack

| Layer | Technology |
|:------|:-----------|
| UI / Web Framework | [Streamlit](https://streamlit.io/) |
| LLM Inference | [Ollama](https://ollama.com/) (local) |
| Fast Scanning | [llm-guard](https://github.com/protectai/llm-guard) |
| Injection Classifier | [Meta Prompt-Guard-86M](https://huggingface.co/meta-llama/Prompt-Guard-86M) via `transformers` + ONNX |
| Safety Moderation LLM | `llama-guard3` via Ollama |
| Cloud Scanning | [Palo Alto Prisma AIRS](https://www.paloaltonetworks.com/) |
| Behavioral Probing | [little-canary](https://github.com/protectai/little-canary) |
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

| Variable | Description |
|:---------|:------------|
| `OLLAMA_HOST` | URL of the Ollama instance (default: `http://localhost:11434`) |
| `PANW_API_KEY` | Palo Alto Networks AIRS API key |

Edit `config.yaml` to set active model names, AIRS profile, and default gate thresholds.

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
