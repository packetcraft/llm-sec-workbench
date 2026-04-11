# LLM Security Workbench — Master Plan Index

This file is the top-level entry point for all planning documents in this project.
It does not contain implementation detail — each domain has its own plan.

---

## Domains

### 1. Chatbot Security Pipeline
Guards a conventional LLM chatbot with a multi-stage input/output security pipeline.
**Threat model:** malicious *user* input and unsafe *model* output.

| Document | Purpose |
|:---------|:--------|
| [chatbot/PLAN.md](docs/chatbot/PLAN.md) | Full implementation plan, phase tracker, gate inventory |
| [chatbot/ARCHITECTURE.md](docs/chatbot/ARCHITECTURE.md) | PipelinePayload, gate sequence, design decisions |
| [chatbot/PLAYGROUND.md](docs/chatbot/PLAYGROUND.md) | Hands-on exercises — basic chat through live prompt injection |
| [chatbot/ADVERSARIAL.md](docs/chatbot/ADVERSARIAL.md) | Gate bypass analysis, OWASP/MITRE mapping, hardening playbook |

> Current status: Phase 4 partial. Gates 0–3 and A–F implemented. Prisma AIRS (Gate 4/H) upcoming.

---

### 2. Agentic Security
Monitors and audits Claude Code (AI agent) tool calls using Claude Code hook events and local Ollama guard models.
**Threat model:** a *compromised or manipulated agent* taking unsafe actions on the host system.

| Document | Purpose |
|:---------|:--------|
| [agentic/PLAN.md](docs/agentic/PLAN.md) | Design decisions, architecture overview, implementation phases |
| [agentic/ARCHITECTURE.md](docs/agentic/ARCHITECTURE.md) | Hook internals, JSONL schema, UI data flow, coverage matrix |
| [agentic/PLAYGROUND.md](docs/agentic/PLAYGROUND.md) | Hands-on exercises — setup, trigger blocks, review audit log |
| [agentic/ADVERSARIAL.md](docs/agentic/ADVERSARIAL.md) | Hook bypass techniques, guard model evasion, MITRE ATLAS mapping |

> Current status: Design complete. Implementation not yet started.

---

### 3. UI & Telemetry
UI enhancements and instrumentation panels for the Chat Workbench.

| Document | Purpose |
|:---------|:--------|
| [ui/TELEMETRY_PLAN.md](docs/ui/TELEMETRY_PLAN.md) | Live Telemetry Panel redesign — right-side column with gate latency, pipeline summary, token chart, Ollama timing breakdown, model info pills, memory countdown |

> Current status: Parked. Phase 5 baseline implemented (inline badges, context bar, sidebar hw panel). Full panel redesign not yet started.

---

## Shared Resources

| File | Purpose |
|:-----|:--------|
| [README.md](README.md) | Project overview, feature list, quick start |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Installation, environment setup, Docker, agentic hook setup |
| [config.yaml](config.yaml) | Runtime config — models, gate thresholds, audit path |
| [.env.example](.env.example) | Environment variable template |
