# Contributing to LLM Security Workbench

Thank you for your interest in contributing. This document covers how to set up a development environment, the conventions used in this project, and the process for submitting changes.

---

## Code of Conduct

Be respectful and constructive. Contributions that introduce backdoors, exfiltration logic, or attack vectors targeting real users will be rejected.

---

## Development Setup

```bash
git clone https://github.com/your-org/llm-sec-workbench.git
cd llm-sec-workbench

# Create an isolated environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install all dependencies
pip install -r requirements.txt

# Copy environment config
cp .env.example .env
```

Ensure [Ollama](https://ollama.com/download) is installed and running before launching the app or running tests.

---

## Project Layout

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design. The short version:

| Directory | Responsibility |
|:----------|:---------------|
| `core/` | `PipelinePayload`, `PipelineManager`, Ollama client |
| `gates/` | Chain-of-Responsibility gate implementations |
| `ui/` | Streamlit view components |
| `redteam/` | Static fuzzer and dynamic PAIR engine |
| `tests/` | Pytest unit tests |

---

## Adding a New Gate

1. Create your class in the appropriate file under `gates/` (or a new file if it doesn't fit).
2. Inherit from `SecurityGate` (defined in `gates/base_gate.py`).
3. Implement the `scan(self, payload: PipelinePayload) -> PipelinePayload` method.
4. Follow the error-handling contract — wrap all logic in `try-except` and never let a gate exception propagate to the pipeline.
5. Append a metrics dict `{gate_name, latency_ms, score, verdict}` to `payload.metrics`.
6. Store raw request/response JSON in `payload.raw_traces[self.name]`.
7. Add a corresponding unit test in `tests/test_gates.py`.

---

## Running Tests

```bash
pytest
```

Tests must pass locally before submitting a pull request. The CI pipeline will also run them automatically.

---

## Conventions

- **Python version:** 3.10+
- **Formatting:** Follow PEP 8. Use 4-space indentation.
- **Type hints:** Required for all public function signatures.
- **Docstrings:** Required for all classes and public methods (Google style).
- **No GPU dependencies in tests:** All test mocks must run on CPU only.
- **No secrets in code:** Use `.env` and `config.yaml`. Never hardcode API keys.

---

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
   ```bash
   git checkout -b feature/my-new-gate
   ```
2. Make your changes and add/update tests.
3. Ensure `pytest` passes with no failures.
4. Open a pull request against `main`. Fill out the PR template completely.
5. A maintainer will review your PR. Please respond to review comments within 7 days.

---

## Reporting Bugs

Use the **Bug Report** issue template. For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do not open a public issue.

## Requesting Features

Use the **Feature Request** issue template. Describe the use case, not just the solution.
