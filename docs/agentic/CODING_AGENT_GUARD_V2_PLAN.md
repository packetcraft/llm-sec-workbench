# Coding Agent Guard — V2 Development Roadmap

This document outlines the proposed expansion of the **Coding Agent Guard** from a "Passive Monitor" to an "Active Defense System." These features aim to provide deeper security for autonomous agents that write, execute, and deploy code.

---

## 🛡️ Executive Summary
The next generation of the Coding Agent Guard will focus on **Static Analysis**, **Runtime Isolation**, and **Supply Chain Integrity**. By moving beyond simple text classification, we can detect vulnerabilities that are semantically valid but structurally dangerous.

---

## 1. Phase 3: Static Analysis Guard (Active Linting)
Currently, `Write` and `Edit` tools are evaluated as raw text by the LLM. Phase 3 introduces structural code verification.

### 1.1 Automated Security Scanning
- **Mechanism**: Intercept `Write` and `Edit` calls. Before the guard model runs, extract the proposed code and pipe it to a language-specific scanner.
- **Tooling**:
    - **Python**: `bandit` (finds common security issues).
    - **JavaScript/TypeScript**: `eslint-plugin-security`.
    - **Go**: `gosec`.
- **Logic**: If the scanner returns a `High` or `Critical` severity finding (e.g., hardcoded credentials, use of `eval()`, or SQL injection patterns), the guard issues an automatic **BLOCK**.

### 1.2 Type-Safe Integrity Check
- **Mechanism**: Ensure that the agent's code changes don't break the build.
- **Logic**: For languages like TypeScript or Rust, run a background `tsc --noEmit` or `cargo check` on a temporary clone of the file. This prevents "Syntactic Injections" that might crash the main application.

---

## 2. Phase 4: Runtime Sandbox & Environment Isolation
Currently, the guard runs in the same environment as the agent. Phase 4 moves execution to a restricted container.

### 2.1 Tool-Call Wrapping
- **Mechanism**: Every `Bash` command is automatically wrapped in a containerized sandbox.
- **Implementation**:
    - Instead of: `sh -c "rm -rf /tmp/data"`
    - Guard executes: `docker run --rm -v $(pwd):/workspace -w /workspace security-sandbox sh -c "rm -rf /tmp/data"`
- **Benefit**: Even if an agent bypasses the Action Guard, it cannot escape the container to access host SSH keys, environment variables, or other projects.

### 2.2 Network Egress Filtering
- **Mechanism**: Restrict `WebFetch` and `Bash` (curl/wget) to an explicit allowlist of domains.
- **Logic**: Block any attempt to send data to unknown IPs or "canary tokens" unless specifically authorized in `config.yaml`.

---

## 3. Phase 5: Supply Chain & Dependency Guard
Agents often install packages to solve problems. This is a prime vector for supply chain attacks.

### 3.1 Malicious Package Detection
- **Mechanism**: Intercept `pip install`, `npm install`, and `cargo add`.
- **Logic**: Check requested packages against:
    - **Blocklist**: Known typosquatting packages (e.g., `requesst` instead of `requests`).
    - **Safety Score**: Use OpenSSF Scorecard or Snyk API to verify package health.
- **Verdict**: BLOCK installation of packages with low reputation or known CVEs.

---

## 4. Phase 6: Exfiltration & Entropy Detection
Detecting sensitive data leaving the system in a way that bypasses regex.

### 4.1 High-Entropy Payload Analysis
- **Mechanism**: Analyze the data payloads in `PostToolUse` (outputs) and `WebFetch` (inputs).
- **Logic**: Calculate the Shannon Entropy of the data. High entropy in a non-binary file suggests encrypted or compressed exfiltration of sensitive data (like a `.git` folder or private keys).
- **Verdict**: Flag high-entropy payloads for Human-in-the-Loop review.

---

## 5. Phase 7: Human-in-the-Loop (HITL) Escalation
Moving from binary ALLOW/BLOCK to a collaborative security model.

### 5.1 Interactive Approval UI
- **Mechanism**: Add a `PENDING` state to the guard.
- **Workflow**:
    1. Guard LLM returns `UNCERTAIN` or `HIGH_RISK_ALLOW`.
    2. The hook script pauses and triggers a Streamlit notification.
    3. The user sees the command and the LLM's concern in the **Live Feed**.
    4. The user clicks **Approve** or **Deny**.
    5. The hook returns the decision to the agent.

---

## 6. Phase 8: Cross-Agent Context Tracking
Detecting "Confused Deputy" attacks where one agent tricks another.

### 6.1 Injection Lineage
- **Mechanism**: Track the "provenance" of data.
- **Logic**: If Agent A (e.g., a Web Researcher) fetches a page containing an injection, and Agent B (e.g., a Coder) reads that output later, the guard should flag the data as `UNTRUSTED_EXTERNAL`.
- **Benefit**: Prevents an injection from "sleeping" in a file and triggering later when a more powerful agent reads it.

---

## 7. Architectural Evolution: Repository Carve-Out
The **Coding Agent Guard** is evolving from a submodule of the Security Workbench into a standalone security primitive. **This carve-out is the immediate next step before implementing V2 features.**

### 7.1 Reasoning for Separation
- **Value Proposition**: The workbench is a diagnostic/research tool; the Guard is a production-grade defense tool for local systems.
- **Portability**: Users should be able to install the Guard as a lightweight CLI/hook without pulling in the entire red-teaming infrastructure and UI.
- **Simplified Installation**: Transitioning to a package-based installation (e.g., `pip install coding-agent-guard`) lowers the barrier to entry for everyday developers using Claude Code or Gemini CLI.
- **Independent Versioning**: Security rules and bypass fixes can be released on a different cadence than the workbench.

### 7.2 Standalone Structure ("Coding-Agent-Guard")
If carved out, the repository will be structured as a dedicated package:
1.  **`coding_agent_guard/core`**: The main hook logic (derived from `hooks/agentic_guard.py`).
2.  **`coding_agent_guard/rules`**: Decoupled security rules (regex patterns, protected paths) stored in YAML/JSON for easy updates.
3.  **`coding_agent_guard/adapters`**: Specialized handlers for different agents (Claude Code, Gemini CLI, GitHub Copilot CLI).
4.  **Telemetry Bridge**: A standard interface to send audit logs to the `llm-sec-workbench` UI or other SOC platforms.

---

## 8. Implementation Priorities

| Priority | Feature | Effort | Impact |
| :--- | :--- | :--- | :--- |
| **P0** | **Repository Carve-Out (Standalone)** | Medium | High |
| **P0** | **Static Analysis Guard** | Medium | High |
| **P0** | **Interactive Approval (HITL)** | Medium | High |
| **P1** | **Supply Chain Guard** | Low | Medium |
| **P1** | **Runtime Sandbox** | High | Extreme |
| **P2** | **Entropy Detection** | Medium | Medium |
| **P3** | **Cross-Agent Lineage** | High | High |
