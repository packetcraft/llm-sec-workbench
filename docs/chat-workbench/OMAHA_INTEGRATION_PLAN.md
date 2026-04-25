# Omaha-Lab Integration Plan

## Overview

This document outlines the architecture, implementation stages, and technical tasks required to integrate key agentic and security capabilities from the `Omaha-Lab` repository into `llm-sec-workbench`. This plan is designed to be handed over to a coding agent for execution.

*Note: Human-in-the-Loop (HITL) tool authorization has been explicitly excluded from this integration phase.*

## Target Capabilities

1. **LangGraph ReAct Agent Workflows**: Introduce an "Agent Sandbox" where users can test complex, multi-step agent reasoning and tool usage against prompt injections.
2. **Transparent "Thinking" Visualization**: Visually expose the LLM's internal monologue (Chain of Thought), tool planning, and tool execution stages directly in the UI. This is critical for educational purposes to help users understand *how* an agent makes decisions and *where* a prompt injection derails its logic.
3. **Canary Token Detection**: Add an output guardrail to detect sensitive canary tokens exfiltrated by an Attacker LLM.
4. **Configurable Agent Personas**: Migrate pre-built agent profiles (e.g., `hr_assistant`, `security_analyst`) to test different behavioral vulnerabilities.
5. **ChromaDB for Advanced RAG**: Upgrade the current RAG simulation with a real vector database (ChromaDB) to accurately test Data Poisoning and Indirect Prompt Injection (IPI) attacks.

---

## Architecture & Integration Points

- **Gates**: New gates will be added to the `gates/` directory (e.g., `gates/output/canary_token.py`).
- **Data**: Personas will be stored in a new `data/personas/` directory as YAML/JSON configuration files.
- **RAG Engine**: A new vector store manager will be implemented in `core/vector_store.py` wrapping ChromaDB.
- **Agent Sandbox**: The ReAct agent logic will be placed in `redteam/agent_sandbox.py` and visualized via a new Streamlit page `ui/pages/agent_sandbox.py`.

---

## Hardware & Model Marshalling Strategy

Given an 8GB VRAM constraint (e.g., RTX 3070), running multiple large models simultaneously (Agent + Guard) will cause RAM spillover and severe latency. To keep all operations entirely on the GPU and maintain a fast, responsive UI, the following model configuration is required:

1. **Pipeline Guard Model**: Use `shieldgemma:2b` (1.7 GB) instead of heavier models like `llama-guard3`. This acts as a fast, VRAM-friendly LLM-as-Judge for the security gates.
2. **RAG Embedder**: Use `nomic-embed-text:latest` (274 MB). It is incredibly lightweight and easily fits in VRAM alongside the agent and guard models.
3. **Reasoning Agent**: 
   - *Preferred (Best Tool Calling)*: `qwen2.5:7b` (4.7 GB). When paired with `shieldgemma:2b` and `nomic-embed-text`, the total footprint is ~6.7 GB, leaving 1.3 GB for the OS and context windows.
   - *Fallback (Max Speed)*: `qwen2.5:1.5b` (986 MB) or `phi3:mini` (2.2 GB) if VRAM pressure causes out-of-memory errors.

---

## Implementation Stages

### Stage 1: Core Guardrails & Personas (Foundation)
**Goal:** Implement the standalone gates and data structures before wiring them into the complex agent or RAG flows.

- [x] **Task 1.1**: Create `data/personas/` directory. Extract and port the persona definitions (e.g., `customer_service`, `hr_assistant`, `security_analyst`, `code_assistant`) from Omaha-Lab into YAML or JSON formats.
- [x] **Task 1.2**: Implement `CanaryTokenGate` (Output Gate). This gate should take a list of predefined canary tokens from `config.yaml` and scan the LLM output (via regex or exact match) to detect potential data exfiltration.
- [x] **Task 1.3**: Update `config.yaml`, the `PipelineManager`, and the main Streamlit UI configuration panels to expose and toggle this new output gate.

### Stage 2: Advanced RAG with ChromaDB
**Goal:** Replace or enhance the basic RAG simulation with actual semantic retrieval.

- [ ] **Task 2.1**: Add `chromadb` and `nomic-embed-text` dependencies to `requirements.txt`.
- [ ] **Task 2.2**: Implement `core/vector_store.py`. Use an Ephemeral ChromaDB instance (`chromadb.EphemeralClient()`). Use Streamlit's `@st.cache_resource` to build an auto-loader that runs exactly once on startup to read and embed all markdown files from the `data/rag/` folder.
- [ ] **Task 2.3**: Update the existing RAG Workbench UI. Allow users to upload dummy documents (or use existing ones like `medical_records_pii.md`), embed them into ChromaDB, and query them.
- [ ] **Task 2.4**: Introduce a "Poison Document" feature where users can inject a payload into the vector store and observe if the LLM retrieves and executes it.

### Stage 3: LangGraph Agent Sandbox (Core Engine)
**Goal:** Introduce the ReAct agent loop, ensuring all LLM calls made by the agent are routed through the `llm-sec-workbench` security pipeline.

- [ ] **Task 3.1**: Add `langgraph` and `langchain-community` dependencies.
- [ ] **Task 3.2**: Create `redteam/agent_sandbox.py`. Implement a standard LangGraph ReAct agent.
- [ ] **Task 3.3**: Wrap the agent's LLM invocation so it calls the local `PipelineManager` instead of a direct raw LLM API. This ensures the agent is protected by the L0-L5 input gates and O·ML output gates.
- [ ] **Task 3.4**: Port and implement the core tools from Omaha-Lab for the agent to use. This includes: `get_weather`, `web_search`, `http_get` (excellent for testing data exfiltration/SSRF), `read_file` (for LFI testing), `write_file`, and a new `query_chroma` tool (to test RAG Data Poisoning).
- [ ] **Task 3.5**: Update `.env.example` to include `WEATHER_API_KEY` (OpenWeatherMap) and `SEARCH_API_KEY` (Tavily) required by the ported tools. Ensure `config.yaml` or the `Agent Sandbox` logic securely passes these keys to the tools.

### Stage 4: Agent Sandbox UI & Visualization
**Goal:** Expose the agent to the user in a visual, interactive Streamlit environment.

- [ ] **Task 4.1**: Create a new standalone Streamlit page named **"Agent Sandbox"** (e.g., `ui/pages/agent_sandbox.py`). Do not integrate it into the existing Chat Workbench to ensure the UI remains clean and focused. Include a dedicated "How it Works" tab on this page to educate users specifically about the ReAct loop, tool interception, and Chain of Thought mechanics.
- [ ] **Task 4.2**: Build a UI panel to select an **Agent Persona** (from Stage 1) and toggle **ChromaDB RAG** (from Stage 2).
- [ ] **Task 4.3**: Implement a chat interface where the user can send inputs. Visually differentiate the "Thinking" and "Execution" phases from the primary chat:
    - **Dimmed Monologue:** Render the agent's internal "Thought", "Action (Tool Call)", and "Observation" sequences using muted typography (e.g., collapsed `st.status()`, `st.caption()`, or custom CSS with reduced opacity/gray text).
    - **Prominent Chat:** Keep the initial User Prompt and the final Agent Response at full opacity and size so the core conversational flow remains clearly visible.
- [ ] **Task 4.4**: Ensure any blocked actions (e.g., a tool call blocked by a security gate) are clearly displayed as Pipeline Interventions in the UI.

---

## Verification Plan

For an agent tasked with executing this plan, they should verify:
1. **Unit Tests**: Add tests for `CanaryTokenGate` ensuring it blocks exfiltrating responses and allows clean ones.
2. **Integration Test**: Run the LangGraph agent with a benign prompt to ensure it successfully calls a tool and returns a response.
3. **Security Test**: Run the LangGraph agent with a known prompt injection (e.g., instructing it to print a canary token). Verify the output pipeline successfully intercepts and blocks the final response.
