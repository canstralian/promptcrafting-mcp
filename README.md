# Promptcrafting-MCP & ACP Bridge

This repository provides a standardized interface for prompt engineering by layering the **Agent Client Protocol (ACP)** over a **Model Context Protocol (MCP)** server. This allows any ACP-compatible IDE (like Zed or future VS Code extensions) to use specialized prompt validation and refinement tools.

## Architecture Overview

- **ACP Client (IDE):** Handles the user interface, diff rendering, and permission dialogs.
- **ACP Agent (Bridge):** Orchestrates session logic and communicates with the MCP server.
- **Promptcrafting-MCP (Server):** The “brain” containing specific logic for validating and refining prompts.

---

## Prerequisites

- **Python 3.10+** (for the MCP Server)
- **Node.js 20+** (for the ACP Agent)
- **MCP Python SDK:** `pip install mcp`
- **ACP/MCP Node SDKs:** `npm install @agent-protocol/sdk @modelcontextprotocol/sdk`

---

## Installation & Setup

### 1) MCP Server (Python)

The server exposes the functional tools to the ACP bridge agent.

```bash
# Navigate to the server directory
cd promptcrafting-mcp

# Run the server in stdio mode
python server.py
```

### 2) ACP Agent (TypeScript)

The ACP bridge agent must be configured to use your Python executable for launching the MCP server.

```bash
# Install dependencies
npm install

# Build the agent
npm run build
```

---

## Available Tools & Commands

| Tool Name | Input | Description |
|---|---|---|
| `promptcraft_validate` | `prompt_text` | Checks for PII, length, and injection patterns. |
| `promptcraft_refine` | `prompt_text`, `target_model` | Transforms raw text into a structured system prompt. |

---

## Integration with IDEs

When using an ACP-compatible editor, trigger these tools via the command palette or slash commands:

- `/refine`: Sends the current buffer to `promptcraft_refine`.
- `/validate`: Returns a list of security findings in the side panel.

---

## Security & Permissions

This implementation follows the Human-in-the-Loop principle:

- The agent calculates a **Plan**.
- If a destructive action is required (for example, rewriting a file), the agent issues a `session/request_permission` call.
- The user must click **Allow** in the IDE before changes are applied to the workspace.

---

## Contributing

- Fork the repository.
- Add tools in `server.py` within the `@app.list_tools()` decorator.
- Update logic in `call_tool()` to handle newly added functionality.
- Test using the included GitHub Actions workflow.
