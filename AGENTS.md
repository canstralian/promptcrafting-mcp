# AGENTS.md

## Repo intent
This repository implements an MCP server for prompt crafting / prompt management.

## Working rules
- Prefer minimal diffs.
- Do not change protocol behavior without adding or updating tests.
- Preserve backwards compatibility for tool names, prompt names, and transport behavior unless the task explicitly requires a breaking change.

## Setup and validation
- Install dependencies with the project’s lockfile-aware package manager.
- After code changes, run:
  - npm test --if-present
  - npm run build --if-present
  - npm run lint --if-present

## MCP-specific checks
- Verify tool/resource/prompt registration paths still load.
- Validate JSON schemas and argument contracts if present.
- Prefer adding smoke tests for MCP handlers over broad refactors.

## Done means
- Build passes.
- Tests pass if present.
- Any changed prompt/tool contract is documented in README or docs.
