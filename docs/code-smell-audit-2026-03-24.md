# Code Smell Audit — 2026-03-24

## Scope
- Repository scanned: `promptcrafting-mcp`
- Commands used:
  - `npm run lint`
  - `npm run check`
  - `rg -n --glob 'src/**/*.ts' "TODO|FIXME|any\b|console\.log|@ts-ignore|eslint-disable|non-null assertion|as any"`

## Findings

### 1) Linting pipeline is broken (tooling smell)
- `npm run lint` fails immediately because ESLint v9 requires a flat config file (`eslint.config.js|mjs|cjs`), but none exists.
- Impact: style/smell detection is effectively disabled in CI/local checks.
- Recommendation: add a flat ESLint config and make `npm run lint` part of CI.

### 2) TypeScript health is red with multiple compile errors (maintainability smell)
- `npm run check` reports many TypeScript errors across middleware, MCP agent wiring, and guardrails.
- Representative classes of issues:
  - unsafe/possibly undefined values (`TS2532`, `TS18048`)
  - context key typing mismatch in Hono (`TS2769`)
  - schema incompatibility / wrong shape (`TS2353`)
  - API arity mismatch (`TS2554`)
  - unresolved type name typo (`TS2552`)
- Impact: reduced confidence in refactoring, increased runtime defect risk, and weakened static guarantees.
- Recommendation: treat `npm run check` as a release gate and resolve errors by category (typing contracts first, then API mismatches).

### 3) Production-style logging via `console.log` in core tool path (operability smell)
- Found in `src/tools/prompt-tools.ts` around HITL approval flow.
- Impact: inconsistent log formatting and observability; may leak operational details in noisy environments.
- Recommendation: route through a structured logger abstraction and include log levels.

### 4) Repository hygiene issue: missing baseline `.gitignore` entries
- Root `.gitignore` only contained `.agents/.env`, allowing large dependency trees/artifacts to appear as untracked content.
- Impact: accidental commits, noisy working tree, slower git operations.
- Recommendation: include standard Node/Worker ignores (`node_modules/`, `.wrangler/`, `dist/`, etc.).

## Prioritized remediation plan
1. Restore linting by adding ESLint flat config.
2. Drive TypeScript errors to zero and enforce in CI.
3. Replace direct `console.log` calls with structured logger.
4. Keep repo clean with robust `.gitignore` defaults.
