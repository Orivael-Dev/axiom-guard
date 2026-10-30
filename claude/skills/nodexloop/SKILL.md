---
name: nodexloop
description: "Build, check and simulate governed agent loops (.loop.yaml) with the NodeXLoop MCP tools — offline guard preflight, static compile check, sim runs with canned agents, trace replay, template suggestions, and a gated Python package resolver. Use when the user creates or edits a .loop.yaml, asks to design an agent loop or multi-agent workflow, wants to know whether a loop works, wants to replay a sim run, or wants to vet a Python package before installing it."
---

# NodeXLoop

NodeXLoop's engine runs locally inside this plugin as the `nodexloop` MCP
server (tools `nxl_*`). Node 18+ is the only requirement. Nothing here calls
a model or spends tokens. Sims use canned agents, and there is no live-run
tool: real model spend stays a NodeXLoop-UI action behind the human gate.

## Tools

| tool | use it to |
|---|---|
| `nxl_suggest_templates` | find shipped templates that match the task before drafting from scratch |
| `nxl_build_loop` | turn a description, template id, or draft YAML into a validated graph (canonical YAML + check report) |
| `nxl_compile_check` | static check: schema, ids, edges, reachability, loop bounds, impl bindings, guard lint on every prompt, module pins |
| `nxl_sim_loop` | sim-mode run: real orchestration and real guard, canned agents, `max_iterations` ≤ 5 |
| `nxl_get_trace` | replay a sim run, or one step of it |
| `nxl_guard_preflight` | classify a prompt or plan offline against the Axiom policy packs |
| `nxl_build_and_harden` | build → check → sim → mechanical repair, ≤ 5 iterations; lands in sandbox review, never release |
| `nxl_module_resolve` | gate a Python package (allowlist, typosquat distance, pin, sha256, license); `install=true` installs into an isolated venv |

## Workflow for any `.loop.yaml`

1. Run `nxl_compile_check` before finishing any edit.
2. Run `nxl_sim_loop` before claiming the loop works.
3. A loop is done when the sim passes with no guard blocks, not when the
   YAML parses.
4. On a weak score or a stall, read the failing step with `nxl_get_trace`,
   fix it, then check and sim again.

## Discipline

- A `block` verdict from `nxl_guard_preflight` (or a guard block in a check or
  sim) is authoritative. Do not reword the prompt to get past it. Tell the user
  what was blocked and why.
- A sim pass shows that orchestration and policy work. It says nothing about
  model quality. Say so when reporting a pass.
- `nxl_build_and_harden` uses no model, and its repairs are mechanical. If it
  stops for a human, report that instead of working around it. Lower the score
  threshold only when the user agrees (`allow_threshold_relaxation=true`).
- Run `nxl_module_resolve` with `install=true` only when the user asks for the
  install. A FAIL is a stop, not a warning.

## State

Runs, receipts, sandbox output and isolated envs are written to
`.nodexloop/` in the current project. Set `NXL_MCP_STATE` to put them
somewhere else. Receipts are HMAC-sealed under a key derived from
`AXIOM_MASTER_KEY` when it is set (`sealed_by: axiom`). Otherwise they use a
per-process key (`sealed_by: local`), which makes them tamper-evident but not
third-party proof.

For prompts or actions that need a signed manifest from a Guard runtime
(not just the offline classifier), use the `axiom-guard` skill's `guard_*`
tools.
