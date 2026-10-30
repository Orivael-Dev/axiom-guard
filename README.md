# axiom-guard plugin

Kimi and Claude Code plugin for the [AXIOM Governance Runtime](https://orivael.dev/axiom-runtime.html)
— constitutional guardrails and signed audit trails for AI agents.

## What it does

- **Gate prompts and actions** before they execute (`check`, `input`) — blocked
  requests never reach a model call.
- **Screen outputs** before display (`output`).
- **Redact PII** — HIPAA / GDPR / PCI (`redact`).
- **Produce evidence** — every decision returns an HMAC-SHA256 signed manifest;
  query the trail (`manifests`, `manifest`) and verify signatures locally
  (`verify`).
- **Build governed agent loops** (Claude Code only) — NodeXLoop's offline
  guard, `.loop.yaml` compile check, sim runs, trace replay and a gated Python
  package resolver, as the `nodexloop` MCP server.

## Layout

```
axiom-guard/
├── kimi.plugin.json              # Kimi plugin manifest
├── .claude-plugin/
│   ├── plugin.json               # Claude Code plugin manifest
│   └── marketplace.json          # this repo is also a Claude Code marketplace
├── .mcp.json                     # Claude Code: the two MCP servers below
├── skills/axiom-guard/           # SKILL.md — governance workflow (both hosts)
├── claude/skills/nodexloop/      # SKILL.md — loop workflow (Claude Code only)
├── scripts/axiom_guard_tool.py   # Guard API REST client (stdlib only)
├── mcp/axiom_guard_mcp.mjs       # Guard API as MCP tools (guard_*), Node 18+
├── nodexloop/                    # vendored NodeXLoop MCP engine (nxl_*), see VENDORED.md
└── locales/zh-CN.json            # Kimi catalog display metadata
```

## Runtime

By default the plugin uses Orivael's hosted Guard API at
`https://firewall.orivael.dev` — nothing to install. Checks (`check`, `input`,
`output`, `redact`, `status`, `agents`) need no key. Text you check is sent to
that server.

The audit trail (`manifests`, `manifest`), `configure` and `verify` are
operator features: on the hosted guard they need its operator token, and
`verify` needs the server's master key. To get them for your own decisions —
or to keep text on your machine — self-host:

```bash
# Keep this key: `verify` needs the same one to check signatures.
export AXIOM_MASTER_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
docker run -d --name axiom-guard -p 8001:8001 -e AXIOM_MASTER_KEY \
  orivaeldev/axiom-guard:latest
export AXIOM_BASE_URL=http://localhost:8001
```

Env vars: `AXIOM_BASE_URL`, `AXIOM_API_TOKEN` (operator bearer token),
`AXIOM_MASTER_KEY` (for `verify`).

Check it is up before using the plugin:

```bash
python3 scripts/axiom_guard_tool.py status
```

## Install in Kimi Work

In the Kimi Work desktop app, open the plugin market → 「自定义插件」 (or type
`/plugin-builder` in a session) and give it this repository's URL. Plugin
Builder validates `kimi.plugin.json` and registers the plugin under the
「个人」 tab; click ＋ there to install it.

## Install in Claude Code

Needs Node 18+ on PATH. `guard_verify` also needs Python 3.

```
/plugin marketplace add Orivael-Dev/axiom-guard
/plugin install axiom-guard@orivael
```

Restart Claude Code, then run `/mcp`. Two servers should show as connected:

- `axiom-guard`, with the tools `guard_status`, `guard_check`, `guard_input`,
  `guard_output`, `guard_redact`, `guard_agents`, `guard_manifests`,
  `guard_manifest`, `guard_verify` and `guard_configure`. They make the same
  calls as `scripts/axiom_guard_tool.py` and read the same env vars.
- `nodexloop`, with the tools `nxl_guard_preflight`, `nxl_build_loop`,
  `nxl_compile_check`, `nxl_sim_loop`, `nxl_get_trace`,
  `nxl_module_resolve`, `nxl_build_and_harden` and `nxl_suggest_templates`.
  These run offline, make no model calls and have no live-run tool. Runs and
  receipts are written to `.nodexloop/` in the project (`NXL_MCP_STATE`
  overrides).

To try a local checkout without installing it:
`claude --plugin-dir /path/to/axiom-guard`.
