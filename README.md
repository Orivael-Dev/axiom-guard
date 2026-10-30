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

## Layout

```
axiom-guard/
├── kimi.plugin.json              # Kimi plugin manifest
├── .claude-plugin/
│   ├── plugin.json               # Claude Code plugin manifest
│   └── marketplace.json          # this repo is also a Claude Code marketplace
├── .mcp.json                     # Claude: the public keyless guard (remote MCP)
├── skills/axiom-guard/           # SKILL.md — governance workflow (all hosts)
├── scripts/axiom_guard_tool.py   # Guard API REST client (stdlib only)
├── mcp/axiom_guard_mcp.mjs       # local MCP server for a self-hosted guard, Node 18+
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

## Install in Claude (claude.ai, Cowork, Claude Code)

The plugin connects to Orivael's public keyless guard at
`https://mcp.orivael.dev/guard/mcp`. You don't need to install anything or
have an API key, and it works on every Claude surface. Its six free-tier tools
are `guard_status`, `guard_check`, `guard_input`, `guard_output`,
`guard_redact` and `guard_agents`. They're rule-based and make no model
calls. Text you check is sent to that server. It isn't logged, but don't send
secrets.

From a terminal:

```
claude plugin marketplace add Orivael-Dev/axiom-guard
claude plugin install axiom-guard@orivael
```

Or, inside a Claude Code session:
`/plugin install axiom-guard --marketplace Orivael-Dev/axiom-guard`.

Then run `/mcp`. `axiom-guard` should show as connected.

To try a local checkout without installing it, run
`claude --plugin-dir /path/to/axiom-guard`.

### Self-hosted guard: audit trail and verify

The audit trail, `verify` and `configure` need your own guard (see
[Runtime](#runtime)). Register the local server against it. It needs Node
18+, and `guard_verify` also needs Python 3:

```bash
claude mcp add axiom-guard-local -s user \
  -e AXIOM_BASE_URL=http://localhost:8001 -e AXIOM_MASTER_KEY \
  -- node /path/to/axiom-guard/mcp/axiom_guard_mcp.mjs
```

That server adds `guard_manifests`, `guard_manifest`, `guard_verify` and
`guard_configure` to the six above. It reads the same env vars as
`scripts/axiom_guard_tool.py`.
