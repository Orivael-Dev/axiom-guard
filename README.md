# axiom-guard plugin

Kimi plugin for the [AXIOM Governance Runtime](https://orivael.dev/axiom-runtime.html)
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
├── kimi.plugin.json          # plugin manifest
├── skills/axiom-guard/       # SKILL.md — governance workflow + discipline
├── scripts/axiom_guard_tool.py  # Guard API REST client (stdlib only)
└── locales/zh-CN.json        # catalog display metadata
```

## Runtime prerequisite

The plugin talks to a running Guard API (default `http://localhost:8001`):

```bash
docker run -d -p 8001:8001 \
  -e AXIOM_MASTER_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))') \
  orivaeldev/axiom-guard:latest
```

Optional env vars: `AXIOM_BASE_URL`, `AXIOM_API_TOKEN` (bearer, only if the
server requires auth), `AXIOM_MASTER_KEY` (for `verify`).

Check it is up before using the plugin:

```bash
python3 scripts/axiom_guard_tool.py status
```

## Install in Kimi Work

In the Kimi Work desktop app, open the plugin market → 「自定义插件」 (or type
`/plugin-builder` in a session) and give it this repository's URL. Plugin
Builder validates `kimi.plugin.json` and registers the plugin under the
「个人」 tab; click ＋ there to install it.
