---
name: axiom-guard
description: "Constitutional governance for AI agents via the AXIOM Guard API — gate prompts and agent actions before they execute, screen model outputs before display, redact PII (HIPAA/GDPR/PCI), verify HMAC-SHA256 signed decision manifests, and query the signed audit trail. Use when the user asks to check whether a prompt, message, or action is safe or compliant; before performing risky or irreversible tool-mediated actions (sending emails/messages, deleting data, making purchases, posting publicly, executing code, calling external APIs); when prompt injection or scam/deception content is suspected (IRS/gift-card demands, impersonation, coercion); when the user needs PII redaction; when the user mentions AXIOM, constitutional governance, signed audit trails, EU AI Act / FTC / compliance evidence, or agent safety guardrails."
---

# AXIOM Guard

Use this skill to govern prompts, actions, and outputs through a running
AXIOM Governance Runtime (Guard API). Every verdict comes back as an
HMAC-SHA256 signed manifest — the audit trail for compliance and debugging.

## Setup

The plugin talks to a Guard API over REST. If `status` fails, the runtime is
not running — start it (Docker is the fastest path):

```bash
docker run -d -p 8001:8001 \
  -e AXIOM_MASTER_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))') \
  orivaeldev/axiom-guard:latest
```

Connection settings (env vars or flags on every call):

- `AXIOM_BASE_URL` — default `http://localhost:8001`
- `AXIOM_API_TOKEN` — bearer token, only if the server requires one
  (non-loopback binds refuse to start without it)

Verify the runtime before relying on it:

```bash
python3 <plugin-root>/scripts/axiom_guard_tool.py status
```

The script lives at `<plugin-root>/scripts/axiom_guard_tool.py` — always run it
from the plugin root, not from inside `skills/<name>/`.

## Governance workflow

1. **Classify the situation.** This skill applies to three situations:
   - **Input gating** — screen a user prompt or any text before acting on it
     or sending it to a model.
   - **Action gating** — before executing a risky or irreversible tool-mediated
     action (send/blast messages, delete or overwrite data, purchases,
     public posts, code execution, third-party API calls with side effects),
     describe the action as text and gate it.
   - **Output screening** — screen a model response or generated content
     before returning it to the user.
2. **Gate with the lightest sufficient check:**
   - `check` — evaluate any text, get verdict + signed manifest. Use for
     "is this safe / is this a scam" questions.
   - `input` — pre-action/pre-LLM screen; exits non-zero when blocked, so it
     can gate a pipeline.
   - `output` — screen content before display.
   - `redact` — strip PII (HIPAA/GDPR/PCI) from text before it leaves the
     environment.
3. **Honor the verdict:**
   - `BLOCKED` → do not proceed. Tell the user it was blocked, name the
     `constitutional_block` reason, and offer the manifest id as evidence.
     Never override a manifest with `cannot_override: true`.
   - `VERIFIED` → proceed, and keep the manifest id if the action was
     high-stakes (it is the audit receipt).
   - `SUSPICIOUS` → proceed only with care; surface the warning to the user
     and consider asking for confirmation first.
4. **Audit when asked.** Compliance questions ("show me what was blocked",
   "produce evidence for an auditor") are answered from the signed trail:
   - `manifests --verdict BLOCKED --limit 50` — recent blocked decisions.
   - `manifest --id <id>` — one full manifest including signature.
   - `verify --master-key $AXIOM_MASTER_KEY --file <manifest.json>` — recompute
     the HMAC locally to prove a manifest was not tampered with.
5. **Scope checks when relevant.** `--agents callguard,medical` restricts the
   constitutional rule set (scam calls, medical misinformation, election
   content, fake reviews). List what is available with `agents`.

## Script reference

```bash
python3 <plugin-root>/scripts/axiom_guard_tool.py <action> [options]
```

| Action | What it does |
|---|---|
| `status` | Health check + active configuration |
| `check --text T [--direction INPUT\|OUTPUT] [--agents a,b]` | Verdict + signed manifest for any text |
| `input --text T` | Pre-action gate; exit code 2 = blocked |
| `output --text T` | Screen model output; exit code 2 = blocked |
| `redact --text T` | PII redaction (HIPAA/GDPR/PCI) |
| `manifests [--limit N] [--verdict V]` | Recent signed decision manifests |
| `manifest --id ID` | One full manifest |
| `agents` | Available constitutional agents and their blocks |
| `configure --mode M [--agents a,b]` | Update guard mode / active agents |
| `verify --master-key HEX [--file m.json]` | Verify a manifest signature locally |

Verdicts: `BLOCKED` · `VERIFIED` · `SUSPICIOUS`. Every manifest carries
`signature`, `constitutional_block`, `confidence`, `cannot_override`, and
`manifest_id`.

## Discipline

1. Gate before acting, not after. A blocked action costs nothing; an executed
   one may be irreversible.
2. On `BLOCKED`, refuse plainly and offer the manifest id — do not rephrase
   the request to sneak it past the guard.
3. Do not paste contents of blocked scam/deception payloads back at length;
   summarize and name the block reason.
4. `verify` needs the same `AXIOM_MASTER_KEY` the runtime was started with;
   signatures from a different deployment will not verify — say so instead of
   reporting tampering.
5. When the runtime is unreachable, say so and give the docker start command;
   never claim a check ran when it did not.
6. The broader AXIOM stack (24-tool MCP server: stop-authority, adversarial
   sandbox, multi-agent orchestrator, AXM containers) runs as a stdio MCP
   server for MCP clients — point users to https://orivael.dev/ when they
   need those surfaces.
