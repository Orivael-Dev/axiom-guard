#!/usr/bin/env python3
"""
axiom_guard_tool.py — thin client for the AXIOM Guard API.

Talks to a running AXIOM Governance Runtime (Guard API) over REST and
verifies HMAC-SHA256 manifest signatures locally.

Connection (env vars or flags):
  AXIOM_BASE_URL    default http://localhost:8001
  AXIOM_API_TOKEN   optional bearer token (required if the server binds
                    a non-loopback interface)

Quick start (start the runtime first):
  export AXIOM_MASTER_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
  docker run -d --name axiom-guard -p 8001:8001 -e AXIOM_MASTER_KEY \\
    orivaeldev/axiom-guard:latest

Actions:
  status                      GET  /guard/status
  check    --text T           POST /guard/check   (evaluate any text)
  input    --text T           POST /guard/input   (screen a prompt pre-LLM)
  output   --text T           POST /guard/output  (screen a response pre-display)
  redact   --text T           POST /guard/redact  (PII redaction HIPAA/GDPR/PCI)
  manifest --id ID            GET  /guard/manifest/{id}
  manifests [--limit N] [--verdict V]
                              GET  /guard/manifests
  agents                      GET  /guard/agents
  configure [--mode M] [--agents a,b] [--block-on-suspicious] [--anthropic-model M]
                              POST /guard/configure
  verify   --master-key HEX [--file manifest.json]
                              verify a manifest signature locally (file or stdin)

All actions print a JSON result on stdout. `input`/`output` exit non-zero
when the text is blocked (proceed=false), so they can gate shell pipelines.

Examples:
  python3 axiom_guard_tool.py check --text "summarise this document"
  python3 axiom_guard_tool.py check --text "IRS agent — send gift cards or face arrest"
  python3 axiom_guard_tool.py manifests --verdict BLOCKED --limit 20
  cat manifest.json | python3 axiom_guard_tool.py verify --master-key $AXIOM_MASTER_KEY
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE_URL = os.environ.get("AXIOM_BASE_URL", "http://localhost:8001")
DEFAULT_TIMEOUT = 15
SIGNING_NAMESPACE = b"axiom-guard-api-v1"
# /guard/check stamps these onto FTC-reportable manifests after signing them.
POST_SIGNING_FIELDS = ("ftc_report_generated", "ftc_report_id")


class GuardError(RuntimeError):
    pass


def _load_signing_key(master_key_hex: str) -> bytes:
    """Mirror axiom_signing.derive_key: HMAC-SHA256(salt, master).

    The server keys on the env var's UTF-8 text, not on hex-decoded bytes.
    """
    master = master_key_hex.strip().encode("utf-8")
    if not master:
        raise GuardError("master key is empty")
    return hmac.new(SIGNING_NAMESPACE, master, hashlib.sha256).digest()


def verify_manifest(manifest: dict, master_key_hex: str) -> dict:
    """Recompute the HMAC signature of a manifest the way the Guard API does.

    Server convention (axiom_guard_api.py): sign every field except
    `signature`, canonicalised as json.dumps(obj, sort_keys=True), under
    derive_key(b"axiom-guard-api-v1"). The stored signature is either the
    full hex digest or the first 32 hex chars followed by "...".
    POST_SIGNING_FIELDS are excluded, since the server adds them after signing.
    """
    sig_field = manifest.get("signature", "")
    if not isinstance(sig_field, str) or not sig_field.startswith("hmac-sha256:"):
        return {"verified": False, "reason": "manifest has no hmac-sha256 signature"}
    presented = sig_field[len("hmac-sha256:"):]
    body = {k: v for k, v in manifest.items()
            if k != "signature" and k not in POST_SIGNING_FIELDS}
    payload = json.dumps(body, sort_keys=True).encode("utf-8")
    key = _load_signing_key(master_key_hex)
    expected_full = hmac.new(key, payload, hashlib.sha256).hexdigest()
    expected_truncated = expected_full[:32] + "..."
    verified = hmac.compare_digest(presented, expected_full) or hmac.compare_digest(
        presented, expected_truncated
    )
    return {
        "verified": verified,
        "presented": presented,
        "expected": expected_full,
        "manifest_id": manifest.get("manifest_id"),
    }


def _request(base_url: str, token: str | None, method: str, path: str,
             body: dict | None = None) -> dict:
    url = base_url.rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500]
        raise GuardError(f"Guard API returned HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise GuardError(
            f"cannot reach Guard API at {base_url} ({e.reason}). "
            "Start the runtime: export AXIOM_MASTER_KEY=<64 hex chars, keep it>; "
            "docker run -d --name axiom-guard -p 8001:8001 -e AXIOM_MASTER_KEY "
            "orivaeldev/axiom-guard:latest"
        )
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        raise GuardError(f"Guard API returned non-JSON ({raw[:200]})")


def _print(obj: dict) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def main() -> int:
    p = argparse.ArgumentParser(
        description="AXIOM Guard API client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("action", choices=[
        "status", "check", "input", "output", "redact",
        "manifest", "manifests", "agents", "configure", "verify",
    ])
    p.add_argument("--base-url", default=DEFAULT_BASE_URL)
    p.add_argument("--token", default=os.environ.get("AXIOM_API_TOKEN"))
    p.add_argument("--text")
    p.add_argument("--id")
    p.add_argument("--direction", choices=["INPUT", "OUTPUT"], default="INPUT")
    p.add_argument("--agents", help="comma-separated constitutional agent names")
    p.add_argument("--metadata-json", default="{}", help="JSON object attached to the check")
    p.add_argument("--limit", type=int)
    p.add_argument("--verdict", choices=["BLOCKED", "VERIFIED", "SUSPICIOUS"])
    p.add_argument("--mode", choices=["INPUT_FILTER", "OUTPUT_FILTER", "BIDIRECTIONAL"])
    p.add_argument("--block-on-suspicious", action="store_true")
    p.add_argument("--anthropic-model")
    p.add_argument("--master-key", default=os.environ.get("AXIOM_MASTER_KEY", ""))
    p.add_argument("--file", help="manifest JSON file for verify (default: stdin)")
    args = p.parse_args()

    try:
        if args.action == "verify":
            if args.file:
                with open(args.file, "r", encoding="utf-8") as fh:
                    manifest = json.load(fh)
            else:
                manifest = json.load(sys.stdin)
            if not args.master_key:
                raise GuardError("verify needs --master-key or AXIOM_MASTER_KEY")
            _print(verify_manifest(manifest, args.master_key))
            return 0

        if args.action in ("check", "input", "output", "redact") and not args.text:
            raise GuardError(f"action '{args.action}' needs --text")

        agents = [a.strip() for a in args.agents.split(",")] if args.agents else None

        if args.action == "status":
            _print(_request(args.base_url, args.token, "GET", "/guard/status"))
        elif args.action == "check":
            body = {"text": args.text, "direction": args.direction}
            if agents:
                body["agents"] = agents
            body["metadata"] = json.loads(args.metadata_json)
            _print(_request(args.base_url, args.token, "POST", "/guard/check", body))
        elif args.action in ("input", "output"):
            body = {"text": args.text, "direction": "INPUT" if args.action == "input" else "OUTPUT"}
            if agents:
                body["agents"] = agents
            body["metadata"] = json.loads(args.metadata_json)
            result = _request(args.base_url, args.token, "POST", f"/guard/{args.action}", body)
            _print(result)
            return 0 if result.get("proceed", True) else 2
        elif args.action == "redact":
            _print(_request(args.base_url, args.token, "POST", "/guard/redact",
                            {"text": args.text}))
        elif args.action == "manifest":
            if not args.id:
                raise GuardError("manifest needs --id")
            _print(_request(args.base_url, args.token, "GET",
                            "/guard/manifest/" + urllib.parse.quote(args.id)))
        elif args.action == "manifests":
            qs = {}
            if args.limit:
                qs["limit"] = args.limit
            if args.verdict:
                qs["verdict"] = args.verdict
            path = "/guard/manifests" + ("?" + urllib.parse.urlencode(qs) if qs else "")
            _print(_request(args.base_url, args.token, "GET", path))
        elif args.action == "agents":
            _print(_request(args.base_url, args.token, "GET", "/guard/agents"))
        elif args.action == "configure":
            body = {}
            if args.mode:
                body["mode"] = args.mode
            if agents:
                body["active_agents"] = agents
            if args.block_on_suspicious:
                body["block_on_suspicious"] = True
            if args.anthropic_model:
                body["anthropic_model"] = args.anthropic_model
            if not body:
                raise GuardError("configure needs at least one of --mode/--agents/--block-on-suspicious/--anthropic-model")
            _print(_request(args.base_url, args.token, "POST", "/guard/configure", body))
    except GuardError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError:
        print("error: --metadata-json is not valid JSON", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
