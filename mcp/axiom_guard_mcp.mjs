#!/usr/bin/env node
/**
 * AXIOM Guard MCP server — JSON-RPC 2.0 over stdio.
 *
 *     node mcp/axiom_guard_mcp.mjs
 *
 * The same Guard API calls scripts/axiom_guard_tool.py makes, exposed as MCP
 * tools so Claude Code can gate prompts, actions and outputs natively.
 * Hand-rolled protocol (initialize / tools/list / tools/call / ping), like the
 * NodeXLoop server next to it — Node 18+ and nothing to install.
 *
 * Connection (env, inherited from the client):
 *   AXIOM_BASE_URL    default https://firewall.orivael.dev (Orivael's hosted guard)
 *   AXIOM_API_TOKEN   operator bearer token (audit trail and configure)
 *   AXIOM_MASTER_KEY  for guard_verify
 *
 * guard_verify is delegated to the Python script on purpose: the server signs
 * json.dumps(sort_keys=True) output, which JavaScript cannot reproduce byte for
 * byte (1.0 parses to 1, separators and escaping differ).
 *
 * Tool descriptions are security boundaries — the calling model reads them as
 * instructions, so the verdict rules are stated as hard constraints.
 */
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const HERE = dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = resolve(HERE, '..');
const TOOL_SCRIPT = join(PLUGIN_ROOT, 'scripts', 'axiom_guard_tool.py');

export const PROTOCOL = '2024-11-05';
export const SERVER = { name: 'axiom-guard', version: '1.2.0' };
export const HOSTED_BASE_URL = 'https://firewall.orivael.dev';
const TIMEOUT_MS = 15000;
const USER_AGENT = `axiom-guard-plugin/${SERVER.version} (+https://github.com/Orivael-Dev/axiom-guard)`;

export class GuardError extends Error {}

const baseUrl = () => (process.env.AXIOM_BASE_URL || HOSTED_BASE_URL).replace(/\/+$/, '');

const VERDICT_RULE =
  'If the verdict is BLOCKED (proceed=false) do not perform the action, do not rephrase or retry to get past the guard, ' +
  'tell the user it was blocked with the constitutional_block reason and the manifest_id; never override cannot_override=true. ' +
  'SUSPICIOUS: surface the warning and confirm with the user before acting.';
const SENDS_TEXT = 'The text is sent to the Guard API at AXIOM_BASE_URL (Orivael\'s hosted guard by default).';

const text = (d) => ({ type: 'string', description: d });
const agentsProp = { type: 'array', items: { type: 'string' },
  description: 'restrict to these constitutional agents, e.g. ["callguard","medical"] (see guard_agents)' };
const metadataProp = { type: 'object', description: 'optional JSON metadata attached to the check' };

export const TOOLS = [
  { name: 'guard_status',
    description: 'Health check and active configuration of the AXIOM Guard API. Call this first; if it fails, report that the guard is unreachable ' +
      'and never claim a later check ran.',
    inputSchema: { type: 'object', properties: {} },
    annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: 'guard_check',
    description: 'Evaluate any text (a prompt, a message, or a description of an action you are about to take) and get a verdict ' +
      '(BLOCKED | VERIFIED | SUSPICIOUS) plus an HMAC-SHA256 signed manifest. Use for "is this safe / is this a scam" questions. ' +
      VERDICT_RULE + ' ' + SENDS_TEXT,
    inputSchema: { type: 'object', properties: {
      text: text('the text or action description to evaluate'),
      direction: { type: 'string', enum: ['INPUT', 'OUTPUT'], description: 'INPUT (default) or OUTPUT' },
      agents: agentsProp, metadata: metadataProp }, required: ['text'] },
    annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: 'guard_input',
    description: 'Fail-closed pre-action gate. Call BEFORE any risky or irreversible tool-mediated action — sending emails or messages, deleting or ' +
      'overwriting data, purchases, public posts, code execution, third-party API calls with side effects — with the action described as text. ' +
      VERDICT_RULE + ' ' + SENDS_TEXT,
    inputSchema: { type: 'object', properties: { text: text('the prompt or action description to gate'), agents: agentsProp, metadata: metadataProp },
      required: ['text'] },
    annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: 'guard_output',
    description: 'Screen model output or generated content before it is shown or sent. ' + VERDICT_RULE + ' ' + SENDS_TEXT,
    inputSchema: { type: 'object', properties: { text: text('the content to screen'), agents: agentsProp, metadata: metadataProp },
      required: ['text'] },
    annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: 'guard_redact',
    description: 'Redact PII (HIPAA / GDPR / PCI identifiers) from text before it leaves the environment. Returns the redacted text. ' + SENDS_TEXT,
    inputSchema: { type: 'object', properties: { text: text('the text to redact') }, required: ['text'] },
    annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: 'guard_agents',
    description: 'List the constitutional agents (rule sets such as callguard, medical, electionguard, retailwatcher, truthwatcher) and what each blocks.',
    inputSchema: { type: 'object', properties: {} },
    annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: 'guard_manifests',
    description: 'Recent signed decision manifests from the audit trail. Operator-only on the hosted guard (needs AXIOM_API_TOKEN); ' +
      'if it says operator-only, explain that and offer self-hosting — do not retry.',
    inputSchema: { type: 'object', properties: {
      limit: { type: 'integer', minimum: 1, maximum: 500 },
      verdict: { type: 'string', enum: ['BLOCKED', 'VERIFIED', 'SUSPICIOUS'] } } },
    annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: 'guard_manifest',
    description: 'One full signed manifest by id, including its signature. Operator-only on the hosted guard.',
    inputSchema: { type: 'object', properties: { id: text('manifest_id') }, required: ['id'] },
    annotations: { readOnlyHint: true, openWorldHint: true } },
  { name: 'guard_verify',
    description: 'Recompute a manifest\'s HMAC-SHA256 signature locally, offline, to prove it was not tampered with. Needs the AXIOM_MASTER_KEY the ' +
      'Guard runtime was started with (env, or master_key). A manifest from a different deployment will not verify — say that instead of ' +
      'reporting tampering. Pass manifest_json — the manifest as JSON text copied verbatim from a guard_* result, not re-typed (a float ' +
      'written 1.0 as 1 changes the signed bytes) — or manifest_id to fetch it first (operator-only on the hosted guard). Requires Python 3.',
    inputSchema: { type: 'object', properties: {
      manifest_json: text('the manifest as JSON text, verbatim'),
      manifest_id: text('fetch this manifest from the guard, then verify it'),
      master_key: text('master key text; defaults to AXIOM_MASTER_KEY') } },
    annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: 'guard_configure',
    description: 'Change the Guard runtime\'s mode or active agents. This MUTATES a shared runtime: only call when the user explicitly asks to ' +
      'reconfigure their own guard. Operator-only (needs AXIOM_API_TOKEN).',
    inputSchema: { type: 'object', properties: {
      mode: { type: 'string', enum: ['INPUT_FILTER', 'OUTPUT_FILTER', 'BIDIRECTIONAL'] },
      agents: agentsProp,
      block_on_suspicious: { type: 'boolean' },
      anthropic_model: text('model the runtime uses for escalation') } },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true } },
];

/** A Guard API response, kept as the server's own bytes. Re-serialising it in
 * JavaScript would rewrite floats (1.0 -> 1) and break manifest signatures. */
export class RawJson {
  constructor(text) { this.text = text; }
  parse() { return JSON.parse(this.text); }
}

export async function request(method, path, body) {
  const url = baseUrl() + path;
  const headers = { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT };
  if (process.env.AXIOM_API_TOKEN) headers.Authorization = `Bearer ${process.env.AXIOM_API_TOKEN}`;
  let resp;
  try {
    resp = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body),
                              signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (e) {
    const reason = (e && e.cause && e.cause.code) || (e && e.name === 'TimeoutError' ? 'timed out' : String(e && e.message || e));
    if (baseUrl() === HOSTED_BASE_URL) throw new GuardError(`cannot reach the hosted Guard API at ${baseUrl()} (${reason})`);
    throw new GuardError(`cannot reach Guard API at ${baseUrl()} (${reason}). Start the runtime: export AXIOM_MASTER_KEY=<64 hex chars, keep it>; ` +
      'docker run -d --name axiom-guard -p 8001:8001 -e AXIOM_MASTER_KEY orivaeldev/axiom-guard:latest');
  }
  const raw = await resp.text();
  if (resp.status === 401) {
    throw new GuardError(`${path} is operator-only on ${baseUrl()} and needs AXIOM_API_TOKEN. The audit trail, configure and verify are for a ` +
      'self-hosted guard; check/input/output/redact work without a token.');
  }
  if (!resp.ok) throw new GuardError(`Guard API returned HTTP ${resp.status}: ${raw.slice(0, 500)}`);
  if (!raw) return new RawJson('{}');
  try { JSON.parse(raw); } catch { throw new GuardError(`Guard API returned non-JSON (${raw.slice(0, 200)})`); }
  return new RawJson(raw);
}

function needText(a, tool) {
  if (typeof a.text !== 'string' || !a.text) throw new GuardError(`${tool} needs text`);
}
function checkBody(a, direction) {
  const body = { text: a.text, direction };
  if (Array.isArray(a.agents) && a.agents.length) body.agents = a.agents;
  body.metadata = a.metadata && typeof a.metadata === 'object' ? a.metadata : {};
  return body;
}

function findPython() {
  const cands = process.env.AXIOM_PYTHON ? [process.env.AXIOM_PYTHON] : ['python3', 'python', 'py'];
  for (const c of cands) {
    const r = spawnSync(c, ['-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'], { encoding: 'utf8' });
    if (r.status === 0) return c;
  }
  return null;
}

async function verify(a) {
  const key = a.master_key || process.env.AXIOM_MASTER_KEY || '';
  if (!key) throw new GuardError('guard_verify needs master_key or AXIOM_MASTER_KEY');
  let manifestText = typeof a.manifest_json === 'string' ? a.manifest_json : '';
  if (!manifestText && a.manifest_id) manifestText = (await request('GET', '/guard/manifest/' + encodeURIComponent(a.manifest_id))).text;
  if (!manifestText) throw new GuardError('guard_verify needs manifest_json or manifest_id');
  let parsed;
  try { parsed = JSON.parse(manifestText); } catch { throw new GuardError('manifest_json is not valid JSON'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new GuardError('manifest_json must be a JSON object');
  const py = findPython();
  if (!py) throw new GuardError('guard_verify needs Python 3 on PATH (or AXIOM_PYTHON); it reuses scripts/axiom_guard_tool.py so the ' +
    'canonical JSON matches the server byte for byte');
  // The key goes through the environment, never argv, so it stays out of process listings.
  const r = spawnSync(py, [TOOL_SCRIPT, 'verify'], { input: manifestText, encoding: 'utf8',
    env: { ...process.env, AXIOM_MASTER_KEY: key, PYTHONIOENCODING: 'utf-8' } });
  if (r.status !== 0) throw new GuardError((r.stderr || r.stdout || 'verify failed').trim().replace(/^error: /, ''));
  return JSON.parse(r.stdout);
}

export async function callTool(name, args) {
  const a = args || {};
  switch (name) {
    case 'guard_status': return request('GET', '/guard/status');
    case 'guard_agents': return request('GET', '/guard/agents');
    case 'guard_check':
      needText(a, name);
      return request('POST', '/guard/check', checkBody(a, a.direction === 'OUTPUT' ? 'OUTPUT' : 'INPUT'));
    case 'guard_input':
    case 'guard_output': {
      needText(a, name);
      const dir = name === 'guard_input' ? 'input' : 'output';
      return request('POST', `/guard/${dir}`, checkBody(a, dir.toUpperCase()));
    }
    case 'guard_redact':
      needText(a, name);
      return request('POST', '/guard/redact', { text: a.text });
    case 'guard_manifests': {
      const qs = new URLSearchParams();
      if (a.limit) qs.set('limit', String(a.limit));
      if (a.verdict) qs.set('verdict', a.verdict);
      const q = qs.toString();
      return request('GET', '/guard/manifests' + (q ? '?' + q : ''));
    }
    case 'guard_manifest':
      if (!a.id) throw new GuardError('guard_manifest needs id');
      return request('GET', '/guard/manifest/' + encodeURIComponent(a.id));
    case 'guard_verify': return verify(a);
    case 'guard_configure': {
      const body = {};
      if (a.mode) body.mode = a.mode;
      if (Array.isArray(a.agents) && a.agents.length) body.active_agents = a.agents;
      if (a.block_on_suspicious) body.block_on_suspicious = true;
      if (a.anthropic_model) body.anthropic_model = a.anthropic_model;
      if (!Object.keys(body).length) throw new GuardError('guard_configure needs at least one of mode/agents/block_on_suspicious/anthropic_model');
      return request('POST', '/guard/configure', body);
    }
    default: throw new GuardError(`unknown tool ${name}`);
  }
}

const content = (obj, isError = false) => ({
  content: [{ type: 'text', text: obj instanceof RawJson ? obj.text : JSON.stringify(obj, null, 2) }],
  ...(isError ? { isError: true } : {}) });

export async function handle(req) {
  const { id, method, params = {} } = req || {};
  const reply = (result) => (id === undefined ? null : { jsonrpc: '2.0', id, result });
  const fail = (code, message) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
  try {
    if (method === 'initialize') return reply({ protocolVersion: PROTOCOL, capabilities: { tools: {} }, serverInfo: SERVER });
    if (typeof method === 'string' && method.startsWith('notifications/')) return null;
    if (method === 'ping') return reply({});
    if (method === 'tools/list') return reply({ tools: TOOLS });
    if (method === 'tools/call') {
      try {
        return reply(content(await callTool(params.name, params.arguments)));
      } catch (e) {
        return reply(content({ error: String(e && e.message || e) }, true));
      }
    }
    return fail(-32601, `Method not found: ${method}`);
  } catch (e) {
    return fail(-32000, String(e && e.message || e));
  }
}

export async function serve(input = process.stdin, output = process.stdout) {
  const rl = createInterface({ input, crlfDelay: Infinity });
  for await (const line of rl) {
    const s = line.trim();
    if (!s) continue;
    let req;
    try { req = JSON.parse(s); }
    catch { output.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n'); continue; }
    const res = await handle(req);
    if (res) output.write(JSON.stringify(res) + '\n');
  }
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  process.stdin.setEncoding('utf8');
  serve().catch(e => { process.stderr.write('axiom-guard-mcp: ' + (e && e.stack || e) + '\n'); process.exit(1); });
}
