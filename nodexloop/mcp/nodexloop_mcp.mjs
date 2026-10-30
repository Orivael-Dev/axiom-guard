#!/usr/bin/env node
/**
 * NodeXLoop MCP server — JSON-RPC 2.0 over stdio.
 *
 *     node nodexloop/mcp/nodexloop_mcp.mjs          (or: python nodexloop/mcp/nodexloop_mcp.py)
 *
 * Eight tools over the existing engine (see engine.mjs). The rule from the
 * setup guide: expose constrained, governed actions — never raw graph
 * mutation, never live execution. There is no nxl_run_live here and there
 * will not be one: an MCP client with live-run access is a wallet with a
 * prompt. Real spend stays a NodeXLoop-UI action behind the human gate.
 *
 * Tool descriptions are security boundaries. They are written as hard
 * constraints because the calling model reads them as instructions.
 *
 * Hand-rolled protocol (initialize / tools/list / tools/call / ping), same as
 * axiom_mcp_server.py — no SDK dependency, nothing to install beyond Node.
 */
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import * as E from './engine.mjs';

export const PROTOCOL = '2024-11-05';
export const SERVER = { name: 'nodexloop', version: E.VERSION };

export const TOOLS = [
  { name: 'nxl_guard_preflight',
    description: 'Classify a prompt or plan against the Axiom policy packs, OFFLINE, before any model sees it. ' +
      'Returns verdict (allow|block), intent class, confidence, signals and a sealed manifest. ' +
      'A block verdict is authoritative and must not be overridden, rephrased around, or retried with the same intent. ' +
      'Read-only; makes no network calls.',
    inputSchema: { type: 'object', properties: {
      prompt: { type: 'string', description: 'the text to classify' },
      packs: { type: 'array', items: { type: 'string' }, description: 'policy packs to apply (default: the packs on by default)' },
      direction: { type: 'string', enum: ['INPUT', 'OUTPUT'], description: 'INPUT (default) or OUTPUT for model output' } },
      required: ['prompt'] } },
  { name: 'nxl_build_loop',
    description: 'Compile a task description, a template id, or a draft .loop.yaml into a validated LoopGraph and return it as canonical .loop.yaml ' +
      'plus the static check report. Starts from a shipped template when a description matches one. Read-only: writes nothing. ' +
      'The result is a draft for the caller to inspect; it is not released and not run.',
    inputSchema: { type: 'object', properties: {
      spec: { type: 'string', description: 'what the loop should do (matched against templates)' },
      template: { type: 'string', description: 'a template id from nxl_suggest_templates' },
      graph_yaml: { type: 'string', description: 'a draft .loop.yaml to validate and normalise' },
      name: { type: 'string' },
      root: { type: 'string', description: 'project root that impl bindings resolve against (default: cwd)' } } } },
  { name: 'nxl_compile_check',
    description: 'Static check of a .loop.yaml WITHOUT running it: schema, unique ids, dangling edges, source/sink, reachability, ' +
      'every loop bounded, impl bindings resolve to real files and symbols, guard lint on every authored prompt, module version pins present. ' +
      'Returns structured errors only. Always run this before claiming a loop is finished.',
    inputSchema: { type: 'object', properties: {
      graph_yaml: { type: 'string' },
      root: { type: 'string', description: 'project root that impl bindings resolve against (default: cwd)' } },
      required: ['graph_yaml'] } },
  { name: 'nxl_sim_loop',
    description: 'Execute a .loop.yaml in SIM mode: canned agents, real orchestration (exec order, critic iterations, gates, merges, output compose), ' +
      'real guard. Makes NO model calls and NO network calls; no tokens are spent. Returns run_id, per-node steps, stop reason ' +
      '(COMPLETED | LOOP_STALLED | LOOP_FLAT | ...), guard verdicts and estimated tokens saved. ' +
      'max_iterations is clamped server-side to 5; breakpoints are ignored so the run completes. ' +
      'A sim pass proves orchestration and policy, not model quality.',
    inputSchema: { type: 'object', properties: {
      graph_yaml: { type: 'string' },
      max_iterations: { type: 'integer', minimum: 1, maximum: 5 },
      label: { type: 'string' } },
      required: ['graph_yaml'] } },
  { name: 'nxl_get_trace',
    description: 'Replay a recorded run: the full trace, or one step with its inputs, guard verdicts and logs. ' +
      'This is what to read before deciding the next fix. Read-only.',
    inputSchema: { type: 'object', properties: {
      run_id: { type: 'string' },
      step: { type: 'integer', minimum: 1, description: 'omit for the whole run' } },
      required: ['run_id'] } },
  { name: 'nxl_module_resolve',
    description: 'Governed Python package resolution through the seven-check gate: allowlisted registry, typosquat distance, pinned version, ' +
      'sha256 from registry metadata, install-script warning, license, isolated env. Raises on any FAIL — never silently installs. ' +
      'Default is resolve-only (no install). install=true performs the pinned install into an isolated venv under the state dir, ' +
      'records the pin in modules.json and appends a sealed receipt. It never touches the caller\'s interpreter.',
    inputSchema: { type: 'object', properties: {
      package: { type: 'string' },
      pin: { type: 'string', description: 'exact version; default = latest non-yanked' },
      install: { type: 'boolean', description: 'default false' },
      reason: { type: 'string', description: 'why the loop wants it — copied into the receipt' },
      capabilities: { type: 'array', items: { type: 'string' }, description: 'declared access, e.g. network, local_files' } },
      required: ['package'] } },
  { name: 'nxl_build_and_harden',
    description: 'The thick call: build -> compile check -> sim -> mechanical repair -> repeat, budget-capped server-side (<=5 iterations). ' +
      'Repairs are mechanical only (dangling edges dropped, unbounded loops bounded, missing thresholds set); NO model is consulted. ' +
      'Guard blocks and broken bindings stop the loop for a human. The result lands in sandbox review (a .loop.yaml + review.json under the ' +
      'state dir, and an org submission when signed in) — never in a released template. There is no path from this tool to release.',
    inputSchema: { type: 'object', properties: {
      spec: { type: 'string' }, template: { type: 'string' }, graph_yaml: { type: 'string' }, name: { type: 'string' },
      root: { type: 'string' },
      threshold: { type: 'number', minimum: 0, maximum: 1, description: 'critic score to reach (default 0.8)' },
      max_iterations: { type: 'integer', minimum: 1, maximum: 5 },
      allow_threshold_relaxation: { type: 'boolean', description: 'opt in to lowering critic thresholds to the observed score; recorded as a relaxation' } } } },
  { name: 'nxl_suggest_templates',
    description: 'Shipped templates (and org-released ones when this machine is signed in via nxl-admin) that match a described task, ' +
      'so the agent starts from a human-approved loop. Read-only.',
    inputSchema: { type: 'object', properties: {
      task: { type: 'string' }, limit: { type: 'integer', minimum: 1, maximum: 20 } },
      required: ['task'] } }
];

const HANDLERS = {
  async nxl_guard_preflight(a) {
    const v = await E.preflight(a.prompt, { packs: a.packs, direction: a.direction || 'INPUT' });
    v.receipt = E.seal('nxl_guard_preflight', { input_sha256: v.input_sha256, summary: { verdict: v.verdict, class: v.class } });
    return v;
  },
  async nxl_build_loop(a) {
    const r = await E.buildLoop(a);
    r.receipt = E.seal('nxl_build_loop', { source: r.source, name: r.name, summary: { ok: r.check.ok, errors: r.check.errors.length } });
    return r;
  },
  async nxl_compile_check(a) {
    const p = E.parseYaml(a.graph_yaml);
    const r = await E.compileCheck(p.graph, { root: a.root, problems: p.problems });
    r.receipt = E.seal('nxl_compile_check', { graph_sha256: E.sha256(a.graph_yaml), summary: { ok: r.ok, errors: r.errors.length, warnings: r.warnings.length } });
    return r;
  },
  async nxl_sim_loop(a) {
    const p = E.parseYaml(a.graph_yaml);
    const r = await E.simRun(p.graph, { maxIterations: a.max_iterations, label: a.label });
    r.receipt = E.seal('nxl_sim_loop', { run_id: r.run_id, graph_sha256: E.sha256(a.graph_yaml),
                                         summary: { status: r.status, stop_reason: r.stop_reason, score: r.score, guard_blocked: r.guard && r.guard.blocked } });
    return r;
  },
  async nxl_get_trace(a) { return E.getTrace(a.run_id, a.step); },
  async nxl_module_resolve(a) {
    const r = await E.resolveModule(a);
    r.receipt_summary = E.seal('nxl_module_resolve', { package: r.package, version: r.version, summary: { installed: r.installed, blocked: false } });
    return r;
  },
  async nxl_build_and_harden(a) {
    const r = await E.buildAndHarden(a);
    r.receipt = E.seal('nxl_build_and_harden', { summary: { status: r.final && r.final.status, iterations: r.history.length, sandbox: r.sandbox.yaml } });
    return r;
  },
  async nxl_suggest_templates(a) {
    const local = E.suggestTemplates(a.task, a.limit || 5);
    const org = await E.orgReleased();
    return { ...local, org };
  }
};

export async function callTool(name, args) {
  const h = HANDLERS[name];
  if (!h) throw new E.ToolError(`unknown tool: ${name}`, { available: TOOLS.map(t => t.name) });
  if (args !== undefined && (typeof args !== 'object' || Array.isArray(args) || args === null)) throw new E.ToolError('arguments must be an object');
  return h(args || {});
}

function content(obj, isError) {
  return { content: [{ type: 'text', text: JSON.stringify(obj) }], ...(isError ? { isError: true } : {}) };
}

export async function handle(req) {
  const id = req.id === undefined ? null : req.id;
  const method = req.method || '';
  const params = req.params || {};
  const reply = result => ({ jsonrpc: '2.0', id, result });
  const fail = (code, message, data) => ({ jsonrpc: '2.0', id, error: { code, message, ...(data ? { data } : {}) } });
  try {
    if (method === 'initialize') return reply({ protocolVersion: PROTOCOL, capabilities: { tools: {} }, serverInfo: SERVER });
    if (method === 'notifications/initialized' || method.startsWith('notifications/')) return null;
    if (method === 'ping') return reply({});
    if (method === 'tools/list') return reply({ tools: TOOLS });
    if (method === 'tools/call') {
      try {
        const r = await callTool(params.name, params.arguments);
        return reply(content(r));
      } catch (e) {
        if (e instanceof E.ToolError) return reply(content({ error: e.message, ...(e.data ? { data: e.data } : {}) }, true));
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
  // Nothing but protocol goes to stdout; the engine's own noise is silenced in the VM.
  serve().catch(e => { process.stderr.write('nodexloop-mcp: ' + (e && e.stack || e) + '\n'); process.exit(1); });
}
