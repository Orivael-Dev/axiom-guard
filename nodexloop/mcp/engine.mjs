/**
 * NodeXLoop engine facade for the MCP server.
 *
 * Everything the tools touch is the SAME code the app and extension run —
 * the guard kernel (guard/axiom-guard.js), the graph <-> .loop.yaml serialiser
 * (codelink/codelink.js), the app's own sim executor and template library
 * (app/index.html booted in a VM behind the DOM shim tools/demo-trace.mjs
 * uses), and the compiled module resolver (loop-graph-vscode/out). Nothing is
 * reimplemented here: a verdict from nxl_guard_preflight is the verdict the
 * canvas would give, and a sim run is the run the canvas would show.
 *
 * Boundaries this module enforces regardless of what a caller asks for:
 *   - no model calls, no network from a sim run (fetch throws inside the VM);
 *   - MAX_ITER clamps every loop bound server-side;
 *   - the guard runs with escalation OFF — offline is the authority here;
 *   - module installs go through the seven-check gate and into an isolated
 *     env under the state dir, never the caller's interpreter;
 *   - every call appends a sealed receipt to the manifest.
 */
import { readFileSync, existsSync, mkdirSync, writeFileSync, appendFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve, isAbsolute, basename } from 'node:path';
import { webcrypto, createHmac, createHash, randomBytes } from 'node:crypto';
import { execFile, spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));
export const NXL_ROOT = resolve(HERE, '..');
export const REPO_ROOT = resolve(NXL_ROOT, '..');
export const VERSION = '0.1.0';
export const MAX_ITER = 5;                       // enforced here, never trusted to the caller
export const SIM_DEADLINE_MS = 60000;

export function stateDir() {
  const d = process.env.NXL_MCP_STATE || join(REPO_ROOT, '.nodexloop');
  mkdirSync(d, { recursive: true });
  return d;
}

export class ToolError extends Error {
  constructor(message, data) { super(message); this.data = data || null; }
}

/* ======================================================================
 * Receipts — sealed, appended to the manifest on every call
 * ==================================================================== */
let _key = null, _sealedBy = 'local';
function receiptKey() {
  if (_key) return _key;
  const master = process.env.AXIOM_MASTER_KEY || '';
  if (master) {
    // Mirrors axiom_signing.derive_key(salt): HMAC(key=salt, msg=master).
    _key = createHmac('sha256', Buffer.from('nodexloop-mcp-v1')).update(master, 'utf8').digest();
    _sealedBy = 'axiom';
  } else {
    _key = randomBytes(32);
    _sealedBy = 'local';                        // tamper-evident within this process only
  }
  return _key;
}
export function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  }
  return JSON.stringify(v === undefined ? null : v);
}
export function sha256(s) { return createHash('sha256').update(String(s), 'utf8').digest('hex'); }
export function seal(tool, payload) {
  const body = { tool, at: new Date().toISOString(), payload_sha256: sha256(canonical(payload)),
                 summary: payload && payload.summary !== undefined ? payload.summary : null,
                 sealed_by: _sealedBy };
  receiptKey();
  body.sealed_by = _sealedBy;
  body.signature = createHmac('sha256', receiptKey()).update(canonical(body)).digest('hex');
  try { appendFileSync(join(stateDir(), 'mcp-receipts.jsonl'), JSON.stringify(body) + '\n'); } catch { /* the receipt is still returned */ }
  return body;
}

/* ======================================================================
 * Guard kernel
 * ==================================================================== */
let _guard = null;
export function guard() {
  if (_guard) return _guard;
  const built = join(NXL_ROOT, 'guard', 'axiom-guard.build.js');
  if (!existsSync(built)) {
    const r = spawnSync(process.execPath, [join(NXL_ROOT, 'tools', 'build-guard.mjs'), '--kernel-only'],
                        { cwd: NXL_ROOT, encoding: 'utf8' });
    if (r.status !== 0 || !existsSync(built)) {
      throw new ToolError('guard kernel is not built and could not be built: ' + (r.stderr || r.stdout || 'unknown'));
    }
  }
  _guard = require(built);
  _guard.config({ enabled: true, escalate: false });   // offline is the authority; never phone home
  return _guard;
}
export function packNames() { return guard().packs.map(p => p.name); }

/**
 * Classify text offline. A 'block' verdict is authoritative. Returns the
 * guard's own sealed manifest plus a flat summary the caller can branch on.
 */
export async function preflight(text, { packs, direction = 'INPUT', stage = 'preflight', nodeName, adversaryPersona } = {}) {
  const G = guard();
  if (typeof text !== 'string') throw new ToolError('prompt must be a string');
  if (packs !== undefined) {
    if (!Array.isArray(packs) || !packs.every(p => typeof p === 'string')) throw new ToolError('packs must be a list of pack names');
    const known = new Set(packNames());
    const bad = packs.filter(p => !known.has(p));
    if (bad.length) throw new ToolError('unknown pack(s): ' + bad.join(', '), { available_packs: packNames() });
    G.config({ packs: packs.slice() });
  }
  const m = await G.check(text, { direction, stage, nodeName, adversaryPersona: !!adversaryPersona });
  return {
    verdict: m.verdict,                                    // 'allow' | 'block'
    blocked: m.verdict === 'block',
    class: m.intent && m.intent.class,
    confidence: m.intent && m.intent.confidence,
    signals: (m.intent && m.intent.signals) || [],
    pack: m.pack || null,
    input_sha256: m.inputSha256,
    sealed_by: m.sealedBy || 'local',
    manifest: m
  };
}

/* ======================================================================
 * Codelink — graph <-> .loop.yaml
 * ==================================================================== */
let _cl = null;
export function codelink() {
  if (_cl) return _cl;
  const src = readFileSync(join(NXL_ROOT, 'codelink', 'codelink.js'), 'utf8');
  const scope = {};
  new Function('window', src)(scope);
  _cl = scope.NodeXLoopCodeLink;
  return _cl;
}
export function parseYaml(text) {
  if (typeof text !== 'string' || !text.trim()) throw new ToolError('graph_yaml must be a non-empty .loop.yaml document');
  const r = codelink().fromYaml(text);
  if (!r.ok) throw new ToolError('yaml does not parse as a LoopGraph: ' + r.error, { line: r.line || null });
  return r;                                                // { ok, problems, graph }
}
export function toYaml(graph) { return codelink().toYaml(graph); }

/* ======================================================================
 * The app, booted headless (same shim as tools/demo-trace.mjs)
 * ==================================================================== */
function makeElement(id) {
  const store = {
    id: id || '', className: '', textContent: '', innerHTML: '', value: '',
    checked: false, disabled: false, scrollTop: 0, scrollHeight: 0,
    offsetWidth: 800, offsetHeight: 600, clientWidth: 800, clientHeight: 600,
    style: {}, dataset: {}, children: [], childNodes: [],
    parentNode: null, firstChild: null, nextSibling: null,
    classList: { _s: new Set(),
      add(...c) { c.forEach(x => this._s.add(x)); }, remove(...c) { c.forEach(x => this._s.delete(x)); },
      toggle(c) { this._s.has(c) ? this._s.delete(c) : this._s.add(c); }, contains(c) { return this._s.has(c); } }
  };
  const el = new Proxy(store, {
    get(t, k) {
      if (k in t) return t[k];
      if (k === 'getBoundingClientRect') return () => ({ left: 0, top: 0, width: 800, height: 600, right: 800, bottom: 600 });
      if (k === 'querySelectorAll') return () => [];
      if (k === 'querySelector' || k === 'closest') return () => null;
      if (k === 'getAttribute') return () => null;
      if (typeof k === 'symbol') return undefined;
      return () => el;
    },
    set(t, k, v) {
      t[k] = v;
      if (k === 'textContent') t.innerHTML = String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      return true;
    }
  });
  return el;
}
function makeSandbox() {
  const elements = new Map();
  const document = {
    getElementById(id) { if (!elements.has(id)) elements.set(id, makeElement(id)); return elements.get(id); },
    createElement: () => makeElement(), createElementNS: () => makeElement(),
    querySelector: () => null, querySelectorAll: () => [],
    addEventListener() {}, removeEventListener() {},
    body: makeElement('body'), documentElement: makeElement('html'), head: makeElement('head')
  };
  const storage = new Map();
  const sandbox = {
    console: { log() {}, warn() {}, error() {}, info() {}, debug() {} },
    document,
    navigator: { userAgent: 'nodexloop-mcp', clipboard: { writeText: async () => {} } },
    location: { origin: 'https://nodexloop.orivael.dev', href: '#', hash: '' },
    localStorage: { getItem: k => (storage.has(k) ? storage.get(k) : null),
                    setItem: (k, v) => storage.set(k, String(v)), removeItem: k => storage.delete(k) },
    crypto: webcrypto, performance,
    // Sim pacing sleeps 400-850ms per step; clamp so a run takes milliseconds. Order is preserved.
    setTimeout: (fn, ms, ...a) => setTimeout(fn, Math.min(ms || 0, 4), ...a), clearTimeout,
    setInterval: (fn, ms, ...a) => setInterval(fn, Math.min(ms || 0, 4), ...a), clearInterval,
    requestAnimationFrame: fn => setTimeout(fn, 0),
    // The boundary: nothing inside a sim run reaches the network.
    fetch: async () => { throw new Error('network disabled: sim runs make no model calls'); },
    AbortController, TextEncoder, TextDecoder, URL, URLSearchParams, Blob: class {},
    atob: s => Buffer.from(s, 'base64').toString('binary'), btoa: s => Buffer.from(s, 'binary').toString('base64'),
    alert() {}, confirm: () => true, prompt: () => null,
    addEventListener() {}, removeEventListener() {},
    matchMedia: () => ({ matches: false, addListener() {}, addEventListener() {} })
  };
  sandbox.window = sandbox; sandbox.globalThis = sandbox; sandbox.self = sandbox;
  return sandbox;
}
let _blocks = null;
function appBlocks() {
  if (_blocks) return _blocks;
  const app = process.env.NXL_APP || join(NXL_ROOT, 'app', 'index.html');
  const html = readFileSync(app, 'utf8');
  const blocks = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  if (blocks.length !== 2) throw new ToolError(`expected 2 script blocks in ${app}, found ${blocks.length} — run node tools/build-guard.mjs`);
  _blocks = blocks;
  return _blocks;
}
const HOOKS = `
;globalThis.__t = {
  get nodes() { return nodes; }, set nodes(v) { nodes = v; },
  get edges() { return edges; }, set edges(v) { edges = v; },
  get isRunning() { return isRunning; },
  get runMode() { return runMode; }, set runMode(v) { runMode = v; },
  get runHistory() { return runHistory; },
  get TEMPLATE_DEFS() { return TEMPLATE_DEFS; },
  templateGraph: templateGraph,
  buildExecOrder: buildExecOrder,
  startRun: startRun
};`;
const SEED_RNG = `
;(() => { let s = 0x5eed1234 >>> 0; Math.random = function () {
  s = (s + 0x6D2B79F5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; })();`;

export function bootApp() {
  const blocks = appBlocks();
  const ctx = vm.createContext(makeSandbox());
  new vm.Script(blocks[0]).runInContext(ctx);
  new vm.Script(SEED_RNG + blocks[1] + HOOKS).runInContext(ctx);
  return ctx;
}
const clone = v => JSON.parse(JSON.stringify(v));
function snapshot(ctx) {
  return { nodes: clone(ctx.__t.nodes), edges: clone(ctx.__t.edges.map(e => ({ from: e.from, to: e.to, type: e.type || 'normal', label: e.label || '' }))) };
}

/* ======================================================================
 * Templates
 * ==================================================================== */
let _defs = null;
export function templateDefs() {
  if (_defs) return _defs;
  const ctx = bootApp();
  _defs = clone(ctx.__t.TEMPLATE_DEFS).map(d => ({ id: d.id, title: d.title, desc: d.desc || '', group: d.group || '',
                                                   loops: !!d.loops, experimental: !!d.exp }));
  return _defs;
}
export function templateGraph(id) {
  const def = templateDefs().find(d => d.id === id);
  if (!def) throw new ToolError(`unknown template '${id}'`, { available: templateDefs().map(d => d.id) });
  const ctx = bootApp();
  ctx.__t.templateGraph(id);
  const g = snapshot(ctx);
  return { name: def.title, nodes: g.nodes, edges: g.edges, nextNodeId: g.nodes.reduce((m, n) => Math.max(m, Number(n.id) || 0), 0) + 1 };
}
const STOP = new Set(['the', 'and', 'for', 'with', 'that', 'this', 'from', 'into', 'then', 'loop', 'agent', 'agents', 'build', 'make', 'want', 'need', 'please', 'until']);
export function suggestTemplates(task, limit = 5) {
  if (typeof task !== 'string' || !task.trim()) throw new ToolError('task must be a non-empty description');
  const words = [...new Set(task.toLowerCase().match(/[a-z][a-z0-9-]{2,}/g) || [])].filter(w => !STOP.has(w));
  const scored = templateDefs().map(d => {
    const hay = (d.id + ' ' + d.title + ' ' + d.desc + ' ' + d.group).toLowerCase();
    const matched = words.filter(w => hay.includes(w));
    return { ...d, score: matched.length, matched };
  }).filter(d => d.score > 0).sort((a, b) => b.score - a.score || a.title.localeCompare(b.title));
  return { local: scored.slice(0, limit), terms: words };
}

/** Org-released templates, best effort: only when this machine is signed in
 *  via nxl-admin (~/.nodexloop/admin.json). Never blocks a local answer. */
export async function orgReleased(timeoutMs = 4000) {
  const cfgPath = join(homedir(), '.nodexloop', 'admin.json');
  if (!existsSync(cfgPath)) return { available: false, reason: 'not signed in (nxl-admin login)' };
  let cfg;
  try { cfg = JSON.parse(readFileSync(cfgPath, 'utf8')); } catch { return { available: false, reason: 'admin.json unreadable' }; }
  const api = (process.env.NXL_API || cfg.api || 'https://nodexloop.orivael.dev/api').replace(/\/+$/, '');
  if (!cfg.token) return { available: false, reason: 'no token in admin.json' };
  const ac = new AbortController(); const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(api + '/org/state', { headers: { Authorization: 'Bearer ' + cfg.token }, signal: ac.signal });
    if (!r.ok) return { available: false, reason: 'org/state ' + r.status };
    const j = await r.json();
    const out = [];
    (function walk(v) {
      if (Array.isArray(v)) return v.forEach(walk);
      if (v && typeof v === 'object') {
        if (v.status === 'released' && (v.title || v.name)) out.push({ id: v.id, title: v.title || v.name, releasedBy: v.releasedBy || null });
        Object.values(v).forEach(walk);
      }
    })(j);
    return { available: true, org: j.org && j.org.name, released: out };
  } catch (e) {
    return { available: false, reason: String(e.message || e) };
  } finally { clearTimeout(t); }
}

/* ======================================================================
 * Compile check — static, no run
 * ==================================================================== */
const SOURCES = new Set(['input']);
const SINKS = new Set(['output']);
const LOOPY = new Set(['critic', 'loop']);

export async function compileCheck(graph, { root, problems = [], lintPrompts = true } = {}) {
  const errors = [], warnings = [];
  const projectRoot = root ? resolve(root) : process.cwd();
  problems.forEach(p => errors.push({ node: null, issue: p }));

  const nodes = graph.nodes || [], edges = graph.edges || [];
  if (!nodes.length) errors.push({ node: null, issue: 'graph has no nodes' });
  const ids = nodes.map(n => n.id);
  if (new Set(ids).size !== ids.length) errors.push({ node: null, issue: 'node ids are not unique' });
  nodes.forEach(n => { if (!n.type) errors.push({ node: n.id, issue: 'node has no type' }); });
  const idSet = new Set(ids);
  edges.forEach((e, i) => {
    if (!idSet.has(e.from) || !idSet.has(e.to)) errors.push({ node: null, issue: `edge #${i + 1} ${e.from} -> ${e.to} references a missing node` });
  });
  if (!nodes.some(n => SOURCES.has(n.type))) errors.push({ node: null, issue: 'no input node — nothing starts the run' });
  if (!nodes.some(n => SINKS.has(n.type))) errors.push({ node: null, issue: 'no output node — the run has nowhere to land' });

  // reachability from every source
  const fwd = new Map(ids.map(i => [i, []]));
  edges.forEach(e => { if (fwd.has(e.from)) fwd.get(e.from).push(e.to); });
  const seen = new Set();
  const queue = nodes.filter(n => SOURCES.has(n.type)).map(n => n.id);
  while (queue.length) { const id = queue.shift(); if (seen.has(id)) continue; seen.add(id); (fwd.get(id) || []).forEach(t => queue.push(t)); }
  nodes.forEach(n => { if (!seen.has(n.id) && !SOURCES.has(n.type)) errors.push({ node: n.id, issue: `'${n.name}' is unreachable from the input` }); });

  // every loop bounded
  nodes.forEach(n => {
    const cfg = n.config || {};
    const loopsBack = edges.some(e => e.type === 'loop' && (e.from === n.id || e.to === n.id));
    if (LOOPY.has(n.type) || loopsBack) {
      const mi = cfg.maxIterations;
      if (!(typeof mi === 'number' && mi >= 1 && Number.isFinite(mi))) errors.push({ node: n.id, issue: `'${n.name}' has no maxIterations bound` });
      else if (mi > MAX_ITER) warnings.push({ node: n.id, issue: `'${n.name}' maxIterations ${mi} exceeds the sim cap ${MAX_ITER}; sim clamps it` });
    }
    if (n.type === 'critic') {
      const th = cfg.threshold;
      if (!(typeof th === 'number' && th > 0 && th <= 1)) errors.push({ node: n.id, issue: `'${n.name}' critic threshold must be in (0, 1]` });
    }
    if (n.type === 'module') {
      if (!cfg.packageName) errors.push({ node: n.id, issue: `module node '${n.name}' names no package` });
      else if (!cfg.moduleVersion) errors.push({ node: n.id, issue: `module '${cfg.packageName}' has no version pin (moduleVersion)` });
    }
  });

  // bindings resolve to real files / symbols
  const CL = codelink();
  const binds = CL.bindings(graph);
  binds.forEach(b => {
    const p = isAbsolute(b.file) ? b.file : join(projectRoot, b.file);
    if (!existsSync(p)) { errors.push({ node: b.nodeId, issue: `impl file not found: ${b.file}` }); return; }
    if (b.symbol) {
      const hit = CL.findSymbol(readFileSync(p, 'utf8'), b.symbol);
      if (!hit) errors.push({ node: b.nodeId, issue: `impl symbol '${b.symbol}' not found in ${b.file}` });
    }
  });

  // guard lint on every authored prompt
  let prompts = 0;
  if (lintPrompts) {
    const lint = await lintGraphPrompts(graph);
    prompts = lint.length;
    lint.forEach(v => {
      if (v.blocked) errors.push({ node: v.nodeId, issue: `guard blocks ${v.field} on '${v.node}': ${v.class} (${v.signals.slice(0, 4).join(', ')})` });
      else if (v.class === 'UNCERTAIN') warnings.push({ node: v.nodeId, issue: `guard is uncertain about ${v.field} on '${v.node}' (confidence ${v.confidence})` });
    });
  }
  return { ok: errors.length === 0, errors, warnings,
           summary: { nodes: nodes.length, edges: edges.length, bindings_checked: binds.length, prompts_checked: prompts } };
}

/** Preflight every authored prompt/systemPrompt in a graph. The static half of
 *  what the guard does at run time; sim mode makes no model calls, so this is
 *  the only guard a sim run has — and a block here means the run does not start. */
export async function lintGraphPrompts(graph) {
  const out = [];
  for (const n of graph.nodes || []) {
    const cfg = n.config || {};
    for (const field of ['prompt', 'systemPrompt']) {
      const text = cfg[field];
      if (typeof text !== 'string' || !text.trim()) continue;
      const v = await preflight(text, { stage: 'lint', nodeName: n.name, adversaryPersona: !!cfg.adversary });
      out.push({ nodeId: n.id, node: n.name, field, verdict: v.verdict, blocked: v.blocked, class: v.class,
                 confidence: v.confidence, signals: v.signals, input_sha256: v.input_sha256 });
    }
  }
  return out;
}

/* ======================================================================
 * Sim run + trace store
 * ==================================================================== */
const runs = new Map();
function runsDir() { const d = join(stateDir(), 'mcp-runs'); mkdirSync(d, { recursive: true }); return d; }

export async function simRun(graph, { maxIterations = MAX_ITER, label } = {}) {
  const cap = Math.max(1, Math.min(Number(maxIterations) || MAX_ITER, MAX_ITER));
  const lint = await lintGraphPrompts(graph);
  const blockedPrompts = lint.filter(v => v.blocked);
  if (blockedPrompts.length) {
    // The guard's promise: a blocked prompt costs zero calls. Nothing runs.
    const runId = 'nxl-' + Date.now().toString(36) + '-' + randomBytes(3).toString('hex');
    const record = {
      run_id: runId, label: label || graph.name || 'untitled', mode: 'sim', at: new Date().toISOString(),
      completed: true, status: 'blocked', stop_reason: 'GUARD_BLOCK', score: null, iterations: 0,
      max_iterations: cap, breakpoints_ignored: 0, bounds_clamped: 0,
      guard: { checked: lint.length, blocked: blockedPrompts.length, iterations_saved: 0, est_tokens_saved: 0,
               stops: blockedPrompts.map(v => ({ reason: 'GUARD_BLOCK', node: v.node, field: v.field, class: v.class })) },
      guard_verdicts: lint.map(v => ({ node: v.node, stage: 'preflight', direction: 'INPUT', verdict: v.verdict, class: v.class, confidence: v.confidence, field: v.field })),
      steps: [], logs: blockedPrompts.map(v => ({ level: 'error', msg: `[axiom-guard] ${v.field} on '${v.node}' blocked before the run started: ${v.class}`, nodeId: v.nodeId })),
      output_head: '', graph: { name: graph.name || null, nodes: (graph.nodes || []).length, edges: (graph.edges || []).length }
    };
    runs.set(runId, record);
    try { writeFileSync(join(runsDir(), runId + '.json'), JSON.stringify(record, null, 1)); } catch { /* memory copy still served */ }
    return record;
  }
  const ctx = bootApp();
  let breakpointsIgnored = 0, clamped = 0;
  const nodes = clone(graph.nodes || []).map(n => {
    if (n.breakpoint) { breakpointsIgnored++; delete n.breakpoint; }   // headless: a paused run never finishes
    n.config = n.config || {};
    if (typeof n.config.maxIterations === 'number' && n.config.maxIterations > cap) { n.config.maxIterations = cap; clamped++; }
    return n;
  });
  ctx.__t.nodes = nodes;
  ctx.__t.edges = clone(graph.edges || []);
  ctx.__t.runMode = 'sim';
  if (ctx.AxiomGuard) { ctx.AxiomGuard.config({ escalate: false }); ctx.AxiomGuard.setEnabled(true); }
  ctx.__t.startRun();
  const deadline = Date.now() + SIM_DEADLINE_MS;
  while (ctx.__t.isRunning && Date.now() < deadline) await new Promise(r => setTimeout(r, 5));
  const completed = !ctx.__t.isRunning;
  const run = ctx.__t.runHistory[0] || {};
  const gs = ctx.AxiomGuard ? ctx.AxiomGuard.stats() : null;
  const manifests = ctx.AxiomGuard ? ctx.AxiomGuard.manifests(50) : [];
  const logs = (run.logs || []).map(l => ({ level: l.level, msg: l.msg, nodeId: l.nodeId === undefined ? null : l.nodeId }));
  const stopFromLog = logs.map(l => (l.msg.match(/\b(LOOP_STALLED|LOOP_FLAT|CONSTITUTIONAL[A-Z_]*|BUDGET[A-Z_]*)\b/) || [])[1]).find(Boolean) || null;
  const stopReason = (gs && gs.stops && gs.stops[0] && gs.stops[0].reason) || stopFromLog
    || (completed ? (run.status === 'completed' ? 'COMPLETED' : String(run.status || 'unknown').toUpperCase()) : 'DEADLINE');
  const runId = 'nxl-' + Date.now().toString(36) + '-' + randomBytes(3).toString('hex');
  const record = {
    run_id: runId, label: label || graph.name || 'untitled', mode: 'sim', at: new Date().toISOString(),
    completed, status: run.status || (completed ? 'unknown' : 'timeout'), stop_reason: stopReason,
    score: run.stats && run.stats.finalScore !== undefined ? run.stats.finalScore : null,
    iterations: (run.stats && run.stats.iterations) || 0,
    max_iterations: cap, breakpoints_ignored: breakpointsIgnored, bounds_clamped: clamped,
    guard: { checked: lint.length + (gs ? gs.checked : 0), blocked: gs ? gs.blocked : 0,
             iterations_saved: gs ? gs.iterationsSaved : 0, est_tokens_saved: gs ? gs.estTokensSaved : 0, stops: gs ? gs.stops : [] },
    guard_verdicts: lint.map(v => ({ node: v.node, stage: 'preflight', direction: 'INPUT', verdict: v.verdict, class: v.class, confidence: v.confidence, field: v.field }))
      .concat(manifests.map(m => ({ node: m.nodeName || m.nodeId || null, stage: m.stage, direction: m.direction,
                                   verdict: m.verdict, class: m.intent && m.intent.class, confidence: m.intent && m.intent.confidence }))),
    steps: (run.steps || []).map((s, i) => ({ step: i + 1, nodeId: s.nodeId === undefined ? null : s.nodeId, agent: s.agent,
                                             action: s.action, output: s.output, icon: s.icon })),
    logs,
    output_head: String(run.output || '').split('\n').slice(0, 8).join('\n'),
    graph: { name: graph.name || null, nodes: nodes.length, edges: (graph.edges || []).length }
  };
  runs.set(runId, record);
  try { writeFileSync(join(runsDir(), runId + '.json'), JSON.stringify(record, null, 1)); } catch { /* memory copy still served */ }
  return record;
}

export function getTrace(runId, step) {
  if (typeof runId !== 'string' || !/^nxl-[a-z0-9]+-[a-f0-9]+$/.test(runId)) throw new ToolError('run_id must look like nxl-<time>-<hex>');
  let rec = runs.get(runId);
  if (!rec) {
    const p = join(runsDir(), runId + '.json');
    if (!existsSync(p)) throw new ToolError(`unknown run ${runId}`, { known: listRuns().slice(0, 10) });
    rec = JSON.parse(readFileSync(p, 'utf8'));
    runs.set(runId, rec);
  }
  if (step === undefined || step === null) return rec;
  const n = Number(step);
  const s = rec.steps.find(x => x.step === n);
  if (!s) throw new ToolError(`run ${runId} has ${rec.steps.length} steps; no step ${step}`);
  const inputs = rec.steps.filter(x => x.step < n).slice(-2);
  const verdicts = rec.guard_verdicts.filter(v => v.node === s.agent || v.node === s.nodeId);
  const logs = rec.logs.filter(l => l.nodeId !== null ? l.nodeId === s.nodeId : l.msg.includes('[' + s.agent + ']'));
  return { run_id: runId, step: s, inputs_from: inputs, guard_verdicts: verdicts, logs,
           stop_reason: rec.stop_reason, score: rec.score };
}
export function listRuns() {
  try { return readdirSync(runsDir()).filter(f => f.endsWith('.json')).map(f => f.slice(0, -5)).sort().reverse(); } catch { return []; }
}

/* ======================================================================
 * Build loop
 * ==================================================================== */
function slug(s) { return String(s || 'loop').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'loop'; }

export async function buildLoop({ spec, graph_yaml, template, name, root } = {}) {
  let graph, source, problems = [];
  if (graph_yaml) {
    const r = parseYaml(graph_yaml); graph = r.graph; problems = r.problems || []; source = 'draft_yaml';
  } else if (template) {
    graph = templateGraph(template); source = 'template:' + template;
  } else if (spec) {
    const s = suggestTemplates(spec, 1);
    if (!s.local.length) throw new ToolError('no template matches that description; supply graph_yaml or a template id', { available: templateDefs().map(d => d.id) });
    graph = templateGraph(s.local[0].id); source = 'template:' + s.local[0].id;
    graph.name = String(spec).slice(0, 80);
  } else {
    throw new ToolError('give one of: spec (a task description), template (an id), or graph_yaml (a draft)');
  }
  if (name) graph.name = String(name);
  const check = await compileCheck(graph, { root, problems });
  return { source, name: graph.name, graph_yaml: toYaml(graph), check,
           graph_summary: { nodes: graph.nodes.length, edges: graph.edges.length,
                            types: [...new Set(graph.nodes.map(n => n.type))] } };
}

/* ======================================================================
 * Build and harden — the thick call, budget-capped, lands in sandbox
 * ==================================================================== */
export async function buildAndHarden({ spec, graph_yaml, template, name, root, threshold = 0.8, max_iterations = MAX_ITER, allow_threshold_relaxation = false } = {}) {
  const budget = Math.max(1, Math.min(Number(max_iterations) || MAX_ITER, MAX_ITER));
  const target = Math.min(1, Math.max(0, Number(threshold) || 0.8));
  let built = await buildLoop({ spec, graph_yaml, template, name, root });
  let graph = parseYaml(built.graph_yaml).graph;
  const history = [];
  let final = null;

  for (let iter = 1; iter <= budget; iter++) {
    const repairs = [];
    let check = await compileCheck(graph, { root });
    // mechanical repairs only — no model is consulted, and it says so
    if (!check.ok) {
      const idSet = new Set(graph.nodes.map(n => n.id));
      const before = graph.edges.length;
      graph.edges = graph.edges.filter(e => idSet.has(e.from) && idSet.has(e.to));
      if (graph.edges.length !== before) repairs.push(`dropped ${before - graph.edges.length} dangling edge(s)`);
      graph.nodes.forEach(n => {
        n.config = n.config || {};
        const loopsBack = graph.edges.some(e => e.type === 'loop' && (e.from === n.id || e.to === n.id));
        if ((LOOPY.has(n.type) || loopsBack) && !(typeof n.config.maxIterations === 'number' && n.config.maxIterations >= 1)) {
          n.config.maxIterations = 3; repairs.push(`bounded '${n.name}' at 3 iterations`);
        }
        if (n.type === 'critic' && !(typeof n.config.threshold === 'number' && n.config.threshold > 0 && n.config.threshold <= 1)) {
          n.config.threshold = target; repairs.push(`set '${n.name}' threshold to ${target}`);
        }
      });
      check = await compileCheck(graph, { root });
    }
    const unfixable = check.errors.filter(e => /guard blocks|impl (file|symbol)|no input|no output|unreachable|names no package|version pin/.test(e.issue));
    if (unfixable.length) {
      history.push({ iteration: iter, repairs, check, sim: null, stopped: 'needs a human: ' + unfixable.map(e => e.issue).join('; ') });
      final = { status: 'blocked', reason: 'static errors a mechanical repair cannot fix', errors: unfixable };
      break;
    }
    const sim = await simRun(graph, { maxIterations: budget, label: graph.name });
    const entry = { iteration: iter, repairs, check: { ok: check.ok, errors: check.errors.length, warnings: check.warnings.length },
                    sim: { run_id: sim.run_id, status: sim.status, stop_reason: sim.stop_reason, score: sim.score, iterations: sim.iterations,
                           guard_blocked: sim.guard ? sim.guard.blocked : 0 } };
    history.push(entry);
    const passed = sim.completed && sim.status === 'completed' && (sim.guard ? sim.guard.blocked === 0 : true)
      && (sim.score === null || sim.score >= target);
    if (passed) { final = { status: 'hardened', run_id: sim.run_id, score: sim.score, iterations_used: iter }; break; }
    // the only score-related repair is explicit opt-in, and it is recorded as a relaxation, not a fix
    if (sim.score !== null && sim.score < target && allow_threshold_relaxation) {
      graph.nodes.forEach(n => { if (n.type === 'critic' && typeof n.config.threshold === 'number' && n.config.threshold > sim.score) {
        entry.relaxed = `'${n.name}' threshold ${n.config.threshold} -> ${sim.score} (opt-in relaxation)`; n.config.threshold = sim.score; } });
      continue;
    }
    if (iter === budget) final = { status: 'budget_exhausted', run_id: sim.run_id, score: sim.score, target };
    else if (sim.score !== null && sim.score < target) { final = { status: 'below_threshold', run_id: sim.run_id, score: sim.score, target,
      note: 'no model is consulted by this tool; read nxl_get_trace and repair the prompts, or opt into threshold relaxation' }; break; }
  }

  // sandbox review, never release
  const sb = join(stateDir(), 'sandbox'); mkdirSync(sb, { recursive: true });
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '');
  const base = join(sb, `${slug(graph.name)}-${stamp}`);
  const yaml = toYaml(graph);
  writeFileSync(base + '.loop.yaml', yaml);
  const review = { name: graph.name, built_from: built.source, final, history, submitted_at: new Date().toISOString(),
                   review_path: 'sandbox', release: 'requires a named human through the org pipeline' };
  writeFileSync(base + '.review.json', JSON.stringify(review, null, 1));
  let org = { submitted: false, reason: 'not signed in' };
  try {
    const cfgPath = join(homedir(), '.nodexloop', 'admin.json');
    if (existsSync(cfgPath) && process.env.NXL_MCP_SUBMIT !== '0') {
      const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
      const api = (process.env.NXL_API || cfg.api || 'https://nodexloop.orivael.dev/api').replace(/\/+$/, '');
      if (cfg.token) {
        const ac = new AbortController(); const t = setTimeout(() => ac.abort(), 6000);
        const r = await fetch(api + '/org/submit', { method: 'POST', signal: ac.signal,
          headers: { Authorization: 'Bearer ' + cfg.token, 'Content-Type': 'application/json' },
          body: JSON.stringify({ title: graph.name, data: { nodes: graph.nodes, edges: graph.edges }, agents: graph.nodes.length }) });
        clearTimeout(t);
        org = r.ok ? { submitted: true, status: 'sandbox', submission_id: (await r.json()).submissionId } : { submitted: false, reason: 'org/submit ' + r.status };
      }
    }
  } catch (e) { org = { submitted: false, reason: String(e.message || e) }; }
  return { final, history, graph_yaml: yaml, sandbox: { yaml: base + '.loop.yaml', review: base + '.review.json', org } };
}

/* ======================================================================
 * Module resolver — the seven-check gate, isolated env
 * ==================================================================== */
let _res = null;
function resolverLib() {
  if (_res) return _res;
  const p = join(NXL_ROOT, 'loop-graph-vscode', 'out', 'moduleResolver.js');
  if (!existsSync(p)) throw new ToolError('module resolver is not compiled: cd nodexloop/loop-graph-vscode && npm install && npm run compile');
  _res = require(p);
  return _res;
}
const deps = {
  async fetchJson(url) {
    const ac = new AbortController(); const t = setTimeout(() => ac.abort(), 15000);
    try { const r = await fetch(url, { signal: ac.signal, headers: { Accept: 'application/json' } });
          if (!r.ok) throw new Error('HTTP ' + r.status); return await r.json(); }
    finally { clearTimeout(t); }
  },
  exec(cmd, args, opts = {}) {
    return new Promise(res => {
      execFile(cmd, args, { cwd: opts.cwd, timeout: opts.timeoutMs || 120000, maxBuffer: 16 * 1024 * 1024, windowsHide: true },
        (err, stdout, stderr) => res({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: String(stdout || ''), stderr: String(stderr || '') }));
    });
  }
};

export async function resolveModule({ package: pkg, pin, install = false, reason = '', capabilities = [], offline = false } = {}) {
  const M = resolverLib();
  if (typeof pkg !== 'string' || !pkg.trim()) throw new ToolError('package is required');
  if (!M.isValidPkgName(pkg)) throw new ToolError(`'${pkg}' is not a valid package name`);
  const req = { ecosystem: 'python', packageName: pkg.trim(), requestedVersion: pin || undefined, reason: String(reason || ''), capabilities: Array.isArray(capabilities) ? capabilities.map(String) : [] };
  const resolver = new M.PythonResolver(offline ? { ...deps, fetchJson: async () => { throw new Error('offline'); } } : deps);
  const r = await resolver.resolve(req);
  const out = { package: req.packageName, requested_pin: pin || null, version: r.version, source: r.meta ? r.meta.source : null,
                license: r.meta ? r.meta.license : null, summary: r.meta ? r.meta.summary : null,
                integrity_sha256: r.meta && r.version ? M.artifactHash(r.meta, r.version) : null,
                gate: r.gate, blocked: r.blocked, installed: false, env: null };
  if (r.blocked) throw new ToolError(`gate failed: ${r.blocked.check} — ${r.blocked.detail}`, out);
  if (!install) { out.note = 'gate passed; install=true performs the pinned install into an isolated env'; return out; }
  const python = await resolver.findPython(process.env.NXL_PYTHON);
  if (!python) throw new ToolError('no python interpreter found for the isolated env (set NXL_PYTHON)', out);
  const envDir = join(stateDir(), 'envs', M.normalizePkgName(req.packageName));
  mkdirSync(join(stateDir(), 'envs'), { recursive: true });
  const inst = await resolver.install(python, envDir, req.packageName, r.version);
  out.env = envDir; out.installed = inst.ok; out.install_log_tail = inst.log.split('\n').slice(-12).join('\n');
  if (!inst.ok) throw new ToolError('install failed inside the isolated env', out);
  // manifest + receipt, in the same files the extension writes
  const manPath = join(stateDir(), 'modules.json');
  let existing = null; try { existing = JSON.parse(readFileSync(manPath, 'utf8')); } catch { existing = null; }
  const merged = M.mergeManifest(existing, { name: M.normalizePkgName(req.packageName), version: r.version, source: out.source || 'pypi',
                                             permissions: req.capabilities, hash: out.integrity_sha256 || '' });
  writeFileSync(manPath, JSON.stringify(merged, null, 2));
  const payload = { package: out.package, version: out.version, hash: out.integrity_sha256, env: envDir, reason: req.reason,
                    capabilities: req.capabilities, gate: r.gate, at: new Date().toISOString(), by: 'nodexloop-mcp' };
  payload.signature = M.signReceipt(payload, receiptKey().toString('hex'));
  appendFileSync(join(stateDir(), 'module-receipts.jsonl'), JSON.stringify(payload) + '\n');
  out.receipt = payload;
  return out;
}
