/* ===========================================================================
 * NodeXLoop Code Link — graph <-> .loop.yaml
 * ---------------------------------------------------------------------------
 * The workflow definition lives in the repo, next to the code it drives, and
 * the canvas is a view onto it. Edit the graph, the file changes. Edit the
 * file, the graph changes.
 *
 * This module is deliberately PURE: graph object in, YAML text out, and back.
 * It never touches the DOM, `nodes`, `edges` or the VS Code bridge. That is not
 * tidiness for its own sake — the app's state lives in top-level `let` bindings
 * that an injected <script> cannot see, so the stateful half (debounce, file
 * watch, conflict handling) has to be injected *inside* the app's scope. Making
 * the hard part — serialisation — pure is what makes it testable.
 *
 * The round-trip guarantee this file owes its callers:
 *
 *     fromYaml(toYaml(g)).graph  deep-equals  normalise(g)
 *
 * `tools/test-codelink.mjs` asserts it over hand-written and generated graphs.
 * =========================================================================== */
(function (global) {
  'use strict';

  var VERSION = '1.0';
  var API = 'nodexloop/v1';

  /* ---------------------------------------------------------------------
   * The schema
   *
   * Only fields listed here survive a round trip. Runtime-only state —
   * `running`, `active`, `guard` — is deliberately absent: it describes an
   * execution, not the workflow, and committing it would produce diff noise
   * on every run.
   * ------------------------------------------------------------------ */
  var CONFIG_FIELDS = [
    { key: 'model', type: 'string' },
    { key: 'temperature', type: 'number' },
    { key: 'maxIterations', type: 'number' },
    { key: 'threshold', type: 'number' },
    { key: 'autoTerminate', type: 'boolean' },
    { key: 'passContext', type: 'boolean' },
    { key: 'format', type: 'string' },
    { key: 'systemPrompt', type: 'string' },
    { key: 'prompt', type: 'string' },
    { key: 'attachments', type: 'list' },
    { key: 'command', type: 'string' },
    { key: 'manifest', type: 'string' },
    { key: 'cwd', type: 'string' },
    { key: 'query', type: 'string' },
    { key: 'maxResults', type: 'number' },
    { key: 'adversary', type: 'boolean' },
    { key: 'permissions', type: 'map' }
  ];

  var PERMISSION_FIELDS = ['files', 'network', 'shell', 'git', 'secrets'];

  /* =====================================================================
   * Emit
   * =================================================================== */

  // A scalar needs quoting when it could otherwise parse as something else,
  // or when leading/trailing space would be lost.
  function needsQuote(s) {
    if (s === '') return true;
    if (/[\n\r]/.test(s)) return true;      // a bare scalar cannot span lines
    if (/^[\s]|[\s]$/.test(s)) return true;
    if (/^(true|false|null|yes|no|on|off|~)$/i.test(s)) return true;
    if (/^[-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?$/.test(s)) return true;
    if (/^[-?:,[\]{}#&*!|>'"%@`]/.test(s)) return true;
    if (/:\s|\s#/.test(s)) return true;
    return false;
  }

  function quote(s) {
    return '"' + String(s)
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\t/g, '\\t') + '"';
  }

  function scalar(v) {
    if (v === null || v === undefined) return 'null';
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'number') return String(v);
    var s = String(v);
    return needsQuote(s) ? quote(s) : s;
  }

  // Edges are emitted as an inline flow mapping to keep them one line each, and
  // inside `{ ... }` the structural characters bite anywhere in the value, not
  // just at the start: a comma ends the entry, a brace or bracket ends the
  // collection. `label: cold, next tick` therefore emits a file that this
  // module's own parser rejects, and `label: retry } done` one that a
  // standards-compliant YAML parser rejects — both from an edge label a user
  // could reasonably type. Block context is unaffected, so this is only for the
  // flow line.
  function flowScalar(v) {
    var s = String(v);
    if (typeof v === 'string' && /[,{}\[\]]/.test(s)) return quote(s);
    return scalar(v);
  }

  // Multi-line strings become literal block scalars. A prompt is the field
  // people most want to edit by hand, and `"You are...\n\nDo X"` is unreadable
  // in a diff; `|-` keeps it as text.
  //
  // Only when `|-` is exact, though. It strips trailing newlines, so a value
  // that ends in one falls back to a quoted scalar: ugly beats lossy, and this
  // is the difference between a prompt surviving a sync and being silently
  // rewritten in the user's repo.
  function blockSafe(value) {
    return typeof value === 'string'
      && value.indexOf('\n') !== -1
      && !/\n$/.test(value);
  }

  function emitString(key, value, indent) {
    var pad = new Array(indent + 1).join(' ');
    if (blockSafe(value)) {
      var lines = value.split('\n').map(function (l) {
        return l ? pad + '  ' + l : '';
      });
      return [pad + key + ': |-'].concat(lines);
    }
    return [pad + key + ': ' + scalar(value)];
  }

  function toYaml(graph) {
    var g = normalise(graph);
    var L = [];

    L.push('# NodeXLoop graph manifest — commit this next to the code it drives.');
    L.push('# Edit either side: the canvas writes this file, this file redraws the canvas.');
    L.push('apiVersion: ' + API);
    L.push('kind: LoopGraph');
    L.push('metadata:');
    L.push('  name: ' + scalar(g.name));
    L.push('spec:');
    L.push('  nodes:');

    g.nodes.forEach(function (n) {
      L.push('    - id: ' + n.id);
      L.push('      type: ' + scalar(n.type));
      L.push('      name: ' + scalar(n.name));
      if (n.desc) L.push('      description: ' + scalar(n.desc));
      if (n.color) L.push('      color: ' + scalar(n.color));
      L.push('      position: { x: ' + n.x + ', y: ' + n.y + ' }');
      if (n.breakpoint) L.push('      breakpoint: true');

      if (n.impl && (n.impl.file || n.impl.symbol)) {
        L.push('      impl:');
        if (n.impl.file) L.push('        file: ' + scalar(n.impl.file));
        if (n.impl.symbol) L.push('        symbol: ' + scalar(n.impl.symbol));
      }

      var cfgLines = [];
      CONFIG_FIELDS.forEach(function (f) {
        var v = n.config[f.key];
        if (v === undefined || v === null) return;
        if (f.type === 'list') {
          if (!v.length) return;
          cfgLines.push('        ' + f.key + ': [' + v.map(scalar).join(', ') + ']');
        } else if (f.type === 'map') {
          var keys = PERMISSION_FIELDS.filter(function (k) { return v[k] !== undefined && v[k] !== ''; });
          if (!keys.length) return;
          cfgLines.push('        permissions:');
          keys.forEach(function (k) { cfgLines.push('          ' + k + ': ' + scalar(v[k])); });
        } else if (f.type === 'string') {
          if (v === '') return;
          emitString(f.key, v, 8).forEach(function (l) { cfgLines.push(l); });
        } else {
          cfgLines.push('        ' + f.key + ': ' + scalar(v));
        }
      });
      if (cfgLines.length) {
        L.push('      config:');
        cfgLines.forEach(function (l) { L.push(l); });
      }
    });

    L.push('  edges:');
    g.edges.forEach(function (e) {
      var parts = ['from: ' + e.from, 'to: ' + e.to, 'type: ' + flowScalar(e.type)];
      if (e.label) parts.push('label: ' + flowScalar(e.label));
      L.push('    - { ' + parts.join(', ') + ' }');
    });

    return L.join('\n') + '\n';
  }

  /* =====================================================================
   * Parse
   *
   * A schema-shaped subset of YAML, not a general implementation: block maps
   * and sequences, inline flow maps and lists, literal block scalars, quoted
   * and bare scalars, comments. Anything outside that is reported as an error
   * with a line number rather than silently half-read — a graph that parses
   * "mostly" would overwrite the file with the half it understood.
   * =================================================================== */

  function stripComment(line) {
    var out = '', q = null;
    for (var i = 0; i < line.length; i++) {
      var c = line[i];
      if (q) {
        out += c;
        if (c === '\\' && q === '"') { out += line[++i] || ''; continue; }
        if (c === q) q = null;
      } else if (c === '"' || c === "'") { q = c; out += c; }
      else if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) break;
      else out += c;
    }
    return out;
  }

  function parseScalar(raw, lineNo) {
    var s = raw.trim();
    if (s === '') return '';
    if (s === 'null' || s === '~') return null;
    if (s === 'true' || s === 'True') return true;
    if (s === 'false' || s === 'False') return false;
    if (s[0] === '"') {
      if (s[s.length - 1] !== '"' || s.length < 2) throw err('unterminated quoted string', lineNo);
      return s.slice(1, -1)
        .replace(/\\n/g, '\n').replace(/\\t/g, '\t')
        .replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    }
    if (s[0] === "'") {
      if (s[s.length - 1] !== "'" || s.length < 2) throw err('unterminated quoted string', lineNo);
      return s.slice(1, -1).replace(/''/g, "'");
    }
    if (/^[-+]?[0-9]+$/.test(s)) return parseInt(s, 10);
    if (/^[-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?$/.test(s)) return parseFloat(s);
    return s;
  }

  function err(msg, lineNo) {
    var e = new Error('line ' + (lineNo + 1) + ': ' + msg);
    e.line = lineNo + 1;
    e.isCodeLinkParseError = true;
    return e;
  }

  // `{ a: 1, b: "x, y" }` and `[a, b]`
  function splitFlow(body, lineNo) {
    var out = [], depth = 0, cur = '', q = null;
    for (var i = 0; i < body.length; i++) {
      var c = body[i];
      if (q) {
        cur += c;
        if (c === '\\' && q === '"') { cur += body[++i] || ''; continue; }
        if (c === q) q = null;
        continue;
      }
      if (c === '"' || c === "'") { q = c; cur += c; continue; }
      if (c === '{' || c === '[') { depth++; cur += c; continue; }
      if (c === '}' || c === ']') { depth--; cur += c; continue; }
      if (c === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
      cur += c;
    }
    if (q) throw err('unterminated quoted string in flow value', lineNo);
    if (cur.trim() !== '') out.push(cur);
    return out;
  }

  function parseFlowValue(s, lineNo) {
    s = s.trim();
    if (s[0] === '{') {
      if (s[s.length - 1] !== '}') throw err('unterminated flow mapping', lineNo);
      var map = {};
      splitFlow(s.slice(1, -1), lineNo).forEach(function (part) {
        var idx = indexOfSep(part);
        if (idx === -1) throw err('expected "key: value" inside { }', lineNo);
        map[part.slice(0, idx).trim()] = parseScalar(part.slice(idx + 1), lineNo);
      });
      return map;
    }
    if (s[0] === '[') {
      if (s[s.length - 1] !== ']') throw err('unterminated flow sequence', lineNo);
      var inner = s.slice(1, -1).trim();
      if (!inner) return [];
      return splitFlow(inner, lineNo).map(function (p) { return parseScalar(p, lineNo); });
    }
    return parseScalar(s, lineNo);
  }

  // First ": " (or trailing ":") outside quotes.
  function indexOfSep(s) {
    var q = null;
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (q) { if (c === '\\' && q === '"') { i++; continue; } if (c === q) q = null; continue; }
      if (c === '"' || c === "'") { q = c; continue; }
      if (c === ':' && (i + 1 === s.length || /[\s]/.test(s[i + 1]))) return i;
    }
    return -1;
  }

  /**
   * Parse an indented block starting at `i`, at indentation `indent`.
   * Returns [value, nextIndex]. Handles maps, sequences and block scalars.
   */
  function parseBlock(lines, i, indent) {
    var isSeq = false, j = i;
    while (j < lines.length && lines[j].blank) j++;
    if (j < lines.length && lines[j].indent === indent && /^-\s|^-$/.test(lines[j].text)) isSeq = true;

    if (isSeq) {
      var arr = [];
      while (i < lines.length) {
        if (lines[i].blank) { i++; continue; }
        if (lines[i].indent < indent) break;
        if (lines[i].indent > indent) throw err('unexpected indentation in sequence', lines[i].no);
        var t = lines[i].text;
        if (!/^-(\s|$)/.test(t)) break;
        var rest = t.slice(1).trim();
        if (rest === '') {
          var r0 = parseBlock(lines, i + 1, indent + 2);
          arr.push(r0[0]); i = r0[1];
        } else if (rest[0] === '{' || rest[0] === '[') {
          arr.push(parseFlowValue(rest, lines[i].no)); i++;
        } else {
          // "- key: value" opens a mapping whose indent is the key column.
          var keyIndent = lines[i].indent + 2;
          var synth = [{ indent: keyIndent, text: rest, no: lines[i].no, blank: false }];
          var k = i + 1;
          while (k < lines.length && (lines[k].blank || lines[k].indent >= keyIndent)) { synth.push(lines[k]); k++; }
          var r1 = parseBlock(synth, 0, keyIndent);
          arr.push(r1[0]); i = k;
        }
      }
      return [arr, i];
    }

    var map = {};
    while (i < lines.length) {
      if (lines[i].blank) { i++; continue; }
      if (lines[i].indent < indent) break;
      if (lines[i].indent > indent) throw err('unexpected indentation', lines[i].no);
      var line = lines[i];
      var sep = indexOfSep(line.text);
      if (sep === -1) throw err('expected "key: value"', line.no);
      var key = line.text.slice(0, sep).trim();
      var val = line.text.slice(sep + 1).trim();

      if (val === '|' || val === '|-' || val === '|+') {
        // Everything about the body comes from the untouched line: a prompt
        // line reading "  # step 1" is text, and the comment-stripped copy
        // would report it as blank and end the block early.
        var blockLines = [], bi = i + 1, bIndent = null;
        while (bi < lines.length) {
          var o = lines[bi].orig;
          var oBlank = o.trim() === '';
          var oIndent = o.length - o.replace(/^\s*/, '').length;
          if (!oBlank && oIndent <= indent) break;
          if (oBlank) { blockLines.push(''); bi++; continue; }
          if (bIndent === null) bIndent = oIndent;
          blockLines.push(o.slice(bIndent));
          bi++;
        }
        while (blockLines.length && blockLines[blockLines.length - 1] === '') blockLines.pop();
        map[key] = blockLines.join('\n') + (val === '|' || val === '|+' ? '\n' : '');
        i = bi;
      } else if (val === '') {
        var r = parseBlock(lines, i + 1, indent + 2);
        map[key] = r[0]; i = r[1];
      } else {
        map[key] = parseFlowValue(val, line.no);
        i++;
      }
    }
    return [map, i];
  }

  function tokenise(text) {
    return String(text).replace(/\r\n?/g, '\n').split('\n').map(function (raw, idx) {
      var noComment = stripComment(raw);
      var trimmed = noComment.replace(/\s+$/, '');
      var blank = trimmed.trim() === '';
      return {
        // `orig` is the untouched line. Inside a literal block scalar a `#` is
        // text, not a comment, and trailing spaces are content — so block
        // bodies are read from here, never from the comment-stripped copy.
        orig: raw,
        raw: noComment,
        text: trimmed.trim(),
        indent: blank ? 0 : trimmed.length - trimmed.replace(/^\s*/, '').length,
        no: idx,
        blank: blank
      };
    });
  }

  /**
   * Parse `.loop.yaml` into a graph.
   * Returns { ok: true, graph } or { ok: false, error, line }.
   */
  function fromYaml(text) {
    var doc;
    try {
      doc = parseBlock(tokenise(text), 0, 0)[0];
    } catch (e) {
      return { ok: false, error: e.message, line: e.line || null };
    }

    if (!doc || typeof doc !== 'object') return { ok: false, error: 'file is empty or not a mapping' };
    if (doc.apiVersion && String(doc.apiVersion) !== API) {
      return { ok: false, error: 'unsupported apiVersion ' + doc.apiVersion + ' (this build understands ' + API + ')' };
    }
    var spec = doc.spec;
    if (!spec || !Array.isArray(spec.nodes)) {
      return { ok: false, error: 'spec.nodes is missing or not a list' };
    }

    var seen = {}, nodes = [], problems = [];

    spec.nodes.forEach(function (raw, idx) {
      if (!raw || typeof raw !== 'object') { problems.push('node #' + (idx + 1) + ' is not a mapping'); return; }
      var id = raw.id;
      if (typeof id !== 'number') { problems.push('node #' + (idx + 1) + ' has a missing or non-numeric id'); return; }
      if (seen[id]) { problems.push('duplicate node id ' + id); return; }
      seen[id] = 1;
      if (!raw.type) { problems.push('node ' + id + ' has no type'); return; }

      var pos = raw.position || {};
      var cfg = raw.config || {};
      // Legacy: the first export flattened these onto the node.
      CONFIG_FIELDS.forEach(function (f) {
        if (cfg[f.key] === undefined && raw[f.key] !== undefined) cfg[f.key] = raw[f.key];
      });

      var node = {
        id: id,
        type: String(raw.type),
        name: raw.name === undefined ? String(raw.type) : String(raw.name),
        desc: raw.description === undefined ? '' : String(raw.description),
        color: raw.color === undefined ? '' : String(raw.color),
        x: typeof pos.x === 'number' ? pos.x : 0,
        y: typeof pos.y === 'number' ? pos.y : 0,
        config: {}
      };
      if (raw.breakpoint === true) node.breakpoint = true;
      if (raw.impl && (raw.impl.file || raw.impl.symbol)) {
        node.impl = {};
        if (raw.impl.file) node.impl.file = String(raw.impl.file);
        if (raw.impl.symbol) node.impl.symbol = String(raw.impl.symbol);
      }

      CONFIG_FIELDS.forEach(function (f) {
        var v = cfg[f.key];
        if (v === undefined || v === null) return;
        if (f.type === 'list') { node.config[f.key] = Array.isArray(v) ? v.slice() : [v]; }
        else if (f.type === 'map') {
          if (typeof v !== 'object') return;
          var p = {};
          PERMISSION_FIELDS.forEach(function (k) { if (v[k] !== undefined && v[k] !== '') p[k] = v[k]; });
          if (Object.keys(p).length) node.config.permissions = p;
        }
        else if (f.type === 'number') { if (typeof v === 'number') node.config[f.key] = v; }
        else if (f.type === 'boolean') { node.config[f.key] = !!v; }
        else { node.config[f.key] = String(v); }
      });

      nodes.push(node);
    });

    var edges = [];
    // A key with an empty block ("edges:" and nothing under it) is
    // indistinguishable from an empty mapping at the syntax layer, so the
    // schema decides: edges is a list, and absent means none.
    var rawEdges = Array.isArray(spec.edges) ? spec.edges : [];
    rawEdges.forEach(function (raw, idx) {
      if (!raw || typeof raw !== 'object') { problems.push('edge #' + (idx + 1) + ' is not a mapping'); return; }
      if (!seen[raw.from]) { problems.push('edge #' + (idx + 1) + ' has unknown "from" node ' + raw.from); return; }
      if (!seen[raw.to]) { problems.push('edge #' + (idx + 1) + ' has unknown "to" node ' + raw.to); return; }
      var e = { from: raw.from, to: raw.to, type: raw.type ? String(raw.type) : 'normal' };
      if (raw.label) e.label = String(raw.label);
      edges.push(e);
    });

    if (!nodes.length) return { ok: false, error: 'no valid nodes: ' + problems.join('; ') };

    var maxId = nodes.reduce(function (m, n) { return Math.max(m, n.id); }, 0);
    return {
      ok: true,
      problems: problems,
      graph: {
        name: (doc.metadata && doc.metadata.name) ? String(doc.metadata.name) : 'Untitled',
        nodes: nodes,
        edges: edges,
        nextNodeId: maxId + 1
      }
    };
  }

  /* =====================================================================
   * Normalise — the canonical form both sides compare against
   * =================================================================== */
  function normalise(graph) {
    var nodes = (graph.nodes || []).map(function (n) {
      var cfg = n.config || {};
      var out = {
        id: n.id,
        type: String(n.type),
        name: n.name === undefined ? String(n.type) : String(n.name),
        desc: n.desc ? String(n.desc) : '',
        color: n.color ? String(n.color) : '',
        x: Math.round(Number(n.x) || 0),
        y: Math.round(Number(n.y) || 0),
        config: {}
      };
      if (n.breakpoint) out.breakpoint = true;
      if (n.impl && (n.impl.file || n.impl.symbol)) {
        out.impl = {};
        if (n.impl.file) out.impl.file = String(n.impl.file);
        if (n.impl.symbol) out.impl.symbol = String(n.impl.symbol);
      }
      CONFIG_FIELDS.forEach(function (f) {
        var v = cfg[f.key];
        if (v === undefined || v === null) return;
        if (f.type === 'list') { if (v.length) out.config[f.key] = v.slice(); }
        else if (f.type === 'map') {
          var p = {};
          PERMISSION_FIELDS.forEach(function (k) { if (v[k] !== undefined && v[k] !== '') p[k] = v[k]; });
          if (Object.keys(p).length) out.config.permissions = p;
        }
        else if (f.type === 'string') { if (v !== '') out.config[f.key] = String(v); }
        else if (f.type === 'number') { if (typeof v === 'number') out.config[f.key] = v; }
        else { out.config[f.key] = !!v; }
      });
      return out;
    });

    var ids = {};
    nodes.forEach(function (n) { ids[n.id] = 1; });

    var edges = (graph.edges || [])
      .filter(function (e) { return ids[e.from] && ids[e.to]; })
      .map(function (e) {
        var out = { from: e.from, to: e.to, type: e.type ? String(e.type) : 'normal' };
        if (e.label) out.label = String(e.label);
        return out;
      });

    return {
      name: graph.name ? String(graph.name) : 'Untitled',
      nodes: nodes,
      edges: edges,
      nextNodeId: nodes.reduce(function (m, n) { return Math.max(m, n.id); }, 0) + 1
    };
  }

  /* =====================================================================
   * Bindings — the node <-> source half
   * =================================================================== */

  /** Every distinct {file, symbol} a graph declares. */
  function bindings(graph) {
    var out = [];
    (graph.nodes || []).forEach(function (n) {
      if (n.impl && n.impl.file) {
        out.push({ nodeId: n.id, nodeName: n.name, file: n.impl.file, symbol: n.impl.symbol || '' });
      }
    });
    return out;
  }

  /** Node ids bound to `file`, for "reveal in graph" from the active editor. */
  function nodesForFile(graph, file) {
    if (!file) return [];
    var norm = String(file).replace(/\\/g, '/').toLowerCase();
    return (graph.nodes || []).filter(function (n) {
      if (!n.impl || !n.impl.file) return false;
      var f = String(n.impl.file).replace(/\\/g, '/').toLowerCase();
      return f === norm || norm.slice(-(f.length + 1)) === '/' + f;
    }).map(function (n) { return n.id; });
  }

  /**
   * Find a named symbol in source text. Deliberately shallow — a regex over
   * the common declaration forms in JS/TS/Python, not a parser. It reports
   * only what it can see, and `null` means "not found", which the caller
   * surfaces as a broken binding rather than guessing a line.
   */
  function findSymbol(source, symbol) {
    if (!source || !symbol) return null;
    var name = String(symbol).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    var patterns = [
      'function\\s+' + name + '\\s*\\(',
      'def\\s+' + name + '\\s*\\(',
      'class\\s+' + name + '\\b',
      '(?:const|let|var)\\s+' + name + '\\s*=',
      '^\\s*(?:async\\s+)?' + name + '\\s*\\([^)]*\\)\\s*[:{]',
      '^\\s*' + name + '\\s*[:=]\\s*(?:async\\s*)?(?:function|\\()'
    ];
    var lines = String(source).split(/\r\n?|\n/);
    for (var p = 0; p < patterns.length; p++) {
      var re = new RegExp(patterns[p]);
      for (var i = 0; i < lines.length; i++) {
        if (re.test(lines[i])) return { line: i + 1, text: lines[i].trim().slice(0, 200) };
      }
    }
    return null;
  }

  global.NodeXLoopCodeLink = {
    VERSION: VERSION,
    apiVersion: API,
    toYaml: toYaml,
    fromYaml: fromYaml,
    normalise: normalise,
    bindings: bindings,
    nodesForFile: nodesForFile,
    findSymbol: findSymbol
  };
})(typeof window !== 'undefined' ? window : globalThis);
