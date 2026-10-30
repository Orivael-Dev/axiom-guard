"use strict";
/* ==========================================================================
 * Module Resolver — governed capability loading for loops.
 *
 * Turns "this loop needs pygame" into: resolve the package against its
 * registry, run a deterministic policy gate, install into an isolated
 * environment the developer chose, index the *installed* version's API so
 * generation and debugging nodes get version-correct context, and record the
 * whole decision as a locally-sealed receipt.
 *
 * Generic by construction: everything ecosystem-specific sits behind
 * EcosystemDriver. v1 ships the Python driver; npm and friends reuse the
 * same request/resolved/gate/receipt contract without touching callers.
 *
 * Two hard rules, mirrored from the rest of NodeXLoop:
 *  - No model anywhere in this path. Resolution, gating and indexing are
 *    deterministic; the LLM consumes the output, it never produces it.
 *  - The gate refuses, it does not nag. A FAIL blocks the install; a WARN is
 *    shown and recorded in the receipt. Silence is never approval.
 *
 * Host-side egress from this file goes to exactly one place: the package
 * registry (pypi.org for the Python driver). Nothing else, and nothing at all
 * until the developer asked for a package by name.
 * ======================================================================== */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.PythonResolver = void 0;
exports.normalizePkgName = normalizePkgName;
exports.isValidPkgName = isValidPkgName;
exports.typosquatSuspicion = typosquatSuspicion;
exports.metaFromPypiJson = metaFromPypiJson;
exports.pickVersion = pickVersion;
exports.artifactHash = artifactHash;
exports.hasWheel = hasWheel;
exports.runGate = runGate;
exports.gateBlocked = gateBlocked;
exports.signReceipt = signReceipt;
exports.verifyReceipt = verifyReceipt;
exports.mergeManifest = mergeManifest;
const crypto = __importStar(require("crypto"));
/* ---- Python name handling ------------------------------------------------ */
/** PEP 503 normalization: case-insensitive, runs of -_. collapse to "-". */
function normalizePkgName(name) {
    return name.toLowerCase().replace(/[-_.]+/g, '-');
}
const PKG_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
function isValidPkgName(name) {
    return PKG_NAME_RE.test(name) && name.length <= 100;
}
/* High-traffic PyPI names. A request whose normalized name is one edit away
 * from one of these — but is not the name itself — is how typosquats work
 * ("reqeusts", "numpyy"). The list is deliberately small and curated: it only
 * has to cover the packages squatters actually imitate. */
const TOP_PYPI = [
    'requests', 'numpy', 'pandas', 'scipy', 'matplotlib', 'pillow', 'django',
    'flask', 'fastapi', 'pytest', 'setuptools', 'wheel', 'pip', 'urllib3',
    'boto3', 'botocore', 'certifi', 'charset-normalizer', 'idna', 'packaging',
    'python-dateutil', 'pyyaml', 'six', 'typing-extensions', 'cryptography',
    'pydantic', 'sqlalchemy', 'aiohttp', 'httpx', 'click', 'rich', 'tqdm',
    'openai', 'anthropic', 'langchain', 'transformers', 'torch', 'tensorflow',
    'scikit-learn', 'beautifulsoup4', 'lxml', 'selenium', 'pygame', 'colorama',
    'attrs', 'jinja2', 'werkzeug', 'psycopg2', 'redis', 'celery', 'gunicorn',
];
/* Damerau-Levenshtein (optimal string alignment): an adjacent transposition
 * costs 1, because "reqeusts" IS the classic squat of "requests" and plain
 * Levenshtein scores it 2 — the first version of this function missed it and
 * the test caught that. */
function editDistance(a, b) {
    if (Math.abs(a.length - b.length) > 1) {
        return 2;
    } // caller only needs <=1
    const rows = [Array.from({ length: b.length + 1 }, (_, j) => j)];
    for (let i = 1; i <= a.length; i++) {
        const row = [i];
        for (let j = 1; j <= b.length; j++) {
            let d = Math.min(rows[i - 1][j] + 1, row[j - 1] + 1, rows[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
            if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
                d = Math.min(d, rows[i - 2][j - 2] + 1);
            }
            row.push(d);
        }
        rows.push(row);
    }
    return rows[a.length][b.length];
}
/** Non-null when the name looks like a typosquat of a well-known package. */
function typosquatSuspicion(name) {
    const n = normalizePkgName(name);
    for (const top of TOP_PYPI) {
        if (n === top) {
            return null;
        } // the real thing
    }
    for (const top of TOP_PYPI) {
        if (editDistance(n, top) === 1) {
            return { lookalikeOf: top };
        }
    }
    return null;
}
/** Shape the PyPI JSON API response into the small slice the gate needs. */
function metaFromPypiJson(d) {
    const info = d?.info ?? {};
    return {
        name: String(info.name ?? ''),
        source: 'pypi',
        latestVersion: String(info.version ?? ''),
        license: String(info.license || info.license_expression || ''),
        summary: String(info.summary ?? ''),
        releases: d?.releases ?? {},
    };
}
const PRERELEASE_RE = /(a|b|rc|dev)\d*$/i;
/** Choose the version to pin: the requested one (which must exist and not be
 *  fully yanked), else the registry's latest, else the highest stable release.
 *  Returns null when nothing installable exists — the gate turns that into a
 *  FAIL rather than letting pip improvise. */
function pickVersion(meta, requested) {
    const usable = (v) => {
        const files = meta.releases[v] ?? [];
        return files.length > 0 && files.some((f) => !f.yanked);
    };
    if (requested) {
        return usable(requested) ? requested : null;
    }
    if (meta.latestVersion && usable(meta.latestVersion)) {
        return meta.latestVersion;
    }
    const stable = Object.keys(meta.releases)
        .filter((v) => usable(v) && !PRERELEASE_RE.test(v))
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    return stable.length ? stable[stable.length - 1] : null;
}
/** The registry sha256 for the artifact pip will prefer (wheel over sdist). */
function artifactHash(meta, version) {
    const files = (meta.releases[version] ?? []).filter((f) => !f.yanked);
    const wheel = files.find((f) => f.packagetype === 'bdist_wheel');
    return (wheel ?? files[0])?.digests?.sha256 ?? '';
}
function hasWheel(meta, version) {
    return (meta.releases[version] ?? []).some((f) => !f.yanked && f.packagetype === 'bdist_wheel');
}
/* ---- the policy gate ------------------------------------------------------ */
function runGate(req, meta, version) {
    const checks = [];
    const squat = typosquatSuspicion(req.packageName);
    checks.push(squat
        ? { check: 'typosquat', outcome: 'FAIL',
            detail: `"${req.packageName}" is one edit from "${squat.lookalikeOf}" — ` +
                `if you meant ${squat.lookalikeOf}, request that; if this is ` +
                `really a different package, its author chose a bad name` }
        : { check: 'typosquat', outcome: 'PASS', detail: 'name is not a near-miss of a well-known package' });
    checks.push(meta
        ? { check: 'package_exists', outcome: 'PASS', detail: `${meta.name} found on ${meta.source}` }
        : { check: 'package_exists', outcome: 'FAIL', detail: 'not found on the registry' });
    checks.push({ check: 'registry_allowed',
        outcome: !meta || meta.source === 'pypi' ? 'PASS' : 'FAIL',
        detail: meta ? `source: ${meta.source}` : 'no registry consulted' });
    checks.push(version
        ? { check: 'version_pinned', outcome: 'PASS', detail: `pinned to ${version}` }
        : { check: 'version_pinned', outcome: 'FAIL',
            detail: req.requestedVersion
                ? `requested version ${req.requestedVersion} does not exist or is yanked`
                : 'no installable release found' });
    if (meta && version) {
        checks.push(artifactHash(meta, version)
            ? { check: 'integrity_hash', outcome: 'PASS', detail: 'registry publishes a sha256 for the artifact' }
            : { check: 'integrity_hash', outcome: 'WARN', detail: 'registry lists no digest; install proceeds on pip verification only' });
        checks.push(hasWheel(meta, version)
            ? { check: 'install_scripts', outcome: 'PASS', detail: 'binary wheel available — no setup.py runs at install' }
            : { check: 'install_scripts', outcome: 'WARN',
                detail: 'source-only release: setup.py executes at install time' });
        checks.push(meta.license
            ? { check: 'license_declared', outcome: 'PASS', detail: meta.license.slice(0, 80) }
            : { check: 'license_declared', outcome: 'WARN', detail: 'no license metadata declared' });
    }
    return checks;
}
function gateBlocked(checks) {
    return checks.find((c) => c.outcome === 'FAIL') ?? null;
}
/* ---- receipts: locally sealed, tamper-evident on this machine ------------- */
function signReceipt(payload, keyHex) {
    const canonical = JSON.stringify(payload, Object.keys(payload).sort());
    return crypto.createHmac('sha256', Buffer.from(keyHex, 'hex'))
        .update(canonical).digest('hex');
}
function verifyReceipt(receipt, keyHex) {
    const { signature, ...payload } = receipt;
    if (typeof signature !== 'string') {
        return false;
    }
    const expect = signReceipt(payload, keyHex);
    return signature.length === expect.length &&
        crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expect));
}
/** Add or replace one module entry; same normalized name replaces in place so
 *  a version bump does not leave two pins for one package. */
function mergeManifest(existing, entry, pythonVersion) {
    const m = existing ?? { environment: 'python', modules: [] };
    if (pythonVersion) {
        m.python = pythonVersion;
    }
    const key = normalizePkgName(entry.name);
    m.modules = m.modules.filter((e) => normalizePkgName(e.name) !== key);
    m.modules.push(entry);
    m.modules.sort((a, b) => a.name.localeCompare(b.name));
    return m;
}
class PythonResolver {
    deps;
    constructor(deps) {
        this.deps = deps;
    }
    async resolve(req) {
        // The typosquat check runs before any network: a squatted name should not
        // even earn the DNS lookup.
        if (!isValidPkgName(req.packageName) || typosquatSuspicion(req.packageName)) {
            const gate = runGate(req, null, null);
            return { meta: null, version: null, gate, blocked: gateBlocked(gate) };
        }
        let meta = null;
        try {
            const url = `https://pypi.org/pypi/${encodeURIComponent(req.packageName)}/json`;
            meta = metaFromPypiJson(await this.deps.fetchJson(url));
        }
        catch {
            meta = null;
        }
        const version = meta ? pickVersion(meta, req.requestedVersion) : null;
        const gate = runGate(req, meta, version);
        return { meta, version, gate, blocked: gateBlocked(gate) };
    }
    /** Locate a Python interpreter: explicit setting first, then the platform's
     *  usual suspects. Returns the command that answered, or null. */
    async findPython(preferred) {
        const candidates = [preferred, 'python3', 'python', 'py']
            .filter((c) => !!c);
        for (const c of candidates) {
            const r = await this.deps.exec(c, ['--version'], { timeoutMs: 15000 });
            if (r.code === 0) {
                return c;
            }
        }
        return null;
    }
    /** Create (or reuse) the venv and install name==version into it. Returns the
     *  env's python path and the full installer log — the log goes into the
     *  receipt because "what did the installer actually do" is the question a
     *  future audit asks. */
    async install(python, envDir, name, version) {
        const sep = process.platform === 'win32' ? '\\Scripts\\python.exe' : '/bin/python';
        const envPython = envDir + sep;
        let logText = '';
        const venv = await this.deps.exec(python, ['-m', 'venv', envDir], { timeoutMs: 120000 });
        logText += venv.stdout + venv.stderr;
        if (venv.code !== 0) {
            return { envPython, log: logText, ok: false };
        }
        const pin = `${name}==${version}`;
        const pip = await this.deps.exec(envPython, ['-m', 'pip', 'install', '--no-input', '--disable-pip-version-check', pin], { timeoutMs: 600000 });
        logText += '\n$ pip install ' + pin + '\n' + pip.stdout + pip.stderr;
        return { envPython, log: logText, ok: pip.code === 0 };
    }
    /** Run the bundled probe inside the env: version, symbols, signatures,
     *  docstring heads — the context index generation nodes consume. */
    async probe(envPython, probeScript, name) {
        const r = await this.deps.exec(envPython, [probeScript, name], { timeoutMs: 120000 });
        if (r.code !== 0) {
            return null;
        }
        try {
            return JSON.parse(r.stdout);
        }
        catch {
            return null;
        }
    }
}
exports.PythonResolver = PythonResolver;
