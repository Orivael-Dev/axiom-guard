# Vendored NodeXLoop MCP engine

This is a copy of the NodeXLoop MCP server from the Orivael `axiom` repo
(`nodexloop/`), vendored so the Claude Code plugin works after install with
Node 18+ and nothing else. Do not edit these files here. Change them
upstream and re-copy.

Source: `axiom@f0d2b36d` (2026-10-05). Copied 2026-10-30.

| file | upstream | notes |
|---|---|---|
| `mcp/engine.mjs`, `mcp/nodexloop_mcp.mjs` | `nodexloop/mcp/` | unchanged |
| `mcp/launch.mjs` | — | plugin-only: puts state in `<cwd>/.nodexloop` instead of the plugin cache |
| `guard/axiom-guard.build.js` | built by `node tools/build-guard.mjs --kernel-only` | gitignored upstream, committed here |
| `codelink/codelink.js` | `nodexloop/codelink/` | unchanged |
| `app/index.html` | `nodexloop/app/` | the sim executor and template library, same file served at nodexloop.orivael.dev |
| `loop-graph-vscode/out/moduleResolver.js` | compiled from `loop-graph-vscode/src/moduleResolver.ts` | `tsc --module commonjs --target ES2022` |
| `package.json` | `nodexloop/package.json` | pins `*.js` to CommonJS |

## Re-sync

From the axiom checkout:

```sh
cd nodexloop
node tools/build-guard.mjs --kernel-only
npx -p typescript@5 tsc loop-graph-vscode/src/moduleResolver.ts --outDir /tmp/modres \
  --module commonjs --target ES2022 --lib ES2022 --strict --esModuleInterop --skipLibCheck
P=/path/to/axiom-guard/nodexloop
cp mcp/engine.mjs mcp/nodexloop_mcp.mjs "$P/mcp/"
cp guard/axiom-guard.build.js "$P/guard/"
cp codelink/codelink.js "$P/codelink/"
cp app/index.html "$P/app/"
cp package.json "$P/"
cp /tmp/modres/moduleResolver.js "$P/loop-graph-vscode/out/"
```

Then update the source line above, bump `version` in
`.claude-plugin/plugin.json` and `marketplace.json`, and run
`claude plugin validate .` from the plugin root.
