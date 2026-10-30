#!/usr/bin/env node
/**
 * Plugin entry point for the vendored NodeXLoop MCP server.
 *
 * Upstream, engine.mjs keeps its state in <repo>/.nodexloop — the parent of
 * nodexloop/. Installed as a plugin that parent is the plugin cache, which is
 * replaced on every update, so runs and receipts would vanish and trace replay
 * would break. Default the state dir to the project Claude Code was opened in
 * (the server's cwd) instead; NXL_MCP_STATE still overrides.
 */
import { join } from 'node:path';

if (!process.env.NXL_MCP_STATE) process.env.NXL_MCP_STATE = join(process.cwd(), '.nodexloop');

const { serve } = await import('./nodexloop_mcp.mjs');
process.stdin.setEncoding('utf8');
serve().catch(e => { process.stderr.write('nodexloop-mcp: ' + (e && e.stack || e) + '\n'); process.exit(1); });
