import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { PLUGIN_ROOT } from "./helpers.mjs";

const verify = "verify_completion";
const handoff = "manage_handoff";
const save = { action: "save", objective: "transport check", verified_facts: [], failed_approaches: [], remaining_tasks: [] };
const call = (name, args) => ({ method: "tools/call", params: { name, arguments: args } });

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "hstack-session-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return { dir, session: { conversationId: "from-hook", cwd: dir, transcriptPath: join(dir, "transcript.jsonl") } };
}

function rpc(dir, messages, host = "claude", env = {}) {
  return new Promise((resolve, reject) => {
    const proc = execFile(process.execPath, [join(PLUGIN_ROOT, "scripts/mcp/server.mjs")], {
      cwd: dir, env: { ...process.env, HSTACK_HOST: host, PLUGIN_DATA: dir, ...env }, timeout: 15000,
    }, (error, stdout, stderr) => {
      if (error || stderr) return reject(error ?? new Error(stderr));
      try { resolve(stdout.trim().split("\n").map(line => JSON.parse(line).result)); }
      catch (err) { reject(err); }
    });
    proc.stdin.end(messages.map((msg, id) => JSON.stringify({ jsonrpc: "2.0", id, ...msg })).join("\n") + "\n");
  });
}

test("session: Claude stdio lists an optional strict-schema context string; Agy does not", async t => {
  const { dir } = fixture(t);
  for (const host of ["claude", "claude-code", "", "agy"]) {
    const [{ tools }] = await rpc(dir, [{ method: "tools/list" }], host, { CLAUDE_PLUGIN_DATA: dir });
    for (const name of [verify, handoff]) {
      const { inputSchema } = tools.find(tool => tool.name === name);
      assert.equal(inputSchema.additionalProperties, false);
      assert.equal(inputSchema.properties._hstackContext?.type, host === "agy" ? undefined : "string");
      assert.ok(!inputSchema.required.includes("_hstackContext"));
      assert.ok(!Object.hasOwn(inputSchema.properties, "_session"));
    }
  }
});

test("session: neither Claude tool accepts missing context or forged inline session", async t => {
  const { dir, session } = fixture(t);
  const results = await rpc(dir, [call(verify, { _session: session }), call(handoff, { ...save, _session: session })]);
  assert.deepEqual(results.map(r => r.isError), [true, true]);
  assert.deepEqual(readdirSync(dir), []);
});

test("session: two stdio servers racing for one context save once as the hook's identity", async t => {
  const { dir, session } = fixture(t);
  const { issueMcpContext } = await import("../scripts/host/mcp-session.mjs");
  const token = issueMcpContext(handoff, session, dir);
  const request = call(handoff, { ...save, _hstackContext: token });
  const results = (await Promise.all([rpc(dir, [request]), rpc(dir, [request])])).flat();
  assert.deepEqual(results.map(r => r.isError).sort(), [false, true]);
  const log = readFileSync(join(dir, "audit.jsonl"), "utf8");
  const audit = log.trim().split("\n").map(line => JSON.parse(line));
  assert.deepEqual(audit.map(r => [r.event, r.conversationId]), [["handoff_save", session.conversationId]]);
  assert.equal((log + JSON.stringify(results)).includes(token), false);
});

test("session: altered, wrong-tool and expired contexts refuse; abandoned private state is pruned", async t => {
  const { dir, session } = fixture(t);
  const { issueMcpContext } = await import("../scripts/host/mcp-session.mjs");
  const token = issueMcpContext(verify, session, dir);
  const [storeName] = readdirSync(dir);
  const store = join(dir, storeName);
  const [fileName] = readdirSync(store);
  const file = join(store, fileName);
  assert.equal(statSync(store).mode & 0o077, 0);
  assert.equal(statSync(file).mode & 0o077, 0);
  const altered = (token[0] === "a" ? "b" : "a") + token.slice(1);
  const rejected = await rpc(dir, [
    call(verify, { _hstackContext: altered }), call(handoff, { ...save, _hstackContext: token }),
  ]);
  assert.deepEqual(rejected.map(r => r.isError), [true, true]);
  const expired = issueMcpContext(handoff, session, dir);
  const abandoned = issueMcpContext(handoff, session, dir);
  for (const f of readdirSync(store)) utimesSync(join(store, f), 1, 1);
  const [stale] = await rpc(dir, [call(handoff, { ...save, _hstackContext: expired })]);
  assert.equal(stale.isError, true);
  issueMcpContext(verify, session, dir);
  assert.equal(readdirSync(store).length, 1);
  assert.equal(JSON.stringify([...rejected, stale]).includes(abandoned), false);
});

test("packaged Claude mcp.json does not clobber host-injected CLAUDE_PLUGIN_DATA with a literal placeholder", () => {
  const mcpConfig = JSON.parse(readFileSync(join(PLUGIN_ROOT, ".claude-plugin", "mcp.json"), "utf8"));
  const env = mcpConfig?.mcpServers?.gate?.env ?? {};
  assert.equal(Object.hasOwn(env, "CLAUDE_PLUGIN_DATA"), false);
});
