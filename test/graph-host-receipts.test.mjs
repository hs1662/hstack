import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const entry = fileURLToPath(new URL("../scripts/graph/cli.mjs", import.meta.url));
const run = "host";

async function fixture(t, host) {
  const dir = await mkdtemp(join(tmpdir(), "graph-host-receipts-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const cwd = join(dir, "workspace");
  const root = join(dir, "store");
  await mkdir(cwd);
  const env = { ...process.env, HSTACK_HOST: host };
  async function cli(args) {
    const argv = [entry, ...args, "--root", root, "--workspace", cwd, "--run", run];
    try {
      const { stdout } = await exec(process.execPath, argv, { cwd, env });
      return { status: 0, body: JSON.parse(stdout) };
    } catch (error) {
      if (!Number.isInteger(error.code) || !error.stdout) throw error;
      return { status: error.code, body: JSON.parse(error.stdout) };
    }
  }
  async function ok(...args) {
    const { status, body } = await cli(args);
    assert.equal(status, 0, JSON.stringify(body));
    return body.result;
  }
  const spec = join(dir, "spec.json");
  await writeFile(spec, JSON.stringify({ schemaVersion: 1,
    nodes: ["a", "b"].map(id => ({ id, kind: "read", prompt: `Read ${id}` })) }));
  await ok("init");
  await ok("compile", "--spec", spec);
  async function start(id) {
    const { instructionPath } = await ok("claim", "--node", id, "--expected-rev", "1", "--op-id", `claim-${id}`);
    await ok("start", "--token", instructionPath, "--host-handle", `handle-${id}`);
    return ["settle", "--token", instructionPath, "--outcome", "blocked", "--op-id", `settle-${id}`];
  }
  return { dir, root, cli, ok, start };
}

async function publishReceipt(path) {
  const staging = path + ".tmp";
  const file = await open(staging, "wx", 0o600);
  try {
    await file.writeFile(JSON.stringify({ reason: "needs input" }));
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(staging, path);
  const directory = await open(dirname(path), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

test("O-H-3: settle before receipt publication leaves WAL unchanged and the same opId succeeds after rename", async t => {
  const { root, cli, ok, start } = await fixture(t, "claude-code");
  const inbox = join(root, "runs", run, "inbox");
  await mkdir(inbox);
  const receipt = join(inbox, "e1.json");
  const args = [...await start("a"), "--receipt", receipt];
  const wal = join(root, "runs", run, "wal", "events.jsonl");
  const before = await readFile(wal);
  const early = await cli(args);
  assert.equal(early.status, 65);
  assert.equal(early.body.error.code, "ERR_CLI_INPUT_FILE");
  assert.deepEqual(await readFile(wal), before);
  await publishReceipt(receipt);
  assert.equal((await ok(...args)).status, "held_blocked");
});

for (const [host, costUsd] of [["antigravity", null], ["claude-code", 0.75]]) {
  test(`O-H-4: ${host} records only headless host-json usage and sums host-supported metrics`, async t => {
    const { dir, cli, ok, start } = await fixture(t, host);
    const telemetry = join(dir, "telemetry.json");
    const a = [...await start("a"), "--telemetry", telemetry];
    const usage = { inputTokens: 11, outputTokens: 3, costUsd: 0.25 };
    for (const dispatch of [undefined, "subagent", "unknown"]) {
      await writeFile(telemetry, JSON.stringify({ usage, usageSource: "host-json", dispatch }));
      const bad = await cli(a);
      assert.equal(bad.status, 65);
      assert.equal(bad.body.error.code, "ERR_CLI_HOST_DATA");
    }
    await writeFile(telemetry, JSON.stringify({ usage, usageSource: "host-json", dispatch: "headless-process" }));
    await ok(...a);
    const b = [...await start("b"), "--telemetry", telemetry];
    await writeFile(telemetry, JSON.stringify({ dispatch: "subagent", usage: { inputTokens: 7, outputTokens: 5, costUsd: 0.5 } }));
    await ok(...b);
    const { nodes } = await ok("status");
    assert.equal(nodes.a.attempt.usageSource, "host-json");
    assert.equal(Object.hasOwn(nodes.b.attempt, "usageSource"), false);
    assert.equal(Object.hasOwn(nodes.a.attempt.observedUsage, "costUsd"), host === "claude-code");
    assert.deepEqual((await ok("metrics")).usage, { inputTokens: 18, outputTokens: 8, costUsd });
  });
}
