import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import {
  existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, utimesSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import * as store from "../scripts/governance/handoff-store.mjs";

function fixture(t) {
  const cwd = mkdtempSync(join(tmpdir(), "hstack-snapshot-pins-"));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  const dataDir = join(cwd, "data");
  const workspaceKey = store.computeWorkspaceKey(cwd);
  const workspaceDir = join(dataDir, "handoffs", workspaceKey);
  const options = { cwd, dataDir };
  return {
    ...options, workspaceKey, workspaceDir, options,
    save: (pinOwner) => store.saveHandoffSnapshot({ ...options, pinOwner }).snapshot.snapshotId,
    load: (snapshotId) => store.loadHandoffSnapshot({ ...options, snapshotId }),
    listPins: () => store.listPinnedSnapshots(workspaceKey, dataDir),
  };
}

test("owners are idempotent, independent roots outside retention, without rewriting snapshot bytes", (t) => {
  const f = fixture(t);
  const id = f.save("canary:one");
  const path = join(f.workspaceDir, `${id}.json`);
  const original = readFileSync(path);
  assert.deepEqual(f.listPins(), [{ snapshotId: id, pinOwners: ["canary:one"] }]);
  assert.equal(store.pinSnapshot(f.workspaceKey, id, "canary:two", f.dataDir), true);
  assert.equal(store.pinSnapshot(f.workspaceKey, id, "canary:two", f.dataDir), false);

  const ordinary = Array.from({ length: 23 }, () => f.save());
  assert.deepEqual(f.listPins(), [{ snapshotId: id, pinOwners: ["canary:one", "canary:two"] }]);
  assert.deepEqual(readFileSync(path), original);
  assert.equal(ordinary.filter((snapshotId) => f.load(snapshotId).ok).length, 20);

  assert.equal(store.unpinSnapshot(f.workspaceKey, id, "unknown", f.dataDir), false);
  assert.equal(store.unpinSnapshot(f.workspaceKey, id, "canary:one", f.dataDir), true);
  assert.equal(store.clearHandoffSnapshots(f.options).clearedCount, 20);
  assert.equal(f.load().ok, false);
  assert.equal(f.load(id).ok, true);
  assert.deepEqual(f.listPins(), [{ snapshotId: id, pinOwners: ["canary:two"] }]);
  assert.equal(store.unpinSnapshot(f.workspaceKey, id, "canary:two", f.dataDir), true);
  assert.deepEqual(f.listPins(), []);
  assert.equal(store.clearHandoffSnapshots(f.options).clearedCount, 1);
  assert.equal(f.load(id).ok, false);
});

test("prune protects the latest pointer target even when older entries tie and outrank it", (t) => {
  const f = fixture(t);
  const timestamp = 2_000_000_000;
  for (let i = 0; i < 20; i += 1) {
    const path = join(f.workspaceDir, `${f.save()}.json`);
    utimesSync(path, timestamp, timestamp);
  }
  const id = f.save();
  assert.equal(f.load().snapshot.snapshotId, id);
  assert.equal(f.load(id).ok, true);
  assert.ok(store.listHandoffSnapshots(f.options).items.some((item) => item.snapshotId === id));

  const pinnedCurrent = f.save("canary");
  store.clearHandoffSnapshots(f.options);
  assert.equal(f.load().snapshot.snapshotId, pinnedCurrent);
  assert.equal(f.load(pinnedCurrent).ok, true);
});

test("invalid keys, metadata aliases, foreign snapshots and corruption cannot remove roots", (t) => {
  const f = fixture(t);
  const id = f.save("canary");
  const other = fixture(t);
  other.save();
  const path = join(f.workspaceDir, "pins.json");
  assert.throws(() => store.pinSnapshot("../outside", id, "canary", f.dataDir));
  assert.throws(() => store.pinSnapshot(f.workspaceKey, "../latest", "canary", f.dataDir));
  assert.throws(() => store.pinSnapshot(f.workspaceKey, "latest", "canary", f.dataDir));
  assert.throws(() => store.unpinSnapshot(f.workspaceKey, "latest", "canary", f.dataDir));
  assert.throws(() => store.pinSnapshot(f.workspaceKey, "pins", "canary", f.dataDir));
  assert.throws(() => store.pinSnapshot(f.workspaceKey, id, "canary\n", f.dataDir));
  assert.equal(store.pinSnapshot(other.workspaceKey, id, "canary", other.dataDir), false);
  assert.equal(f.load("latest").snapshot.snapshotId, id);
  assert.equal(f.load("pins").ok, false);
  const latest = join(f.workspaceDir, "latest.json");
  const originalPointer = readFileSync(latest);
  assert.throws(() => f.save("../invalid"));
  assert.deepEqual(readFileSync(latest), originalPointer);

  const original = readFileSync(path);
  for (const broken of ["{", "{}", '{"schemaVersion":1,"pins":{"latest":["canary"]}}']) {
    writeFileSync(path, broken);
    assert.throws(f.listPins);
    assert.throws(() => store.unpinSnapshot(f.workspaceKey, id, "canary", f.dataDir));
    assert.throws(() => store.clearHandoffSnapshots(f.options));
    assert.throws(() => f.save("another"));
    assert.equal(readFileSync(path, "utf8"), broken);
    assert.deepEqual(readFileSync(latest), originalPointer);
    assert.equal(f.load(id).ok, true);
  }
  rmSync(path);
  const outside = join(other.cwd, "outside.json");
  writeFileSync(outside, original);
  symlinkSync(outside, path);
  assert.throws(() => store.clearHandoffSnapshots(f.options));
  assert.deepEqual(readFileSync(outside), original);
  assert.equal(f.load(id).ok, true);
});

test("independent processes serialize root additions and releases across concurrent prune runs", { timeout: 15_000 }, async (t) => {
  const f = fixture(t);
  const id = f.save("keeper");
  for (const owner of ["remove:1", "remove:2"]) {
    store.pinSnapshot(f.workspaceKey, id, owner, f.dataDir);
  }
  const moduleUrl = new URL("../scripts/governance/handoff-store.mjs", import.meta.url).href;
  const code = `
    import { pinSnapshot, unpinSnapshot, saveHandoffSnapshot } from ${JSON.stringify(moduleUrl)};
    const [workspaceKey, id, cwd, dataDir, job] = process.argv.slice(1);
    process.stdout.write("ready");
    for await (const chunk of process.stdin) {}
    if (job.startsWith("remove")) unpinSnapshot(workspaceKey, id, job, dataDir);
    if (job.startsWith("add")) pinSnapshot(workspaceKey, id, job, dataDir);
    if (job.startsWith("save")) {
      for (let i = 0; i < 25; i++) saveHandoffSnapshot({ cwd, dataDir });
      const { snapshot } = saveHandoffSnapshot({ cwd, dataDir, pinOwner: job });
      process.stdout.write(snapshot.snapshotId);
    }
  `;
  const jobs = ["remove:1", "remove:2", "add:1", "add:2", "save:1", "save:2"];
  const workers = jobs.map((job) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", code, f.workspaceKey, id, f.cwd, f.dataDir, job]);
    t.after(() => { if (child.exitCode === null) child.kill(); });
    let output = "";
    let diagnostic = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { output += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { diagnostic += chunk; });
    const closed = once(child, "close");
    const ready = Promise.race([once(child.stdout, "data"), closed]).then(() => {
      assert.equal(output, "ready", diagnostic);
    });
    return { child, ready, result: async () => {
      assert.deepEqual(await closed, [0, null], diagnostic);
      return output.slice("ready".length);
    } };
  });
  await Promise.all(workers.map(({ ready }) => ready));
  for (const { child } of workers) child.stdin.end();
  const outputs = await Promise.all(workers.map(({ result }) => result()));

  const roots = new Map(f.listPins().map(({ snapshotId, pinOwners }) => [snapshotId, pinOwners]));
  assert.equal(roots.size, 3);
  assert.deepEqual(roots.get(id), ["add:1", "add:2", "keeper"]);
  for (const index of [4, 5]) {
    assert.deepEqual(roots.get(outputs[index]), [jobs[index]]);
    assert.equal(f.load(outputs[index]).ok, true);
  }
  assert.equal(f.load(id).ok, true);
  assert.ok(outputs.slice(4).includes(f.load().snapshot.snapshotId));
});

test("real MCP stdio discovers and applies save-with-pin, pin, unpin, list and clear", (t) => {
  const f = fixture(t);
  const server = fileURLToPath(new URL("../scripts/mcp/server.mjs", import.meta.url));
  const run = (requests) => {
    const result = spawnSync(process.execPath, [server], {
      env: { ...process.env, PLUGIN_DATA: f.dataDir },
      input: requests.map((request, id) => JSON.stringify({ jsonrpc: "2.0", id, ...request })).join("\n") + "\n",
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    const responses = result.stdout.trim().split("\n").map((line) => JSON.parse(line));
    assert.equal(responses.length, requests.length);
    return responses.map(({ result: payload, error }) => {
      assert.equal(error, undefined);
      return payload;
    });
  };
  const call = (action, args = {}) => ({
    method: "tools/call",
    params: { name: "manage_handoff", arguments: { action, ...args, _session: { cwd: f.cwd } } },
  });
  const [, tools] = run([
    { method: "initialize", params: { protocolVersion: "2024-11-05" } },
    { method: "tools/list" },
    call("save", { pin_owner: "first", objective: "MCP", verified_facts: [], failed_approaches: [], remaining_tasks: [] }),
  ]);
  const actions = tools.tools.find(({ name }) => name === "manage_handoff").inputSchema.properties.action.enum;
  for (const action of ["pin", "unpin", "list_pinned", "clear"]) assert.ok(actions.includes(action));
  const [{ snapshotId: id, pinOwners }] = f.listPins();
  assert.deepEqual(pinOwners, ["first"]);
  const [alias] = run([call("load", { snapshot_id: "latest" })]);
  assert.ok(alias.content[0].text.includes(id));
  const second = { snapshot_id: id, pin_owner: "second" };
  const [, listed] = run([call("pin", second), call("list_pinned"), call("unpin", { ...second, pin_owner: "first" }), call("clear")]);
  assert.ok(listed.content[0].text.includes(id));
  assert.deepEqual(f.listPins(), [{ snapshotId: id, pinOwners: ["second"] }]);
  assert.equal(f.load().snapshot.snapshotId, id);
  run([call("unpin", second), call("clear")]);
  assert.deepEqual(f.listPins(), []);
  assert.equal(existsSync(join(f.workspaceDir, `${id}.json`)), false);
  assert.equal(f.load().ok, false);
});
