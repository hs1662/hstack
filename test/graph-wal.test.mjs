import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { once } from "node:events";
import test from "node:test";
import { readState, recover, transaction } from "../scripts/graph/wal-store.mjs";
import { collectGarbage } from "../scripts/graph/gc.mjs";

const request = (opId, payload = {}) => ({ opId, type: "Changed", payload });
const result = (n) => ({ state: { n }, response: { receipt: n } });
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const blob = (root, bytes) => join(root, "cas", "sha256", hash(bytes).slice(0, 2), hash(bytes));
const wal = (root) => join(root, "runs", "r", "wal", "events.jsonl");
const corrupt = { code: "ERR_JOURNAL_CORRUPT" };

async function fixture(t) {
  const root = await fs.mkdtemp(join(tmpdir(), "hstack-wal-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

test("request replay uses type and canonical payload, and returns the original receipt", async (t) => {
  const root = await fixture(t);
  const secret = "raw-dispatch-secret";
  const req = request("claim", { nonce: secret, node: 2 });
  const first = await transaction(root, "r", req, (prev) => {
    assert.equal(prev, null);
    return result(1);
  });
  await transaction(root, "r", request("start"), () => result(2));
  const before = await fs.readFile(wal(root), "utf8");
  assert.deepEqual(first, { receipt: 1 });
  assert.deepEqual(await transaction(root, "r", request("claim", { node: 2, nonce: secret }), assert.fail), first);
  for (const changed of [{ ...req, type: "Start" }, request("claim", { node: 3 })]) {
    await assert.rejects(transaction(root, "r", changed, assert.fail), { code: "ERR_OP_CONFLICT" });
  }
  assert.equal(before.includes(secret), false);
  assert.equal(await fs.readFile(wal(root), "utf8"), before);
  assert.deepEqual(await readState(root, "r"), { n: 2 });
});

test("read-only reads neither initialize an empty run nor repair a torn tail", async (t) => {
  const root = await fixture(t);
  assert.equal(await readState(join(root, "absent-clone", ".hstack", "graph"), "r"), null);
  assert.equal(await readState(root, "r"), null);
  assert.deepEqual(await fs.readdir(root), []);
  await transaction(root, "r", request("a"), () => result(1));
  await fs.appendFile(wal(root), Buffer.from([123, 34, 0xf0]));
  const before = await fs.readFile(wal(root));
  assert.deepEqual(await readState(root, "r"), { n: 1 });
  assert.deepEqual(await fs.readFile(wal(root)), before);
});

test("beforeReplay fences a cached receipt under lock before a torn-tail repair", async (t) => {
  const root = await fixture(t);
  const op = request("settle");
  await transaction(root, "r", { ...op, beforeReplay: assert.fail }, () => result(1));
  await transaction(root, "r", request("new-epoch"), () => result(2));
  await fs.appendFile(wal(root), "{");
  const before = await fs.readFile(wal(root));
  const stale = Object.assign(new Error("stale epoch"), { code: "ERR_STALE_FENCING_TOKEN" });
  for (const beforeReplay of [() => { throw stale; }, async state => {
    assert.equal(JSON.parse(await fs.readFile(join(root, "lock", "owner.json"))).pid, process.pid);
    assert.deepEqual(state, { n: 2 });
    throw stale;
  }]) {
    await assert.rejects(transaction(root, "r", { ...op, beforeReplay }, assert.fail), stale);
    assert.deepEqual(await fs.readFile(wal(root)), before);
    assert.deepEqual(await fs.readdir(dirname(wal(root))), ["events.jsonl"]);
  }
});

test("a retired attempt cannot use idempotent replay to bypass its current fence", async (t) => {
  const root = await fixture(t);
  await transaction(root, "r", request("issue"), () => result(1));
  const req = { ...request("settle"), guard: state => {
    if (state.n !== 1) throw Object.assign(new Error("retired"), { code: "ERR_STALE_FENCING_TOKEN" });
  } };
  await transaction(root, "r", req, prev => result(prev.n));
  await transaction(root, "r", request("retire"), () => result(2));
  const before = await fs.readFile(wal(root));
  await assert.rejects(transaction(root, "r", req, assert.fail), { code: "ERR_STALE_FENCING_TOKEN" });
  assert.deepEqual(await fs.readFile(wal(root)), before);
});

// Interpose only on the child's real WAL descriptor. Both fault points run the
// actual kernel operation first; the process cannot unwind finally/release/ACK.
function killedWriter(root, point) {
  const script = `
    import fs from "node:fs/promises";
    import { syncBuiltinESMExports } from "node:module";
    const open = fs.open.bind(fs);
    const die = () => process.kill(process.pid, "SIGKILL");
    fs.open = async (path, ...args) => {
      const fd = await open(path, ...args);
      if (path === ${JSON.stringify(wal(root))}) {
        if (${JSON.stringify(point)} === "mid-write") {
          for (const name of ["write", "writeFile", "appendFile"]) {
            const write = fd[name].bind(fd);
            fd[name] = async data => { await write(Buffer.from(data).subarray(0, 37)); die(); };
          }
        } else {
          const sync = fd.sync.bind(fd);
          fd.sync = async () => { await sync(); die(); };
        }
      }
      return fd;
    };
    syncBuiltinESMExports();
    const {transaction} = await import(${JSON.stringify(new URL("../scripts/graph/wal-store.mjs", import.meta.url).href)});
    await transaction(${JSON.stringify(root)}, "r", ${JSON.stringify(request("lost"))},
      prev => ({state:{n:prev.n+1},response:{receipt:19}}));`;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], { timeout: 15000, encoding: "utf8" });
  assert.ifError(child.error);
  assert.equal(child.signal, "SIGKILL", child.stderr);
}

test("SIGKILL during a real append preserves the damaged file before rolling back only its tail", async (t) => {
  const root = await fixture(t);
  await transaction(root, "r", request("seed"), () => result(1));
  const good = await fs.readFile(wal(root));
  killedWriter(root, "mid-write");
  const torn = await fs.readFile(wal(root));
  assert.equal(torn.length, good.length + 37);
  assert.deepEqual(await recover(root, "r"), { n: 1 });
  assert.deepEqual(await fs.readFile(wal(root)), good);
  const backups = (await fs.readdir(dirname(wal(root)))).filter(n => n !== "events.jsonl");
  assert.equal(backups.length, 1);
  assert.deepEqual(await fs.readFile(join(dirname(wal(root)), backups[0])), torn);
  assert.deepEqual(await transaction(root, "r", request("lost"), prev => result(prev.n + 1)), { receipt: 2 });
});

test("SIGKILL after WAL fsync but before ACK replays the committed response exactly once", async (t) => {
  const root = await fixture(t);
  await transaction(root, "r", request("seed"), () => result(1));
  killedWriter(root, "after-sync");
  await collectGarbage(root); // A crash may leave pins and the checkpoint one commit behind.
  assert.deepEqual(await transaction(root, "r", request("lost"), assert.fail), { receipt: 19 });
  assert.deepEqual(await recover(root, "r"), { n: 2 });
  assert.equal((await fs.readFile(wal(root), "utf8")).trimEnd().split("\n").length, 2);
});

for (const damage of ["checksum", "sequence gap", "missing CAS", "changed CAS", "snapshot", "complete bad last line"]) {
  test(`recovery and GC fail closed on ${damage} without truncating evidence or sweeping`, async (t) => {
    const root = await fixture(t);
    for (const n of [1, 2, 3]) {
      await transaction(root, "r", request(String(n)), async (_, io) => {
        await io.put(Buffer.from("orphan"));
        return { ...result(n), refs: n === 2 ? [await io.put(Buffer.from("historical"))] : [] };
      });
    }
    const file = wal(root);
    const lines = (await fs.readFile(file, "utf8")).trimEnd().split("\n");
    if (damage === "checksum") lines[1] = lines[1].replace('"Changed"', '"INVALID"');
    if (damage === "sequence gap") lines.splice(1, 1);
    if (damage === "missing CAS") await fs.unlink(blob(root, "historical"));
    if (damage === "changed CAS") await fs.writeFile(blob(root, "historical"), "other");
    if (damage === "snapshot") await fs.writeFile(join(root, "runs", "r", "snapshots", "3.json"), "{}\n");
    if (damage === "complete bad last line") lines.push("{");
    const damaged = lines.join("\n") + '\n{"alsoTorn":';
    await fs.writeFile(file, damaged);
    await assert.rejects(recover(root, "r"), corrupt);
    await assert.rejects(collectGarbage(root), corrupt);
    assert.equal(await fs.readFile(file, "utf8"), damaged);
    assert.equal(await fs.readFile(blob(root, "orphan"), "utf8"), "orphan");
  });
}

test("CAS publication is immutable; GC traces current, historical, and transitive JSON roots", async (t) => {
  const root = await fixture(t);
  const fields = ["attemptInput", "heldCandidate", "handoff", "staged", "audit"];
  const refs = await transaction(root, "r", request("claim"), async (_, io) => {
    const pins = {};
    for (const key of fields) pins[key] = await io.put(Buffer.from(key));
    const manifest = await io.put(Buffer.from(JSON.stringify(pins)));
    return { state: { attempts: [{ manifest }] }, refs: [await io.put("input")], response: { manifest } };
  });
  const original = await fs.stat(blob(root, "input"));
  await transaction(root, "r", request("release"), async (prev, io) => {
    assert.equal((await io.get(prev.attempts[0].manifest)).length > 0, true);
    assert.equal(await io.put("input"), `cas://sha256/${hash("input")}`);
    await io.put("unreferenced");
    return result(2);
  });
  assert.equal((await fs.stat(blob(root, "input"))).ino, original.ino);
  const pin = await fs.readFile(join(root, "gcroots", "r.pin.json"), "utf8");
  assert.ok(pin.includes(refs.manifest));
  assert.equal((await collectGarbage(root)).removed, 1);
  for (const key of [...fields, "input"]) assert.equal(await fs.readFile(blob(root, key), "utf8"), key);
  await assert.rejects(fs.stat(blob(root, "unreferenced")), { code: "ENOENT" });
  assert.deepEqual(await recover(root, "r"), { n: 2 });
});

test("a missing transitive target cannot be committed; a raw attempt token cannot be journaled", async (t) => {
  const root = await fixture(t);
  await assert.rejects(transaction(root, "r", request("dangling"), async (_, io) => ({
    ...result(1), refs: [await io.put(JSON.stringify({ evidence: `cas://sha256/${"a".repeat(64)}` }))],
  })), corrupt);
  await assert.rejects(transaction(root, "r", request("secret"), () => ({
    state: {}, response: { dispatch: { attemptToken: "private" } },
  })), { code: "ERR_SECRET_IN_RECORD" });
  assert.equal(await readState(root, "r"), null);
});

test("volatile progress can be replaced without advancing or repairing the journal", async (t) => {
  const root = await fixture(t);
  await transaction(root, "r", request("seed"), () => result(1));
  const before = await fs.readFile(wal(root));
  const { writeHeartbeats } = await import("../scripts/graph/wal-store.mjs");
  for (const progress of [2, 7]) await writeHeartbeats(root, "r", { worker: { progress } });
  assert.deepEqual(JSON.parse(await fs.readFile(join(root, "runs", "r", "runtime", "heartbeats.json"))), {
    worker: { progress: 7 },
  });
  assert.deepEqual(await fs.readFile(wal(root)), before);
  assert.deepEqual(await readState(root, "r"), { n: 1 });
});

test("GC protects staging after the writer dies; recovery releases the uncommitted pin", async (t) => {
  const root = await fixture(t);
  await transaction(root, "r", request("seed"), () => result(1));
  const module = new URL("../scripts/graph/wal-store.mjs", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { transaction } from ${JSON.stringify(module)};
    await transaction(${JSON.stringify(root)}, "r", ${JSON.stringify(request("stage"))}, async (_, io) => {
      await io.put("pending");
      process.kill(process.pid, "SIGKILL");
    });`], { timeout: 15000, encoding: "utf8" });
  assert.ifError(child.error);
  assert.equal(child.signal, "SIGKILL", child.stderr);
  await collectGarbage(root);
  assert.equal(await fs.readFile(blob(root, "pending"), "utf8"), "pending");
  await recover(root, "r");
  assert.equal((await collectGarbage(root)).removed, 1);
  await assert.rejects(fs.stat(blob(root, "pending")), { code: "ENOENT" });
});

test("a concurrent GC sees the writer's committed roots, not the in-flight pin set", { timeout: 30000 }, async (t) => {
  const root = await fixture(t);
  let finished;
  await transaction(root, "r", request("claim"), async (_, io) => {
    const input = await io.put("claimed");
    await io.put("discarded");
    // Signal on real lock contention, not on a timer or on child startup.
    const child = spawn(process.execPath, ["--input-type=module", "-e", `
      import fs from "node:fs/promises";
      import { syncBuiltinESMExports } from "node:module";
      const mkdir = fs.mkdir.bind(fs);
      let signaled = false;
      fs.mkdir = async (path, ...args) => {
        try { return await mkdir(path, ...args); } catch (err) {
          if (!signaled && err.code === "EEXIST" && path === ${JSON.stringify(join(root, "lock"))}) {
            process.send("contending"); signaled = true;
          }
          throw err;
        }
      };
      syncBuiltinESMExports();
      const {collectGarbage} = await import(${JSON.stringify(new URL("../scripts/graph/gc.mjs", import.meta.url).href)});
      process.send(await collectGarbage(${JSON.stringify(root)}));
      process.disconnect();`], { stdio: ["ignore", "ignore", "inherit", "ipc"] });
    t.after(() => child.kill());
    const closed = once(child, "exit");
    assert.equal((await once(child, "message"))[0], "contending");
    finished = Promise.all([once(child, "message"), closed]);
    return { ...result(1), refs: [input] };
  });
  const [[report], [code]] = await finished;
  assert.equal(code, 0);
  assert.equal(report.removed, 1);
  assert.equal(await fs.readFile(blob(root, "claimed"), "utf8"), "claimed");
  await assert.rejects(fs.stat(blob(root, "discarded")), { code: "ENOENT" });
});
