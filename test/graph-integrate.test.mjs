import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { factDigest } from "../scripts/graph/reducer.mjs";
import { dispatch } from "../scripts/graph/state-machine.mjs";

export const exec = promisify(execFile);
export const writer = (id, extra) => ({ id, kind: "write", prompt: `Write ${id}`, writeScope: [id],
  gateArgv: [process.execPath, "-e", `require('fs').accessSync(${JSON.stringify(id)})`], ...extra });
export const ref = "refs/hstack/runs/r/accepted";

export async function fixture(t, nodes = [writer("B")], files = { source: "base\n" }) {
  const dir = await mkdtemp(join(tmpdir(), "graph-integrate-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const workspace = join(dir, "repo"), root = join(dir, "store"), options = { root, workspace, run: "r" };
  await mkdir(workspace);
  await mkdir(root);
  const git = async (...args) => (await exec("git", args, { cwd: workspace })).stdout.trim();
  await git("init", "-q", "-b", "main");
  await git("config", "user.name", "Fixture");
  await git("config", "user.email", "fixture@invalid");
  for (const [name, text] of Object.entries(files)) await writeFile(join(workspace, name), text);
  await git("add", ".");
  await git("commit", "-qm", "base");
  const call = (command, args) => dispatch(command, { ...options, ...args });
  await call("compile", { spec: { schemaVersion: 2, nodes, policy: { integration: { maxOpenWorktrees: 4 } } } });
  const claim = id => call("claim", { node: id, expectedRev: 1, opId: `claim-${id}` });
  const start = async id => {
    const c = await claim(id);
    await call("start", { token: c.instructionPath, hostHandle: id });
    return c;
  };
  const settle = async (id, c, path) => {
    const provenance = { evidenceSpans: [{ spanId: "s", path, startLine: 1, endLine: 1 }],
      claims: [{ claimId: "c", text: id, spanIds: ["s"] }], edgeCases: [], failureEvidence: [] };
    provenance.factDigest = factDigest(provenance);
    return call("settle", { opId: `seal-${id}`, token: c.instructionPath, outcome: "success",
      receipt: { workerReportedStatus: "completed", inlineSummary: id, provenance } });
  };
  const seal = async (id, path = id, bytes = `${id}\n`) => {
    const c = await start(id);
    await writeFile(join(c.worktreePath, path), bytes);
    assert.equal((await settle(id, c, path)).status, "sealed");
    return c;
  };
  const wal = join(root, "runs/r/wal/events.jsonl");
  const frames = async () => (await readFile(wal, "utf8")).trimEnd().split("\n").map(line => JSON.parse(line));
  return { ...options, dir, options, git, call, claim, start, settle, seal, frames, wal,
    integrate: opId => call("integrate", { opId }) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  test("O-D-2/3: publish both siblings with two parents; a diamond waits for both", async t => {
    const f = await fixture(t, [writer("B"), writer("C"), writer("D", { dependsOn: ["B", "C"] })]);
    await f.seal("B");
    await f.seal("C");
    let previous = await f.git("rev-parse", "HEAD");
    for (const id of ["B", "C"]) {
      const response = await f.integrate(`publish-${id}`);
      assert.equal(response.status, "accepted");
      const s = await f.call("status");
      assert.equal(s.acceptedTip, await f.git("rev-parse", ref));
      assert.deepEqual((await f.git("show", "-s", "--format=%P", ref)).split(" "), [previous, s.nodes[id].attempt.sealedCommit]);
      previous = s.acceptedTip;
      if (id === "B") await assert.rejects(f.claim("D"), { code: "ERR_NOT_READY" });
    }
    const before = await readFile(f.wal);
    assert.deepEqual(await f.integrate("no-work"), { status: "idle" });
    assert.deepEqual(await readFile(f.wal), before);
  });

  test("patching an integrating writer while its candidate gate runs still releases the candidate worktree slot", async t => {
    const gateGate = join(tmpdir(), `gate-pause-${process.pid}-${Date.now()}`);
    const gateReady = `${gateGate}.ready`;
    t.after(() => Promise.all([rm(gateGate, { force: true }), rm(gateReady, { force: true })]));
    const script = [
      `const fs = require("node:fs");`,
      `fs.writeFileSync(${JSON.stringify(gateReady)}, "1");`,
      `const start = Date.now();`,
      `while (!fs.existsSync(${JSON.stringify(gateGate)}) && Date.now() - start < 5000) {}`,
      `fs.accessSync("B");`,
    ].join(" ");
    const f = await fixture(t, [
      writer("B", { gateArgv: [process.execPath, "-e", script] }),
      writer("C"),
    ]);
    await f.seal("B");
    await f.seal("C");
    const integrating = f.integrate("int-b");
    const waitReady = async () => {
      for (let i = 0; i < 200; i++) {
        try { await readFile(gateReady); return; } catch {}
        await new Promise(r => setTimeout(r, 10));
      }
      throw new Error("candidate gate did not start");
    };
    await waitReady();
    const s1 = await f.call("status");
    await f.call("amend", { node: "B", expectedRev: s1.graphRev, opId: "amend-mid-gate", patch: { exec: { prompt: "Write B v2" } } });
    await writeFile(gateGate, "go");
    await integrating;
    const after = await f.call("status");
    assert.equal(after.worktrees["cand-g0.1"].phase, "released");
    assert.equal(after.worktrees["cand-g0.1"].settled, true);
  });
}
