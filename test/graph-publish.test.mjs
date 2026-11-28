import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import fs, { appendFile, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import { getBlob } from "../scripts/graph/gc.mjs";
import { runCli } from "../scripts/graph/cli.mjs";
import { exec, fixture, ref, writer } from "./graph-integrate.test.mjs";

const blob = async (f, uri) => JSON.parse(await getBlob(f.root, uri));
test("O-D-1/O-P-6: each published tip has a prior durable green measurement; D inherits both sealed commits", async t => {
  const f = await fixture(t, [writer("B"), writer("C"), writer("D", { dependsOn: ["B", "C"] })]);
  await f.seal("B");
  await f.seal("C");
  let previous = "";
  const open = fs.open;
  // Observe the actual ref before each green WAL append, not just the eventual ordering of frame names.
  fs.open = async (...args) => {
    const fd = await open(...args);
    if (args[0] === f.wal && args[1] === "a") {
      const write = fd.writeFile.bind(fd);
      fd.writeFile = async bytes => {
        if (JSON.parse(bytes).type === "GateMeasured") {
          assert.equal(await f.git("for-each-ref", "--format=%(objectname)", ref), previous, "ref moved before GateMeasured");
        }
        return write(bytes);
      };
    }
    return fd;
  };
  syncBuiltinESMExports();
  t.after(() => { fs.open = open; syncBuiltinESMExports(); });
  for (const id of ["B", "C"]) {
    const { candidateId } = await f.integrate(`publish-${id}`), frames = await f.frames();
    const measured = frames.findLast(frame => frame.type === "GateMeasured");
    const intended = frames.findLast(frame => frame.type === "PublishIntended");
    const published = frames.findLast(frame => frame.type === "Published");
    assert.ok(measured.seq < intended.seq && intended.seq < published.seq);
    const cand = (await blob(f, measured.body.stateUri)).candidates[candidateId];
    assert.equal(cand.state, "green");
    assert.equal(cand.candidateCommit, await f.git("rev-parse", ref));
    assert.equal((await blob(f, cand.measuredUri)).first.exitCode, 0);
    previous = cand.candidateCommit;
  }
  const d = await f.claim("D"), s = await f.call("status");
  for (const id of ["B", "C"]) await f.git("merge-base", "--is-ancestor", s.nodes[id].sealedCommit, d.baseSha);
});

test("resume repairs a rolled-back accepted ref without repeating a promotion or gate", async t => {
  const f = await fixture(t);
  await f.seal("B");
  const r = await f.integrate("promote");
  await f.git("update-ref", "-d", ref, r.acceptedTip);
  for (let i = 0; i < 2; i++) {
    const s = await f.call("resume");
    assert.equal(await f.git("rev-parse", ref), r.acceptedTip);
    assert.deepEqual([s.integrationGeneration, s.publishRepairs], [1, 1]);
  }
  assert.equal((await f.frames()).filter(frame => frame.type === "PublishRepaired").length, 1);
});

test("O-P-5/O-SE-15: a foreign accepted-ref write from a worker is held without overwriting it", async t => {
  const f = await fixture(t), c = await f.seal("B");
  await exec("git", ["update-ref", ref, c.baseSha], { cwd: c.worktreePath });
  const r = await f.integrate("promote");
  assert.deepEqual([r.status, r.reason], ["held_integration", "ERR_INTEGRATION_DIVERGED"]);
  assert.equal(await f.git("rev-parse", ref), c.baseSha);
  assert.equal((await f.call("status")).acceptedTip, null);
});

for (const flaky of [false, true]) test(`red candidate gate does not publish (${flaky ? "flaky" : "logic"})`, async t => {
  const f = await fixture(t, [writer("B", { gateArgv: [process.execPath, "-e", "process.exit(3)"], flaky })]);
  await f.seal("B");
  const r = await f.integrate("promote"), s = await f.call("status");
  assert.equal(r.status, flaky ? "held_flaky" : "failed_logic");
  assert.equal(await f.git("for-each-ref", ref), "");
  const cand = s.candidates[r.candidateId], failure = await blob(f, s.nodes.B.receiptUri);
  assert.equal(failure.candidateCommit, cand.candidateCommit);
  assert.equal((await blob(f, cand.measuredUri)).first.exitCode, 3);
  if (!flaky) assert.deepEqual(s.nodes.B.failedExecKeys, [s.nodes.B.execKey]);
});

test("O-SE-18: engine holds a real conflict without adopting its tree or running the global driver", async t => {
  const nodes = ["B", "C"].map(id => writer(id, { writeScope: ["file"], gateArgv: ["true"] }));
  const f = await fixture(t, nodes, { ".gitattributes": "* merge=probe\n", file: "base\n" });
  const b = await f.seal("B", "file"), c = await f.seal("C", "file");
  const mark = join(f.dir, "invoked");
  await writeFile(join(f.dir, ".gitconfig"), `[merge "probe"]\n\tdriver = touch '${mark}'\n`);
  const saved = process.env.HOME;
  process.env.HOME = f.dir;
  t.after(() => { if (saved === undefined) delete process.env.HOME; else process.env.HOME = saved; });
  const first = await f.integrate("first"), conflict = await f.integrate("second");
  const s = await f.call("status");
  assert.deepEqual([conflict.status, conflict.reason, s.nodes.C.conflict.paths], ["held_conflict", "ERR_MERGE_CONFLICT", ["file"]]);
  assert.ok((await getBlob(f.root, s.nodes.C.conflict.messagesUri)).includes("CONFLICT"));
  assert.deepEqual(Object.keys(s.candidates), [first.candidateId]);
  assert.equal(await f.git("rev-parse", ref), first.acceptedTip);
  assert.equal(existsSync(mark), false);
  assert.equal(b.baseSha, c.baseSha);
  await f.git("merge-tree", "--write-tree", `--merge-base=${c.baseSha}`, first.acceptedTip, s.nodes.C.attempt.sealedCommit);
  assert.equal(existsSync(mark), true, "plain Git invoked the configured driver");
});

test("O-SE-12: changed info/exclude holds a sealed node before building a candidate", async t => {
  const f = await fixture(t);
  await f.seal("B");
  await appendFile(join(f.workspace, ".git/info/exclude"), "\nchanged\n");
  assert.equal((await f.integrate("promote")).reason, "ERR_REPO_CONFIG_TAMPERED");
  assert.deepEqual((await f.call("status")).candidates, {});
});

test("O-SE-13: modified shared filters and fsmonitor never execute on seal or integration", async t => {
  const f = await fixture(t, [writer("B"), writer("C")], { ".gitattributes": "* filter=probe\n", source: "base\n" });
  await f.seal("B");
  const c = await f.start("C");
  await writeFile(join(c.worktreePath, "C"), "C\n");
  const clean = join(f.dir, "clean"), monitor = join(f.dir, "monitor"), script = join(f.dir, "monitor.sh");
  await writeFile(script, `#!/bin/sh\ntouch '${monitor}'\n`, { mode: 0o700 });
  await f.git("config", "filter.probe.clean", `touch '${clean}'; cat`);
  await f.git("config", "core.fsmonitor", script);
  for (const result of [await f.settle("C", c, "C"), await f.integrate("promote")]) {
    assert.deepEqual([result.status, result.reason], ["held_integration", "ERR_REPO_CONFIG_TAMPERED"]);
  }
  assert.deepEqual([existsSync(clean), existsSync(monitor)], [false, false]);
});

test("gc --scope git drops published pins and retains live pins and the accepted ref", async t => {
  const f = await fixture(t, [writer("B"), writer("C")]);
  await f.seal("B");
  await f.seal("C");
  const r = await f.integrate("first"), s = await f.call("status");
  let line;
  const code = await runCli(["gc", "--scope", "git", "--root", f.root, "--run", f.run], {
    cwd: f.workspace, env: {}, stdout: { write: text => { line = text; } } });
  assert.equal(code, 0, line);
  const result = JSON.parse(line).result;
  assert.deepEqual(result.removed.sort(), [s.nodes.B.attempt.pinRef, ...s.candidates[r.candidateId].pinRefs].sort());
  assert.deepEqual((await f.git("for-each-ref", "--format=%(refname)", "refs/hstack")).split("\n").sort(),
    [s.nodes.C.attempt.pinRef, ref].sort());
  assert.equal(await f.git("rev-parse", ref), r.acceptedTip);
});
