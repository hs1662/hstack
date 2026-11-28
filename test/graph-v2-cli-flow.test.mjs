import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { factDigest } from "../scripts/graph/reducer.mjs";

const exec = promisify(execFile);
const cli = fileURLToPath(new URL("../scripts/graph/cli.mjs", import.meta.url));
const run = "diamond";
const accepted = `refs/hstack/runs/${run}/accepted`;
const waves = [["A"], ["B", "C"], ["D"]];
const diamond = { A: [], B: ["A"], C: ["A"], D: ["B", "C"] };

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), "graph-v2-cli-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const cwd = join(dir, "repo"), root = join(dir, "store");
  await mkdir(cwd);
  const execOptions = { cwd, timeout: 20_000 };
  const git = async (...args) => (await exec("git", args, execOptions)).stdout.trim();
  const call = async (command, ...args) => {
    const { stdout } = await exec(process.execPath, [cli, command, "--root", root, ...args], execOptions)
      .catch(error => {
        if (error instanceof Error && typeof error.code === "number") assert.fail(error.stdout);
        throw error;
      });
    const result = JSON.parse(stdout);
    assert.equal(result.ok, true, stdout);
    return result.result;
  };
  await git("init", "-qb", "main");
  await git("config", "user.name", "Fixture");
  await git("config", "user.email", "fixture@invalid");
  await writeFile(join(cwd, "source"), "base\n");
  await git("add", "source");
  await git("commit", "-qm", "base");
  const startBase = await git("rev-parse", "HEAD");
  const spec = join(dir, "spec.json");
  await writeFile(spec, JSON.stringify({ schemaVersion: 2, policy: { integration: { maxOpenWorktrees: 2 } },
    nodes: Object.entries(diamond).map(([id, dependsOn]) => ({
      id, dependsOn, kind: "write", prompt: `Write ${id}`, writeScope: [id],
      gateArgv: [process.execPath, "-e", `require('node:fs').accessSync(${JSON.stringify(id)})`],
    })) }));
  await call("init");
  await call("compile", "--run", run, "--spec", spec, "--op-id", "compile");
  return { cwd, git, call, startBase };
}

async function deliverReceipt(path, id) {
  const evidenceSpans = [{ spanId: "s", path: id, startLine: 1, endLine: 1 }];
  const claims = [{ claimId: "c", text: id, spanIds: ["s"] }];
  const provenance = { evidenceSpans, claims, edgeCases: [], failureEvidence: [] };
  const receipt = { workerReportedStatus: "completed", inlineSummary: id,
    provenance: { ...provenance, factDigest: factDigest(provenance) } };
  const temp = `${path}.tmp`;
  const file = await open(temp, "wx", 0o600);
  try {
    await file.writeFile(JSON.stringify(receipt));
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(temp, path);
}

test("v2 CLI publishes and lands a diamond, preserves both parents, and collects its pins", async t => {
  const { cwd, git, call, startBase } = await fixture(t);
  for (const wave of waves) {
    const page = await call("ready", "--run", run);
    assert.deepEqual(page.ready.map(node => node.id), wave);
    for (const { id } of page.ready) {
      const { instructionPath, worktreePath, receiptPath } = await call("claim", "--run", run, "--node", id,
        "--expected-rev", String(page.graphRev), "--op-id", `claim-${id}`);
      await writeFile(join(worktreePath, id), `${id}\n`);
      await call("start", "--token", instructionPath, "--host-handle", `worker-${id}`, "--op-id", `start-${id}`);
      await deliverReceipt(receiptPath, id);
      const settled = await call("settle", "--token", instructionPath, "--outcome", "accepted",
        "--receipt", receiptPath, "--op-id", `settle-${id}`);
      assert.equal(settled.status, "sealed");
    }
    for (let step = 0; ; step += 1) {
      const result = await call("integrate", "--run", run, "--op-id", `integrate-${wave[0]}-${step}`);
      if (result.status === "idle") {
        assert.equal(step, wave.length);
        break;
      }
      assert.equal(result.status, "accepted", JSON.stringify(result));
      assert.ok(step < wave.length, "integrate must reach idle after publishing the wave");
      if (wave.length === 2 && step === 0) assert.deepEqual((await call("ready", "--run", run)).ready, []);
    }
  }

  await call("land", "--run", run, "--op-id", "land", "--mode", "ff-only");
  const state = await call("status", "--run", run);
  assert.equal(state.status, "completed");
  assert.equal(await git("rev-parse", "HEAD"), await git("rev-parse", accepted));
  for (const id of Object.keys(diamond)) assert.equal(await readFile(join(cwd, id), "utf8"), `${id}\n`);
  const range = `${startBase}..${accepted}`;
  assert.equal(await git("rev-list", "--first-parent", "--count", range), "4");
  assert.equal(await git("rev-list", "--first-parent", "--min-parents=2", "--max-parents=2", "--count", range), "4");
  for (const id of diamond.D) {
    await git("merge-base", "--is-ancestor", state.nodes[id].sealedCommit, state.nodes.D.sealedCommit);
  }
  assert.deepEqual((await git("worktree", "list", "--porcelain")).split("\n").filter(line => line.startsWith("worktree ")),
    [`worktree ${cwd}`]);

  const pins = `refs/hstack/pin/${run}`;
  const before = (await git("for-each-ref", "--format=%(refname)", pins)).split("\n");
  assert.equal(before.length, 4);
  const gc = await call("gc", "--scope", "git", "--run", run);
  assert.equal(await git("for-each-ref", "--format=%(refname)", "refs/hstack/pin"), "");
  assert.deepEqual(gc.removed.filter(name => name.startsWith(`${pins}/`)).sort(), before.sort());
  assert.equal(await git("rev-parse", accepted), state.acceptedTip);
});
