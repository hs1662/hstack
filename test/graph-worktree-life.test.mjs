import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { factDigest } from "../scripts/graph/reducer.mjs";
import { seal } from "../scripts/graph/seal.mjs";
import { dispatch } from "../scripts/graph/state-machine.mjs";
import { listWorktrees, nodeKey, pinRef } from "../scripts/graph/worktree.mjs";

const exec = promisify(execFile);
async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), "worktree-life-"));
  t.after(() => rm(dir, { force: true, recursive: true }));
  const root = join(dir, "state"), workspace = join(dir, "repo");
  await mkdir(root);
  await mkdir(workspace);
  const git = async (...args) => (await exec("git", args, { cwd: workspace })).stdout.trim();
  await git("init", "-q", "-b", "main");
  await git("config", "user.name", "Fixture");
  await git("config", "user.email", "fixture@invalid");
  await git("commit", "--allow-empty", "-qm", "base");
  const call = (command, opts) => dispatch(command, { root, workspace, run: "r", ...opts });
  const writeScope = ["result"];
  await call("compile", { spec: { schemaVersion: 2, nodes: [
    { id: "w", kind: "write", prompt: "Write result", writeScope, gateArgv: ["false"] },
  ] } });
  const claim = () => call("claim", { node: "w", expectedRev: 1, opId: "claim" });
  const running = async () => {
    const c = await claim();
    await call("start", { token: c.instructionPath, hostHandle: "worker" });
    return c;
  };
  return { root, workspace, git, claim, running, call, writeScope };
}

test("O-W-2: claim replay holds on a foreign worktree without overwriting its files or lock", async t => {
  const { root, git, claim, call, workspace } = await fixture(t);
  const blocker = join(root, "worktrees");
  await writeFile(blocker, "not a directory");
  await assert.rejects(claim(), { code: "ENOTDIR" });
  const { worktree } = (await call("status")).nodes.w.attempt;
  await rm(blocker);
  await git("worktree", "add", "--detach", "--lock", "--reason", "foreign", worktree.path, "HEAD");
  await writeFile(join(worktree.path, "result"), "foreign bytes");
  for (let i = 0; i < 2; i++) await assert.rejects(claim(), { code: "ERR_GIT_FAILED" });
  const n = (await call("status")).nodes.w;
  assert.deepEqual([n.status, n.heldReason], ["held_infra", "ERR_GIT_FAILED"]);
  assert.equal(await readFile(join(worktree.path, "result"), "utf8"), "foreign bytes");
  assert.equal((await listWorktrees(workspace)).find(w => w.path === worktree.path).locked, "foreign");
});

test("O-W-5: only a fenced worker's authentic directive can release its worktree", async t => {
  const { running, root, call, workspace } = await fixture(t);
  const { instructionPath: token, worktreePath } = await running();
  const release = () => call("release", { token, opId: "release" });
  await assert.rejects(release(), { code: "ERR_NOT_READY" });
  await call("amend", { node: "w", expectedRev: 1, opId: "amend", patch: { exec: { prompt: "New task" } } });
  assert.ok((await listWorktrees(workspace)).some(w => w.path === worktreePath));
  const bytes = await readFile(token);
  await chmod(token, 0o600);
  await writeFile(token, "{}");
  await assert.rejects(release(), { code: "ERR_STALE_FENCING_TOKEN" });
  await writeFile(token, bytes);
  const cli = fileURLToPath(new URL("../scripts/graph/cli.mjs", import.meta.url));
  const argv = [cli, "release", "--workspace", workspace, "--root", root, "--token", token];
  await assert.rejects(exec(process.execPath, argv), e => JSON.parse(e.stdout).error.code === "ERR_CLI_MISSING_FLAG");
  const viaCli = async () => JSON.parse((await exec(process.execPath, [...argv, "--op-id", "release"])).stdout).result;
  const response = await viaCli();
  assert.deepEqual((await listWorktrees(workspace)).map(w => w.path), [workspace]);
  assert.deepEqual(await viaCli(), response);
});

test("O-H-2: response and directive dispatch in the engine worktree without host isolation", async t => {
  const { claim } = await fixture(t);
  const c = await claim();
  const directive = JSON.parse(await readFile(c.instructionPath));
  for (const value of [directive, c]) assert.deepEqual(value.dispatch, { cwd: c.worktreePath, isolation: "none" });
});

test("infra_transient settlement removes the worktree and frees its recorded slot", async t => {
  const { call, running, workspace } = await fixture(t);
  const c = await running();
  const r = await call("settle", { token: c.instructionPath, outcome: "infra_transient", opId: "retry-later" });
  assert.equal(r.status, "retry_wait");
  assert.deepEqual((await listWorktrees(workspace)).map(w => w.path), [workspace]);
  const s = await call("status");
  assert.equal(s.worktrees[s.nodes.w.attempt.worktree.id].phase, "released");
});

for (const same of [true, false]) test(`seal pin re-entry with ${same ? "matching" : "divergent"} OID`, async t => {
  const { root, git, running, call, writeScope } = await fixture(t);
  const c = await running();
  await writeFile(join(c.worktreePath, "result"), "new\n");
  const { attempt } = (await call("status")).nodes.w;
  const key = nodeKey("w"), ref = pinRef("r", key, c.epoch);
  const preexisting = same ? (await seal({ worktree: c.worktreePath, baseSha: c.baseSha, policy: {}, writeScope,
    indexPath: join(root, "control.index"), claimSec: attempt.claimSec, message: `hstack seal r/${key}/e${c.epoch}` })).commit : c.baseSha;
  await git("update-ref", ref, preexisting);
  const provenance = { evidenceSpans: [{ spanId: "s", path: "result", startLine: 1, endLine: 1 }],
    claims: [{ claimId: "c", text: "new", spanIds: ["s"] }], edgeCases: [], failureEvidence: [] };
  provenance.factDigest = factDigest(provenance);
  const r = await call("settle", { token: c.instructionPath, opId: "seal", outcome: "success",
    receipt: { workerReportedStatus: "completed", provenance, inlineSummary: "new" } });
  assert.equal(r.status, same ? "sealed" : "held_integration");
  if (!same) assert.equal(r.reason, "ERR_INTEGRATION_DIVERGED");
  assert.equal(await git("rev-parse", ref), preexisting);
});
