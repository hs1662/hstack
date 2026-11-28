import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { factDigest } from "../scripts/graph/reducer.mjs";
import { dispatch } from "../scripts/graph/state-machine.mjs";
import { listWorktrees } from "../scripts/graph/worktree.mjs";

const exec = promisify(execFile);
const writer = id => ({ id, kind: "write", writeScope: ["result"], prompt: "Write result", gateArgv: ["false"] });
async function fixture(t, policy = {}) {
  const root = await mkdtemp(join(tmpdir(), "v2-claim-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  const workspace = join(root, "repo");
  await mkdir(workspace);
  const git = async (...args) => (await exec("git", args, { cwd: workspace })).stdout;
  await git("init", "-q", "-b", "main");
  await git("config", "user.name", "Fixture");
  await git("config", "user.email", "fixture@invalid");
  await writeFile(join(workspace, "source"), "base\n");
  await git("add", "source");
  await git("commit", "-qm", "base");
  const call = (cmd, opts) => dispatch(cmd, { workspace, root, run: "r", ...opts });
  await call("compile", { spec: { schemaVersion: 2, policy, nodes: [writer("a"), writer("b"),
    { id: "reader", kind: "read", prompt: "Read" }] } });
  const claim = (node = "a") => call("claim", { node, opId: node, expectedRev: 1 });
  const start = token => call("start", { token, hostHandle: "host" });
  return { root, workspace, git, call, claim, start };
}

function evidence(path) {
  const provenance = { evidenceSpans: [{ spanId: "s", path, startLine: 1, endLine: 1 }],
    claims: [{ claimId: "c", text: "written", spanIds: ["s"] }], edgeCases: [], failureEvidence: [] };
  provenance.factDigest = factDigest(provenance);
  return { inlineSummary: "written", workerReportedStatus: "completed", provenance };
}

test("O-W-6: worker bytes alone become a single-parent pinned commit; private caches stay outside", async t => {
  const { root, git, claim, call, start } = await fixture(t);
  const c = await claim();
  const directive = JSON.parse(await readFile(c.instructionPath));
  const tmp = join(root, "runs/r/tmp", basename(c.worktreePath));
  for (const value of [directive, c]) {
    assert.equal(value.tmpDir, tmp);
    assert.deepEqual(value.env, { TMPDIR: tmp, npm_config_cache: join(tmp, "npm-cache"), XDG_CACHE_HOME: join(tmp, "xdg-cache") });
    for (const dir of Object.values(value.env)) assert.ok((await stat(dir)).isDirectory());
    assert.equal(value.receiptPath, c.receiptPath);
    assert.equal(value.baseSha, (await git("rev-parse", "HEAD")).trim());
  }
  assert.equal((await stat(dirname(c.receiptPath))).mode & 0o777, 0o700);
  await start(c.instructionPath);
  await writeFile(join(c.worktreePath, "result"), "worker bytes\n");
  await writeFile(join(tmp, "scratch"), "private");
  const r = await call("settle", { token: c.instructionPath, opId: "settle", outcome: "success", receipt: evidence("result") });
  assert.equal(r.status, "sealed");
  const n = (await call("status")).nodes.a;
  assert.match(n.workerReceiptUri, /^cas:\/\/sha256\/[0-9a-f]{64}$/);
  const oid = (await git("rev-parse", n.attempt.pinRef)).trim();
  assert.equal(oid, n.attempt.sealedCommit);
  assert.equal(await git("show", "-s", "--format=%P", oid), `${c.baseSha}\n`);
  assert.equal(await git("ls-tree", "-r", "--name-only", oid), "result\nsource\n");
  assert.equal(await git("cat-file", "blob", `${oid}:result`), "worker bytes\n");
  await assert.rejects(call("release", { token: c.instructionPath, opId: "release" }), { code: "ERR_NOT_READY" });
});

test("O-W-3: occupied writer slot blocks writers but not readers", async t => {
  const { claim } = await fixture(t, { integration: { maxOpenWorktrees: 1 } });
  await claim();
  await assert.rejects(claim("b"), { code: "ERR_HELD_CAPACITY", message: "held:capacity: worktree slots" });
  assert.equal((await claim("reader")).nodeId, "reader");
});

for (const [name, policy, path, receipt, reason, status] of [
  ["scope violation", {}, "outside", evidence("source"), "ERR_SCOPE_VIOLATION", "failed_logic"],
  ["seal limit", { seal: { maxBlobBytes: 1 } }, "result", evidence("result"), "ERR_SEAL_LIMIT", "held_blocked"],
  ["missing evidence", {}, "result", {}, "ERR_MISSING_EVIDENCE", "held_blocked"],
  ["missing sealed path", {}, "result", evidence("workspace-only"), "ERR_FORGED_EVIDENCE", "failed_logic"],
]) test(`write settle records ${name} and releases the worktree`, async t => {
  const { workspace, claim, start, call } = await fixture(t, policy);
  await writeFile(join(workspace, "workspace-only"), "not sealed\n");
  const c = await claim();
  await start(c.instructionPath);
  await writeFile(join(c.worktreePath, path), "new\n");
  const r = await call("settle", { token: c.instructionPath, outcome: "success", opId: "settle", receipt });
  assert.deepEqual([r.status, r.reason], [status, reason]);
  assert.deepEqual((await listWorktrees(workspace)).map(w => w.path), [workspace]);
});

test("claim commits a config tamper hold and replays the error after config restoration", async t => {
  const { claim, workspace, git, call } = await fixture(t);
  const config = join(workspace, ".git/config");
  const original = await readFile(config);
  await git("config", "test.tamper", "true");
  await assert.rejects(claim(), { code: "ERR_REPO_CONFIG_TAMPERED" });
  const n = (await call("status")).nodes.a;
  assert.deepEqual([n.status, n.heldReason], ["held_integration", "ERR_REPO_CONFIG_TAMPERED"]);
  await writeFile(config, original);
  await assert.rejects(claim(), { code: "ERR_REPO_CONFIG_TAMPERED" });
});

test("start refuses a committed planned attempt until provision completes", async t => {
  const { root, claim, call, start } = await fixture(t);
  const blocker = join(root, "worktrees");
  await writeFile(blocker, "not a directory");
  await assert.rejects(claim(), { code: "ENOTDIR" });
  const a = (await call("status")).nodes.a.attempt;
  assert.equal(a.worktree.phase, "planned");
  await assert.rejects(start(a.instructionPath), { code: "ERR_NOT_READY" });
  await rm(blocker);
  assert.equal((await claim()).instructionPath, a.instructionPath);
  assert.equal((await start(a.instructionPath)).status, "running");
});
