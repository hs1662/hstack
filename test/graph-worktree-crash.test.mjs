import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { dispatch } from "../scripts/graph/state-machine.mjs";
import { getBlob } from "../scripts/graph/gc.mjs";
import { listWorktrees } from "../scripts/graph/worktree.mjs";

const exec = promisify(execFile);
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "worktree-crash-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  const workspace = join(root, "repo"), run = "crash";
  await mkdir(workspace);
  const git = (...args) => exec("git", args, { cwd: workspace });
  await git("init", "-q", "-b", "main");
  await git("config", "user.name", "Fixture");
  await git("config", "user.email", "fixture@invalid");
  await git("commit", "--allow-empty", "-qm", "base");
  await dispatch("compile", { root, workspace, run, spec: { schemaVersion: 2,
    nodes: [{ id: "w", kind: "write", writeScope: ["out"], prompt: "Write", gateArgv: ["true"] }] } });
  return { root, run };
}

async function killedBefore(command, o, opId) {
  const script = `
    import fs from "node:fs/promises";
    import { syncBuiltinESMExports } from "node:module";
    const open = fs.open;
    fs.open = async (path, ...args) => {
      const fd = await open(path, ...args);
      if (args[0] === "a" && path.endsWith("/wal/events.jsonl")) {
        const write = fd.writeFile.bind(fd);
        fd.writeFile = bytes => {
          if (JSON.parse(bytes).opId === ${JSON.stringify(opId)}) process.kill(process.pid, "SIGKILL");
          return write(bytes);
        };
      }
      return fd;
    };
    syncBuiltinESMExports();
    const { dispatch } = await import(${JSON.stringify(new URL("../scripts/graph/state-machine.mjs", import.meta.url))});
    await dispatch(${JSON.stringify(command)}, ${JSON.stringify(o)});`;
  await assert.rejects(exec(process.execPath, ["--input-type=module", "-e", script], { timeout: 20000 }), { signal: "SIGKILL" });
}

test("O-W-1: claim replay reuses the worktree created before the provision frame was appended", async t => {
  const { root, run } = await fixture(t);
  const workspace = join(root, "repo");
  const o = { root, run, node: "w", opId: "claim", expectedRev: 1 };
  await killedBefore("claim", o, "@hstack-worktree/claim");
  const status = () => dispatch("status", { root, run });
  const frames = (await readFile(join(root, "runs", run, "wal/events.jsonl"), "utf8")).trim().split("\n");
  const last = JSON.parse(frames.at(-1));
  assert.equal(last.type, "AttemptClaimed");
  const a = JSON.parse(await getBlob(root, last.body.stateUri)).nodes.w.attempt;
  assert.equal(a.worktree.phase, "planned");
  const count = async () => (await listWorktrees(workspace)).filter(w => w.path === a.worktree.path).length;
  assert.equal(await count(), 1);
  const c = await dispatch("claim", o);
  assert.equal(c.instructionPath, a.instructionPath);
  assert.equal(await count(), 1);
  assert.equal((await status()).nodes.w.attempt.worktree.phase, "ready");
  assert.equal((await dispatch("start", { root, token: c.instructionPath, hostHandle: "worker" })).status, "running");
});

test("a committed seal rejects a changed settle payload after loss of the main frame", async t => {
  const { root, run } = await fixture(t);
  const { instructionPath: token } = await dispatch("claim", { root, run, node: "w", opId: "claim", expectedRev: 1 });
  await dispatch("start", { root, token, hostHandle: "host" });
  const o = { root, token, opId: "settle", outcome: "success" };
  await killedBefore("settle", o, o.opId);
  await assert.rejects(dispatch("settle", { ...o, outcome: "infra_transient" }), { code: "ERR_OP_CONFLICT" });
  assert.equal((await dispatch("settle", o)).reason, "ERR_MISSING_EVIDENCE");
});
