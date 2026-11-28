import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { compileGraph } from "../scripts/graph/admission.mjs";
import { runCli } from "../scripts/graph/cli.mjs";
import { canonical } from "../scripts/graph/fingerprint.mjs";
import { digest } from "../scripts/graph/gc.mjs";
import { repoConfigDigest } from "../scripts/graph/git.mjs";
import { factDigest } from "../scripts/graph/reducer.mjs";
import { SCHEMA_VERSION, validateRunRecords, V2_WRITE_ERROR } from "../scripts/graph/schema.mjs";
import { dispatch } from "../scripts/graph/state-machine.mjs";
import * as wal from "../scripts/graph/wal-store.mjs";

const exec = promisify(execFile);
const invalid = { code: "ERR_GRAPH_SCHEMA" };
const unavailable = { code: V2_WRITE_ERROR };
const repo = fileURLToPath(new URL("..", import.meta.url));
const readNode = { id: "read", kind: "read", prompt: "Read the source" };
const writer = (id, options) => ({
  id, kind: "write", prompt: `Write ${id}`, writeScope: ["src"], gateArgv: [process.execPath, "--version"], ...options,
});
let archive;
let oldDispatch;
let oldWal;

before(async () => {
  archive = await mkdtemp(join(tmpdir(), "graph-v1-archive-"));
  const tar = join(archive, "v1.tar");
  await exec("git", ["-C", repo, "archive", "--output=" + tar, "56d4bb1", "scripts"]);
  await exec("tar", ["-xf", tar, "-C", archive]);
  const old = name => import(pathToFileURL(join(archive, "scripts", "graph", name + ".mjs")).href);
  ({ dispatch: oldDispatch } = await old("state-machine"));
  oldWal = await old("wal-store");
});
after(async () => {
  if (archive) await rm(archive, { recursive: true, force: true });
});

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), "graph-v2-schema-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const root = join(dir, "store");
  const workspace = join(dir, "workspace");
  await mkdir(root);
  await mkdir(workspace);
  const git = async (...args) => (await exec("git", args, { cwd: workspace })).stdout.trim();
  await git("init", "-q", "-b", "main");
  await git("config", "user.name", "Graph Test");
  await git("config", "user.email", "graph@example.invalid");
  await writeFile(join(workspace, "source"), "source\n");
  await git("add", "source");
  await git("commit", "-qm", "fixture");
  return { root, workspace, run: "example", git };
}

test("O-S-2: archived v1 rejects compiling or reading v2 while the current engine supports both", async t => {
  const { git, ...options } = await fixture(t);
  const spec = { schemaVersion: 2, nodes: [readNode] };
  await assert.rejects(oldDispatch("compile", { ...options, spec }), invalid);
  await dispatch("compile", { ...options, spec });
  await assert.rejects(oldDispatch("status", options), invalid);
  assert.equal((await dispatch("status", options)).schemaVersion, 2);
});

test("O-S-3: identical v1 read claims keep their historical execKey", async t => {
  const { git, ...options } = await fixture(t);
  const oldRoot = join(options.root, "historical");
  await mkdir(oldRoot);
  const spec = { schemaVersion: 1, nodes: [readNode] };
  const claim = async (send, context) => {
    await send("compile", { ...context, spec });
    return send("claim", { ...context, node: readNode.id, expectedRev: 1, opId: "read" });
  };
  assert.equal(SCHEMA_VERSION, 1);
  const historical = await claim(oldDispatch, { ...options, root: oldRoot });
  const current = await claim(dispatch, options);
  assert.match(historical.execKey, /^[a-f0-9]{64}$/);
  assert.equal(current.execKey, historical.execKey);
});

test("O-S-4: every reserved prefix is rejected before a user operation commits", async t => {
  const { git, ...options } = await fixture(t);
  const spec = { schemaVersion: 1, nodes: [readNode] };
  for (const prefix of ["verifier", "gate-proof", "worktree", "seal", "publish", "published"]) {
    await assert.rejects(dispatch("compile", { ...options, spec, opId: `@hstack-${prefix}/user` }),
      { ...invalid, message: "Reserved operation ID" }, prefix);
  }
  await dispatch("compile", { ...options, spec, opId: "user" });
});

test("O-S-5: historical full refs and v2 delta refs recover the same root union in both readers", async t => {
  const { git, ...options } = await fixture(t);
  const { root, run } = options;
  const v2 = { ...options, run: "v2" };
  await dispatch("compile", { ...v2, spec: { schemaVersion: 2, nodes: [readNode] } });
  const stateV2 = { ...await dispatch("status", v2), runId: run };
  const framePath = join(root, "runs", run, "wal", "events.jsonl");
  const readFrames = async () => (await readFile(framePath, "utf8")).trimEnd().split("\n").map(line => JSON.parse(line));
  await oldDispatch("compile", { ...options, spec: { schemaVersion: 1, nodes: [readNode] } });
  const oldFrame = (await readFrames())[0];
  const refs = [oldFrame.body.stateUri];
  await wal.transaction(root, run, { opId: "v2", type: "GraphCompiled", payload: {} }, async (state, io) => {
    assert.equal(state.schemaVersion, 1);
    const extra = await io.put(Buffer.from("v2 reference"));
    refs.push(extra);
    return { state: stateV2, response: {}, refs };
  });
  const frames = await readFrames();
  assert.equal(frames.length, 2);
  assert.ok(frames.every(frame => frame.schemaVersion === 1));
  assert.ok(!frames[1].body.refs.includes(refs[0]), "v2 writer must omit the previously rooted ref");
  // Make the first v1 record an explicit full refs frame, including its already
  // implicit state address, and keep the hash chain valid.
  frames[0].body.refs = [refs[0]];
  const rehash = ({ recordHash, ...frame }) => ({ ...frame, recordHash: digest(canonical(frame)) });
  const full = rehash(frames[0]);
  const delta = rehash({ ...frames[1], prevHash: full.recordHash });
  await rm(join(root, "runs", run, "snapshots"), { recursive: true, force: true });
  await writeFile(framePath, `${canonical(full)}\n${canonical(delta)}\n`);
  const expected = new Set([refs[0], refs[1], delta.body.stateUri]);
  const pinPath = join(root, "gcroots", `${run}.pin.json`);
  for (const reader of [oldWal, wal]) {
    await rm(pinPath);
    assert.deepEqual(await reader.recover(root, run), stateV2);
    assert.deepEqual(new Set(JSON.parse(await readFile(pinPath, "utf8")).refs), expected);
    const marked = new Set();
    await reader.markJournal(root, run, marked);
    assert.deepEqual(marked, expected);
  }
});

test("v2 keeps parallel and serial overlapping writers separate and counts overlap against f", () => {
  const compile = nodes => compileGraph({ schemaVersion: 2, nodes });
  const parallel = compile([writer("a", { schemaVersion: 2 }), writer("b")]);
  const serial = compile([writer("a"), writer("b", { dependsOn: ["a"] })]);
  assert.equal(parallel.schemaVersion, 2);
  assert.equal(parallel.metrics.f, 0);
  assert.equal(compile([writer("a"), writer("b", { writeScope: ["elsewhere"] })]).metrics.f, 1);
  for (const graph of [parallel, serial]) assert.deepEqual(graph.nodes.map(node => node.id), ["a", "b"]);
});

test("v2 admission rejects integrate nodes, write nodes without a gate, and mismatched spec versions", () => {
  const compile = node => compileGraph({ schemaVersion: 2, nodes: [node] });
  assert.throws(() => compile({ ...readNode, kind: "integrate" }), unavailable);
  assert.throws(() => compile(writer("a", { gateArgv: undefined })), { ...invalid, message: "v2 write nodes need gateArgv" });
  assert.throws(() => compile({ ...readNode, schemaVersion: 1 }), invalid);
});

test("v2 compile records Git context, policy, and include paths and rejects invalid inputs", async t => {
  const { git, ...options } = await fixture(t);
  const startBase = await git("rev-parse", "HEAD");
  const blob = await git("rev-parse", "HEAD:source");
  await writeFile(join(options.workspace, "source"), "longer content\n");
  await git("add", "source");
  await git("commit", "-qm", "advance");
  await mkdir(join(options.workspace, "sub"));
  await writeFile(join(options.workspace, ".worktreeinclude"), "# ignored\n\nsource\nsub/file\nsource\n");
  const defaults = { schemaVersion: 2, nodes: [writer("a"), readNode] };
  const spec = { ...defaults, baseSha: startBase, policy: {
    mode: "exact", integration: { maxOpenWorktrees: 3 }, seal: { allowSymlinks: true, maxChangedPaths: 7 },
  } };
  await dispatch("compile", { ...options, spec });
  const state = await dispatch("status", options);
  assert.equal(state.startBase, startBase);
  assert.equal(state.checkoutBytes, Buffer.byteLength("source\n"));
  assert.equal(state.repoConfigDigest, await repoConfigDigest(options.workspace));
  assert.equal(state.integrationRef, "refs/hstack/runs/example/accepted");
  assert.deepEqual(state.worktreeInclude, ["source", "sub/file"]);
  assert.deepEqual(state.policy, { mode: "exact", integration: { B0: 1, Bmax: 1, K: 5, maxOpenWorktrees: 3 },
    seal: { allowSymlinks: true, maxChangedPaths: 7, maxBlobBytes: 1048576 } });
  for (const request of [
    { run: "a..b" }, { run: "x.lock" }, { workspace: join(options.workspace, "sub") },
    { spec: { ...defaults, baseSha: blob } },
    { spec: { ...defaults, policy: { integration: { maxOpenWorktrees: 65 } } } },
    { spec: { ...defaults, policy: { seal: { allowSymlinks: 1 } } } },
  ]) await assert.rejects(dispatch("compile", { ...options, run: "invalid", spec: defaults, ...request }), invalid);
  assert.ok((await dispatch("claim", { ...options, node: "a", opId: "write", expectedRev: 1 })).worktreePath);
  assert.deepEqual(await dispatch("integrate", { ...options, opId: "idle" }), { status: "idle" });
  await dispatch("claim", { ...options, node: "read", opId: "reader", expectedRev: 1 });
  assert.equal((await dispatch("status", options)).nodes.read.status, "claimed");
});

test("v2 read nodes settle through the v1 evidence path and are accepted", async t => {
  const { git, ...options } = await fixture(t);
  const node = { ...readNode, gateArgv: [process.execPath, "-e", "require('fs').accessSync('source')"] };
  await dispatch("compile", { ...options, spec: { schemaVersion: 2, nodes: [node] } });
  const { instructionPath: token } = await dispatch("claim", { ...options, node: "read", opId: "claim", expectedRev: 1 });
  await dispatch("start", { root: options.root, token, hostHandle: "worker:read" });
  const provenance = { evidenceSpans: [{ spanId: "s", path: "source", startLine: 1, endLine: 1 }],
    claims: [{ claimId: "c", spanIds: ["s"], text: "a fact" }], edgeCases: [], failureEvidence: [] };
  provenance.factDigest = factDigest(provenance);
  const settled = await dispatch("settle", { root: options.root, token, outcome: "accepted", opId: "settle",
    receipt: { schemaVersion: 1, workerReportedStatus: "completed", provenance, inlineSummary: "a fact" } });
  assert.equal(settled.status, "accepted");
  assert.equal((await dispatch("status", options)).status, "completed");
});

test("runtime validator permits integration-only statuses only in v2 write nodes", async t => {
  const { git, ...options } = await fixture(t);
  for (const schemaVersion of [1, 2]) {
    const context = { ...options, run: `v${schemaVersion}` };
    await dispatch("compile", { ...context, spec: { schemaVersion, nodes: [writer("write"), readNode] } });
    const state = await dispatch("status", context);
    for (const status of ["sealed", "integrating", "held_conflict", "held_integration"]) {
      for (const id of ["read", "write"]) {
        const draft = structuredClone(state);
        draft.nodes[id].status = status;
        if (schemaVersion === 2 && id === "write") assert.deepEqual(validateRunRecords(draft), draft);
        else assert.throws(() => validateRunRecords(draft), invalid, `${schemaVersion}/${id}/${status}`);
      }
    }
  }
});

test("CLI integrate dispatches an existing v2 run but never an existing v1 run", async t => {
  const { git, ...options } = await fixture(t);
  for (const schemaVersion of [1, 2]) {
    const run = `v${schemaVersion}`;
    await dispatch("compile", { ...options, run, spec: { schemaVersion, nodes: [readNode] } });
    const calls = [];
    const exit = await runCli(["integrate", "--root", options.root, "--run", run, "--op-id", "integrate"], {
      cwd: options.workspace, env: {}, stdout: { write() {} },
      dispatch(command, { run: dispatchedRun }) { calls.push([command, dispatchedRun]); },
    });
    assert.deepEqual({ exit, calls }, schemaVersion === 1 ? { exit: 69, calls: [] } : { exit: 0, calls: [["integrate", run]] });
  }
});
