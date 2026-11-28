import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { commitTree, repoConfigDigest } from "../scripts/graph/git.mjs";
import { land } from "../scripts/graph/land.mjs";

const exec = promisify(execFile);
const fixtureEnv = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_"))),
  GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_OPTIONAL_LOCKS: "0" };
const plain = async (cwd, ...args) =>
  (await exec("git", ["-c", "core.hooksPath=/dev/null", ...args], { cwd, env: fixtureEnv, timeout: 30_000 })).stdout.trim();
const file = (repo, path) => readFile(join(repo.workspace, path));
const put = (repo, path, bytes) => writeFile(join(repo.workspace, path), bytes);
const err = code => ({ code: `ERR_${code}` });
const dirtyAllow = ["dirty-nonoverlap"];

async function treeWith(repo, changes) {
  for (const [path, bytes] of Object.entries(changes)) await put(repo, path, bytes);
  await plain(repo.workspace, "update-index", "--add", "--", ...Object.keys(changes));
  return plain(repo.workspace, "write-tree");
}

async function fixture(t, divergence) {
  const root = await mkdtemp(join(tmpdir(), "hstack-land-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const workspace = join(root, "repo");
  const repo = { workspace, root };
  await mkdir(workspace);
  await plain(workspace, "init", "-q", "-b", "main");
  await plain(workspace, "config", "user.name", "Land Test");
  await plain(workspace, "config", "user.email", "land@test.invalid");
  const makeCommit = (tree, parents, message) => commitTree(workspace, { tree, parents, dateSec: 1234567890, message });
  const baseTree = await treeWith(repo, { "shared": "base\n", "staged": "base\n", "unstaged": "base\n" });
  const startBase = await makeCommit(baseTree, [], "base");
  await mkdir(join(workspace, "cache"));
  const acceptedTree = await treeWith(repo, { shared: "accepted\n", added: "added\n", "cache/new": "accepted cache\n" });
  const candidate = await makeCommit(acceptedTree, [startBase], "worker");
  const acceptedTip = await makeCommit(acceptedTree, [startBase, candidate], "accepted");
  await plain(workspace, "update-ref", "refs/hstack/runs/R01/accepted", acceptedTip);
  await plain(workspace, "read-tree", "--reset", "-u", startBase);
  const userTree = divergence ? await treeWith(repo, divergence) : baseTree;
  const oldHead = divergence ? await makeCommit(userTree, [startBase], "user") : startBase;
  await plain(workspace, "update-ref", "refs/heads/main", oldHead);
  const state = { runId: "R01", status: "completed", startBase, acceptedTip,
    repoConfigDigest: await repoConfigDigest(workspace), lastPublished: { new: acceptedTip } };
  return { ...repo, state, oldHead, acceptedTree };
}

async function checkoutState(repo) {
  return {
    head: await plain(repo.workspace, "rev-parse", "HEAD"),
    index: await file(repo, ".git/index"),
    status: await plain(repo.workspace, "status", "--porcelain=v2", "--untracked-files=all", "--ignored=matching"),
    shared: await file(repo, "shared"),
  };
}

test("O-L-1 fast-forwards a clean checkout to the accepted tree", async t => {
  const repo = await fixture(t);
  const result = await land(repo);
  assert.deepEqual(result, { mode: "ff-only", targetRef: "refs/heads/main", oldHead: repo.oldHead,
    newHead: repo.state.acceptedTip, verifiedTree: repo.acceptedTree, verified: true });
  assert.equal(await plain(repo.workspace, "rev-parse", "HEAD"), repo.state.acceptedTip);
  assert.equal(await plain(repo.workspace, "status", "--porcelain"), "");
  assert.equal(String(await file(repo, "shared")), "accepted\n");
});

for (const allow of [[], dirtyAllow]) {
  test(`O-L-2 ${allow.length ? "keeps" : "refuses"} disjoint staged and unstaged edits`, async t => {
    const repo = await fixture(t);
    await put(repo, "staged", "index edit\n");
    await plain(repo.workspace, "update-index", "--", "staged");
    await put(repo, "unstaged", "worktree edit\n");
    if (allow.length) await land({ ...repo, allow });
    else await assert.rejects(land({ ...repo, allow }), err("LAND_DIRTY"));
    assert.equal(await plain(repo.workspace, "rev-parse", "HEAD"), allow.length ? repo.state.acceptedTip : repo.oldHead);
    assert.equal(await plain(repo.workspace, "show", ":staged"), "index edit");
    assert.equal(await plain(repo.workspace, "show", ":unstaged"), "base");
    assert.equal(String(await file(repo, "unstaged")), "worktree edit\n");
  });
}

for (const [label, path] of [["tracked overlap", "shared"], ["untracked collision", "added"]]) {
  test(`O-L-3 refuses ${label} even when disjoint dirt is allowed`, async t => {
    const repo = await fixture(t);
    await put(repo, path, "mine\n");
    await assert.rejects(land({ ...repo, allow: dirtyAllow }), err("LAND_DIRTY"));
    assert.equal(await plain(repo.workspace, "rev-parse", "HEAD"), repo.oldHead);
    assert.equal(String(await file(repo, path)), "mine\n");
  });
}

for (const mode of ["ff-only", "merge"]) {
  for (const allow of [[], dirtyAllow]) {
    test(`O-L-4 ${mode} preserves ignored bytes with ${allow.length ? "dirty allowance" : "default policy"}`, async t => {
      const repo = await fixture(t);
      await put(repo, ".git/info/exclude", "/cache/\n");
      repo.state.repoConfigDigest = await repoConfigDigest(repo.workspace);
      await mkdir(join(repo.workspace, "cache"));
      const bytes = Buffer.from([0, 255, 19, 10]);
      await put(repo, "cache/new", bytes);
      await assert.rejects(land({ ...repo, mode, allow }), err("LAND_DIRTY"));
      assert.deepEqual(await file(repo, "cache/new"), bytes);
      assert.equal(await plain(repo.workspace, "rev-parse", "HEAD"), repo.oldHead);
    });
  }
  test(`O-L-5 ${mode} refuses a divergent conflict without changing the checkout`, async t => {
    const repo = await fixture(t, { shared: "user\n" });
    const before = await checkoutState(repo);
    await assert.rejects(land({ ...repo, mode }), err("LAND_CONFLICT"));
    assert.deepEqual(await checkoutState(repo), before);
  });
}

for (const gateResult of ["green", "absent", "red"]) {
  test(`O-L-6 divergent merge with ${gateResult} gate reports only verified trees and removes the gate worktree`, async t => {
    const repo = await fixture(t, { staged: "user commit\n" });
    const tree = await plain(repo.workspace, "merge-tree", "--write-tree", "HEAD", repo.state.acceptedTip);
    const before = await checkoutState(repo);
    const worktrees = await plain(repo.workspace, "worktree", "list", "--porcelain");
    let gatePath;
    let gateTree;
    let gateContents;
    const gate = gateResult === "absent" ? undefined : async path => {
      gatePath = path;
      gateTree = await plain(path, "rev-parse", "HEAD^{tree}");
      gateContents = await readFile(join(path, "staged"), "utf8");
      await writeFile(join(path, "gate-output"), "must be removed");
      return gateResult === "green";
    };
    if (gateResult === "red") {
      await assert.rejects(land({ ...repo, mode: "merge", gate }), err("GATE_FAILED"));
      assert.deepEqual(await checkoutState(repo), before);
    } else {
      const result = await land({ ...repo, mode: "merge", gate });
      assert.equal(result.verified, gateResult === "green");
      assert.equal(result.verifiedTree, tree);
      assert.equal(await plain(repo.workspace, "rev-parse", "HEAD^{tree}"), tree);
      assert.equal(await plain(repo.workspace, "show", "-s", "--format=%P", "HEAD"), `${repo.oldHead} ${repo.state.acceptedTip}`);
    }
    if (gate) {
      assert.equal(gateTree, tree);
      assert.equal(gateContents, "user commit\n");
      await assert.rejects(access(gatePath), { code: "ENOENT" });
    }
    assert.equal(await plain(repo.workspace, "worktree", "list", "--porcelain"),
      gateResult === "red" ? worktrees : worktrees.replace(repo.oldHead, await plain(repo.workspace, "rev-parse", "HEAD")));
  });
}

for (const branch of [undefined, "topic/custom"]) {
  test(`O-L-7 creates the ${branch ? "named branch from detached HEAD" : "default branch"} without touching checkout`, async t => {
    const repo = await fixture(t);
    if (branch) await plain(repo.workspace, "checkout", "--detach", repo.oldHead);
    await put(repo, "shared", "uncommitted\n");
    const before = await checkoutState(repo);
    const targetRef = `refs/heads/${branch ?? "hstack/R01"}`;
    const result = await land({ ...repo, mode: "branch", branch });
    assert.equal(result.targetRef, targetRef);
    assert.equal(await plain(repo.workspace, "rev-parse", targetRef), repo.state.acceptedTip);
    assert.deepEqual(await checkoutState(repo), before);
  });
}

test("O-L-7 exports a patch that applies three-way at startBase without touching checkout", async t => {
  const repo = await fixture(t);
  const out = join(repo.root, "landing.patch");
  const clone = join(repo.root, "clone");
  const before = await checkoutState(repo);
  const result = await land({ ...repo, mode: "patch", out });
  assert.equal(result.patchPath, out);
  await plain(repo.root, "clone", "-q", repo.workspace, clone);
  assert.equal(await plain(clone, "rev-parse", "HEAD"), repo.state.startBase);
  await plain(clone, "apply", "--check", "--3way", out);
  assert.deepEqual(await checkoutState(repo), before);
});

test("O-L-7 refuses an existing patch path without overwriting it", async t => {
  const repo = await fixture(t);
  const out = join(repo.root, "landing.patch");
  await writeFile(out, "keep me");
  await assert.rejects(land({ ...repo, mode: "patch", out }), err("LAND_PRECONDITION"));
  assert.equal(await readFile(out, "utf8"), "keep me");
});

test("O-L-8 refuses config tampering before changing HEAD, index, or worktree", async t => {
  const repo = await fixture(t, { staged: "user commit\n" });
  await plain(repo.workspace, "config", "user.email", "changed@test.invalid");
  const before = await checkoutState(repo);
  await assert.rejects(land({ ...repo, mode: "merge" }), err("REPO_CONFIG_TAMPERED"));
  assert.deepEqual(await checkoutState(repo), before);
});

test("O-L-9 all landing modes avoid forbidden Git operations", async t => {
  const modes = ["ff-only", "merge", "branch", "patch"];
  const repos = await Promise.all(modes.map(mode => fixture(t, mode === "merge" ? { staged: "user commit\n" } : undefined)));
  const path = process.env.PATH;
  const dir = repos[0].root;
  const log = join(dir, "argv.jsonl");
  const realGit = (await exec("which", ["git"], { timeout: 30_000 })).stdout.trim();
  const shim = `#!${process.execPath}
const { appendFileSync } = require("node:fs");
const { spawnSync } = require("node:child_process");
const argv = process.argv.slice(2);
appendFileSync(${JSON.stringify(log)}, JSON.stringify(argv) + "\\n");
const result = spawnSync(${JSON.stringify(realGit)}, argv, { stdio: "inherit" });
process.exit(result.status ?? 1);
`;
  await writeFile(join(dir, "git"), shim, { mode: 0o700 });
  process.env.PATH = `${dir}${delimiter}${path}`;
  try {
    for (const [i, mode] of modes.entries()) {
      await land({ ...repos[i], mode, out: join(dir, "landing.patch"), gate: () => true });
    }
  } finally {
    process.env.PATH = path;
  }
  const commands = (await readFile(log, "utf8")).trimEnd().split("\n").map(line => {
    const argv = JSON.parse(line);
    let i = 0;
    while (argv[i] === "-c") i += 2;
    return argv.slice(i);
  });
  const operations = new Set(commands.map(([command]) => command));
  for (const command of ["merge", "branch", "diff", "worktree"]) assert.ok(operations.has(command), command);
  const forbidden = commands.filter(([command, ...args]) =>
    (command === "update-ref" && args.some(arg => arg.startsWith("refs/heads/"))) ||
    (command === "reset" && args.includes("--hard")) || ["stash", "cherry-pick"].includes(command));
  assert.deepEqual(forbidden, []);
});

for (const [label, state, detach] of [
  ["missing accepted tip", { acceptedTip: null }],
  ["accepted ref mismatch", { mismatchRef: true }],
  ["WAL publish mismatch", { lastPublished: null }],
  ["held run", { status: "held" }],
  ["open run", { status: "open" }],
  ["degraded run without partial allowance", { status: "degraded" }],
  ["detached HEAD", {}, true],
]) {
  test(`preconditions refuse ${label}`, async t => {
    const repo = await fixture(t);
    if (state.mismatchRef) await plain(repo.workspace, "update-ref", "refs/hstack/runs/R01/accepted", repo.oldHead);
    if (detach) await plain(repo.workspace, "checkout", "--detach", repo.oldHead);
    await assert.rejects(land({ ...repo, state: { ...repo.state, ...state } }), err("LAND_PRECONDITION"));
    assert.equal(await plain(repo.workspace, "rev-parse", "HEAD"), repo.oldHead);
  });
}
