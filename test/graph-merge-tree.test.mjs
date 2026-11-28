import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { promisify } from "node:util";

import { git, repoConfigDigest } from "../scripts/graph/git.mjs";
import { classifyMergeTree, mergeTree, mergeTreeBatch } from "../scripts/graph/merge-tree.mjs";
import { createTempDir } from "./fixtures.mjs";

const run = promisify(execFile);
const plainEnv = extra => {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")));
  return { ...env, GIT_CONFIG_NOSYSTEM: "1", ...extra };
};
const plain = async (cwd, args, extra = {}) =>
  (await run("git", args, { cwd, env: plainEnv(extra), encoding: "utf8" })).stdout.trim();

// Writes files (string content), deletes them (null), or sets the executable bit ({ exec: true }).
function apply(dir, changes) {
  for (const [path, change] of Object.entries(changes)) {
    const abs = join(dir, path);
    if (change === null) rmSync(abs);
    else if (typeof change === "object") chmodSync(abs, change.exec ? 0o755 : 0o644);
    else { mkdirSync(dirname(abs), { recursive: true }); writeFileSync(abs, change); }
  }
}

async function commitAt(dir, parent, changes, message) {
  await plain(dir, ["checkout", "-q", "--detach", parent]);
  apply(dir, changes);
  await plain(dir, ["add", "-A"]);
  await plain(dir, ["commit", "-q", "-m", message]);
  return plain(dir, ["rev-parse", "HEAD"]);
}

async function repo(files = { "a.txt": "a\n" }) {
  const dir = createTempDir("hstack-graph-merge-tree-");
  await plain(dir, ["init", "-q", "-b", "main"]);
  await plain(dir, ["config", "user.name", "Test"]);
  await plain(dir, ["config", "user.email", "test@invalid"]);
  apply(dir, files);
  await plain(dir, ["add", "-A"]);
  await plain(dir, ["commit", "-q", "-m", "base"]);
  return { dir, base: await plain(dir, ["rev-parse", "HEAD"]) };
}

async function fork(files, ours, theirs) {
  const { dir, base } = await repo(files);
  return { dir, base, ours: await commitAt(dir, base, ours, "ours"), theirs: await commitAt(dir, base, theirs, "theirs") };
}

const show = (dir, tree, path) => plain(dir, ["cat-file", "-p", `${tree}:${path}`]);
const rejects = (promise, code, exitCode) => assert.rejects(promise, error => {
  assert.equal(error.code, code);
  if (exitCode !== undefined) assert.equal(error.exitCode, exitCode);
  return true;
});
const FIVE = "1\n2\n3\n4\n5\n";

describe("graph merge-tree", () => {
  it("O-M-1 merges different files and different lines of one file cleanly", async () => {
    const files = { "a.txt": "a\n", "f.txt": FIVE };
    const split = await fork(files, { "a.txt": "A\n" }, { "b.txt": "b\n" });
    const clean = await mergeTree(split.dir, split);
    assert.equal(clean.kind, "clean");
    assert.match(clean.tree, /^[0-9a-f]{40}$/);
    assert.equal(await show(split.dir, clean.tree, "a.txt"), "A");
    assert.equal(await show(split.dir, clean.tree, "b.txt"), "b");

    const lines = await fork(files, { "f.txt": "ONE\n2\n3\n4\n5\n" }, { "f.txt": "1\n2\n3\n4\nFIVE\n" });
    const merged = await mergeTree(lines.dir, lines);
    assert.deepEqual(Object.keys(merged).sort(), ["kind", "tree"]);
    assert.equal(merged.kind, "clean");
    assert.equal(await show(lines.dir, merged.tree, "f.txt"), "ONE\n2\n3\n4\nFIVE");
  });

  it("O-M-2 reports text, rename/delete, modify/delete and mode/delete conflicts with their exact paths", async () => {
    const files = { "f.txt": FIVE, "r.txt": "rename me\n", "m.txt": "modify me\n", "x.sh": "echo x\n" };
    const split = await fork(files,
      { "f.txt": "ours\n2\n3\n4\n5\n", "r.txt": null, "r2.txt": "rename me\n", "m.txt": "modified\n", "x.sh": { exec: true } },
      { "f.txt": "theirs\n2\n3\n4\n5\n", "r.txt": null, "m.txt": null, "x.sh": null });
    const result = await mergeTree(split.dir, split);
    assert.equal(result.kind, "conflict");
    assert.deepEqual(result.paths, ["f.txt", "m.txt", "r2.txt", "x.sh"]);
    assert.ok(Buffer.isBuffer(result.messages) && result.messages.includes("CONFLICT (contents)"));
    // The conflict tree carries marker blobs; it is diagnostics only and never a candidate.
    assert.match(await show(split.dir, result.tree, "f.txt"), /^<<<<<<< /);
  });

  it("O-M-3 classifies a bogus ref and a missing OID as input errors, never as conflicts", async () => {
    const split = await fork({ "a.txt": "a\n" }, { "a.txt": "A\n" }, { "b.txt": "b\n" });
    await rejects(mergeTree(split.dir, { ...split, theirs: "no-such-ref" }), "ERR_GIT_MERGE_INPUT", 1);
    await rejects(mergeTree(split.dir, { ...split, theirs: "1234567890123456789012345678901234567890" }), "ERR_GIT_MERGE_INPUT", 1);
    assert.throws(() => classifyMergeTree({ code: 1, stdout: Buffer.alloc(0), stderr: Buffer.from("x - not something we can merge\n") }),
      { code: "ERR_GIT_MERGE_INPUT" });
    await rejects(mergeTree(split.dir, { ...split, ours: "--allow-unrelated-histories" }), "ERR_GIT_MERGE_INPUT");
  });

  it("O-M-4 fails on a tree merge base, unrelated histories, an extra argument and malformed output", async () => {
    const split = await fork({ "a.txt": "a\n" }, { "a.txt": "A\n" }, { "b.txt": "b\n" });
    const tree = await plain(split.dir, ["rev-parse", `${split.base}^{tree}`]);
    await rejects(mergeTree(split.dir, { ...split, base: tree }), "ERR_GIT_MERGE_FAILED", 128);

    await plain(split.dir, ["checkout", "-q", "--orphan", "lonely"]);
    await plain(split.dir, ["rm", "-q", "-r", "-f", "."]);
    apply(split.dir, { "u.txt": "u\n" });
    await plain(split.dir, ["add", "-A"]);
    await plain(split.dir, ["commit", "-q", "-m", "lonely"]);
    const lonely = await plain(split.dir, ["rev-parse", "HEAD"]);
    const unrelated = await git(["merge-tree", "--write-tree", "-z", "--name-only", split.ours, lonely], { cwd: split.dir });
    assert.equal(unrelated.code, 128);
    assert.throws(() => classifyMergeTree(unrelated), { code: "ERR_GIT_MERGE_FAILED", exitCode: 128 });

    const extra = await git(["merge-tree", "--write-tree", "-z", "--name-only", `--merge-base=${split.base}`,
      split.ours, split.theirs, split.base], { cwd: split.dir });
    assert.equal(extra.code, 129);
    assert.throws(() => classifyMergeTree(extra), { code: "ERR_GIT_MERGE_FAILED", exitCode: 129 });

    const oid = "a".repeat(40);
    for (const bad of [
      { code: 0, stdout: Buffer.from("not-an-oid\0"), stderr: Buffer.alloc(0) },
      { code: 0, stdout: Buffer.from(`${oid}\0f\0\0`), stderr: Buffer.alloc(0) },
      { code: 1, stdout: Buffer.from(`${oid}\0f\0\0`), stderr: Buffer.from("warning\n") },
      { code: 1, stdout: Buffer.from(`${oid}\0f\0`), stderr: Buffer.alloc(0) },
    ]) assert.throws(() => classifyMergeTree(bad), { code: "ERR_GIT_MERGE_FAILED" });
  });

  it("O-M-5 parses conflicted paths with a newline and Hangul characters exactly", async () => {
    const odd = "line\nbreak.txt";
    const hangul = "한글/파일 이름.txt";
    const split = await fork({ [odd]: "base\n", [hangul]: "base\n" },
      { [odd]: "ours\n", [hangul]: "ours\n" }, { [odd]: "theirs\n", [hangul]: "theirs\n" });
    const result = await mergeTree(split.dir, split);
    assert.equal(result.kind, "conflict");
    assert.deepEqual([...result.paths].sort(), [odd, hangul].sort());
  });

  it("O-M-6 reads --stdin per-record status with 1 as clean and 0 as conflict", async () => {
    const { dir, base } = await repo({ "a.txt": "a\n", "f.txt": FIVE });
    const left = await commitAt(dir, base, { "f.txt": "left\n2\n3\n4\n5\n" }, "left");
    const right = await commitAt(dir, base, { "f.txt": "right\n2\n3\n4\n5\n" }, "right");
    const other = await commitAt(dir, base, { "b.txt": "b\n" }, "other");
    const pairs = [{ base, ours: left, theirs: other }, { base, ours: left, theirs: right }, { base, ours: right, theirs: other }];
    const batch = await mergeTreeBatch(dir, pairs);
    assert.deepEqual(batch.map(result => result.kind), ["clean", "conflict", "clean"]);
    assert.deepEqual(batch[1].paths, ["f.txt"]);
    const singles = [];
    for (const pair of pairs) singles.push(await mergeTree(dir, pair));
    assert.deepEqual(batch, singles);
    await rejects(mergeTreeBatch(dir, [pairs[0], { base, ours: left, theirs: "no-such-ref" }]), "ERR_GIT_MERGE_INPUT", 1);
  });

  it("O-SE-18 never runs a global merge driver and the shared config driver changes the digest", async () => {
    const split = await fork({ ".gitattributes": "* merge=evil\n", "f.txt": FIVE },
      { "f.txt": "ONE\n2\n3\n4\n5\n" }, { "f.txt": "1\n2\n3\n4\nFIVE\n" });
    const home = createTempDir("hstack-graph-merge-tree-home-");
    const marker = join(home, "driver-ran");
    const driver = `[merge "evil"]\n\tdriver = touch '${marker}'\n`;
    writeFileSync(join(home, ".gitconfig"), driver);
    const env = { HOME: home, XDG_CONFIG_HOME: join(home, ".config") };

    // The engine inherits HOME from the process; only GIT_CONFIG_GLOBAL=/dev/null keeps the driver out.
    const saved = { HOME: process.env.HOME, XDG_CONFIG_HOME: process.env.XDG_CONFIG_HOME };
    Object.assign(process.env, env);
    let engine;
    try { engine = await mergeTree(split.dir, split); } finally {
      for (const [key, value] of Object.entries(saved)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
    assert.equal(engine.kind, "clean");
    assert.equal(existsSync(marker), false, "the engine merge must not run the global driver");
    await plain(split.dir, ["merge-tree", "--write-tree", `--merge-base=${split.base}`, split.ours, split.theirs], env);
    assert.equal(existsSync(marker), true, "control: plain git with that HOME runs the driver");

    const before = await repoConfigDigest(split.dir);
    await plain(split.dir, ["config", "merge.evil.driver", `touch '${marker}'`]);
    assert.notEqual(await repoConfigDigest(split.dir), before);
  });
});
