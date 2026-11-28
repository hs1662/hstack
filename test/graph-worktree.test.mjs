import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";
import { describe, it } from "node:test";
import { promisify } from "node:util";

import {
  acceptedRef, candRef, candidatePath, freeBytes, inboxPath, listWorktrees, lockReason, nodeKey, pinRef, provision,
  release, sealIndexPath, tmpPath, worktreePath,
} from "../scripts/graph/worktree.mjs";
import { createTempDir } from "./fixtures.mjs";

const run = promisify(execFile);
const plain = (cwd, ...args) => run("git", args, { cwd, env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1" } });
const text = async (cwd, ...args) => (await plain(cwd, ...args)).stdout.trim();

// A workspace with one commit and an engine root beside it; both go away with the temp dir.
async function fixture() {
  const dir = createTempDir("hstack-graph-worktree-");
  const workspace = join(dir, "repo");
  mkdirSync(workspace);
  await plain(workspace, "init", "-q", "-b", "main");
  await plain(workspace, "config", "user.name", "Test");
  await plain(workspace, "config", "user.email", "test@invalid");
  writeFileSync(join(workspace, "a.txt"), "a\n");
  writeFileSync(join(workspace, ".gitignore"), ".env\nconf/local.json\n");
  await plain(workspace, "add", "a.txt", ".gitignore");
  await plain(workspace, "commit", "-q", "-m", "base");
  const root = join(dir, "engine");
  return { dir, workspace, root, baseSha: await text(workspace, "rev-parse", "HEAD") };
}

function slot(root, label = "r1") {
  const wtId = randomUUID();
  const key = nodeKey(`node-${label}`);
  return {
    path: worktreePath(root, label, wtId), tmpDir: tmpPath(root, label, wtId),
    sealIndex: sealIndexPath(root, label, wtId), reason: lockReason(label, key, 1, wtId),
  };
}

const entry = async (workspace, path) => (await listWorktrees(workspace)).filter(item => item.path === path);

describe("graph worktree names", () => {
  it("O-W-4: raw node IDs never reach a path or a ref", async () => {
    const { workspace } = await fixture();
    const root = join(createTempDir("hstack-graph-worktree-root-"), "engine");
    const runId = "r1";
    for (const id of ["a/b", "..", "../../etc", "x::shard::y", "line\nbreak"]) {
      const key = nodeKey(id);
      assert.match(key, /^[0-9a-f]{64}$/);
      const wtId = randomUUID();
      const paths = [
        [worktreePath(root, runId, wtId), join(root, "worktrees", runId)],
        [candidatePath(root, runId, "g1.2"), join(root, "worktrees", runId)],
        [tmpPath(root, runId, wtId), join(root, "runs", runId, "tmp")],
        [sealIndexPath(root, runId, wtId), join(root, "runs", runId, "seal")],
        [inboxPath(root, runId, `${key}.e3`), join(root, "runs", runId, "inbox")],
      ];
      for (const [path, parent] of paths) {
        const rel = relative(parent, path);
        assert.ok(rel && !isAbsolute(rel) && !rel.split(sep).includes(".."), `${path} stays under ${parent}`);
        assert.equal(rel.split(sep).length, 1, `${path} is a direct child of ${parent}`);
        assert.ok(!path.includes(id), `${JSON.stringify(id)} absent from ${path}`);
      }
      for (const ref of [pinRef(runId, key, 3), candRef(runId, "g1.2"), acceptedRef(runId)]) {
        assert.ok(!ref.includes(id), `${JSON.stringify(id)} absent from ${ref}`);
        await plain(workspace, "check-ref-format", ref);
      }
    }
  });
});

describe("graph worktree lifecycle", () => {
  it("O-W-6: provision isolates TMPDIR and caches outside the worktree", async () => {
    const { workspace, root, baseSha } = await fixture();
    const s = slot(root);
    const { env, manifest } = await provision({ workspace, path: s.path, baseSha, reason: s.reason, include: [], tmpDir: s.tmpDir });
    assert.deepEqual(manifest, []);
    assert.equal(env.TMPDIR, s.tmpDir);
    for (const key of ["npm_config_cache", "XDG_CACHE_HOME"]) {
      assert.ok(!relative(s.tmpDir, env[key]).startsWith(".."), `${key} inside tmpDir`);
      assert.ok(statSync(env[key]).isDirectory(), `${key} exists`);
    }
    assert.ok(statSync(s.tmpDir).isDirectory());
    assert.equal(statSync(s.tmpDir).mode & 0o777, 0o700);
    assert.ok(relative(s.path, s.tmpDir).startsWith(".."), "tmpDir is outside the worktree");
    writeFileSync(join(env.TMPDIR, "scratch.txt"), "x\n");
    writeFileSync(join(env.XDG_CACHE_HOME, "cache.bin"), "y\n");
    assert.equal(await text(s.path, "status", "--porcelain", "--untracked-files=all", "--ignored"), "");
  });

  it("provision twice gives one locked worktree at baseSha", async () => {
    const { workspace, root, baseSha } = await fixture();
    const s = slot(root);
    const request = { workspace, path: s.path, baseSha, reason: s.reason, include: [], tmpDir: s.tmpDir };
    const first = await provision(request);
    const second = await provision(request);
    assert.deepEqual(second, first);
    const listed = await entry(workspace, s.path);
    assert.equal(listed.length, 1);
    assert.equal(listed[0].locked, s.reason);
    assert.equal(listed[0].head, baseSha);
    assert.equal(listed[0].detached, true);
    assert.equal(await text(s.path, "rev-parse", "HEAD"), baseSha);
    const free = await freeBytes(s.path);
    assert.ok(Number.isSafeInteger(free) && free > 0, "freeBytes reports the filesystem's available bytes");
  });

  it("O-W-2: a listed path with another lock reason or HEAD fails and stays as it was", async () => {
    const { workspace, root, baseSha } = await fixture();
    const s = slot(root);
    await provision({ workspace, path: s.path, baseSha, reason: s.reason, include: [], tmpDir: s.tmpDir });
    const other = `${s.reason}-other`;
    await assert.rejects(provision({ workspace, path: s.path, baseSha, reason: other, include: [], tmpDir: s.tmpDir }),
      error => error.code === "ERR_GIT_FAILED" && error.message.includes("lock reason"));
    writeFileSync(join(workspace, "b.txt"), "b\n");
    await plain(workspace, "add", "b.txt");
    await plain(workspace, "commit", "-q", "-m", "next");
    const next = await text(workspace, "rev-parse", "HEAD");
    await assert.rejects(provision({ workspace, path: s.path, baseSha: next, reason: s.reason, include: [], tmpDir: s.tmpDir }),
      error => error.code === "ERR_GIT_FAILED" && error.message.includes("HEAD"));
    const listed = await entry(workspace, s.path);
    assert.equal(listed.length, 1);
    assert.equal(listed[0].locked, s.reason);
    assert.equal(listed[0].head, baseSha);
  });

  it("O-SE-14: a shared post-checkout hook does not run during provision", async () => {
    const { dir, workspace, root, baseSha } = await fixture();
    const marker = join(dir, "hook-ran");
    writeFileSync(join(workspace, ".git", "hooks", "post-checkout"), `#!/bin/sh\ntouch '${marker}'\n`, { mode: 0o755 });
    const s = slot(root);
    await provision({ workspace, path: s.path, baseSha, reason: s.reason, include: [], tmpDir: s.tmpDir });
    assert.equal(existsSync(marker), false);
    await plain(workspace, "worktree", "add", "-q", "--detach", join(dir, "control"), baseSha);
    assert.equal(existsSync(marker), true, "control: plain git worktree add runs the hook");
  });

  it("O-SE-3: ignored files reach the worktree only through include, with mode and digest", async () => {
    const { workspace, root, baseSha } = await fixture();
    const secret = Buffer.from("TOKEN=local\n");
    writeFileSync(join(workspace, ".env"), secret);
    chmodSync(join(workspace, ".env"), 0o640);
    mkdirSync(join(workspace, "conf"));
    writeFileSync(join(workspace, "conf", "local.json"), "{}\n");
    const bare = slot(root);
    const none = await provision({ workspace, path: bare.path, baseSha, reason: bare.reason, include: [], tmpDir: bare.tmpDir });
    assert.deepEqual(none.manifest, []);
    assert.equal(existsSync(join(bare.path, ".env")), false);

    const s = slot(root);
    const { manifest } = await provision({ workspace, path: s.path, baseSha, reason: s.reason,
      include: [".env", "conf/local.json"], tmpDir: s.tmpDir });
    assert.deepEqual(readFileSync(join(s.path, ".env")), secret);
    assert.equal(statSync(join(s.path, ".env")).mode & 0o777, 0o640);
    const sha = createHash("sha256").update(secret).digest("hex");
    assert.deepEqual(manifest[0], { path: ".env", sha256: sha, mode: 0o640 });
    assert.equal(manifest[1].path, "conf/local.json");
    assert.equal(readFileSync(join(s.path, "conf", "local.json"), "utf8"), "{}\n");

    symlinkSync(join(workspace, ".env"), join(workspace, "link.env"));
    const linked = slot(root);
    await assert.rejects(provision({ workspace, path: linked.path, baseSha, reason: linked.reason,
      include: ["link.env"], tmpDir: linked.tmpDir }), error => error.code === "ERR_GIT_FAILED");
  });

  it("release unlocks, removes, prunes and deletes its files; a second release is a no-op", async () => {
    const { workspace, root, baseSha } = await fixture();
    const s = slot(root);
    await provision({ workspace, path: s.path, baseSha, reason: s.reason, include: [], tmpDir: s.tmpDir });
    writeFileSync(join(s.path, "dirty.txt"), "worker output\n");
    mkdirSync(join(s.sealIndex, ".."), { recursive: true });
    writeFileSync(s.sealIndex, "index");
    await release({ workspace, path: s.path, tmpDir: s.tmpDir, sealIndex: s.sealIndex });
    assert.deepEqual(await entry(workspace, s.path), []);
    for (const path of [s.path, s.tmpDir, s.sealIndex]) assert.equal(existsSync(path), false, path);
    await release({ workspace, path: s.path, tmpDir: s.tmpDir, sealIndex: s.sealIndex });
    assert.deepEqual(await entry(workspace, s.path), []);
    assert.equal(await text(workspace, "worktree", "list", "--porcelain").then(out => out.includes(s.path)), false);
  });

  it("listWorktrees parses porcelain -z records, including a path with a space", async () => {
    const { workspace, root, baseSha } = await fixture();
    const path = join(root, "with space", "wt");
    const reason = "hstack:r1/key/e1/with space";
    await provision({ workspace, path, baseSha, reason, include: [], tmpDir: join(root, "tmp space") });
    const list = await listWorktrees(workspace);
    assert.equal(list.length, 2);
    const main = list.find(item => item.path === workspace);
    assert.deepEqual(main, { path: workspace, head: baseSha, detached: false, branch: "refs/heads/main", locked: null, prunable: null });
    const wt = list.find(item => item.path === path);
    assert.deepEqual(wt, { path, head: baseSha, detached: true, branch: null, locked: reason, prunable: null });
  });
});
