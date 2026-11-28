import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { link, mkdir, mkdtemp, readFile, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { seal } from "../scripts/graph/seal.mjs";

const run = promisify(execFile);
const gitEnv = {
  ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_"))),
  GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null",
};
const git = async (cwd, ...args) => (await run("git", args, {
  cwd, encoding: "buffer", env: gitEnv, timeout: 10_000,
})).stdout;
const text = async (cwd, ...args) => (await git(cwd, ...args)).toString("utf8").trim();
const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");

async function fixture(t, { files = {}, format = "sha1" } = {}) {
  const root = await mkdtemp(join(tmpdir(), "graph-seal-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repo = join(root, "repo");
  const worktree = join(root, "wt");
  await mkdir(repo);
  await git(repo, "init", "-q", "-b", "main", `--object-format=${format}`);
  await git(repo, "config", "user.name", "Test");
  await git(repo, "config", "user.email", "test@invalid");
  for (const [path, bytes] of Object.entries({
    ".gitignore": ".env\n", "src/modify": "before\n", "src/remove": "remove me\n", outside: "outside\n", ...files,
  })) {
    await mkdir(dirname(join(repo, path)), { recursive: true });
    await writeFile(join(repo, path), bytes);
  }
  await git(repo, "add", ".");
  await git(repo, "commit", "-qm", "base");
  const baseSha = await text(repo, "rev-parse", "HEAD");
  await git(repo, "worktree", "add", "-q", "--detach", worktree);
  return { root, repo, worktree, baseSha, writeScope: ["src"], policy: {},
    indexPath: join(root, "seal.index"), claimSec: 1_700_000_000, message: "seal fixture" };
}

function violates(...paths) {
  return error => {
    assert.equal(error.code, "ERR_SCOPE_VIOLATION");
    assert.deepEqual([...new Set(error.violations.map(({ path, reason }) => {
      assert.equal(typeof reason, "string");
      assert.notEqual(reason, "");
      return path;
    }))].sort(), paths.sort());
    return true;
  };
}

for (const format of ["sha1", "sha256"]) {
  test(`seals add, modify and delete as a reproducible ${format} commit and digests the raw diff`, async t => {
    const spec = await fixture(t, { format });
    const { worktree, baseSha } = spec;
    await writeFile(join(worktree, "src/add"), "add\n", { mode: 0o755 });
    await writeFile(join(worktree, "src/modify"), "after\n");
    await rm(join(worktree, "src/remove"));

    const { commit, tree, changes, scopeDiffDigest } = await seal(spec);
    assert.equal((await seal(spec)).commit, commit);
    const header = (await text(worktree, "cat-file", "commit", commit)).split("\n\n")[0].split("\n");
    assert.deepEqual(header, [
      `tree ${tree}`, `parent ${baseSha}`, "author hstack-graph <hstack-graph@invalid> 1700000000 +0000",
      "committer hstack-graph <hstack-graph@invalid> 1700000000 +0000",
    ]);
    assert.deepEqual(changes, [
      { status: "A", path: "src/add", oldMode: "000000", newMode: "100755" },
      { status: "M", path: "src/modify", oldMode: "100644", newMode: "100644" },
      { status: "D", path: "src/remove", oldMode: "100644", newMode: "000000" },
    ]);
    assert.equal(await text(worktree, "cat-file", "blob", `${commit}:src/add`), "add");
    assert.equal(await text(worktree, "cat-file", "blob", `${commit}:src/modify`), "after");
    assert.equal(scopeDiffDigest, sha256(await git(worktree, "diff-tree", "-r", "-z", "--raw", "--no-renames", baseSha, commit)));
  });
}

for (const [from, to, outside] of [["outside", "src/renamed", "outside"], ["src/remove", "renamed", "renamed"]]) {
  test(`rejects rename ${from} -> ${to} at the out-of-scope end`, async t => {
    const spec = await fixture(t);
    await rename(join(spec.worktree, from), join(spec.worktree, to));
    await assert.rejects(seal(spec), violates(outside));
  });
}

test("reports visible untracked scope violations before adopted blob limits", async t => {
  const spec = await fixture(t);
  await writeFile(join(spec.worktree, "outside-new"), "untracked\n");
  await writeFile(join(spec.worktree, "src/too-big"), "over limit\n");
  await assert.rejects(seal({ ...spec, policy: { maxBlobBytes: 1 } }), violates("outside-new"));
});

test("does not adopt changed ignored files even with whole-repo scope", async t => {
  const spec = await fixture(t);
  const file = join(spec.worktree, ".env");
  assert.equal(existsSync(file), false);
  await writeFile(file, "copied\n");
  await writeFile(file, "worker modification\n");

  const { changes } = await seal({ ...spec, writeScope: ["."] });
  assert.deepEqual(changes, []);
});

for (const [label, mutate] of [
  ["modified", file => writeFile(file, "replaced\n")], ["deleted", file => rm(file)],
]) {
  test(`rejects a ${label} protected ignored file`, async t => {
    const spec = await fixture(t);
    const file = join(spec.worktree, ".env");
    const original = "protected\n";
    await writeFile(file, original, { mode: 0o600 });
    await mutate(file);

    await assert.rejects(seal({ ...spec, protectedFiles: [{ path: ".env", sha256: sha256(original), mode: 0o600 }] }),
      violates(".env"));
  });
}

for (const [target, allowSymlinks] of [
  ["/outside-fixture", false], ["../../outside-fixture", false], ["../outside", false],
  ["/outside-fixture", true], ["../../outside-fixture", true], ["../.GiT/HEAD", true],
]) {
  test(`rejects link to ${target} with allowSymlinks=${allowSymlinks}`, async t => {
    const spec = await fixture(t);
    await symlink(target, join(spec.worktree, "src/link"));
    await assert.rejects(seal({ ...spec, policy: { allowSymlinks } }), violates("src/link"));
  });
}

test("adopts an allowed relative symlink as its link text, not target bytes", async t => {
  const spec = await fixture(t);
  await symlink("./modify", join(spec.worktree, "src/link"));

  const { commit, changes } = await seal({ ...spec, policy: { allowSymlinks: true } });
  assert.deepEqual(changes, [{ status: "A", path: "src/link", oldMode: "000000", newMode: "120000" }]);
  assert.deepEqual(await git(spec.worktree, "cat-file", "blob", `${commit}:src/link`), Buffer.from("./modify"));
});

test("rejects a hardlinked file inside write scope", async t => {
  const spec = await fixture(t);
  const external = join(spec.root, "external");
  await writeFile(external, "linked bytes\n");
  await link(external, join(spec.worktree, "src/link"));
  await assert.rejects(seal(spec), violates("src/link"));
});

test("rejects an untracked nested repository", async t => {
  const spec = await fixture(t);
  const nested = join(spec.worktree, "src/nested");
  await mkdir(nested);
  await git(nested, "init", "-q", "-b", "main");
  await assert.rejects(seal(spec), violates("src/nested"));
});

test("rejects a path with a case-insensitive .git component", async t => {
  const spec = await fixture(t);
  await mkdir(join(spec.worktree, "src/.GiT"));
  await writeFile(join(spec.worktree, "src/.GiT/config"), "metadata\n");
  await assert.rejects(seal(spec), violates("src/.GiT"));
});

test("ignores staged gitlinks and staged-only blobs in the worker index", async t => {
  const spec = await fixture(t);
  const { worktree, baseSha } = spec;
  await git(worktree, "update-index", "--add", "--cacheinfo", `160000,${baseSha},staged-link`);
  await writeFile(join(worktree, "staged-blob"), "staged only\n");
  await git(worktree, "add", "staged-blob");
  await rm(join(worktree, "staged-blob"));

  const { changes } = await seal(spec);
  assert.deepEqual(changes, []);
});

for (const flag of ["assume-unchanged", "skip-worktree"]) {
  test(`detects an out-of-scope modification hidden with ${flag}`, async t => {
    const spec = await fixture(t);
    await git(spec.worktree, "update-index", `--${flag}`, "outside");
    await writeFile(join(spec.worktree, "outside"), "changed\n");
    await assert.rejects(seal(spec), violates("outside"));
  });
}

test("does not run shared clean filter or fsmonitor commands during sealing", async t => {
  const spec = await fixture(t, { files: { ".gitattributes": "* filter=x\n" } });
  const { root, repo, worktree } = spec;
  const filterMarker = join(root, "filter-ran");
  const monitorMarker = join(root, "monitor-ran");
  const monitor = join(root, "monitor");
  await writeFile(monitor, `#!/bin/sh\ntouch '${monitorMarker}'\n`, { mode: 0o755 });
  await git(repo, "config", "filter.x.clean", `touch '${filterMarker}'; tr a-z A-Z`);
  await git(repo, "config", "core.fsmonitor", monitor);
  const bytes = Buffer.from("mixed Case\n");
  await writeFile(join(worktree, "src/add"), bytes);

  const { commit } = await seal(spec);
  assert.equal(existsSync(filterMarker), false);
  assert.equal(existsSync(monitorMarker), false);
  assert.deepEqual(await git(worktree, "cat-file", "blob", `${commit}:src/add`), bytes);
});

test("adopts CRLF byte-for-byte despite text=auto", async t => {
  const spec = await fixture(t, { files: { ".gitattributes": "* text=auto\n" } });
  const bytes = Buffer.from("first\r\nsecond\r\n");
  await writeFile(join(spec.worktree, "src/modify"), bytes);

  const { commit } = await seal(spec);
  assert.deepEqual(await git(spec.worktree, "cat-file", "blob", `${commit}:src/modify`), bytes);
});

async function indexState(path) {
  const { ino, size, mtimeNs } = await stat(path, { bigint: true });
  return { ino, size, mtimeNs, bytes: await readFile(path) };
}

test("preserves worker index inode, size, mtime and bytes", async t => {
  const spec = await fixture(t);
  const { worktree } = spec;
  const index = resolve(worktree, await text(worktree, "rev-parse", "--git-path", "index"));
  await git(worktree, "update-index", "--assume-unchanged", "src/modify");
  const before = await indexState(index);
  await writeFile(join(worktree, "src/modify"), "after\n");

  await seal(spec);
  assert.deepEqual(await indexState(index), before);
});

for (const [label, policy, contents] of [
  ["changed path count", { maxChangedPaths: 1 }, ["a", "b"]],
  ["adopted blob bytes", { maxBlobBytes: 1 }, ["ab"]],
]) {
  test(`enforces the limit on ${label}`, async t => {
    const spec = await fixture(t);
    for (const [i, bytes] of contents.entries()) await writeFile(join(spec.worktree, `src/new${i}`), bytes);
    await assert.rejects(seal({ ...spec, policy }), { code: "ERR_SEAL_LIMIT" });
  });
}

test("rejects an untracked FIFO that Git does not enumerate", async t => {
  const spec = await fixture(t);
  await run("mkfifo", [join(spec.worktree, "src/pipe")]);
  await assert.rejects(seal(spec), violates("src/pipe"));
});

test("rejects two final-tree paths that differ only by case", async t => {
  const spec = await fixture(t);
  await writeFile(join(spec.worktree, "src/Modify"), "collision\n");
  await assert.rejects(seal(spec), violates("src/Modify", "src/modify"));
});

test("rejects a newline in a file name", async t => {
  const spec = await fixture(t);
  const path = "src/line\nbreak";
  await writeFile(join(spec.worktree, path), "new\n");
  await assert.rejects(seal(spec), violates(path));
});
