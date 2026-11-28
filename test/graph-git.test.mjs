import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { promisify } from "node:util";

import { commitTree, git, gitOk, isAncestor, repoConfigDigest, revParse, splitZ } from "../scripts/graph/git.mjs";
import { createTempDir } from "./fixtures.mjs";

const run = promisify(execFile);
const plain = (cwd, ...args) => run("git", args, { cwd, env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1" } });

async function repo() {
  const dir = createTempDir("hstack-graph-git-");
  await plain(dir, "init", "-q", "-b", "main");
  await plain(dir, "config", "user.name", "Test");
  await plain(dir, "config", "user.email", "test@invalid");
  writeFileSync(join(dir, "a.txt"), "a\n");
  await plain(dir, "add", "a.txt");
  await plain(dir, "commit", "-q", "-m", "base");
  return dir;
}
const out = async (args, options) => (await gitOk(args, options)).toString("utf8").trim();

describe("graph git wrapper", () => {
  it("applies the fixed engine configuration to every call", async () => {
    const dir = await repo();
    for (const [key, value] of [["core.hooksPath", "/dev/null"], ["core.fsmonitor", "false"], ["core.quotePath", "false"],
      ["core.fsync", "committed"], ["gc.auto", "0"], ["maintenance.auto", "false"]]) {
      assert.equal(await out(["config", "--get", key], { cwd: dir }), value, key);
    }
  });

  it("never runs repository hooks that a plain git call would run", async () => {
    const dir = await repo();
    const marker = join(dir, "hook-ran");
    writeFileSync(join(dir, ".git", "hooks", "post-commit"), `#!/bin/sh\ntouch '${marker}'\n`, { mode: 0o755 });
    await gitOk(["commit", "-q", "--allow-empty", "-m", "engine"], { cwd: dir });
    assert.equal(existsSync(marker), false);
    await plain(dir, "commit", "-q", "--allow-empty", "-m", "plain");
    assert.equal(existsSync(marker), true, "control: the hook is live for plain git");
  });

  it("drops the user's global config on engine paths and keeps it on user paths", async () => {
    const dir = await repo();
    const home = createTempDir("hstack-graph-git-home-");
    writeFileSync(join(home, ".gitconfig"), "[hstack]\n\tprobe = from-global\n");
    const env = { HOME: home, XDG_CONFIG_HOME: join(home, ".config") };
    assert.equal((await git(["config", "--get", "hstack.probe"], { cwd: dir, env })).code, 1);
    assert.equal(await out(["config", "--get", "hstack.probe"], { cwd: dir, env, scope: "user" }), "from-global");
  });

  it("ignores inherited repository selection and config injection variables", async () => {
    const dir = await repo();
    const other = await repo();
    const saved = { GIT_DIR: process.env.GIT_DIR, GIT_CONFIG_PARAMETERS: process.env.GIT_CONFIG_PARAMETERS };
    process.env.GIT_DIR = join(other, ".git");
    process.env.GIT_CONFIG_PARAMETERS = "'core.hookspath'='/tmp/evil'";
    try {
      assert.equal(await out(["rev-parse", "--absolute-git-dir"], { cwd: dir }), join(dir, ".git"));
      assert.equal(await out(["config", "--get", "core.hooksPath"], { cwd: dir }), "/dev/null");
    } finally {
      for (const [key, value] of Object.entries(saved)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
  });

  it("reports exit statuses as values and failures to run as ERR_GIT_FAILED", async () => {
    const dir = await repo();
    const head = await revParse(dir, "HEAD");
    assert.match(head, /^[0-9a-f]{40}$/);
    assert.equal(await revParse(dir, "refs/heads/missing"), null);
    assert.equal(await isAncestor(dir, head, head), true);
    await plain(dir, "checkout", "-q", "--orphan", "other");
    await plain(dir, "commit", "-q", "--allow-empty", "-m", "unrelated");
    assert.equal(await isAncestor(dir, "HEAD", head), false);
    await assert.rejects(isAncestor(dir, "no-such-ref", head), { code: "ERR_GIT_FAILED" });
    await assert.rejects(gitOk(["rev-parse", "--verify", "no-such-ref"], { cwd: dir }), { code: "ERR_GIT_FAILED", exitCode: 128 });
    await assert.rejects(git(["-c", "alias.wait=!sleep 5", "wait"], { cwd: dir, timeoutMs: 200 }), { code: "ERR_GIT_FAILED" });
  });

  it("builds commits whose identity depends only on tree, parents, date and message", async () => {
    const dir = await repo();
    const head = await revParse(dir, "HEAD");
    const tree = await out(["rev-parse", "HEAD^{tree}"], { cwd: dir });
    const spec = { tree, parents: [head], dateSec: 1_700_000_000, message: "hstack seal r/k/e1" };
    const first = await commitTree(dir, spec);
    assert.equal(await commitTree(dir, spec), first);
    assert.notEqual(await commitTree(dir, { ...spec, dateSec: 1_700_000_001 }), first);
    const raw = await out(["cat-file", "commit", first], { cwd: dir });
    assert.match(raw, /^author hstack-graph <hstack-graph@invalid> 1700000000 \+0000$/m);
    assert.match(raw, /^committer hstack-graph <hstack-graph@invalid> 1700000000 \+0000$/m);
  });

  it("digests shared config, info files and hooks identically from every worktree", async () => {
    const dir = await repo();
    const linked = join(createTempDir("hstack-graph-git-wt-"), "wt");
    await plain(dir, "worktree", "add", "-q", "--detach", linked);
    const base = await repoConfigDigest(dir);
    assert.equal(await repoConfigDigest(linked), base);
    const changes = [
      () => plain(dir, "config", "filter.x.clean", "cat"),
      () => { mkdirSync(join(dir, ".git", "info"), { recursive: true }); writeFileSync(join(dir, ".git", "info", "attributes"), "* text\n"); },
      () => writeFileSync(join(dir, ".git", "info", "exclude"), "secret\n"),
      () => writeFileSync(join(dir, ".git", "hooks", "post-checkout"), "#!/bin/sh\n", { mode: 0o755 }),
    ];
    const seen = new Set([base]);
    for (const change of changes) {
      await change();
      const next = await repoConfigDigest(linked);
      assert.equal(seen.has(next), false, "every shared config change moves the digest");
      seen.add(next);
    }
    await plain(dir, "worktree", "remove", "--force", linked);
  });

  it("splits NUL-terminated output without a trailing empty item", () => {
    assert.deepEqual(splitZ(Buffer.from("a\0b c\0한글\nx\0")), ["a", "b c", "한글\nx"]);
    assert.throws(() => splitZ(Buffer.from([0xff, 0])), { code: "ERR_GIT_FAILED" });
  });
});
