import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

const DOC = new URL("../skills/hstack-graph/references/long-worker.md", import.meta.url);

function sampleScript() {
  const m = readFileSync(DOC, "utf8").match(/```sh\n# hstack-long-worker-sample\n([\s\S]*?)```/);
  assert.ok(m, "doc must contain the tagged sh sample block");
  return m[1];
}

function fixture(t, files) {
  const dir = mkdtempSync(join(tmpdir(), "long-worker-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  writeFileSync(join(dir, "sample.sh"), sampleScript());
  return dir;
}

function run(dir, args, env) {
  // The outer node:test runner sets NODE_TEST_CONTEXT, which makes a nested `node --test` skip running files.
  const { NODE_TEST_CONTEXT, ...base } = process.env;
  return spawnSync("bash", [join(dir, "sample.sh"), ...args], {
    cwd: dir,
    encoding: "utf8",
    env: { ...base, TEST_GLOB: "*.test.mjs", OUT_DIR: join(dir, "out"), ...env },
    timeout: 30_000,
  });
}

const picked = (r) => r.stdout.split("\n").filter((l) => l.startsWith("SAMPLE "));
const PASS = 'import { it } from "node:test"; it("ok", () => {});\n';
const HANG = 'import { it } from "node:test"; it("hang", () => { for (;;) {} });\n';

describe("long-worker doc sample wrapper", () => {
  it("--fast picks the same deterministic subset; default mode runs every file", (t) => {
    const dir = fixture(t, Object.fromEntries(["a", "b", "c", "d", "e"].map((n) => [`${n}.test.mjs`, PASS])));
    const env = { FAST_N: "2", CHECK_TIMEOUT: "20" };
    const first = run(dir, ["--fast"], env);
    const second = run(dir, ["--fast"], env);
    const full = run(dir, [], env);
    assert.equal(first.status, 0, first.stderr + first.stdout);
    assert.equal(full.status, 0, full.stderr + full.stdout);
    assert.equal(picked(first).length, 2);
    assert.deepEqual(picked(first), picked(second));
    assert.equal(picked(full).length, 5);
    assert.equal(existsSync(join(dir, "out", "ERROR.index")), false);
  });

  it("kills a hung suite at the hard timeout and records one ERROR index line", (t) => {
    const dir = fixture(t, { "hang.test.mjs": HANG });
    const started = Date.now();
    const r = run(dir, ["--fast"], { FAST_N: "5", CHECK_TIMEOUT: "2" });
    assert.ok(Date.now() - started < 20_000, "timeout must bound the run");
    assert.equal(r.status, 124, r.stderr + r.stdout);
    const index = readFileSync(join(dir, "out", "ERROR.index"), "utf8").trim().split("\n");
    assert.equal(index.length, 1);
    assert.match(index[0], /^ERROR exit=124 code=E_CHECK_TIMEOUT log=\S+\.log$/);
    assert.ok(existsSync(index[0].split("log=")[1]), "full log kept");
  });
});
