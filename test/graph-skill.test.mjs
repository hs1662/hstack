// Runs the hstack-graph skill's documented example through the real CLI, so the doc cannot drift from the engine.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { factDigest } from "../scripts/graph/reducer.mjs";

const PLUGIN_ROOT = fileURLToPath(new URL("..", import.meta.url));
const SKILL_DIR = join(PLUGIN_ROOT, "skills", "hstack-graph");
const EXAMPLE = join(SKILL_DIR, "references", "example.md");

// Fenced blocks whose info string names a file: ```json spec.json, ```sh run.sh.
function namedBlocks(markdown) {
  const blocks = new Map();
  for (const match of markdown.matchAll(/^```(\w+) ([\w.-]+)\n([\s\S]*?)^```$/gm)) blocks.set(match[2], match[3]);
  return blocks;
}

const cleanEnv = (host) => {
  const env = { ...process.env, HSTACK_HOST: host, PLUGIN_ROOT, CLAUDE_PLUGIN_ROOT: PLUGIN_ROOT };
  for (const key of ["PLUGIN_DATA", "CLAUDE_PLUGIN_DATA", "HSTACK_DATA_DIR"]) delete env[key];
  return env;
};

function runExample(t, host) {
  const blocks = namedBlocks(readFileSync(EXAMPLE, "utf8"));
  const repo = mkdtempSync(join(tmpdir(), "hstack-skill-example-"));
  t.after(() => rmSync(repo, { recursive: true, force: true }));
  execFileSync("git", ["init", "-q", repo]);
  for (const name of ["notes.txt", "spec.json", "receipt.json", "run.sh"]) {
    assert.ok(blocks.has(name), `example.md is missing the ${name} block`);
    writeFileSync(join(repo, name), blocks.get(name));
  }
  const stdout = execFileSync("sh", ["run.sh"], { cwd: repo, env: cleanEnv(host), encoding: "utf8" });
  const lines = stdout.trim().split("\n").map((line) => JSON.parse(line));
  for (const line of lines) assert.equal(line.ok, true, JSON.stringify(line));
  return { blocks, byCommand: new Map(lines.map((line) => [line.command, line.result])) };
}

describe("hstack-graph skill example", () => {
  for (const [host, tool] of [["antigravity", "invoke_subagent"], ["claude-code", "Agent"]]) {
    it(`completes one read node end to end on ${host}`, (t) => {
      const { byCommand } = runExample(t, host);
      assert.equal(byCommand.get("host-caps").dispatchHint, tool);
      assert.equal(byCommand.get("compile").recommendation, "single_session");
      assert.equal(typeof byCommand.get("claim").instructionPath, "string");
      const status = byCommand.get("status");
      assert.equal(status.status, "completed");
      assert.equal(status.nodes.survey.status, "accepted");
    });
  }

  it("ships a receipt whose factDigest matches the engine", () => {
    const receipt = JSON.parse(namedBlocks(readFileSync(EXAMPLE, "utf8")).get("receipt.json"));
    assert.equal(receipt.provenance.factDigest, factDigest(receipt.provenance));
  });

  it("links only to reference files that exist", () => {
    const skill = readFileSync(join(SKILL_DIR, "SKILL.md"), "utf8");
    assert.match(skill, /^---\nname: hstack-graph\ndescription: \S/);
    const files = [join(SKILL_DIR, "SKILL.md"), ...["cli", "example", "mass", "recovery", "live-host"]
      .map((name) => join(SKILL_DIR, "references", `${name}.md`))];
    for (const file of files) {
      for (const [, target] of readFileSync(file, "utf8").matchAll(/\]\(([^)#\s]+\.md)\)/g)) {
        assert.ok(existsSync(join(dirname(file), target)), `${file} links to missing ${target}`);
      }
    }
  });
});
