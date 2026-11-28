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

  it("documents --gate-log for ungated nodes, optional inject-repair --patch, and gateKey in cli.md", async (t) => {
    const cliDoc = readFileSync(join(SKILL_DIR, "references", "cli.md"), "utf8");
    const exampleBlock = cliDoc.match(/```sh\ngraph start[\s\S]*?```/)?.[0] ?? "";
    assert.match(exampleBlock, /--gate-log\b/, "cli.md settle example must illustrate --gate-log for nodes without gateArgv");
    assert.match(cliDoc, /held_blocked/, "cli.md must warn that omitting --gate-log without gateArgv settles as held_blocked");
    assert.match(cliDoc, /inject-repair[^\n]*\[--patch FILE\]/, "cli.md must mark inject-repair --patch as optional");
    assert.match(cliDoc, /gateKey/, "cli.md gate log guidance must mention gateKey");

    // Behavior check: a node without gateArgv blocks without --gate-log and accepts with a measured --gate-log.
    const repo = mkdtempSync(join(tmpdir(), "hstack-skill-cli-doc-"));
    t.after(() => rmSync(repo, { recursive: true, force: true }));
    execFileSync("git", ["init", "-q", repo]);
    writeFileSync(join(repo, "notes.txt"), "alpha\nbeta\n");
    writeFileSync(join(repo, "spec.json"), JSON.stringify({
      schemaVersion: 1,
      nodes: [
        { id: "ungated-a", kind: "read", prompt: "read", readScope: ["notes.txt"], estimatedMinutes: 5 },
        { id: "ungated-b", kind: "read", prompt: "read", readScope: ["notes.txt"], estimatedMinutes: 5 },
      ],
    }));
    const blocks = namedBlocks(readFileSync(EXAMPLE, "utf8"));
    const receipt = JSON.parse(blocks.get("receipt.json"));
    writeFileSync(join(repo, "worker.json"), JSON.stringify(receipt));
    const cli = join(PLUGIN_ROOT, "scripts", "graph", "cli.mjs");
    const env = cleanEnv("antigravity");
    const call = (args) => JSON.parse(execFileSync(process.execPath, [cli, ...args], { cwd: repo, env, encoding: "utf8" }));
    call(["init"]);
    call(["compile", "--run", "doc-check", "--spec", "spec.json", "--op-id", "c1"]);

    const claimA = call(["claim", "--run", "doc-check", "--node", "ungated-a", "--expected-rev", "1", "--op-id", "ca"]);
    call(["start", "--token", claimA.result.instructionPath, "--host-handle", "h-a", "--op-id", "sa"]);
    const blocked = call(["settle", "--token", claimA.result.instructionPath, "--outcome", "accepted", "--receipt", "worker.json", "--op-id", "ta"]);
    assert.equal(blocked.result.status, "held_blocked");

    const { measureGate } = await import("../scripts/graph/verify-gate.mjs");
    const gateLog = await measureGate({ argv: ["test", "-s", "notes.txt"], cwd: repo, subjectDigest: receipt.provenance.factDigest });
    writeFileSync(join(repo, "host-gate.json"), JSON.stringify(gateLog));
    const claimB = call(["claim", "--run", "doc-check", "--node", "ungated-b", "--expected-rev", "1", "--op-id", "cb"]);
    call(["start", "--token", claimB.result.instructionPath, "--host-handle", "h-b", "--op-id", "sb"]);
    const accepted = call(["settle", "--token", claimB.result.instructionPath, "--outcome", "accepted",
      "--receipt", "worker.json", "--gate-log", "host-gate.json", "--op-id", "tb"]);
    assert.equal(accepted.result.status, "accepted");
  });
});
