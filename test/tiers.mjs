// Test tiers (SSOT 4.9, D25) as plain file lists, so one manifest works on Node 18.20.8 and Node 22 without
// name filters or version-specific isolation flags. `node --test test/*.test.mjs` stays the full suite.
//
//   node test/tiers.mjs fast    unit, schema, admission, patch, reducer, small real-engine files
//   node test/tiers.mjs full    every test file, HSTACK_TEST_MASS_SHARDS=8
//   node test/tiers.mjs fault   kill injection, concurrent OS processes, lock recovery, 64-shard engine
//
// test/tiers.test.mjs fails when a fast file uses a FAST_FORBIDDEN marker.
import { spawn, spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const TEST_DIR = dirname(fileURLToPath(import.meta.url));

// Wall-clock timing, synchronous child processes, and kill injection stay out of fast.
export const FAST_FORBIDDEN = ["spawnSync", "SIGKILL", "withCpuLock", "timeUnderCpuLock", "runHookSubprocess"];

export const FAST = [
  "canary-hook.test.mjs",
  "claude-transcript.test.mjs",
  "governance-autonomy.test.mjs",
  "governance-gate.test.mjs",
  "governance-handoff.test.mjs",
  "governance-hardening-p0.test.mjs",
  "governance-hardening-p6.test.mjs",
  "governance-hardening-p7.test.mjs",
  "graph-admission.test.mjs",
  "graph-host.test.mjs",
  "graph-mass.test.mjs",
  "graph-metrics.test.mjs",
  "graph-patch.test.mjs",
  "graph-reducer.test.mjs",
  "graph-run-roots.test.mjs",
  "graph-runtime-records.test.mjs",
  "graph-skill.test.mjs",
  "host-mcp-session.test.mjs",
  "tiers.test.mjs",
  "ui-extractor.test.mjs",
];

export const FAULT = [
  "graph-gate-lock.test.mjs",
  "graph-lock.test.mjs",
  "graph-mass.test.mjs",
  "graph-state.test.mjs",
  "graph-wal.test.mjs",
];

export function allTestFiles() {
  return readdirSync(TEST_DIR).filter((name) => name.endsWith(".test.mjs")).sort();
}

export function forbiddenMarkers(source) {
  return FAST_FORBIDDEN.filter((marker) => source.includes(marker));
}

export const TIERS = {
  fast: { files: () => FAST, env: { HSTACK_TEST_MASS_SHARDS: "8" }, testTimeoutMs: 30_000, wallMs: 60_000 },
  full: { files: allTestFiles, env: { HSTACK_TEST_MASS_SHARDS: "8" }, testTimeoutMs: 300_000, wallMs: 900_000 },
  fault: { files: () => FAULT, env: { HSTACK_TEST_MASS_SHARDS: "64" }, testTimeoutMs: 1_200_000, wallMs: 1_800_000 },
};

// Node 18 has no --test-timeout; the wall-clock kill below still bounds the tier there.
function supportsTestTimeout() {
  const probe = spawnSync(process.execPath, ["--test-timeout=1", "-e", ""], { stdio: "ignore" });
  return probe.status === 0;
}

function runTier(name) {
  const tier = TIERS[name];
  if (!tier) {
    console.error(`usage: node ${relative(process.cwd(), fileURLToPath(import.meta.url))} <${Object.keys(TIERS).join("|")}>`);
    process.exit(2);
  }
  const files = tier.files().map((file) => join(TEST_DIR, file));
  const args = ["--test", ...(supportsTestTimeout() ? [`--test-timeout=${tier.testTimeoutMs}`] : []), ...files];
  // Match the repository gate `env -u PLUGIN_DATA -u PLUGIN_ROOT node --test`; a parent runner's context
  // would make the nested `node --test` skip its files.
  const { PLUGIN_DATA, PLUGIN_ROOT, NODE_TEST_CONTEXT, ...base } = process.env;
  const started = Date.now();
  const child = spawn(process.execPath, args, { stdio: "inherit", env: { ...base, ...tier.env }, detached: true });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    process.kill(-child.pid, "SIGKILL");
  }, tier.wallMs);
  child.on("exit", (code, signal) => {
    clearTimeout(timer);
    const seconds = ((Date.now() - started) / 1000).toFixed(1);
    const exit = timedOut ? 124 : code ?? 1;
    console.error(`tier=${name} files=${files.length} node=${process.version} seconds=${seconds} exit=${exit}${signal ? ` signal=${signal}` : ""}`);
    process.exit(exit);
  });
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) runTier(process.argv[2]);
