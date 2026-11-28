#!/usr/bin/env node
// allow: SIZE_OK - CLI command and input parsing share one JSON protocol boundary.
// Graph command line: parses flags, resolves root/workspace, and prints exactly one JSON line per call.
// The engine (state-machine.mjs dispatch) owns every state decision; this file only validates the boundary.
//
// Positive read-node flow, public CLI only (no CAS writes by hand):
//   cli.mjs init    [--root R] [--workspace W]                         # fs-guard initializeRoot
//   cli.mjs compile --run RUN --spec spec.json --op-id c1
//   cli.mjs ready   --run RUN [--cursor C]                             # read-only
//   cli.mjs claim   --run RUN --node N --expected-rev REV --op-id k1  # result.instructionPath is the token
//   cli.mjs start   --token T --host-handle H --op-id s0
//   cli.mjs settle  --token T --outcome accepted --receipt worker.json --op-id s1  # engine runs the policy gate
//   cli.mjs status  --run RUN
//   cli.mjs metrics --run RUN                                          # read-only, metrics.mjs over the journal
//
// v2 write integration:
//   cli.mjs integrate --run RUN --op-id i1                             # publish the next sealed write
//   cli.mjs release --token T --op-id r1                               # release an eligible worktree
//   cli.mjs land --run RUN --op-id l1 [--mode ff-only|branch|merge|patch] [--branch NAME] [--out FILE] [--allow partial,dirty-nonoverlap]
//   cli.mjs gc --scope git --run RUN                                   # collect obsolete Git refs
// Patches (amend | expand | inject-repair) need --run --node --expected-rev --op-id, plus --patch for amend/expand.
// A gate-only amend of an accepted node makes the next claim a revalidation of the pinned artifact; claim, start
// and settle it like any attempt; the engine measures the gate again against that artifact's factDigest.
//
// Gate evidence. The trusted gate command is node.gateArgv (+ timeoutMs) fixed in the compiled graph spec; a
// worker receipt can never name, replace or vouch for it. On an accepting settle of a policy-gated node the engine
// runs verify-gate.mjs measureGate with that argv and subjectDigest = receipt provenance.factDigest, stores the
// record in CAS and hands the reducer that host-chosen gateLogUri; a WAL replay of the same opId returns the
// committed response without measuring again. A failing or timed-out gate is recorded as measured and never
// accepts. --gate-log (settle only) is trusted transport for a node with no gateArgv whose gate the host ran
// elsewhere; the engine refuses it on a policy-gated node (ERR_GATE_POLICY).
// `gate --run --node --receipt --out FILE` runs the same policy measurement without settling (diagnostics,
// flaky-gate checks) and records { runId, nodeId, graphRev, epoch, argv, envDigest, exit, exitCode, signal,
// timedOut, durationMs, stdoutDigest, stderrDigest, subjectDigest, factDigest, checkedSpans }; it never writes
// engine state and never overwrites FILE.
// --telemetry FILE and --probe FILE (claim/start/settle) carry host-observed records to dispatch as
// options.telemetry / options.probe, separate from the worker receipt, and are validated exactly here:
//   telemetry = { usage?: { inputTokens?, outputTokens?: safe int >= 0, costUsd?: finite >= 0 },
//                 canaryEvent?: "load_failure" | "suspect" | "recovered",
//                 budgetContext?: { verified?: boolean, W_eff?, reservedTokens?: safe int >= 0,
//                                   actualUsage?: { inputTokens?, outputTokens?: safe int >= 0 },
//                                   contentTokens?: { [sha256 hex]: safe int >= 0 } } }
//   probe     = { sessionId: non-empty string, probePassed: boolean, schemaError: boolean }
// Any other key fails ERR_CLI_HOST_DATA, so receipt-shaped fields cannot ride along as host measurements.
// `revalidate --run --node --expected-rev --op-id` asks the engine for a NodeRevalidated reuse check; the
// local execution key is computed by the engine under its lock and is never a CLI input.
// Every repo module is imported lazily inside runCli, so even a failing import still yields the JSON envelope.
import { existsSync, lstatSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const EXIT_CODES = Object.freeze({ ok: 0, engine: 1, stale: 49, usage: 64, input: 65, unavailable: 69, internal: 70 });

export const COMMANDS = Object.freeze([
  "init", "compile", "ready", "claim", "start", "settle", "status", "resume", "retry", "amend", "expand",
  "inject-repair", "reduce", "revalidate", "gc", "host-caps", "metrics", "gate", "integrate", "release", "land",
]);
const COMMAND_SET = new Set(COMMANDS);

// flag -> [option key, value kind]. A Map, so "--__proto__" or "--constructor" can never match an inherited key.
const FLAGS = new Map([
  ["scope", ["scope", "string"]], ["mode", ["mode", "string"]],
  ["branch", ["branch", "string"]], ["allow", ["allow", "list"]],
  ["root", ["root", "path"]], ["workspace", ["workspace", "path"]], ["run", ["run", "string"]],
  ["spec", ["spec", "json"]], ["patch", ["patch", "json"]], ["receipt", ["receipt", "json"]],
  ["node", ["node", "string"]], ["expected-rev", ["expectedRev", "int"]], ["op-id", ["opId", "string"]],
  ["outcome", ["outcome", "string"]], ["token", ["token", "string"]], ["host-handle", ["hostHandle", "string"]],
  ["as-of", ["asOf", "string"]], ["cursor", ["cursor", "string"]], ["gate-log", ["gateLog", "json"]],
  ["telemetry", ["telemetry", "json"]], ["probe", ["probe", "json"]], ["out", ["out", "path"]],
]);
export const FLAG_NAMES = Object.freeze([...FLAGS.keys()]);
// Flags restricted to some commands; everything else is common to all commands.
const ATTEMPT_COMMANDS = ["claim", "start", "settle"];
const COMMAND_ONLY_FLAGS = new Map([
  ["scope", ["gc"]],
  ["mode", ["land"]], ["branch", ["land"]], ["allow", ["land"]],
  ["gate-log", ["settle"]], ["telemetry", ATTEMPT_COMMANDS], ["probe", ATTEMPT_COMMANDS], ["out", ["gate", "land"]],
]);
const FLAG_VALUES = new Map([
  ["mode", ["ff-only", "branch", "merge", "patch"]],
  ["allow", ["partial", "dirty-nonoverlap"]],
  ["scope", ["git", "cas"]],
]);
// Graph patches run inside one GraphPatched transaction keyed by the current physical node and revision.
const REQUIRED_FLAGS = new Map([
  ["release", ["token", "op-id"]],
  ["land", ["run", "op-id"]],
  ["amend", ["node", "expected-rev", "op-id", "patch"]],
  ["expand", ["node", "expected-rev", "op-id", "patch"]],
  ["inject-repair", ["node", "expected-rev", "op-id"]],
  ["revalidate", ["run", "node", "expected-rev", "op-id"]],
  ["gate", ["run", "node", "receipt", "out"]],
  ["metrics", ["run"]],
]);

const MAX_PAYLOAD_BYTES = 8 * 1024 * 1024;
const ENGINE_PATH = fileURLToPath(new URL("./state-machine.mjs", import.meta.url));

function fail(code, message) {
  throw Object.assign(new Error(message), { code });
}

// Returns { command, flags: Map<flag, raw string> } or throws ERR_CLI_*.
export function parseCliArgs(argv) {
  const [command, ...rest] = argv;
  if (command === undefined) fail("ERR_CLI_USAGE", `Usage: cli.mjs <${COMMANDS.join("|")}> [--flag value ...]`);
  if (!COMMAND_SET.has(command)) fail("ERR_CLI_UNKNOWN_COMMAND", `Unknown command: ${command}`);
  const flags = new Map();
  for (let i = 0; i < rest.length; i += 1) {
    const token = rest[i];
    if (!token.startsWith("--")) fail("ERR_CLI_USAGE", `Unexpected argument: ${token}`);
    const eq = token.indexOf("=");
    const name = token.slice(2, eq === -1 ? undefined : eq);
    if (!FLAGS.has(name)) fail("ERR_CLI_UNKNOWN_FLAG", `Unknown flag: --${name}`);
    const only = COMMAND_ONLY_FLAGS.get(name);
    if (only && !only.includes(command)) fail("ERR_CLI_UNKNOWN_FLAG", `--${name} is only accepted by ${only.join(", ")}`);
    let value;
    if (eq !== -1) value = token.slice(eq + 1);
    else {
      value = rest[i + 1];
      if (value === undefined || value.startsWith("--")) fail("ERR_CLI_FLAG_VALUE", `--${name} needs a value`);
      i += 1;
    }
    if (value === "") fail("ERR_CLI_FLAG_VALUE", `--${name} needs a non-empty value`);
    if (flags.has(name)) fail("ERR_CLI_FLAG_VALUE", `--${name} given more than once`);
    flags.set(name, value);
  }
  const missing = (REQUIRED_FLAGS.get(command) ?? []).filter((name) => !flags.has(name));
  if (missing.length) fail("ERR_CLI_MISSING_FLAG", `${command} requires ${missing.map((name) => `--${name}`).join(" ")}`);
  return { command, flags };
}

// Payloads come from bounded regular files only: no FIFO/device (a blocking read), no symlink, no growth mid-read.
async function readJsonFile(path, cwd, flag) {
  const { readRegularFileBounded } = await import("../governance/fact-ledger.mjs");
  const read = readRegularFileBounded(resolve(cwd, path),
    { maxBytes: MAX_PAYLOAD_BYTES, maxLines: Infinity, maxLineChars: Infinity });
  if (!read.ok) fail("ERR_CLI_INPUT_FILE", `Cannot read --${flag} file ${path}: ${read.reason}`);
  const text = read.text;
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    fail("ERR_CLI_INPUT_JSON", `--${flag} file ${path} is not JSON: ${error.message}`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("ERR_CLI_INPUT_JSON", `--${flag} file ${path} must hold a JSON object`);
  }
  return value;
}

const hostDataError = (flag, message) => fail("ERR_CLI_HOST_DATA", `--${flag}: ${message}`);
const isPlainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const isCount = (value) => Number.isSafeInteger(value) && value >= 0;

function checkRecord(flag, label, value, fields) {
  if (!isPlainObject(value)) hostDataError(flag, `${label} must be an object`);
  for (const [key, field] of Object.entries(value)) {
    const check = Object.hasOwn(fields, key) ? fields[key] : null;
    if (!check) hostDataError(flag, `unknown key ${label}.${key}`);
    check(field, `${label}.${key}`);
  }
}
const count = (flag) => (value, label) => { if (!isCount(value)) hostDataError(flag, `${label} must be a non-negative safe integer`); };

// Host-measured records only; the shapes are the metrics/reduction contracts, nothing else passes.
const HOST_DATA = new Map([
  ["telemetry", (value) => {
    const n = count("telemetry");
    checkRecord("telemetry", "telemetry", value, {
      usage: (usage, label) => checkRecord("telemetry", label, usage, {
        inputTokens: n, outputTokens: n,
        costUsd: (cost, l) => { if (!Number.isFinite(cost) || cost < 0) hostDataError("telemetry", `${l} must be a finite non-negative number`); },
      }),
      usageSource: (source, label) => {
        if (source !== "host-json" || value.dispatch !== "headless-process") {
          hostDataError("telemetry", `${label} must be host-json with headless-process dispatch`);
        }
      },
      dispatch: (dispatch, label) => {
        if (!["headless-process", "subagent"].includes(dispatch)) hostDataError("telemetry", `${label} is not a known dispatch`);
      },
      canaryEvent: (event, label) => {
        if (!["load_failure", "suspect", "recovered"].includes(event)) hostDataError("telemetry", `${label} is not a known canary event`);
      },
      budgetContext: (budget, label) => checkRecord("telemetry", label, budget, {
        verified: (flag, l) => { if (typeof flag !== "boolean") hostDataError("telemetry", `${l} must be a boolean`); },
        W_eff: n, reservedTokens: n,
        actualUsage: (usage, l) => checkRecord("telemetry", l, usage, { inputTokens: n, outputTokens: n }),
        contentTokens: (tokens, l) => {
          if (!isPlainObject(tokens)) hostDataError("telemetry", `${l} must be an object`);
          for (const [digest, measured] of Object.entries(tokens)) {
            if (!/^[a-f0-9]{64}$/.test(digest)) hostDataError("telemetry", `${l} keys must be sha256 hex digests`);
            n(measured, `${l}.${digest}`);
          }
        },
      }),
    });
  }],
  ["probe", (value) => {
    const bool = (flag, label) => { if (typeof flag !== "boolean") hostDataError("probe", `${label} must be a boolean`); };
    checkRecord("probe", "probe", value, {
      sessionId: (id, label) => { if (typeof id !== "string" || !id.trim()) hostDataError("probe", `${label} must be a non-empty string`); },
      probePassed: bool, schemaError: bool,
    });
    for (const key of ["sessionId", "probePassed", "schemaError"]) {
      if (!Object.hasOwn(value, key)) hostDataError("probe", `probe.${key} is required`);
    }
  }],
]);

// Converts raw flag strings into camelCase dispatch options. Payload files are read here, so the engine digests
// the request's bytes rather than a caller-chosen path. Path flags stay raw until resolveGraphPaths.
export async function buildOptions(flags, cwd) {
  const options = {};
  for (const [flag, raw] of flags) {
    const [key, kind] = FLAGS.get(flag);
    if (kind === "int") {
      if (!/^(0|[1-9]\d*)$/.test(raw) || !Number.isSafeInteger(Number(raw))) {
        fail("ERR_CLI_FLAG_VALUE", `--${flag} must be a non-negative safe integer`);
      }
      options[key] = Number(raw);
    } else if (kind === "json") {
      options[key] = await readJsonFile(raw, cwd, flag);
      HOST_DATA.get(flag)?.(options[key]);
    } else {
      const values = kind === "list" ? raw.split(",") : [raw];
      const allowed = FLAG_VALUES.get(flag);
      if (allowed && values.some(value => !allowed.includes(value))) {
        fail("ERR_CLI_FLAG_VALUE", `--${flag} accepts ${allowed.join(", ")}`);
      }
      options[key] = kind === "list" ? values : raw;
    }
  }
  return options;
}

// realpath of the deepest existing ancestor plus the not-yet-created remainder.
function realish(path) {
  const tail = [];
  let current = path;
  while (!existsSync(current)) {
    const parent = dirname(current);
    if (parent === current) break;
    tail.unshift(basename(current));
    current = parent;
  }
  return join(realpathSync(current), ...tail);
}

const isWithin = (child, parent) => child === parent || child.startsWith(parent.endsWith(sep) ? parent : parent + sep);

function hostDataDir(env, detectHost) {
  const isClaude = detectHost(env) === "claude-code";
  const candidates = [isClaude ? env.CLAUDE_PLUGIN_DATA : env.PLUGIN_DATA, env.PLUGIN_DATA, env.HSTACK_DATA_DIR];
  const dir = candidates.find((value) => typeof value === "string" && value.trim())?.trim();
  if (!dir || !isAbsolute(dir)) return null;
  try {
    return statSync(dir).isDirectory() ? realpathSync(dir) : null;
  } catch {
    return null;
  }
}

// --root/--workspace win. Otherwise the workspace is the enclosing git root (or cwd), and the root is the
// existing host data dir keyed by workspace, falling back to <workspace>/.hstack/graph.
export async function resolveGraphPaths({ root, workspace }, { cwd, env }) {
  let ws;
  if (workspace !== undefined) {
    const full = resolve(cwd, workspace);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      fail("ERR_CLI_PATH", `--workspace ${workspace} does not exist`);
    }
    if (!stat.isDirectory()) fail("ERR_CLI_PATH", `--workspace ${workspace} is not a directory`);
    ws = realpathSync(full);
  } else {
    const { resolveGitRootFast } = await import("../governance/fact-ledger.mjs");
    ws = resolveGitRootFast(cwd) || realpathSync(cwd);
  }

  let graphRoot;
  let source;
  if (root !== undefined) {
    graphRoot = realish(resolve(cwd, root));
    source = "flag";
  } else {
    const { detectHost } = await import("../host/host-adapter.mjs");
    const data = hostDataDir(env, detectHost);
    if (data) {
      const { computeWorkspaceKey } = await import("../governance/handoff-store.mjs");
      graphRoot = join(data, "graph", computeWorkspaceKey(ws, ws));
      source = "host-data";
    } else {
      graphRoot = join(ws, ".hstack", "graph");
      source = "repo";
      // The fallback is only ever the literal in-repo directory; a link at either level fails closed.
      for (const part of [join(ws, ".hstack"), graphRoot]) {
        let stat;
        try {
          stat = lstatSync(part);
        } catch (error) {
          if (error.code === "ENOENT") break;
          throw error;
        }
        if (!stat.isDirectory()) fail("ERR_CLI_PATH", `Refusing redirected fallback root component ${part}`);
      }
    }
  }
  if (existsSync(graphRoot) && !statSync(graphRoot).isDirectory()) fail("ERR_CLI_PATH", `root ${graphRoot} is not a directory`);
  if (isWithin(ws, graphRoot)) fail("ERR_CLI_PATH", `root ${graphRoot} must not contain the workspace ${ws}`);
  return { root: graphRoot, workspace: ws, source };
}

async function readRun(root, run) {
  const { readState } = await import("./wal-store.mjs");
  const state = await readState(root, run);
  if (!state) fail("ERR_RUN_NOT_FOUND", `No such graph run: ${run}`);
  return state;
}

const ownNode = (state, id) => (typeof id === "string" && Object.hasOwn(state.nodes ?? {}, id) ? state.nodes[id] : null);

// Runs the node's compile-time gate argv; the receipt contributes only the fact digest and spans it is checked for.
async function measurePolicyGate(state, node, receipt, env) {
  if (!Array.isArray(node.gateArgv)) fail("ERR_GATE_POLICY", `Node ${node.id} has no trusted gateArgv in graph policy`);
  const provenance = receipt?.provenance ?? {};
  const { measureGate } = await import("./verify-gate.mjs");
  const measured = await measureGate({ argv: node.gateArgv, cwd: state.workspace, subjectDigest: provenance.factDigest, env,
    ...(node.timeoutMs !== undefined && { timeoutMs: node.timeoutMs }) });
  return { schemaVersion: 1, runId: state.runId, nodeId: node.id, graphRev: state.graphRev, epoch: node.attempt?.epoch ?? null,
    ...measured, factDigest: measured.subjectDigest,
    checkedSpans: Array.isArray(provenance.evidenceSpans) ? provenance.evidenceSpans : [] };
}

async function runGateCommand(options, root, env) {
  const state = await readRun(root, options.run);
  const node = ownNode(state, options.node);
  if (!node) fail("ERR_GRAPH_SCHEMA", "Unknown graph node");
  const log = await measurePolicyGate(state, node, options.receipt, env);
  try {
    writeFileSync(options.out, `${JSON.stringify(log)}\n`, { flag: "wx", mode: 0o600 });
  } catch (error) {
    fail("ERR_CLI_PATH", `Cannot create --out ${options.out}: ${error.code ?? error.message}`);
  }
  return log;
}

async function loadDispatch() {
  if (!existsSync(ENGINE_PATH)) fail("ERR_ENGINE_UNAVAILABLE", "scripts/graph/state-machine.mjs is not installed");
  const engine = await import(ENGINE_PATH);
  if (typeof engine.dispatch !== "function") fail("ERR_ENGINE_UNAVAILABLE", "state-machine.mjs exports no dispatch()");
  return engine.dispatch;
}

export function exitCodeFor(error) {
  const code = typeof error?.code === "string" ? error.code : null;
  if (!code) return EXIT_CODES.internal;
  if (/^ERR_CLI_(USAGE|UNKNOWN_COMMAND|UNKNOWN_FLAG|FLAG_VALUE|MISSING_FLAG)$/.test(code)) return EXIT_CODES.usage;
  if (/^ERR_CLI_(INPUT_FILE|INPUT_JSON|HOST_DATA|PATH)$/.test(code)) return EXIT_CODES.input;
  if (/(^|_)STALE(_|$)/.test(code)) return EXIT_CODES.stale;
  if (code.startsWith("ERR_V2_") || code === "ERR_ENGINE_UNAVAILABLE") return EXIT_CODES.unavailable;
  return EXIT_CODES.engine;
}

function unavailableIntegration() {
  fail("ERR_V2_WRITE_INTEGRATION_NOT_ENABLED", "integrate is only available for v2 runs");
}

async function execute(command, flags, { cwd, env, dispatch }) {
  const options = await buildOptions(flags, cwd);
  if (command === "integrate" && options.run === undefined) unavailableIntegration();
  if (command === "host-caps") {
    const [{ hostCaps }, { detectHost }] = await Promise.all([import("./host-bridge.mjs"), import("../host/host-adapter.mjs")]);
    return hostCaps(detectHost(env));
  }
  const paths = await resolveGraphPaths(options, { cwd, env });
  options.root = paths.root;
  options.workspace = paths.workspace;
  if (options.out !== undefined) options.out = resolve(cwd, options.out);
  if (command === "integrate") {
    const [{ readState }, { STATE_SCHEMA_V2 }] = await Promise.all([import("./wal-store.mjs"), import("./schema.mjs")]);
    const { withLock } = await import("./lock.mjs");
    if (!existsSync(paths.root)) unavailableIntegration();
    const state = await withLock(paths.root, () => readState(paths.root, options.run));
    if (state?.schemaVersion !== STATE_SCHEMA_V2) unavailableIntegration();
  }
  if (Object.hasOwn(options.telemetry?.usage ?? {}, "costUsd")) {
    const { detectHost } = await import("../host/host-adapter.mjs");
    if (detectHost(env) === "antigravity") delete options.telemetry.usage.costUsd;
  }
  if (command === "init") {
    // fs-guard validates both paths and registers the local exclude only for the exact repo fallback.
    const { initializeRoot } = await import("./fs-guard.mjs");
    return { root: await initializeRoot(paths.root, paths.workspace), workspace: paths.workspace, source: paths.source };
  }
  if (command === "gc") {
    if (options.scope === "git") {
      if (!options.run) fail("ERR_CLI_MISSING_FLAG", "gc --scope git needs --run");
      const { collectGit } = await import("./integrator.mjs");
      return collectGit(paths.root, options.run);
    }
    const { collectGarbage } = await import("./gc.mjs");
    return collectGarbage(paths.root);
  }
  if (command === "metrics") {
    const [{ metrics }, { readState }] = await Promise.all([import("./metrics.mjs"), import("./wal-store.mjs")]);
    const state = await readRun(paths.root, options.run);
    // A configured baseline is read from the same root; metrics() itself decides whether it pairs.
    const baselineRunId = state.telemetry?.baseline?.baselineRunId;
    const baseline = typeof baselineRunId === "string" ? await readState(paths.root, baselineRunId) : null;
    return metrics(state, baseline ?? undefined);
  }
  if (command === "gate") return runGateCommand(options, paths.root, env);
  return (dispatch ?? (await loadDispatch()))(command, options);
}

// Runs one CLI call and returns its exit code. io.dispatch replaces the engine (tests); io.stdout receives one line.
export async function runCli(argv, { cwd = process.cwd(), env = process.env, stdout = process.stdout, dispatch } = {}) {
  let command = argv[0] ?? null;
  let line;
  let exitCode;
  try {
    const parsed = parseCliArgs(argv);
    command = parsed.command;
    const result = await execute(command, parsed.flags, { cwd, env, dispatch });
    line = JSON.stringify({ ok: true, command, result });
    exitCode = EXIT_CODES.ok;
  } catch (error) {
    exitCode = exitCodeFor(error);
    const code = exitCode === EXIT_CODES.internal ? "ERR_INTERNAL" : error.code;
    line = JSON.stringify({ ok: false, command, error: { code, message: String(error?.message ?? error) } });
  }
  stdout.write(`${line}\n`);
  return exitCode;
}

const invokedPath = process.argv[1] ? (() => {
  try {
    return realpathSync(process.argv[1]);
  } catch {
    return null;
  }
})() : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  process.exitCode = await runCli(process.argv.slice(2));
}
