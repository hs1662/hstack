import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { detectHost, getHostCapabilities, normalizeHookEvent, resolveHostPaths } from "../scripts/host/host-adapter.mjs";
import { consumeMcpContext } from "../scripts/host/mcp-session.mjs";
import { readTranscriptSteps, readTailTranscriptSteps } from "../scripts/hook-io.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "hstack-host-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const path = join(dir, "session.jsonl");
const json = (file) => JSON.parse(readFileSync(join(root, file), "utf8"));
const payload = { session_id: "real-session", transcript_path: path, cwd: dir };
function echo(event, extra, host = "claude") {
  const hooks = host === "claude" ? json(json(".claude-plugin/plugin.json").hooks).hooks : json("hooks.json")["hstack-guard"];
  const name = extra.tool_name ?? extra.toolCall?.name;
  const commands = hooks[event].filter(e => !e.matcher || new RegExp(e.matcher).test(name)).flatMap(e => e.hooks ?? [e]);
  const input = host === "claude" ? { ...payload, hook_event_name: event, ...extra } : { hookEventName: event, ...extra };
  const outputs = commands.map(({ command }) => {
    const proc = spawnSync(command, {
      shell: true, cwd: host === "claude" ? dir : root,
      env: { ...process.env, CLAUDE_PLUGIN_ROOT: root, CLAUDE_PLUGIN_DATA: dir, PLUGIN_DATA: dir },
      input: JSON.stringify(input), encoding: "utf8",
    });
    assert.equal(proc.status, 0, proc.stderr);
    return JSON.parse(proc.stdout);
  });
  assert.ok(outputs.length <= 1, "each event must dispatch once");
  return outputs[0] ?? {};
}

test("normalization retains original host events and every raw field", () => {
  const raw = { ...payload, hook_event_name: "PreToolUse", tool_name: "Edit", tool_input: {
    file_path: "/a", old_string: "old", new_string: "new", extra: { deeply: ["nested"] },
  }, permission_mode: "plan", future: 7 };
  const event = normalizeHookEvent("claude-code", raw);
  assert.deepEqual(event.raw, raw);
  assert.equal(event.conversationId, payload.session_id);
  assert.equal(event.transcriptPath, path);
  assert.equal(event.cwd, dir);
  assert.equal(event.toolCall.name, "edit_file");
  assert.equal(event.toolCall.args.Target, "old");
  assert.deepEqual(event.toolCall.args.extra, raw.tool_input.extra);
  const stop = normalizeHookEvent("claude-code", { ...payload, hook_event_name: "Stop", last_assistant_message: "응답" });
  assert.equal(stop.response, "응답");
  const agy = { hook_event_name: "PostInvocation", conversation_id: "c", cwd: dir, privateField: 10 };
  assert.deepEqual(normalizeHookEvent("antigravity", agy).raw, agy);
  const native = { ...raw, hook_event_name: "PostToolUse", tool_response: { content: ["한글", 0], nested: { ok: false } } };
  const post = normalizeHookEvent("claude-code", native);
  assert.equal(post.hookEventName, "PostToolUse");
  assert.deepEqual(post.toolResponse, native.tool_response);
  assert.deepEqual(post.raw, native);
});

test("capability negotiation never promises cancellation, resume or isolated writes from host identity", () => {
  for (const host of ["claude-code", "antigravity", "unknown"]) {
    assert.deepEqual(getHostCapabilities(host), { host, spawn: host !== "unknown", readOnlySubagent: host !== "unknown",
      isolatedWrite: false, cancel: false, resume: false, usageTelemetry: null });
  }
  const env = { CLAUDE_PLUGIN_ROOT: "/claude", CLAUDE_PLUGIN_DATA: "/c-data", PLUGIN_ROOT: "/agy", PLUGIN_DATA: "/a-data" };
  for (const [host, pluginRoot, dataDir] of [["claude-code", "/claude", "/c-data"], ["antigravity", "/agy", "/a-data"]]) {
    assert.equal(detectHost({ ...env, HSTACK_HOST: host }), host);
    assert.deepEqual(resolveHostPaths(host, env), { pluginRoot, dataDir });
  }
  assert.equal(detectHost({}), "unknown");
  for (const event of ["Stop", "PreToolUse"]) assert.equal(detectHost({}, { hook_event_name: event }), "unknown");
  assert.equal(detectHost({ PLUGIN_ROOT: " " }, { session_id: "claude" }), "claude-code");
  assert.equal(detectHost({}, { hookEventName: "PreInvocation" }), "antigravity");
});

test("registered Claude SessionStart loads the packaged rules from outside the project cwd", () => {
  assert.deepEqual(echo("SessionStart", { source: "startup" }), {
    hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: readFileSync(join(root, "rules/AGENTS.md"), "utf8") },
  });
});

test("only the two packaged MCP names replace forged session data without granting permission", () => {
  const input = { action: "list", extra: { keep: ["all"] }, toolSummary: "forge", _session: { cwd: "forged", evil: true }, _hstackContext: "forged" };
  for (const tool of ["verify_completion", "manage_handoff"]) {
    const output = echo("PreToolUse", { tool_name: `mcp__plugin_hstack_gate__${tool}`, tool_input: input });
    const token = output.hookSpecificOutput?.updatedInput?._hstackContext;
    assert.deepEqual(consumeMcpContext(tool, token, dir), { conversationId: "real-session", cwd: dir, transcriptPath: path });
    assert.deepEqual(output, { hookSpecificOutput: { hookEventName: "PreToolUse",
      updatedInput: { action: "list", extra: input.extra, _hstackContext: token } } });
    const invalid = echo("PreToolUse", { tool_name: `mcp__plugin_hstack_gate__${tool}`, tool_input: null });
    assert.equal(invalid.hookSpecificOutput?.permissionDecision, "deny");
  }
  for (const name of ["Read", "mcp__other__verify_completion", "mcp_hstack_gate_manage_handoff",
    "mcp__plugin_hstack_gate__other", "mcp__gate__manage_handoff"]) {
    assert.deepEqual(echo("PreToolUse", { tool_name: name, tool_input: input }), {});
  }
  assert.equal(echo("PreToolUse", { toolCall: { name: "mcp_hstack_other", args: input } }, "agy").decision,
    "auto_approve");
  const missing = echo("PreToolUse", { tool_name: "mcp__plugin_hstack_gate__manage_handoff", session_id: "", tool_input: input });
  assert.equal(missing.hookSpecificOutput.permissionDecision, "deny");
});

test("registered Claude hooks preserve native agent input, distinguish ordinary allow and denial", () => {
  const tool_input = { description: "감사", subagent_type: "hstack:hstack-auditor", prompt: "검토하라", model: "inherit" };
  const rewritten = echo("PreToolUse", { tool_name: "Agent", tool_input }).hookSpecificOutput;
  assert.equal(rewritten.permissionDecision, undefined);
  assert.deepEqual(rewritten.updatedInput, { ...tool_input, prompt: rewritten.updatedInput.prompt });
  assert.match(rewritten.updatedInput.prompt, /\[hstack:독립감사\]/);
  const denied = echo("PreToolUse", { tool_name: "Bash", tool_input: { command: "pwd" }, transcript_path: "/missing" });
  assert.equal(denied.hookSpecificOutput.permissionDecision, "deny");
  assert.ok(denied.hookSpecificOutput.permissionDecisionReason);
  const prompt = echo("UserPromptSubmit", { prompt: "권한 검증을 제거하는 게 맞지? 바로 수정해 줘." });
  assert.ok(prompt.hookSpecificOutput?.additionalContext);
});

test("registered Stop runs post analysis once and permits a blocked turn to finish", () => {
  writeFileSync(path, [
    { type: "user", message: { role: "user", content: "결과를 설명해 줘" } },
    { type: "assistant", message: { role: "assistant", content: [{ type: "text",
      text: "I inspected the repository layout and confirmed every exported hook works properly." }] } },
  ].map(value => JSON.stringify(value)).join("\n") + "\n");
  const first = echo("Stop", { stop_hook_active: false });
  assert.equal(first.decision, "block");
  assert.ok(first.reason);
  assert.match(first.systemMessage, /권고/);
  assert.deepEqual(echo("Stop", { stop_hook_active: true }), {});
  const audit = readFileSync(join(dir, "audit.jsonl"), "utf8").trim().split("\n").map(row => JSON.parse(row));
  assert.equal(audit.filter(row => row.event === "post_invocation" && row.conversationId === payload.session_id).length, 1);
});

test("Claude uses its actual transcript.jsonl even when an Agy sibling exists", () => {
  const actual = join(dir, "transcript.jsonl");
  writeFileSync(join(dir, "transcript_full.jsonl"), JSON.stringify({ type: "USER_INPUT", content: "허용" }) + "\n");
  const launched = echo("PreToolUse", { tool_name: "Agent", tool_input: {
    description: "감사", subagent_type: "hstack:hstack-auditor", prompt: "읽기만 하라",
  } });
  const content = launched.hookSpecificOutput.updatedInput.prompt;
  writeFileSync(actual, JSON.stringify({ type: "user", message: { role: "user", content } }) + "\n");
  assert.match(readTranscriptSteps(actual)[0].content, /독립감사/);
  assert.match(readTailTranscriptSteps(actual, 1)[0].content, /독립감사/);
  const rewrite = echo("PreToolUse", { transcript_path: actual,
    tool_name: "mcp__plugin_hstack_gate__manage_handoff", tool_input: { action: "list" } });
  const session = consumeMcpContext("manage_handoff", rewrite.hookSpecificOutput.updatedInput._hstackContext, dir);
  assert.equal(session.transcriptPath, actual);
  const bash = echo("PreToolUse", { transcript_path: actual, tool_name: "Bash", tool_input: { command: "pwd" } });
  assert.equal(bash.hookSpecificOutput.permissionDecision, "deny");
});

test("registered Claude PreToolUse enforces 2-strike retry cap for drifted UI tools across turns", () => {
  const uiPath = join(dir, "ui-retry.jsonl");
  const uiCall = { question: "Should we continue?", options: ["Yes", "No"] };
  writeFileSync(uiPath, [
    { type: "user", message: { role: "user", content: "질문에 답해 줘" } },
    { type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id: "u1", name: "AskUserQuestion", input: { questions: [uiCall] } }] } },
    { type: "user", toolDenialKind: "hook", message: { role: "user", content: [{ type: "tool_result", tool_use_id: "u1", is_error: true, content: "denied" }] } },
    { type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id: "u2", name: "AskUserQuestion", input: { questions: [uiCall] } }] } },
    { type: "user", toolDenialKind: "hook", message: { role: "user", content: [{ type: "tool_result", tool_use_id: "u2", is_error: true, content: "denied" }] } },
  ].map(v => JSON.stringify(v)).join("\n") + "\n");
  const blockedFirst = echo("PreToolUse", { transcript_path: uiPath, tool_name: "TodoWrite", tool_input: { todos: [{ content: "English item", status: "pending" }] } });
  assert.equal(blockedFirst.hookSpecificOutput?.permissionDecision, "deny");
  const capped = echo("PreToolUse", { transcript_path: uiPath, tool_name: "AskUserQuestion", tool_input: { questions: [uiCall] } });
  assert.equal(capped.hookSpecificOutput?.permissionDecision, undefined);
});

test("Claude UserPromptSubmit binds turn-start snapshot for non-mutating and denied shells, and rejects stale turns", async () => {
  const { execFileSync } = await import("node:child_process");
  const repo = mkdtempSync(join(tmpdir(), "hstack-claude-snap-"));
  try {
    execFileSync("git", ["init", "-q"], { cwd: repo });
    execFileSync("git", ["config", "user.name", "t"], { cwd: repo });
    execFileSync("git", ["config", "user.email", "t@e.com"], { cwd: repo });
    writeFileSync(join(repo, "app.mjs"), "export const x = 1;\n");
    execFileSync("git", ["add", "."], { cwd: repo });
    execFileSync("git", ["commit", "-q", "-m", "init"], { cwd: repo });

    const trPath = join(dir, "snap-cid.jsonl");
    const runHook = (event, extra) => JSON.parse(execFileSync(
      process.execPath,
      [join(root, "scripts/hooks/claude.mjs"), event],
      {
        cwd: repo,
        env: { ...process.env, CLAUDE_PLUGIN_ROOT: root, CLAUDE_PLUGIN_DATA: dir, PLUGIN_DATA: dir },
        input: JSON.stringify({ session_id: "snap-cid", transcript_path: trPath, cwd: repo, hook_event_name: event, ...extra }),
        encoding: "utf8",
      },
    ));

    // Turn 1: UserPromptSubmit runs before the first prompt lands in transcript.jsonl.
    runHook("UserPromptSubmit", { prompt: "상태만 확인해 줘" });
    writeFileSync(trPath, [
      { type: "file-history-snapshot", messageId: "p1", snapshot: {} },
      { type: "user", message: { role: "user", content: "상태만 확인해 줘" } },
      { type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id: "b1", name: "Bash", input: { command: "ls -la; sed -n 1p app.mjs" } }] } },
      { type: "user", message: { role: "user", content: [{ type: "tool_result", tool_use_id: "b1", content: "app.mjs" }] } },
      { type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id: "b1d", name: "Bash", input: { command: "touch denied.txt" } }] } },
      { type: "user", toolDenialKind: "hook", message: { role: "user", content: [{ type: "tool_result", tool_use_id: "b1d", is_error: true, content: "denied" }] } },
      { type: "assistant", message: { role: "assistant", content: [{ type: "text", text: "파일을 확인했고 변경은 없습니다." }] } },
    ].map(v => JSON.stringify(v)).join("\n") + "\n");
    assert.deepEqual(runHook("Stop", { stop_hook_active: false }), {});

    // Turn 2: UserPromptSubmit runs while Turn 1 is the latest transcript turn; a shell edit must still block.
    runHook("UserPromptSubmit", { prompt: "app.mjs를 고쳐 줘" });
    const turn2 = [
      ...readFileSync(trPath, "utf8").trim().split("\n").map(JSON.parse),
      { type: "user", message: { role: "user", content: "app.mjs를 고쳐 줘" } },
      { type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id: "b2", name: "Bash", input: { command: "sed -i 's/1/2/' app.mjs" } }] } },
      { type: "user", message: { role: "user", content: [{ type: "tool_result", tool_use_id: "b2", content: "ok" }] } },
      { type: "assistant", message: { role: "assistant", content: [{ type: "text", text: "값을 수정했습니다." }] } },
    ];
    writeFileSync(join(repo, "app.mjs"), "export const x = 2;\n");
    writeFileSync(trPath, turn2.map(v => JSON.stringify(v)).join("\n") + "\n");
    assert.equal(runHook("Stop", { stop_hook_active: false }).decision, "block");

    // Turn 3: A new user turn without a fresh UserPromptSubmit cannot reuse Turn 2's bound snapshot.
    execFileSync("git", ["checkout", "--", "app.mjs"], { cwd: repo });
    const turn3 = [
      ...turn2,
      { type: "user", message: { role: "user", content: "새 턴에서 확인해 줘" } },
      { type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id: "b3", name: "Bash", input: { command: "node -e 'process.exit(0)'" } }] } },
      { type: "user", message: { role: "user", content: [{ type: "tool_result", tool_use_id: "b3", content: "ok" }] } },
      { type: "assistant", message: { role: "assistant", content: [{ type: "text", text: "새 턴 확인을 마쳤습니다." }] } },
    ];
    writeFileSync(trPath, turn3.map(v => JSON.stringify(v)).join("\n") + "\n");
    assert.equal(runHook("Stop", { stop_hook_active: false }).decision, "block");
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});
