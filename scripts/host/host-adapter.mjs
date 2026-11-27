import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeClaudeTool } from "./tools.mjs";

// Capabilities of this package, not grants in a particular session. A separately
// prompted worker isn't a filesystem sandbox, and transcript counters aren't a
// reliable per-worker usage API. Never infer cancel/resume from a session ID.
const unknown = Object.freeze({ host: "unknown", spawn: false, readOnlySubagent: false,
  isolatedWrite: false, cancel: false, resume: false, usageTelemetry: null });
const agy = Object.freeze({ ...unknown, host: "antigravity", spawn: true, readOnlySubagent: true });
const claude = Object.freeze({ ...unknown, host: "claude-code", spawn: true, readOnlySubagent: true });

export function getHostCapabilities(host) {
  return host === "antigravity" ? agy : host === "claude-code" ? claude : unknown;
}

export function detectHost(env = process.env, payload = {}) {
  const explicit = firstPath(env.HSTACK_HOST);
  if (["claude-code", "claude"].includes(explicit)) return "claude-code";
  if (["antigravity", "agy"].includes(explicit)) return "antigravity";
  if (firstPath(env.CLAUDE_PLUGIN_ROOT, env.CLAUDE_PLUGIN_DATA)) return "claude-code";
  if (firstPath(env.PLUGIN_ROOT, env.PLUGIN_DATA)) return "antigravity";
  const event = payload?.hookEventName ?? payload?.hook_event_name;
  const a = Boolean(payload?.conversationId || payload?.conversation_id || payload?.toolCall || payload?.tool_call ||
    ["PreInvocation", "PostInvocation"].includes(event));
  const c = Boolean(payload?.session_id || payload?.tool_name || payload?.stop_hook_active !== undefined ||
    event === "UserPromptSubmit");
  if (a !== c) return a ? "antigravity" : "claude-code";
  return "unknown";
}

export { formatHookResponse } from "./hook-response.mjs";

const firstPath = (...values) => values.find(v => typeof v === "string" && v.trim())?.trim();
export function resolveHostPaths(host = detectHost(), env = process.env) {
  const isClaude = host === "claude-code";
  return {
    pluginRoot: firstPath(isClaude ? env.CLAUDE_PLUGIN_ROOT : env.PLUGIN_ROOT) ??
      fileURLToPath(new URL("../../", import.meta.url)),
    dataDir: firstPath(isClaude ? env.CLAUDE_PLUGIN_DATA : env.PLUGIN_DATA, env.PLUGIN_DATA, env.HSTACK_DATA_DIR) ??
      join(tmpdir(), "hstack-data"),
  };
}

const claudeEvents = new Map([
  ["SessionStart", "SessionStart"], ["UserPromptSubmit", "PreInvocation"], ["PreToolUse", "PreToolUse"],
  ["PostToolUse", "PostToolUse"], ["Stop", "Stop"],
]);

// raw is the wire record, not a reconstructed subset. Canonical fields are a separate
// policy view so a native spelling (or an untrusted lookalike) cannot override dispatch.
export function normalizeHookEvent(host, raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  if (host === "antigravity") {
    return { ...raw, host, raw, hookEventName: raw.hookEventName ?? raw.hook_event_name,
      conversationId: raw.conversationId ?? raw.conversation_id, transcriptPath: raw.transcriptPath ?? raw.transcript_path,
      toolCall: raw.toolCall ?? raw.tool_call, toolResponse: raw.toolResponse ?? raw.tool_response,
      response: raw.response ?? raw.toolResponse ?? raw.tool_response, lastUserInput: raw.lastUserInput ?? raw.last_user_input };
  }
  const hookEventName = host === "claude-code" && claudeEvents.get(raw.hook_event_name);
  if (!hookEventName) return null;
  return { host, raw, hookEventName, cwd: raw.cwd, transcriptPath: raw.transcript_path,
    conversationId: raw.session_id, lastUserInput: raw.prompt, toolResponse: raw.tool_response,
    response: hookEventName === "PostToolUse" ? raw.tool_response : raw.last_assistant_message,
    toolCall: normalizeClaudeTool(raw.tool_name, raw.tool_input) ??
      (hookEventName === "PostToolUse" ? { name: raw.tool_name, args: raw.tool_input } : undefined),
    continuationActive: raw.stop_hook_active === true,
    ...(hookEventName === "Stop" ? { terminationReason: "NO_TOOL_CALL" } : {}) };
}
