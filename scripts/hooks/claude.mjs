import { readFileSync } from "node:fs";
import { join } from "node:path";
import { readFactLedgerAndSteps } from "../governance/fact-ledger.mjs";
import { isDirectExecution, parseHookPayload, runHookCli, withTranscriptHost } from "../hook-io.mjs";
import { formatHookResponse, normalizeHookEvent, resolveHostPaths } from "../host/host-adapter.mjs";
import { claudeDeny } from "../host/hook-response.mjs";
import { handlePostInvocation } from "../post-invocation.mjs";
import { handlePreToolGate } from "../pre-tool-gate.mjs";
import { handlePreInvocation } from "../prompt-router.mjs";
import { handleStop } from "../stop.mjs";
import { PRE_TOOL_USE_UI_TOOLS, decidePreToolUseAction } from "../transcript.mjs";

function evaluate(event) {
  const text = JSON.stringify(event);
  switch (event.hookEventName) {
    case "SessionStart": {
      const rules = readFileSync(join(resolveHostPaths(event.host).pluginRoot, "rules", "AGENTS.md"), "utf8");
      return { injectSteps: [{ systemMessage: { systemMessage: rules } }] };
    }
    case "PreInvocation": return handlePreInvocation(text);
    case "PreToolUse": {
      if (!event.toolCall) return {};
      if (!PRE_TOOL_USE_UI_TOOLS.has(event.toolCall.name)) return handlePreToolGate(text);
      const { ledger, steps } = readFactLedgerAndSteps(event.transcriptPath, event.cwd);
      const decision = decidePreToolUseAction(event.toolCall, steps, { transcriptAvailable: ledger.transcriptAvailable });
      return { decision: decision.action, reason: decision.message };
    }
    case "Stop":
      if (event.continuationActive) return {};
      return { ...handleStop(text), ...handlePostInvocation(JSON.stringify({ ...event, hookEventName: "PostInvocation" })) };
    default: return {};
  }
}

export function handleClaude(stdin, expectedEvent) {
  const raw = parseHookPayload(stdin);
  if (expectedEvent && expectedEvent !== raw?.hook_event_name) return {};
  const event = normalizeHookEvent("claude-code", raw);
  return event ? withTranscriptHost(event.host, () => formatHookResponse(event, evaluate(event))) : {};
}

if (isDirectExecution(import.meta.url)) {
  const expected = process.argv[2];
  runHookCli(stdin => handleClaude(stdin, expected), expected === "PreToolUse"
    ? claudeDeny("도구 호출을 확인하는 중 오류가 발생했습니다.") : {});
}
