import { issueMcpContext } from "./mcp-session.mjs";

export const claudeDeny = reason => ({ hookSpecificOutput: { hookEventName: "PreToolUse",
  permissionDecision: "deny", permissionDecisionReason: reason } });

function preTool(raw, result) {
  if (result.decision === "deny") return claudeDeny(result.reason);
  const input = raw.tool_input;
  const tool = /^mcp__plugin_hstack_gate__(verify_completion|manage_handoff)$/.exec(raw.tool_name)?.[1];
  let updatedInput;
  if (tool) {
    if (!input || typeof input !== "object" || Array.isArray(input) || !result.overwrite?._session) {
      return claudeDeny("도구에 전달할 세션 정보를 확인하지 못했습니다.");
    }
    const { _session, _hstackContext, toolSummary, ...publicInput } = input;
    try {
      updatedInput = { ...publicInput, _hstackContext: issueMcpContext(tool, result.overwrite._session) };
    } catch {
      return claudeDeny("도구에 전달할 세션 정보를 발급하지 못했습니다.");
    }
  } else if (["Task", "Agent"].includes(raw.tool_name) && typeof result.overwrite?.Prompt === "string" &&
    typeof input?.prompt === "string") {
    updatedInput = { ...input, prompt: result.overwrite.Prompt };
  }
  // Full replacement, never an "allow": Claude still owns permission checks.
  return updatedInput ? { hookSpecificOutput: { hookEventName: "PreToolUse", updatedInput } } : {};
}

export function formatHookResponse(event, result = {}) {
  if (event?.host === "antigravity") return result;
  if (event?.host !== "claude-code") return {};
  if (event.hookEventName === "PreToolUse") return preTool(event.raw, result);
  const context = (result.injectSteps ?? []).map(step => step.systemMessage?.systemMessage)
    .filter(text => typeof text === "string" && text.length > 0)
    .map(text => text.replaceAll("`invoke_subagent`", "`Agent`").replaceAll("`ask_question`", "`AskUserQuestion`")).join("\n");
  if (event.hookEventName === "Stop") return {
    ...(result.decision === "continue" ? { decision: "block", reason: result.reason || "완료 전 응답을 다시 확인하세요." } : {}),
    ...(context ? { systemMessage: `hstack 종료 시점 분석 결과 및 권고:\n${context}` } : {}),
  };
  return context ? { hookSpecificOutput: { hookEventName: event.raw.hook_event_name, additionalContext: context } } : {};
}
