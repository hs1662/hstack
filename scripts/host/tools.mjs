import { GATE_TOOL_NAME, HANDOFF_TOOL_NAME } from "../governance/constants.mjs";

// Claude scopes a plugin server as plugin:<plugin>:<server>, then escapes ':' to '_'.
const aliases = new Map(Object.entries({
  Read: "read_file", Edit: "edit_file", Write: "write_file", NotebookEdit: "edit_file",
  Bash: "run_command", PowerShell: "run_command", Agent: "invoke_subagent", Task: "invoke_subagent",
  TodoWrite: "todo_write", TaskCreate: "task_create", TaskUpdate: "task_update", AskUserQuestion: "ask_question",
  mcp__plugin_hstack_gate__verify_completion: GATE_TOOL_NAME,
  mcp__plugin_hstack_gate__manage_handoff: HANDOFF_TOOL_NAME,
}));

export function normalizeClaudeTool(nativeName, input) {
  const name = aliases.get(nativeName);
  if (!name) return undefined;
  if (!input || typeof input !== "object" || Array.isArray(input)) return { name, args: input };
  let args = { ...input };
  switch (nativeName) {
    case "Edit":
      args = { ...args, Path: input.file_path, Target: input.old_string, Replacement: input.new_string };
      break;
    case "NotebookEdit":
      args = { ...args, Path: input.notebook_path, Replacement: input.new_source };
      break;
    case "Read":
    case "Write":
      args = { ...args, Path: input.file_path };
      break;
    case "Bash":
    case "PowerShell":
      args = { ...args, CommandLine: input.command };
      break;
    case "Agent":
    case "Task":
      // Only native fields can select the agent or supply its prompt, not Agy-shaped aliases.
      args = { TypeName: input.subagent_type, Prompt: input.prompt, Role: input.description,
        ...(typeof input.run_in_background === "boolean" ? { Wait: !input.run_in_background } : {}) };
      break;
  }
  return { name, args };
}
