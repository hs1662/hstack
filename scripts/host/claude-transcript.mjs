import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { basename, dirname } from "node:path";
import { GATE_TOOL_NAME } from "../governance/constants.mjs";
import { normalizeClaudeTool } from "./tools.mjs";

const FILE_BYTES = 64 * 1024 * 1024;
const LINE_BYTES = 4 * 1024 * 1024;
const HEADER_BYTES = 4 * 1024 * 1024;
const MAX_RECORDS = 100_000;
const MAX_EVENTS = 25_000;
const MAX_BLOCKS = 256;
const TEXT_CHARS = 16_384;
const AGY_TYPES = new Set(["USER_INPUT", "PLANNER_RESPONSE", "SYSTEM_MESSAGE", "GENERIC", "ERROR_MESSAGE"]);
const CLAUDE_METADATA = new Set(["session-owner", "queue-operation", "attachment", "summary", "file-history-snapshot", "system", "progress"]);
const ignoredPrompt = /^\s*(?:<(?:system-reminder|local-command-caveat|local-command-stdout|command-name|task-notification|teammate-message)(?:\s[^<>]*)?>|\[Request interrupted by user(?: for tool use)?\]\s*$)/i;

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parsedLine(line) {
  try {
    const value = JSON.parse(line.replace(/^\uFEFF/, ""));
    return object(value) && typeof value.type === "string" ? value : null;
  } catch {
    return null;
  }
}

function blockText(blocks, type, key) {
  let text = "";
  for (const block of blocks) {
    if (block?.type === type && typeof block[key] === "string") {
      if (text) text += "\n";
      text += block[key].slice(0, TEXT_CHARS - text.length);
      if (text.length >= TEXT_CHARS) break;
    }
  }
  return text;
}

function userText(content) {
  if (typeof content === "string") {
    return !content.trim() || ignoredPrompt.test(content) ? null :
      content.length > TEXT_CHARS ? { text: "", oversized: true } : { text: content };
  }
  if (!Array.isArray(content) || content.length === 0 ||
      !content.every((block) => ["text", "image", "document"].includes(block?.type))) return null;
  const text = blockText(content, "text", "text");
  if (ignoredPrompt.test(text)) return null;
  if (text.length >= TEXT_CHARS) return { text: "", oversized: true };
  return text.trim() || content.some((block) => block.type !== "text") ? { text } : null;
}

const CLAUDE_ANSWER_PAIR_RE = /"[^"\n]+"\s*=\s*"([^"\n]+)"/g;
const CLAUDE_REJECTED_TEXT_RE = /^(?:Error:|Tool error:|Failed to|Cancelled|Canceled|User cancelled|User canceled|User rejected|Rejected|Dismissed|No answer|Aborted|Timeout)/i;
const MAX_UI_ITEMS = 32;

function clipText(value, limit = TEXT_CHARS) {
  return typeof value === "string" ? value.slice(0, limit) : "";
}

function normalizeQuestionOptions(rawOptions) {
  if (!Array.isArray(rawOptions)) return [];
  const out = [];
  for (const opt of rawOptions.slice(0, MAX_UI_ITEMS)) {
    if (typeof opt === "string") {
      if (opt.trim()) out.push(clipText(opt));
    } else if (object(opt)) {
      if (typeof opt.label === "string" && opt.label.trim()) out.push(clipText(opt.label));
      if (typeof opt.description === "string" && opt.description.trim()) out.push(clipText(opt.description));
    }
  }
  return out;
}

function normalizeAskQuestionAnswers(content, hostResult) {
  const trimmed = content.trim();
  if (CLAUDE_REJECTED_TEXT_RE.test(trimmed)) return content;
  if (/^A\d+\s*:/m.test(trimmed)) return content;
  if (object(hostResult?.answers)) {
    const answers = Object.values(hostResult.answers).filter((v) => typeof v === "string" && v.trim().length > 0);
    if (answers.length > 0) return answers.map((v, i) => `A${i + 1}: ${v.trim()}`).join("\n");
  }
  if (/^User has answered your questions:/i.test(trimmed)) {
    const answers = [...trimmed.matchAll(CLAUDE_ANSWER_PAIR_RE)].map((m) => m[1].trim()).filter(Boolean);
    if (answers.length > 0) return answers.map((v, i) => `A${i + 1}: ${v}`).join("\n");
  }
  return content;
}

function toolCall(block) {
  if (block?.type !== "tool_use" || typeof block.id !== "string" || !block.id || block.id.length > 256 ||
      !object(block.input)) return null;
  const normalized = normalizeClaudeTool(block.name, block.input);
  if (!normalized) return null;
  const { name, args: nativeArgs } = normalized;
  let args;
  switch (name) {
    case "read_file":
    case "write_file":
    case "edit_file":
      args = { Path: typeof nativeArgs.Path === "string" && nativeArgs.Path.length <= 4096 ? nativeArgs.Path : "" };
      break;
    case "run_command":
      // Preserve PowerShell as a non-verification shell execution so Stop shell-write checks still engage.
      args = { command: block.name === "PowerShell" ? "powershell" :
        typeof nativeArgs.CommandLine === "string" && nativeArgs.CommandLine.length <= TEXT_CHARS ? nativeArgs.CommandLine : "" };
      break;
    case GATE_TOOL_NAME:
      args = { toolSummary: "" };
      break;
    case "invoke_subagent":
      args = { TypeName: clipText(nativeArgs.TypeName, 256), Prompt: clipText(nativeArgs.Prompt) };
      break;
    case "todo_write": {
      const list = Array.isArray(block.input.todos) ? block.input.todos.slice(0, MAX_BLOCKS) : [];
      args = {
        todos: list.filter(object).map((item) => ({
          ...(typeof item.content === "string" ? { content: clipText(item.content) } : {}),
          ...(typeof item.title === "string" ? { title: clipText(item.title) } : {}),
          ...(typeof item.subject === "string" ? { subject: clipText(item.subject) } : {}),
        })),
      };
      break;
    }
    case "task_create":
    case "task_update":
      args = {
        ...(typeof block.input.subject === "string" ? { subject: clipText(block.input.subject) } : {}),
        ...(typeof block.input.title === "string" ? { title: clipText(block.input.title) } : {}),
      };
      break;
    case "ask_question": {
      const qs = Array.isArray(block.input.questions) ? block.input.questions.slice(0, MAX_UI_ITEMS) : [];
      args = {
        questions: qs.filter(object).map((q) => ({
          ...(typeof q.question === "string" ? { question: clipText(q.question) } : {}),
          options: normalizeQuestionOptions(q.options),
        })),
      };
      break;
    }
    default:
      return null;
  }
  const { description } = block.input;
  if (typeof description === "string") args.toolSummary = description.slice(0, TEXT_CHARS);
  return { id: block.id, name, args, detached: block.input.run_in_background === true };
}

function toolResult(block, row, call) {
  const hostResult = row.message.content.length === 1 ? row.toolUseResult : null;
  if (block.is_error !== undefined && typeof block.is_error !== "boolean") return null;
  const denied = Boolean(row.toolDenialKind);
  const failed = denied || block.is_error === true || hostResult?.interrupted === true ||
    (Number.isInteger(hostResult?.exitCode) && hostResult.exitCode !== 0);
  if (!failed && (row.isMeta || row.isCompactSummary || row.isVisibleInTranscriptOnly)) return null;
  if (!failed && (call.detached || hostResult?.backgroundTaskId || hostResult?.backgroundedByUser)) return null;
  const payload = block.content;
  const rawContent = typeof payload === "string" ? payload :
    Array.isArray(payload) && payload.length <= MAX_BLOCKS ? blockText(payload, "text", "text") : "";
  const content = !failed && call.name === "ask_question" ? normalizeAskQuestionAnswers(rawContent, hostResult) : rawContent;
  const readMedia = call.name === "read_file" && Array.isArray(payload) && payload.length <= MAX_BLOCKS &&
    payload.some((item) => item?.type === "image" || item?.type === "document");
  if (!failed && call.name !== "read_file" && Array.isArray(payload) && payload.some((item) => item?.type !== "text")) return null;
  if (!failed && !readMedia && !content.trim()) return null;
  // Do not trim a long result into an apparently passing test or gate receipt.
  if (!failed && content.length >= TEXT_CHARS && (call.name === "run_command" || call.name === GATE_TOOL_NAME ||
      call.name === "invoke_subagent")) return null;
  return { type: "GENERIC", toolUseId: call.id, status: failed ? "ERROR" : "DONE", content: content.slice(0, TEXT_CHARS),
    ...(denied ? { error: "tool call denied by pre-tool hook" } : {}) };
}

function decode(lines, headerOnly, sidechain = null) {
  let claude = false;
  let recordIndex = 0;
  let hasHeader = false;
  let malformed = false;
  let sessionId = "";
  const events = [];
  const calls = new Map();
  for (const line of lines) {
    if (line === null || recordIndex >= MAX_RECORDS || events.length >= MAX_EVENTS) {
      return claude ? { available: false, events: [] } : null;
    }
    const row = parsedLine(line);
    if (!row) {
      if (line.trim()) malformed = true;
      continue;
    }
    const stepIndex = recordIndex++;
    if (!claude && AGY_TYPES.has(row.type)) return null;
    const messageType = row.type === "user" || row.type === "assistant";
    claude ||= messageType || (CLAUDE_METADATA.has(row.type) && typeof row.sessionId === "string");
    if (!messageType || row.message?.role !== row.type) continue;
    if (sidechain ? row.isSidechain !== true || row.agentId !== sidechain.agentId || row.sessionId !== sidechain.sessionId :
      row.isSidechain === true) continue;
    if (typeof row.sessionId === "string") {
      if (sessionId && sessionId !== row.sessionId) continue;
      sessionId = row.sessionId;
    }
    const content = row.message.content;
    if (Array.isArray(content) && content.length > MAX_BLOCKS) return { available: false, events: [] };
    if (row.type === "assistant") {
      if (!hasHeader || headerOnly) break;
      if (!Array.isArray(content)) continue;
      const toolCalls = [];
      for (const block of content) {
        if (block?.type !== "tool_use" || typeof block.id !== "string" || !block.id || block.id.length > 256) continue;
        const prev = calls.get(block.id);
        if (prev !== undefined) {
          if (prev?.result) prev.result.ambiguous = true;
          calls.set(block.id, null);
          continue;
        }
        const call = toolCall(block);
        calls.set(block.id, call ? { call, uuid: row.uuid, result: null } : null);
        if (call) toolCalls.push(call);
      }
      const contentText = blockText(content, "text", "text");
      const thinking = blockText(content, "thinking", "thinking");
      if (contentText || thinking || toolCalls.length || row.message.usage) {
        const usage = row.message.usage;
        events.push({ type: "PLANNER_RESPONSE", stepIndex, toolCalls, content: contentText, thinking,
          usage: { input_tokens: usage?.input_tokens, output_tokens: usage?.output_tokens,
            cache_read_tokens: usage?.cache_read_input_tokens } });
      }
      continue;
    }
    if (Array.isArray(content) && content.some((block) => block?.type === "tool_result")) {
      if (headerOnly || !hasHeader) continue;
      for (const block of content) {
        if (block?.type !== "tool_result" || typeof block.tool_use_id !== "string") continue;
        const match = calls.get(block.tool_use_id);
        if (!match || (row.sourceToolAssistantUUID && match.uuid && row.sourceToolAssistantUUID !== match.uuid)) continue;
        if (match.result) {
          match.result.ambiguous = true;
          continue;
        }
        const result = toolResult(block, row, match.call);
        if (result) {
          match.result = { ...result, stepIndex };
          events.push(match.result);
        } else {
          calls.set(block.tool_use_id, null);
        }
      }
      continue;
    }
    if (row.isMeta || row.isCompactSummary || row.isVisibleInTranscriptOnly || row.toolUseResult !== undefined ||
        row.sourceToolAssistantUUID) continue;
    const prompt = userText(content);
    if (!prompt) continue;
    if (!hasHeader && prompt.oversized) return { available: false, events: [] };
    hasHeader = true;
    calls.clear();
    events.push({ type: "USER_INPUT", stepIndex, content: prompt.text });
    if (headerOnly) break;
  }
  if (!claude) return null;
  if (malformed) return { available: false, events: [] };
  return { available: hasHeader, events: events.filter((event) => !event.ambiguous), sidechain: Boolean(sidechain) };
}

function* fileLines(fd, size, headerOnly) {
  const buf = Buffer.allocUnsafe(64 * 1024);
  let pos = 0;
  let pieces = [];
  let bytes = 0;
  while (pos < size) {
    if ((headerOnly && pos >= HEADER_BYTES) || pos >= FILE_BYTES) {
      yield null;
      return;
    }
    const count = readSync(fd, buf, 0, Math.min(buf.length, size - pos), pos);
    if (count <= 0) {
      yield null;
      return;
    }
    pos += count;
    for (let start = 0; start < count;) {
      const nl = buf.indexOf(10, start);
      const end = nl < 0 || nl >= count ? count : nl;
      bytes += end - start;
      if (bytes > LINE_BYTES) {
        yield null;
        return;
      }
      if (end === count) {
        pieces.push(Buffer.from(buf.subarray(start, end)));
      } else {
        yield pieces.length === 0 ? buf.toString("utf8", start, end) :
          Buffer.concat([...pieces, buf.subarray(start, end)], bytes).toString("utf8");
        pieces = [];
        bytes = 0;
      }
      start = end + 1;
    }
  }
  if (pieces.length > 0) yield Buffer.concat(pieces, bytes).toString("utf8");
}

// Its own raw reader keeps host and ledger imports acyclic. Agy exits on its first known record.
export function readClaudeTranscript(filePath, { headerOnly = false } = {}) {
  const fd = openSync(filePath, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) return { available: false, events: [] };
    const parent = dirname(filePath);
    const agent = basename(parent) === "subagents" && /^agent-([a-z0-9-]+)\.jsonl$/i.exec(basename(filePath));
    const sidechain = agent ? { agentId: agent[1], sessionId: basename(dirname(parent)) } : null;
    const lines = fileLines(fd, stat.size, headerOnly);
    const decoded = decode(lines, headerOnly || stat.size > FILE_BYTES, sidechain);
    return decoded && !headerOnly && stat.size > FILE_BYTES ? { available: false, events: [] } : decoded;
  } finally {
    closeSync(fd);
  }
}

export function parseClaudeTranscript(rawText) {
  function* lines() {
    for (let start = 0; start < rawText.length;) {
      const nl = rawText.indexOf("\n", start);
      const end = nl < 0 ? rawText.length : nl;
      yield end > FILE_BYTES || end - start > LINE_BYTES ? null : rawText.slice(start, end);
      if (end > FILE_BYTES || end - start > LINE_BYTES) return;
      start = end + 1;
    }
  }
  return decode(lines(), false);
}
