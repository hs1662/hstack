import { AsyncLocalStorage } from "node:async_hooks";
import { closeSync, existsSync, fstatSync, openSync, readSync, realpathSync, statSync } from "node:fs";
import { detectHost, normalizeHookEvent, resolveHostPaths } from "./host/host-adapter.mjs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  KEPT_STEP_TYPES,
  PRE_TOOL_DENIAL_NEEDLE,
  isPreToolDenialStep,
  parseTranscriptJsonlWithStats,
} from "./transcript.mjs";
import { claudeEventsToSteps, createResultOrdinalCounter, parseRawRecord, parseStepIndex, recordToStep } from "./transcript/steps.mjs";
import { readClaudeTranscript } from "./host/claude-transcript.mjs";

const CHUNK_SIZE = 256 * 1024;
const PREFIX_SCAN_BYTES = 256;
const NEWLINE_BYTE = 0x0a;
const PROBE_MAX_BYTES = 1024 * 1024;
const TAIL_SCAN_MIN_BYTES = 1024 * 1024;
const TAIL_START_BYTES = 256 * 1024;
// Bounds each backward read so a long search does not hold one huge buffer.
const TAIL_MAX_CHUNK_BYTES = 4 * 1024 * 1024;

function isAsciiWhitespace(byte) {
  return byte === 0x20 || byte === 0x09 || byte === 0x0d || byte === 0x0a;
}

function skipWhitespace(buf, start) {
  let i = start;
  while (i < buf.length && isAsciiWhitespace(buf[i])) {
    i += 1;
  }
  return i;
}

const JSON_OBJ = 0;
const JSON_ARR = 1;
const LIT_TRUE = [0x72, 0x75, 0x65];
const LIT_FALSE = [0x61, 0x6c, 0x73, 0x65];
const LIT_NULL = [0x75, 0x6c, 0x6c];

function isDigit(byte) {
  return byte >= 0x30 && byte <= 0x39;
}

function isHexDigit(byte) {
  return isDigit(byte) || (byte >= 0x41 && byte <= 0x46) || (byte >= 0x61 && byte <= 0x66);
}

function isValidEscapeByte(byte) {
  return (
    byte === 0x22 ||
    byte === 0x5c ||
    byte === 0x2f ||
    byte === 0x62 ||
    byte === 0x66 ||
    byte === 0x6e ||
    byte === 0x72 ||
    byte === 0x74
  );
}

function createJsonObjectValidator() {
  return {
    mode: "root",
    stack: [],
    strForKey: false,
    uniLeft: 0,
    numState: "",
    litTarget: null,
    litPos: 0,
    valid: true,
  };
}

function finishContainerOrValue(state) {
  state.mode = state.stack.length === 0 ? "done" : "afterVal";
}

function startJsonValue(state, b) {
  if (b === 0x22) {
    state.mode = "string";
    state.strForKey = false;
  } else if (b === 0x7b) {
    state.stack.push(JSON_OBJ);
    state.mode = "objKeyOrEnd";
  } else if (b === 0x5b) {
    state.stack.push(JSON_ARR);
    state.mode = "arrValOrEnd";
  } else if (b === 0x2d) {
    state.mode = "number";
    state.numState = "sign";
  } else if (b === 0x30) {
    state.mode = "number";
    state.numState = "zero";
  } else if (b >= 0x31 && b <= 0x39) {
    state.mode = "number";
    state.numState = "int";
  } else if (b === 0x74) {
    state.mode = "literal";
    state.litTarget = LIT_TRUE;
    state.litPos = 0;
  } else if (b === 0x66) {
    state.mode = "literal";
    state.litTarget = LIT_FALSE;
    state.litPos = 0;
  } else if (b === 0x6e) {
    state.mode = "literal";
    state.litTarget = LIT_NULL;
    state.litPos = 0;
  } else {
    state.valid = false;
  }
}

const STRING_SPECIAL_RE = /["\\\x00-\x1f]/g;
const NATIVE_SCAN_MIN_BYTES = 4096;

function advanceJsonObjectValidator(state, buf, start, end) {
  // Huge tool outputs are long plain string runs: a latin1 view of the segment lets the regex engine find
  // each run's end natively, once per segment, instead of dispatching on every byte.
  const latin1 = end - start >= NATIVE_SCAN_MIN_BYTES ? buf.toString("latin1", start, end) : null;
  for (let i = start; i < end && state.valid; i += 1) {
    const mode = state.mode;

    if (mode === "string") {
      if (latin1 !== null) {
        STRING_SPECIAL_RE.lastIndex = i - start;
        const special = STRING_SPECIAL_RE.exec(latin1);
        i = special ? start + special.index : end;
      } else {
        while (i < end && buf[i] !== 0x22 && buf[i] !== 0x5c && buf[i] >= 0x20) {
          i += 1;
        }
      }
      if (i === end) {
        break;
      }
      const b = buf[i];
      if (b === 0x22) {
        if (state.strForKey) {
          state.mode = "objColon";
        } else {
          finishContainerOrValue(state);
        }
      } else if (b === 0x5c) {
        state.mode = "escape";
      } else if (b < 0x20) {
        state.valid = false;
      }
      continue;
    }

    const b = buf[i];
    if (mode === "escape") {
      if (b === 0x75) {
        state.mode = "unicode";
        state.uniLeft = 4;
      } else if (isValidEscapeByte(b)) {
        state.mode = "string";
      } else {
        state.valid = false;
      }
      continue;
    }

    if (mode === "unicode") {
      if (!isHexDigit(b)) {
        state.valid = false;
      } else {
        state.uniLeft -= 1;
        if (state.uniLeft === 0) {
          state.mode = "string";
        }
      }
      continue;
    }

    if (mode === "number") {
      const ns = state.numState;
      if (ns === "sign") {
        if (b === 0x30) state.numState = "zero";
        else if (b >= 0x31 && b <= 0x39) state.numState = "int";
        else state.valid = false;
      } else if (ns === "zero") {
        if (b === 0x2e) state.numState = "dot";
        else if (b === 0x65 || b === 0x45) state.numState = "expSign";
        else {
          finishContainerOrValue(state);
          i -= 1;
        }
      } else if (ns === "int") {
        if (isDigit(b)) continue;
        if (b === 0x2e) state.numState = "dot";
        else if (b === 0x65 || b === 0x45) state.numState = "expSign";
        else {
          finishContainerOrValue(state);
          i -= 1;
        }
      } else if (ns === "dot") {
        if (isDigit(b)) state.numState = "frac";
        else state.valid = false;
      } else if (ns === "frac") {
        if (isDigit(b)) continue;
        if (b === 0x65 || b === 0x45) state.numState = "expSign";
        else {
          finishContainerOrValue(state);
          i -= 1;
        }
      } else if (ns === "expSign") {
        if (b === 0x2b || b === 0x2d) state.numState = "exp";
        else if (isDigit(b)) state.numState = "expDigits";
        else state.valid = false;
      } else if (ns === "exp") {
        if (isDigit(b)) state.numState = "expDigits";
        else state.valid = false;
      } else if (ns === "expDigits") {
        if (isDigit(b)) continue;
        finishContainerOrValue(state);
        i -= 1;
      }
      continue;
    }

    if (mode === "literal") {
      if (b !== state.litTarget[state.litPos]) {
        state.valid = false;
      } else {
        state.litPos += 1;
        if (state.litPos === state.litTarget.length) {
          finishContainerOrValue(state);
        }
      }
      continue;
    }

    if (isAsciiWhitespace(b)) {
      continue;
    }

    if (mode === "root") {
      if (b === 0x7b) {
        state.stack.push(JSON_OBJ);
        state.mode = "objKeyOrEnd";
      } else {
        state.valid = false;
      }
    } else if (mode === "objKeyOrEnd") {
      if (b === 0x7d) {
        state.stack.pop();
        finishContainerOrValue(state);
      } else if (b === 0x22) {
        state.mode = "string";
        state.strForKey = true;
      } else {
        state.valid = false;
      }
    } else if (mode === "objKey") {
      if (b === 0x22) {
        state.mode = "string";
        state.strForKey = true;
      } else {
        state.valid = false;
      }
    } else if (mode === "objColon") {
      if (b === 0x3a) {
        state.mode = "value";
      } else {
        state.valid = false;
      }
    } else if (mode === "arrValOrEnd") {
      if (b === 0x5d) {
        state.stack.pop();
        finishContainerOrValue(state);
      } else {
        startJsonValue(state, b);
      }
    } else if (mode === "value") {
      startJsonValue(state, b);
    } else if (mode === "afterVal") {
      const top = state.stack[state.stack.length - 1];
      if (b === 0x2c) {
        state.mode = top === JSON_OBJ ? "objKey" : "value";
      } else if (b === 0x7d && top === JSON_OBJ) {
        state.stack.pop();
        finishContainerOrValue(state);
      } else if (b === 0x5d && top === JSON_ARR) {
        state.stack.pop();
        finishContainerOrValue(state);
      } else {
        state.valid = false;
      }
    } else {
      state.valid = false;
    }
  }
}

function isValidJsonObjectComplete(state) {
  return Boolean(state && state.valid && state.mode === "done" && state.stack.length === 0);
}

function scanJsonStringEnd(buf, openQuoteIdx) {
  const len = buf.length;
  let hasEscape = false;
  for (let i = openQuoteIdx + 1; i < len; i += 1) {
    const b = buf[i];
    if (b === 0x5c) {
      hasEscape = true;
      i += 1;
      continue;
    }
    if (b === 0x22) {
      return { end: i, hasEscape };
    }
  }
  return null;
}

export function resolvePluginDataDir() {
  return resolveHostPaths(transcriptHost.getStore() ?? detectHost()).dataDir;
}

export function extractLinePrefixType(prefixBuf) {
  const len = prefixBuf.length;
  let i = skipWhitespace(prefixBuf, 0);
  if (i >= len || prefixBuf[i] !== 0x7b) {
    return null;
  }

  let depth = 0;
  let expectKeyAtDepth1 = false;

  while (i < len) {
    const b = prefixBuf[i];
    if (b === 0x22) {
      const str = scanJsonStringEnd(prefixBuf, i);
      if (!str) {
        return null;
      }

      if (depth === 1 && expectKeyAtDepth1) {
        expectKeyAtDepth1 = false;
        if (str.hasEscape) {
          return null;
        }
        if (str.end - i === 5 && prefixBuf.toString("latin1", i + 1, str.end) === "type") {
          let j = skipWhitespace(prefixBuf, str.end + 1);
          if (j >= len || prefixBuf[j] !== 0x3a) {
            return null;
          }
          j = skipWhitespace(prefixBuf, j + 1);
          if (j >= len || prefixBuf[j] !== 0x22) {
            return null;
          }
          const val = scanJsonStringEnd(prefixBuf, j);
          if (!val || val.hasEscape) {
            return null;
          }
          return prefixBuf.subarray(j + 1, val.end).toString("latin1");
        }
      }

      i = str.end + 1;
      continue;
    }

    if (b === 0x7b || b === 0x5b) {
      depth += 1;
      if (depth === 1 && b === 0x7b) {
        expectKeyAtDepth1 = true;
      }
    } else if (b === 0x7d || b === 0x5d) {
      depth -= 1;
      if (depth <= 0) {
        break;
      }
    } else if (depth === 1) {
      if (b === 0x2c) {
        expectKeyAtDepth1 = true;
      } else if (b === 0x3a) {
        expectKeyAtDepth1 = false;
      }
    }

    i += 1;
  }

  return null;
}

function stripBomBytes(buf, isFirstLine) {
  const hasBom = isFirstLine && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf;
  return hasBom ? buf.subarray(3) : buf;
}

function isBlankAsciiBuffer(buf) {
  for (let i = 0; i < buf.length; i += 1) {
    if (!isAsciiWhitespace(buf[i])) {
      return false;
    }
  }
  return true;
}

function isValidSkippedShortLine(buf) {
  const state = createJsonObjectValidator();
  advanceJsonObjectValidator(state, buf, 0, buf.length);
  return isValidJsonObjectComplete(state);
}

/**
 * Streams a JSONL transcript file in 256KiB chunks without loading huge skipped lines into memory.
 *
 * Visitor contract:
 * 1. Peek phase: `visitor(prefixType, null)` is called once the top-level `"type"` is scanned from the
 *    first 256 bytes (or for short lines <= 256B, before delivery).
 *    - Return `false` to skip the line without buffering or JSON.parse (the line is still validated in
 *      O(1) memory so `validRecordCount` stays exact).
 *    - Return a positive finite number to buffer the line up to that byte cap and drop to skip mode if exceeded.
 *    - Return anything else to buffer the full line.
 * 2. Record phase: `visitor(prefixType, lineBuf, recordIndex)` receives a Buffer (UTF-8 BOM stripped on line 1)
 *    and the 0-based count of valid JSON records seen before this line. Return `false` if the record was NOT a
 *    valid tracked JSON object; otherwise `validRecordCount` is incremented.
 */
export function streamTranscriptRecords(filePath, visitor, options = {}) {
  const onSkipped = typeof options?.onSkipped === "function" ? options.onSkipped : null;
  const shouldStop = typeof options?.shouldStop === "function" ? options.shouldStop : () => false;
  let filePos = Number.isSafeInteger(options?.startOffset) && options.startOffset > 0 ? options.startOffset : 0;
  let discardPartialLine = filePos > 0;
  const fd = openSync(filePath, "r");
  const prefixBuf = Buffer.allocUnsafe(PREFIX_SCAN_BYTES);

  let validRecordCount = 0;
  let lineState = "undecided";
  let linePrefixType = null;
  let lineByteLimit = Infinity;
  let prefixLen = 0;
  let lineChunks = [];
  let lineBytes = 0;
  let skipValidator = null;
  let isFirstLine = !discardPartialLine;
  let lineStartPos = 0;

  const startSkipValidator = (buffers) => {
    skipValidator = createJsonObjectValidator();
    for (let i = 0; i < buffers.length; i += 1) {
      const segment = i === 0 ? stripBomBytes(buffers[i], isFirstLine) : buffers[i];
      advanceJsonObjectValidator(skipValidator, segment, 0, segment.length);
    }
  };

  const applyPeekDecision = (prefixSlice, decision, prefixView) => {
    if (decision === false) {
      lineState = "skip";
      startSkipValidator([prefixSlice]);
      return;
    }
    lineState = "keep";
    lineByteLimit = typeof decision === "number" && Number.isFinite(decision) && decision > 0 ? decision : Infinity;
    lineChunks = [prefixView ?? Buffer.from(prefixSlice)];
    lineBytes = prefixSlice.length;
  };

  // Every read gets a fresh buffer, so kept lines hold views into it instead of copies.
  const pushView = (view, start, end) => {
    const last = lineChunks[lineChunks.length - 1];
    if (last && last.buffer === view.buffer && last.byteOffset + last.length === view.byteOffset + start) {
      lineChunks[lineChunks.length - 1] = Buffer.from(view.buffer, last.byteOffset, last.length + end - start);
    } else {
      lineChunks.push(view.subarray(start, end));
    }
  };

  const appendSegment = (view, start, end) => {
    if (start >= end) {
      return;
    }
    if (lineByteLimit !== Infinity) {
      lineBytes += end - start;
      if (lineBytes > lineByteLimit) {
        lineState = "skip";
        startSkipValidator(lineChunks);
        advanceJsonObjectValidator(skipValidator, view, start, end);
        lineChunks = [];
        return;
      }
    }
    pushView(view, start, end);
  };

  const deliverLine = (prefixType, buf) => {
    const accepted = visitor(prefixType, buf, validRecordCount);
    if (accepted !== false) {
      validRecordCount += 1;
    }
  };

  const finishSkippedLine = (prefixType, isValid) => {
    const recordIndex = validRecordCount;
    if (isValid) {
      validRecordCount += 1;
    }
    if (onSkipped) {
      onSkipped(prefixType, isValid, recordIndex);
    }
  };

  const finalizeLine = () => {
    if (lineState === "skip") {
      finishSkippedLine(linePrefixType, isValidJsonObjectComplete(skipValidator));
    } else if (lineState === "undecided") {
      const prefixSlice = stripBomBytes(prefixBuf.subarray(0, prefixLen), isFirstLine);
      if (!isBlankAsciiBuffer(prefixSlice)) {
        const prefixType = extractLinePrefixType(prefixSlice);
        const decision = visitor(prefixType, null);
        if (decision === false) {
          finishSkippedLine(prefixType, isValidSkippedShortLine(prefixSlice));
        } else if (typeof decision === "number" && Number.isFinite(decision) && decision > 0 && prefixSlice.length > decision) {
          finishSkippedLine(prefixType, isValidSkippedShortLine(prefixSlice));
        } else {
          deliverLine(prefixType, prefixSlice);
        }
      }
    } else if (lineChunks.length > 0) {
      const joined = lineChunks.length === 1 ? lineChunks[0] : Buffer.concat(lineChunks);
      deliverLine(linePrefixType, joined);
    }

    isFirstLine = false;
    lineState = "undecided";
    linePrefixType = null;
    lineByteLimit = Infinity;
    prefixLen = 0;
    lineChunks = [];
    lineBytes = 0;
    skipValidator = null;
  };

  try {
    for (;;) {
      const chunk = Buffer.allocUnsafe(CHUNK_SIZE);
      const bytesRead = readSync(fd, chunk, 0, CHUNK_SIZE, filePos);
      if (bytesRead <= 0) {
        break;
      }
      filePos += bytesRead;
      const view = chunk.subarray(0, bytesRead);
      let pos = 0;
      // A line that starts this read starts at byte 0 of it, not where the last read ended.
      lineStartPos = 0;
      if (discardPartialLine) {
        const nlIdx = view.indexOf(NEWLINE_BYTE);
        if (nlIdx === -1) {
          continue;
        }
        discardPartialLine = false;
        pos = nlIdx + 1;
        lineStartPos = pos;
      }
      if (lineState !== "undecided" || prefixLen > 0) {
        lineStartPos = -1;
      }
      while (pos < bytesRead) {
        const nlIdx = view.indexOf(NEWLINE_BYTE, pos);
        const segEnd = nlIdx !== -1 ? nlIdx : bytesRead;

        if (lineState === "undecided") {
          const copyLen = Math.min(PREFIX_SCAN_BYTES - prefixLen, segEnd - pos);
          view.copy(prefixBuf, prefixLen, pos, pos + copyLen);
          prefixLen += copyLen;
          pos += copyLen;
          if (prefixLen === PREFIX_SCAN_BYTES && (pos < segEnd || nlIdx === -1)) {
            const prefixSlice = stripBomBytes(prefixBuf, isFirstLine);
            const prefixView = lineStartPos >= 0 ? stripBomBytes(view.subarray(lineStartPos, pos), isFirstLine) : null;
            linePrefixType = extractLinePrefixType(prefixSlice);
            applyPeekDecision(prefixSlice, visitor(linePrefixType, null), prefixView);
          }
        }
        if (lineState === "skip") {
          advanceJsonObjectValidator(skipValidator, view, pos, segEnd);
        } else if (lineState === "keep") {
          appendSegment(view, pos, segEnd);
        }
        pos = segEnd;
        if (nlIdx !== -1) {
          finalizeLine();
          if (shouldStop()) {
            return { hasContent: validRecordCount > 0, validRecordCount };
          }
          pos = nlIdx + 1;
          lineStartPos = pos;
        }
      }
    }
    if (prefixLen > 0 || lineChunks.length > 0 || skipValidator !== null) {
      finalizeLine();
    }
  } finally {
    closeSync(fd);
  }

  return { hasContent: validRecordCount > 0, validRecordCount };
}

// Collects hook steps from streamed records. With a `limit`, keeps only the last `limit` steps plus the
// latest USER_INPUT, so drift checks on huge sessions replay a bounded tail.
export function createStepCollector(limit = Infinity) {
  let steps = [];
  let latestUserStep = null;
  let decision = true;
  let count = 0;
  // Skipped GENERIC lines still count as results, so ordinals come from the line type, not from kept steps.
  const results = createResultOrdinalCounter();
  let ordinal = -1;
  return {
    get count() {
      return count;
    },
    peek(prefixType) {
      ordinal = prefixType === null ? -1 : results.next(prefixType);
      if (prefixType === null || KEPT_STEP_TYPES.has(prefixType)) {
        decision = true;
      } else {
        decision = prefixType === "GENERIC" ? PROBE_MAX_BYTES : false;
      }
      return decision;
    },
    visit(prefixType, lineBytes, rawLine, parsed, recordIndex) {
      if (prefixType === null) {
        ordinal = results.next(parsed.type);
      }
      if (decision === false || (typeof decision === "number" && lineBytes > decision)) {
        return;
      }
      if (prefixType === "GENERIC" && !(rawLine.toLowerCase().includes(PRE_TOOL_DENIAL_NEEDLE) && isPreToolDenialStep(parsed))) {
        return;
      }
      const step = recordToStep(parsed, recordIndex);
      if (!step) {
        return;
      }
      if (step.type === "GENERIC") {
        step.resultOrdinal = ordinal;
      }
      steps.push(step);
      count += 1;
      if (step.type === "USER_INPUT") {
        latestUserStep = step;
      }
      if (steps.length >= limit * 2) {
        steps = steps.slice(-limit);
      }
    },
    steps() {
      const tail = steps.length > limit ? steps.slice(-limit) : steps;
      return latestUserStep && !tail.includes(latestUserStep) ? [latestUserStep, ...tail] : tail;
    },
  };
}

function readTranscriptStepsFast(filePath) {
  const claude = readClaudeTranscript(filePath);
  if (claude) return { hasContent: claude.available, steps: claudeEventsToSteps(claude.events) };
  const collector = createStepCollector();
  const { hasContent } = streamTranscriptRecords(filePath, (prefixType, lineBuf, recordIndex) => {
    if (lineBuf === null) {
      return collector.peek(prefixType);
    }
    const rawLine = lineBuf.toString("utf8");
    const parsed = parseRawRecord(rawLine);
    if (!parsed) {
      return false;
    }
    collector.visit(prefixType, lineBuf.length, rawLine, parsed, recordIndex);
    return true;
  });

  return { hasContent, steps: collector.steps() };
}

// The last `limit` steps from a tail window that doubles until it holds them. Small files, and windows
// with a record lacking a numeric step index (its fallback index needs the full count), read everything.
export function readTailTranscriptSteps(filePath, limit) {
  const claude = readClaudeTranscript(filePath);
  if (claude) return claudeEventsToSteps(claude.events, limit);
  const size = statSync(filePath).size;
  for (let window = TAIL_START_BYTES; size > TAIL_SCAN_MIN_BYTES && window < size; window *= 2) {
    const collector = createStepCollector(limit);
    let indexed = true;
    streamTranscriptRecords(
      filePath,
      (prefixType, lineBuf, recordIndex) => {
        if (lineBuf === null) {
          return collector.peek(prefixType);
        }
        const rawLine = lineBuf.toString("utf8");
        const parsed = parseRawRecord(rawLine);
        if (!parsed) {
          return false;
        }
        indexed &&= parseStepIndex(parsed.step_index !== undefined ? parsed.step_index : parsed.stepIndex, null) !== null;
        collector.visit(prefixType, lineBuf.length, rawLine, parsed, recordIndex);
        return true;
      },
      { startOffset: size - window },
    );
    if (!indexed) {
      break;
    }
    if (collector.count >= limit) {
      return collector.steps();
    }
  }
  return readTranscriptStepsFast(filePath).steps;
}

export const LINE_TOO_LONG = Symbol("line too long");

// Byte offset of the last line before `end` that contains `needle` and that `accept` takes (it returns a truthy
// value, given back as `value`), reading backwards in chunks that double from 256KiB. Null when no line that
// starts at or after `start` qualifies; LINE_TOO_LONG when a line over 4MiB is in the way, so buffers stay bounded.
export function findLastLine(filePath, needle, accept, { start = 0, end = Infinity } = {}) {
  const needleBuf = Buffer.from(needle);
  const fd = openSync(filePath, "r");
  try {
    let hi = Math.min(end, fstatSync(fd).size);
    // Bytes past `hi` that belong to the first, possibly partial, line of the region already searched; they are
    // read again with the next chunk rather than copied, since that line is usually short.
    let carryLen = 0;
    for (let chunk = TAIL_START_BYTES; hi > start; chunk = Math.min(chunk * 2, TAIL_MAX_CHUNK_BYTES)) {
      // Reading one byte before `start` shows whether a line begins exactly at `start`.
      const lo = hi - chunk > start ? hi - chunk : Math.max(0, start - 1);
      const buf = Buffer.allocUnsafe(hi - lo + carryLen);
      for (let got = 0; got < buf.length; ) {
        const n = readSync(fd, buf, got, buf.length - got, lo + got);
        if (n <= 0) {
          return null;
        }
        got += n;
      }
      const firstNl = lo === 0 ? -1 : buf.indexOf(NEWLINE_BYTE);
      const complete = lo === 0 ? 0 : firstNl === -1 ? buf.length : firstNl + 1;
      for (let from = buf.length; from >= complete; ) {
        const hit = buf.lastIndexOf(needleBuf, from);
        if (hit < complete) {
          break;
        }
        const lineStart = buf.lastIndexOf(NEWLINE_BYTE, hit) + 1;
        const nl = buf.indexOf(NEWLINE_BYTE, hit);
        const value = accept(buf.subarray(lineStart, nl === -1 ? buf.length : nl));
        if (value) {
          return { offset: lo + lineStart, value };
        }
        from = lineStart - 1;
      }
      if (lo > start && complete > TAIL_MAX_CHUNK_BYTES) {
        return LINE_TOO_LONG;
      }
      carryLen = complete;
      hi = lo;
    }
    return null;
  } finally {
    closeSync(fd);
  }
}

// Every ledger reader, including nested calls, must use the host-supplied path on Claude.
const transcriptHost = new AsyncLocalStorage();
export function withTranscriptHost(host, callback) {
  return transcriptHost.run(host, callback);
}

export function resolveTranscriptCandidates(transcriptPath) {
  if ((transcriptHost.getStore() ?? detectHost()) !== "claude-code" && basename(transcriptPath) === "transcript.jsonl") {
    const full = join(dirname(transcriptPath), "transcript_full.jsonl");
    if (existsSync(full)) {
      try {
        if (readClaudeTranscript(transcriptPath, { headerOnly: true }) !== null) return [transcriptPath];
      } catch (error) {
        if (error.code !== "ENOENT" && error.code !== "ENOTDIR") return [transcriptPath];
      }
    }
    return [full, transcriptPath];
  }
  return [transcriptPath];
}

export function pickPreferredTranscriptPath(rawTranscriptPath) {
  if (typeof rawTranscriptPath !== "string") {
    return "";
  }
  const trimmed = rawTranscriptPath.trim();
  if (trimmed.length === 0) {
    return "";
  }
  for (const candidate of resolveTranscriptCandidates(trimmed)) {
    try {
      if (existsSync(candidate)) {
        return candidate;
      }
    } catch {
      continue;
    }
  }
  return trimmed;
}

function readTranscript(transcriptPath, readTextFile) {
  let available = false;
  for (const candidatePath of resolveTranscriptCandidates(transcriptPath)) {
    try {
      let result;
      if (typeof readTextFile === "function") {
        const content = readTextFile(candidatePath);
        if (typeof content !== "string" || content.trim().length === 0) {
          continue;
        }
        const parsed = parseTranscriptJsonlWithStats(content);
        result = { hasContent: parsed.validRecordCount > 0, steps: parsed.steps };
      } else {
        result = readTranscriptStepsFast(candidatePath);
      }
      if (result.steps.length > 0) {
        return { steps: result.steps, available: true };
      }
      available = available || result.hasContent;
    } catch {
      continue;
    }
  }
  return { steps: [], available };
}

export function readTranscriptSteps(transcriptPath, readTextFile) {
  return readTranscript(transcriptPath, readTextFile).steps;
}

export function parseHookPayload(stdinText, expectedEventName) {
  if (typeof stdinText !== "string" || stdinText.trim().length === 0) {
    return null;
  }
  let payload;
  try {
    payload = JSON.parse(stdinText);
  } catch {
    return null;
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return null;
  }
  const name = payload.hookEventName ?? payload.hook_event_name;
  if (expectedEventName && name !== undefined && name !== null && name !== "" && name !== expectedEventName) {
    return null;
  }
  // Claude's ingress calls this without an expectedName for its untouched wire
  // record. Legacy handlers take the same canonical view for both Agy spellings.
  return expectedEventName && payload.host !== "claude-code" ? normalizeHookEvent("antigravity", payload) : payload;
}

export function isDirectExecution(moduleUrl) {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(fileURLToPath(moduleUrl)) === realpathSync(resolve(process.argv[1]));
  } catch {
    return fileURLToPath(moduleUrl) === resolve(process.argv[1]);
  }
}

export function payloadTranscriptPath(payload) {
  const rawPath = payload.transcriptPath ?? payload.transcript_path;
  return typeof rawPath === "string" ? rawPath.trim() : "";
}

export function loadHookContext(stdinText, eventName, readTextFile) {
  const payload = parseHookPayload(stdinText, eventName);
  if (!payload) return null;
  const transcriptPath = payloadTranscriptPath(payload);
  const { steps, available } =
    transcriptPath.length > 0 ? readTranscript(transcriptPath, readTextFile) : { steps: [], available: false };
  return { payload, transcriptPath, steps, transcriptAvailable: available };
}

function isPlainObject(value) {
  return !!value && typeof value === "object" && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}

export async function runHookCli(handler, fallbackOutput = {}) {
  let output;
  try {
    process.stdin.setEncoding("utf8");
    let stdinText = "";
    for await (const chunk of process.stdin) stdinText += chunk;
    output = handler(stdinText);
  } catch {
    output = fallbackOutput;
  }
  process.stdout.write(`${JSON.stringify(isPlainObject(output) ? output : fallbackOutput)}\n`);
}
