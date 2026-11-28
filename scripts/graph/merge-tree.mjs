// The integrator's three-way merge (SSOT 4.5, D16): `git merge-tree --write-tree` on the engine git scope,
// classified by exit code AND output shape, never by exit code alone.
//
// Byte layouts measured against git 2.43.0 (-z --name-only):
//   single, clean     rc 0  <tree>\0
//   single, conflict  rc 1  <tree>\0 <path>\0 ... \0 <message>...
//   --stdin, per line rc 0  <status>\0 <tree>\0 [<path>\0 ... \0 <message>...] \0
//   <message> is      <count>\0 <path>\0 x count <type>\0 <text>\0   e.g. 1\0f\0Auto-merging\0Auto-merging f\n\0
// A clean merge prints no message section even after an auto-merge. Under --stdin the status is inverted
// (1 = clean, 0 = conflict), the process exits 0 with conflicts, and exits 1 with the earlier records already
// written when one line names something it cannot merge. A bad ref or missing OID in single mode is rc 1 with
// empty stdout; a tree as --merge-base is 128, an extra argument 129, unrelated histories (without
// --merge-base) 128.
import { git } from "./git.mjs";
import { graphError } from "./schema.mjs";

const TREE = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
const COUNT = /^[1-9][0-9]*$/;
// Refs reach git as argv words or --stdin line words: no option lookalikes, no whitespace.
const REF = /^[^\s-]\S*$/;
const decoder = new TextDecoder("utf-8", { fatal: true });

const failed = (message, result) => Object.assign(graphError("ERR_GIT_MERGE_FAILED", message),
  { exitCode: result.code, stderr: result.stderr.toString("utf8") });
const inputError = (message, result) => Object.assign(graphError("ERR_GIT_MERGE_INPUT", message),
  result ? { exitCode: result.code, stderr: result.stderr.toString("utf8") } : {});

class Malformed extends Error {}

// A cursor over NUL-terminated tokens that keeps byte offsets, so message bytes stay raw for the CAS.
function tokens(buffer) {
  let pos = 0;
  return {
    get pos() { return pos; },
    atEnd: () => pos === buffer.length,
    peekEmpty: () => buffer[pos] === 0,
    next() {
      const end = buffer.indexOf(0, pos);
      if (end < 0) throw new Malformed("unterminated token");
      const token = buffer.subarray(pos, end);
      pos = end + 1;
      return token;
    },
    text(token) {
      try { return decoder.decode(token); } catch (cause) {
        if (cause instanceof TypeError) throw new Malformed("token is not UTF-8");
        throw cause;
      }
    },
  };
}

function readTree(cursor) {
  const tree = cursor.text(cursor.next());
  if (!TREE.test(tree)) throw new Malformed("missing tree OID");
  return tree;
}

// Conflicted paths up to the empty separator, then whole messages until the end of the record.
function readConflict(cursor, buffer, endOfRecord) {
  const paths = [];
  for (let token = cursor.next(); token.length; token = cursor.next()) paths.push(cursor.text(token));
  if (!paths.length) throw new Malformed("conflict without paths");
  const start = cursor.pos;
  while (!endOfRecord()) {
    const count = cursor.text(cursor.next());
    if (!COUNT.test(count)) throw new Malformed("message without a path count");
    for (let i = 0; i < Number(count) + 2; i += 1) cursor.next(); // paths, type, text
  }
  return { paths, messages: Buffer.from(buffer.subarray(start, cursor.pos)) };
}

/** Clean tree, or conflict paths and raw message bytes. The conflict tree holds marker blobs: diagnostics only. */
export function classifyMergeTree({ code, stdout, stderr }) {
  const result = { code, stdout, stderr };
  if (code === 1 && stdout.length === 0) throw inputError("git merge-tree could not resolve its inputs", result);
  if (code !== 0 && !(code === 1 && stderr.length === 0)) throw failed(`git merge-tree exited ${code}`, result);
  const cursor = tokens(stdout);
  try {
    const tree = readTree(cursor);
    if (code === 0) {
      if (!cursor.atEnd()) throw new Malformed("trailing bytes after a clean tree");
      return { kind: "clean", tree };
    }
    return { kind: "conflict", tree, ...readConflict(cursor, stdout, cursor.atEnd) };
  } catch (error) {
    if (error instanceof Malformed) throw failed(`git merge-tree output is malformed: ${error.message}`, result);
    throw error;
  }
}

function refsOf({ base, ours, theirs }) {
  const refs = [base, ours, theirs];
  if (!refs.every(ref => typeof ref === "string" && REF.test(ref))) throw inputError("merge-tree refs must be plain revisions");
  return refs;
}

/** One merge on the engine scope with an explicit base; unrelated-history merges are never allowed. */
export async function mergeTree(cwd, request) {
  const [base, ours, theirs] = refsOf(request);
  return classifyMergeTree(await git(["merge-tree", "--write-tree", "-z", "--name-only", `--merge-base=${base}`, ours, theirs],
    { cwd }));
}

/** Many merges in one process; results follow request order. */
export async function mergeTreeBatch(cwd, requests) {
  if (!Array.isArray(requests) || !requests.length) throw inputError("merge-tree batch needs at least one request");
  const input = requests.map(request => {
    const [base, ours, theirs] = refsOf(request);
    return `${base} -- ${ours} ${theirs}\n`;
  }).join("");
  const result = await git(["merge-tree", "--write-tree", "-z", "--name-only", "--stdin"], { cwd, input });
  if (result.code === 1) throw inputError("git merge-tree --stdin could not resolve a request", result);
  if (result.code !== 0) throw failed(`git merge-tree --stdin exited ${result.code}`, result);
  const cursor = tokens(result.stdout);
  const records = [];
  try {
    while (!cursor.atEnd()) {
      const status = cursor.text(cursor.next());
      const tree = readTree(cursor);
      if (status === "1") records.push({ kind: "clean", tree });
      else if (status === "0") records.push({ kind: "conflict", tree, ...readConflict(cursor, result.stdout, cursor.peekEmpty) });
      else throw new Malformed(`unknown record status ${JSON.stringify(status)}`);
      if (cursor.next().length) throw new Malformed("record without terminator");
    }
    if (records.length !== requests.length) throw new Malformed(`${records.length} records for ${requests.length} requests`);
  } catch (error) {
    if (error instanceof Malformed) throw failed(`git merge-tree --stdin output is malformed: ${error.message}`, result);
    throw error;
  }
  return records;
}
