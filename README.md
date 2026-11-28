# hstack

[한국어](README.ko.md)

`hstack` (v0.3.0) is a governance plugin for Antigravity CLI (`agy`) and Claude Code. It's built on Node.js 18+ ESM with zero npm dependencies. It combines a Korean-native thinking, UI, and response guard, a deterministic evidence-grounded completion gate with preflight vote-bypass enforcement, risk-tiered independent code auditing, fact-distilled cross-session handoff, zero-command autonomous governance (`smart` mode), and the daemonless local POSIX graph workflow (`hstack:graph` v1) in one plugin. See [Dual-host surface](#dual-host-surface) for how each host loads it.

## Bundled components (Agy manifest)

| Component | Count | Details |
| --- | :---: | --- |
| `rules` | `1` | `rules/AGENTS.md` (pure Korean, zero ASCII letters) |
| `hooks` | `1` | `hstack-guard` in `hooks.json` (`PreInvocation`, `PreToolUse`, `PostInvocation`, `Stop`) |
| `mcpServers` | `1` | `gate` in `mcp_config.json` (`verify_completion`, `manage_handoff`) |
| `agents` | `3` | `hstack-auditor`, `hstack-worker`, `hstack-challenger` |
| `skills` | `3` | `hstack-graph` (`hstack:hstack-graph` on Claude Code), `hstack-handoff`, `hstack-preflight` |

## Architecture

`hstack` organizes its rules, hooks, eager MCP tools, subagents, and skills into three layers plus zero-command autonomous governance.

### Layer 1: Korean-native thinking, UI, and response guard

- `rules/AGENTS.md` is an always-on, pure-Korean rule file (zero ASCII letters) loaded into `<user_rules>`. It fixes Korean as the model's native language across internal reasoning, thought summaries, final responses, and user-facing tool UI labels. It caps internal reasoning at 2 to 3 short paragraphs (at most 2 sentences per paragraph, 6 sentences total) with a Korean summary-language declaration at the start of each paragraph, while keeping file names, paths, code identifiers, commands, proper nouns, and everyday English technical terms verbatim inside natural Korean replies.
- `PreToolUse` (`scripts/pre-tool-use.mjs`) checks pure UI display tools (`update_steps`, `ask_question`, `todo_write`, `task_create`, `task_update`, `update_plan`) before they render. English step titles or option labels receive `decision: "deny"` with a Korean correction reason, capped at one retry per turn. Short technical proper names such as `React Router` or `Docker Compose` are allowed.
- `PostInvocation` (`scripts/post-invocation.mjs`) scans `transcript_full.jsonl` after each model invocation and evaluates `thinking`, `content`, and user-facing `tool_calls` text through `scripts/analyzer.mjs`. The stripper (`scripts/analyzer/stripper.mjs`) excludes closed fenced code blocks, inline code spans, paths, flags, identifiers, XML tags, `http://`, `https://`, `ftp://`, `file://`, and `conversation://` URLs, and server-side summarizer boilerplate while catching English prose, clauses, and English UI task labels. Drift triggers a non-blocking Korean `[한국어사고:영어이탈]` `systemMessage` with recovery-aware backoff (`2` consecutive unrecovered cap for `thinking`-only or `ui`-only drift). Explicit translation or foreign-language requests in `USER_INPUT` exempt `content` while keeping `thinking` and checklists in Korean. It also logs deduplicated `preflight_complete` records (`mode: "auto" | "manual"`) and triggers once-per-turn self-healing handoff prompts when thrashing is confirmed in `smart` mode while skipping pollution updates for `auditor` and `challenger` sessions.
- Unified `Stop` (`scripts/stop.mjs`) runs before a normal `NO_TOOL_CALL` turn ends. It checks both completion-gate compliance and Korean `content` drift in one orchestrator (global cap: 2 executions per turn). It returns `decision: "continue"` with `continue_gate`, `continue_lang`, or `continue_dual` when needed, skips `auditor` and `challenger` sessions as well as turns with pending post-write async audits or challenges, and fails open (`{}`) on errors or abnormal termination.

### Layer 2: deterministic evidence-grounded completion gate

- Eager MCP server (`mcp_config.json`, `scripts/mcp/server.mjs`, `version: "0.3.0"`) exposes `mcp_hstack_gate_verify_completion` (`verify_completion`) without requiring schema discovery turns.
- `PreToolUse` (`scripts/pre-tool-gate.mjs`) intercepts `^mcp_hstack_.*$` calls to return `decision: "auto_approve"`, set a Korean `toolSummary`, and inject hidden `_session` metadata (`conversationId`, `transcriptPath`, `cwd`) stripped before schema validation.
- `scripts/governance/fact-ledger.mjs` and `scripts/governance/decide-gate.mjs` cross-check claimed `modified_files`, `inspected_files`, `verification_runs`, `unverified_scope`, and `self_assessment` against transcript read/write/execution/preflight/vote history and Git working tree state (`git status --porcelain`, `git diff --numstat`). Denied write calls (`PreToolUse` `deny`) and failed write tool steps (`ERROR`/`FAILED`) are excluded from `turnWrittenFiles`, `turnCodeWrittenFiles`, and `fileEditCounts`.
- External MCP verification tools such as `mcp_agy-fast_fast_run_checks` (and `mcp_agy-fast_fast_apply_edits` / `mcp_agy-fast_apply_edits` for writes) are recognized directly in the ledger alongside `run_command`.
- Gate rules (`R1` through `R9`) and exceptions (`E1` through `E11`):
	- `R1_UNREAD_INSPECTED`: blocks when `inspected_files` lists a file never read in the session (newly created files via `write_file`/`write_to_file` count as read).
	- `R2_STALE_VERIFICATION`: blocks when code files were modified and no verification command ran after the last code write. Exempt for doc/asset-only edits (`E1`, `.md`, `.txt`, `.rst`, `.adoc`, `.svg`, image assets, `docs/`, `LICENSE`), or downgraded to warning when no test infrastructure exists and `not_applicable` with a concrete reason and non-empty `unverified_scope` are provided (`E2`).
	- `R3_CONCEALED_FAILURE`: blocks when any post-write verification failure remains unresolved by a subsequent passing run of the same command or covering segment.
	- `R4_UNREPORTED_MODIFIED`: blocks when a file modified in the turn and still dirty in Git is omitted from `modified_files` (reverted/clean files are exempt under `E5`).
	- `R5_FABRICATED_COMMAND`: blocks when a `verification_runs` entry claims `outcome: "pass"` with no matching post-write passing execution (supports shell segments, `run_command`, and `mcp_agy-fast_fast_run_checks` aliases/labels).
	- `R6_PHANTOM_MODIFIED`: warns when a claimed modified file is absent from both turn writes and Git dirty state, and blocks when no turn writes exist while Git is available.
	- `R7_HEDGE_DETECTED`: warns when `self_assessment` contains 2 or more hedging expressions (`scripts/governance/hedge-detector.mjs`) while effective `unverified_scope` is empty (filler entries such as `"없음"` or `"none"` are filtered out).
	- `R8_AUDIT_REJECTED` / `R8_AUDIT_ERROR`: blocks when a required `TIER_1` post-write `hstack-auditor` review rejects or errors/omits a verdict (`E9`/`E10` degrade to `PASS_WITH_AUDIT_DEGRADATION` after 2 rejections or 2 consecutive trailing errors with explicit `unverified_scope`).
	- `R9_PREFLIGHT_UNVOTED`: evaluated before `TIER_1` escalation whenever a `main` session modifies code in the same turn as a completed preflight challenge without a subsequent valid `ask_question` user vote. In `manual` mode (`/hstack-preflight`), unvoted `RETHINK` verdicts `BLOCK` (`REJECT`), while unvoted `CONDITIONAL`, `PROCEED`, `ERROR`, or `MISSING_VERDICT` emit `WARN` (`PASS_WITH_WARNING`). In `auto` mode (`[hstack:자동사전검토]` or circuit-breaker challenges), `PROCEED` and `CONDITIONAL` pass silently with zero warning (`Silent-on-Green`), `RETHINK` blocks (`Stop-on-Red`), and `ERROR`/`MISSING_VERDICT` warn to avoid deadlocks. Exception `E11` (aligned with `E7`) prevents permanent deadlock on the 4th attempt after 3 prior rejects when `unverified_scope` discloses the missing vote, without ever exempting `TIER_1` post-write `hstack-auditor` escalation.
	- Additional exceptions include session-missing skip (`SKIPPED_NO_SESSION`, `E8`), repeated-reject graceful degradation (`E7`), `auditor`/`challenger` session bypass, and subagent role isolation.

### Layer 3: isolation plane and zero-command autonomous governance (`smart` mode)

- Zero-command autonomous governance (`autonomyMode: "smart"`, default):
	- **`PreInvocation` autonomous prompt router (`scripts/prompt-router.mjs`)**: runs only on `invocationNum === 0` in `main` sessions when no explicit `/hstack-preflight` or `/hstack-handoff` command was typed. When a prompt combines structural or safety-removal signals (removing file locks, `timingSafeEqual`, expiry/auth/CSRF checks, compatibility fallbacks, or whole-architecture replacements) with leading design-review phrasing, it injects a Korean `systemMessage` once per turn (`prompt_route`) instructing the model to run `hstack-challenger` (`mode: "auto"`) first. Normal bug fixes and optimizations pass with zero overhead.
	- **`PreToolUse` destructive-edit circuit breaker (`scripts/governance/destructive-edit.mjs` + `scripts/pre-tool-gate.mjs`)**: inspects code-writing tools (`edit_file`, `write_file`, `write_to_file`, `replace_file_content`, `multi_replace_file_content`, `mcp_agy-fast_fast_apply_edits`, `mcp_agy-fast_apply_edits`; never `run_command`) in `main` sessions (`auditor`/`challenger`/`worker` exempt). It detects safety-primitive removals (`timingSafeEqual`, `openSync("wx")`/lock/atomic `renameSync`, auth/expiry/empty-token guards, `legacy`/`deprecated` compatibility fallbacks, `try/catch` block deletions; stripped of comments to prevent comment-based bypasses) and `TIER_1` sensitive-path mass deletions (`>= 25` net lines or `>= 40%` shrink on overwrites, resolving `gitRoot` and symlinks). Normal fixes, tests, docs, comment-only changes, and new files pass immediately. On a destructive edit without a completed `hstack-challenger` review, it blocks once per turn (`decision: "deny"`, logs `autonomy_event` `circuit_breaker`), holds pending async challenges, and persistently blocks writes after an unvoted `RETHINK` verdict until `ask_question` resolves.
	- **Silent-on-Green / Stop-on-Red (`skills/hstack-preflight/SKILL.md`, `scripts/governance/decide-gate.mjs`)**: in automatic preflight challenges (`mode: "auto"`), `PROCEED` and `CONDITIONAL` verdicts proceed autonomously without user popups or gate warnings, while `RETHINK` stops edits and requires `ask_question` confirmation (or stops read-only in non-interactive runs). Preflight never exempts `TIER_1` post-write `hstack-auditor` auditing.
	- **Thrashing-triggered self-healing handoff (`scripts/governance/thrashing-detector.mjs` + `scripts/post-invocation.mjs`)**: healthy high-token sessions with at most 1 failure do not trigger. When confirmed thrashing occurs (`>= 4` verification failures in turn, `>= 5` edits to the same file with `>= 2` verification failures, or `>= 150000` `inputTokens` with `>= 2` consecutive verification failures) in a `main` session where `hstack-worker` has not completed, `PostInvocation` emits a once-per-turn `auto_handoff` event and injects `[hstack:자가치유위임]` instructing the model to save distilled facts via `manage_handoff(action: "save")` and delegate remaining work to an isolated `hstack-worker`.
- Adversarial preflight challenge (`skills/hstack-preflight/SKILL.md`, `agents/hstack-challenger.md`):
	- Supports three explicit modes: `/hstack-preflight [proposal]` (default), `/hstack-preflight plan [proposal]` (design-only, zero file edits), and `/hstack-preflight strict [proposal]` (red-team hypothesis favoring rejection), plus autonomous `[hstack:자동사전검토]` invocation.
	- Flow: read relevant files and draft a 4-item neutral brief stripped of leading tone -> dispatch read-only `hstack-challenger` (`invoke_subagent`) for 4-axis `file:line` challenge ending with `[사전검토 판정: 진행 가능]`, `[사전검토 판정: 조건부 진행]`, or `[사전검토 판정: 재설계 권고]` -> follow manual vote or Silent-on-Green / Stop-on-Red branching. In non-interactive runs (`agy -p`) where `ask_question` returns blank (`A1:` empty) or errors, it prints the comparison table and choices without editing files.
- Risk-tiered independent code auditor (`agents/hstack-auditor.md`, `scripts/governance/risk-classifier.mjs`):
	- `classifyRisk` assigns `TIER_1` when a code change touches a sensitive path (`sensitive_path`, such as `auth`, `security`, `crypto`, `token`, `session`, `migrations`, `hooks.json`, `mcp_config.json`, `scripts/mcp/`, `scripts/governance/`), modifies 4 or more code files (`large_file_count`), or changes 150 or more code lines (`large_diff_lines`). All other changes are `TIER_0`.
	- On `TIER_1` code edits in `main` sessions with `auditEscalation: "auto"`, `verify_completion` returns `ESCALATE_AUDIT_REQUIRED` until a post-write `hstack-auditor` read-only review completes and ends with `[감사 판정: 통과]` or `[감사 판정: 반려]`.
	- `PreToolUse` (`scripts/pre-tool-gate.mjs`) intercepts `invoke_subagent` for `hstack-auditor`, `hstack-challenger`, and `hstack-worker` to inject Korean role labels, session role markers (`[hstack:독립감사]`, `[hstack:사전검토]`, `[hstack:격리작업]`), workspace path, and transcript anchors.
- Fact-distilled cross-session handoff (`skills/hstack-handoff/SKILL.md`, `agents/hstack-worker.md`, `scripts/governance/handoff-store.mjs`):
	- Eager MCP tool `mcp_hstack_gate_manage_handoff` (`manage_handoff`) supports `save`, `load`, and `list` actions per workspace key (`computeWorkspaceKey`), combining distilled facts (`objective`, `verified_facts`, `failed_approaches`, `remaining_tasks`, `open_risks`) with machine evidence (Git branch, HEAD, dirty files, read/written files, verification runs) and flagging stale working trees on load.
	- Context pollution tracking (`updateSessionPollutionState` in `scripts/post-invocation.mjs`) monitors `inputTokens`, failed executions in turn, and repeated single-file edit churn, appending a non-blocking `[컨텍스트 열화 주의]` notice to gate receipts when thresholds trip.

## Dual-host surface

One tree carries two manifests. Agy reads `plugin.json`, `hooks.json`, and `mcp_config.json`. Claude Code reads `.claude-plugin/plugin.json`, which references `./.claude-plugin/hooks.json`, `./.claude-plugin/mcp.json`, and the agent files in `./.claude-plugin/agents/` explicitly. Explicit paths keep Agy from flagging Claude's default `.mcp.json` and `hooks/hooks.json` locations. Sections above that name Agy tools (`invoke_subagent`, `PostInvocation`, `agy -p`) are Agy-only.

### Daemonless graph workflow (`hstack:graph` v1)

- **Skill surface (`skills/hstack-graph/`):** Registered as `hstack-graph` on Agy and `hstack:hstack-graph` on Claude Code, with CLI, example, mass fan-in, long-worker, recovery, and live-host references under `skills/hstack-graph/references/`.
- **Local POSIX graph engine (`scripts/graph/*`):** Driven via short-lived `node .../scripts/graph/cli.mjs` calls (no background daemon):
	- **Admission (`compile`):** DAG validation, topology limits, and single-session vs. `dag_approved` read fan-out recommendation.
	- **Durable state & fencing:** Monotonic `epoch` fencing tokens (`claim`/`start`/`settle`), `fsync`-backed WAL (`wal-store.mjs`), tombstone lock reclamation (`lock.mjs`), IO-uncertain freeze, and CAS root-pin GC (`gc.mjs`).
	- **Lossless fan-in (`mass`):** Up to 64 shards across shard → cluster reducer → final reducer (`mass.mjs`, `reducer.mjs`), returning `partial` with preserved missing/failure obligations whenever coverage is incomplete.
	- **Dual budgets, canary integration & metrics:** Dynamic `W_eff` token or byte-mode wave/node budgets, canary `probe` and pinned `context_rot_abort` handoff carryover (`host-bridge.mjs`), and observed-only telemetry (`metrics.mjs`, reporting `null` when host usage isn't observed).

### Load and validate in Claude Code

```sh
claude plugin validate --strict --json .
claude --plugin-dir /path/to/hstack
```

`--plugin-dir <path>` loads a plugin from a directory or `.zip` for that session only, and you can repeat it (`--plugin-dir A --plugin-dir B.zip`). Nothing is installed. Run `/mcp` inside the session to confirm that the `gate` server connected.

### Claude hooks

`./.claude-plugin/hooks.json` routes four events through `scripts/hooks/claude.mjs`.

| Claude event | What hstack does |
| --- | --- |
| `SessionStart` | Adds `rules/AGENTS.md` to the session as context. This is the Claude counterpart of Agy's always-on rule file. |
| `UserPromptSubmit` | Runs the prompt router (Agy `PreInvocation`) and adds any notice as context. |
| `PreToolUse` | Matches `Bash`, `PowerShell`, `Edit`, `Write`, `NotebookEdit`, `Agent`, `Task`, `TodoWrite`, `TaskCreate`, `TaskUpdate`, `AskUserQuestion`, and the two gate tools. It denies English UI labels and gated edits with a Korean reason, adds role markers to subagent prompts, and attaches `_hstackContext` to gate calls. |
| `Stop` | Runs the completion gate and the post-turn analysis (Agy `PostInvocation`). A gate failure blocks with a Korean reason, and analysis notices arrive as one `systemMessage`. When `stop_hook_active` is set it returns nothing, so it never blocks twice in a row. |

Native tools map to the Agy names the gate already knows. `Edit`, `Write`, and `NotebookEdit` become edits, `Bash` and `PowerShell` become `run_command`, `Agent` and `Task` become `invoke_subagent`, and `TodoWrite`, `TaskCreate`, `TaskUpdate`, and `AskUserQuestion` become UI tools. `Read` has no hook and is seen only through the transcript.

### Namespaced MCP and `_hstackContext`

`./.claude-plugin/mcp.json` sets `HSTACK_HOST=claude` and inherits the host-injected `CLAUDE_PLUGIN_DATA` directory without overriding it. Claude Code scopes plugin servers as `plugin:<plugin>:<server>`, so the tools appear as `mcp__plugin_hstack_gate__verify_completion` and `mcp__plugin_hstack_gate__manage_handoff`. They aren't loaded eagerly.

On Claude Code, `_session` never travels through the tool call. `PreToolUse` drops any caller-supplied `_session` or `_hstackContext` and attaches a fresh `_hstackContext`, a random one-use reference. The server redeems it exactly once. It has to match the tool it was issued for, be less than 120 seconds old, and sit in an owner-only directory under the plugin data directory. A missing, reused, expired, or forged reference fails the call with a Korean error instead of running it without a session. The hook doesn't auto-approve the call, so Claude's normal permission rules still apply.

### Host capability contract

`scripts/host/host-adapter.mjs` exports `getHostCapabilities(host)` for the host IDs `antigravity`, `claude-code`, and `unknown`. `detectHost()` picks one from `HSTACK_HOST`, then from the Claude or Agy plugin environment variables. Every result has exactly these keys:

| Key | `antigravity` | `claude-code` | `unknown` |
| --- | :---: | :---: | :---: |
| `host` | `"antigravity"` | `"claude-code"` | `"unknown"` |
| `spawn` | `true` | `true` | `false` |
| `readOnlySubagent` | `true` | `true` | `false` |
| `isolatedWrite` | `false` | `false` | `false` |
| `cancel` | `false` | `false` | `false` |
| `resume` | `false` | `false` | `false` |
| `usageTelemetry` | `null` | `null` | `null` |

These values describe the package, not the grants in any one session.

- `readOnlySubagent` means hstack ships read-only reviewers. Claude limits their tools to `Read`, `Glob`, and `Grep`; the worker also has `Edit`, `Write`, and `Bash`. Agy uses reviewer instructions and a `PreToolUse` hook that denies managed writes and commands for those roles.
- `isolatedWrite` is `false` because a separately prompted worker isn't a filesystem sandbox.
- `cancel` and `resume` are `false` and `usageTelemetry` is `null` on every host. hstack doesn't claim them, and it never infers them from a session ID.

### Handoff pins and cleanup

`manage_handoff` keeps `save`, `load`, and `list` and adds `pin`, `unpin`, `list_pinned`, and `clear`. The same API exists in `scripts/governance/handoff-store.mjs`.

- `save` takes an optional `pin_owner` and pins the new snapshot in the same call. If you need it kept, don't save first and pin later.
- `pin` and `unpin` need a concrete `snapshot_id` and a `pin_owner`. Each reports whether that owner's membership changed. A snapshot stays pinned while any owner remains.
- `list_pinned` reports the pinned IDs and their owners. The JavaScript API `listPinnedSnapshots` returns sorted `{ snapshotId, pinOwners }` entries; MCP renders them as text.
- `clear` reports how many unpinned snapshots it removed. The JavaScript API `clearHandoffSnapshots` returns `{ workspaceKey, clearedCount }`. It keeps a pinned current snapshot. If the current one is unpinned, it removes the pointer and doesn't promote another snapshot. `clear` takes no `snapshot_id`.
- `pin_owner` is only valid on `save`, `pin`, and `unpin`. Owners are case-sensitive, 1 to 128 characters, start with an ASCII letter or digit, and may contain ASCII letters, digits, `.`, `_`, `:`, and `-` (for example `canary:run-42`). They're retention labels, not credentials.
- Retention keeps 20 unpinned snapshots plus every pinned one. Once the last owner unpins a snapshot, ordinary retention applies to it right away.
- `load` still accepts the read-only `latest` alias and never loads `pins` as a snapshot.
- If pin metadata is corrupt or unreadable, mutations abort. It's never read as an empty set.
- Operations share the workspace cross-process lock and use atomic file replacement. A save publishes the snapshot, then the root, then `latest`, and only then prunes. That isn't a power-loss transaction, though. An interruption before `latest` is published can leave an orphan snapshot or a retained root.

### Language canary (`languageCanary`)

The canary is advisory only. It never changes a `verify_completion` verdict and never blocks a turn. It samples the final reply of each real user turn in a `main` session (Agy at `PostInvocation`, Claude Code at `Stop`). Each user turn counts at most once, even if a hook is replayed. Code fences, quoted lines and spans, JSON and YAML blocks, hashes, and short English glosses after Hangul are stripped first. Replies shorter than `minProseChars` and turns where the user explicitly asked for English are skipped and don't move any counter.

| Event | When |
| --- | --- |
| `load_failure` | Only when the **first applicable turn** drifts. It warns that the Korean rules may not have loaded and does not start the drift count. If the first applicable turn is normal, any later drift counts normally. |
| `suspect` | After that, `kWarn` consecutive drifting turns (default `2`). |
| `handoff_required` | `kReset` consecutive drifting turns (default `3`), outside cooldown. hstack saves a pinned handoff and resets the drift count. |
| `handoff_suppressed` | `kReset` reached while cooldown is active. Nothing is saved. |
| `recovered` | `recoverCleanTurns` consecutive Korean turns (default `3`) after `suspect` or `handoff_required`. |

After a handoff, `cooldownTurns` (default `5`) applicable turns must pass before another one can be saved. Skipped turns don't use up cooldown.

On `handoff_required` the notice names the snapshot ID and its owner, `canary:<first 24 hex chars of sha256(conversation id)>`. To release it:

1. Start a new session and run `manage_handoff` with `action: "load"` and that `snapshot_id`.
2. When you no longer need it, run `manage_handoff` with `action: "unpin"`, the same `snapshot_id`, and `pin_owner` set to the `canary:...` owner. Use `list_pinned` if you lost the notice.

Until you unpin it, the snapshot survives retention and `clear`.

Tune the canary under `languageCanary` in `config.json`:

```json
{
	"languageCanary": {
		"kWarn": 2,
		"kReset": 3,
		"minProseChars": 40,
		"recoverCleanTurns": 3,
		"cooldownTurns": 5
	}
}
```

`kWarn`, `kReset`, and `recoverCleanTurns` must be integers `>= 1`. `minProseChars` and `cooldownTurns` must be integers `>= 0`, and `kWarn` can't exceed `kReset`. `minHangulRatio` (`0` to `1`) defaults to the analyzer's shared ratio. An invalid value turns the canary off quietly for that turn. The completion gate isn't affected.

### Pre-merge interactive checklist

Run these by hand in logged-in sessions before you merge, and record what you observe.

Claude Code (`claude --plugin-dir .` from the repository root):

1. `claude plugin validate .` passes.
2. The session starts with the Korean rules from `SessionStart` in context.
3. `/mcp` lists `gate` as connected with both `mcp__plugin_hstack_gate__*` tools.
4. An English todo label in `TodoWrite` is denied with a Korean reason.
5. Call `verify_completion` once. Claude's normal permission rules apply, and the call returns a gate verdict rather than the Korean session error.
6. Edit a code file, then try to finish without running a check. `Stop` blocks with a Korean reason, and the next stop isn't blocked again.
7. `manage_handoff` `save` with `pin_owner`, then `list_pinned`, `clear`, and `unpin`. The pinned snapshot survives `clear`.
8. In a fresh session, observe four consecutive applicable turns that drift without a request for English: turn 1 warns `load_failure`, turn 3 warns `suspect`, and turn 4 gives `handoff_required` with a snapshot ID and `canary:` owner. Load that ID in a new session before releasing the pin.

Agy (`agy plugin install .`, new session):

1. `agy plugin validate --strict --json .` reports `"findings": []`.
2. `mcp_hstack_gate_*` tools are eager and auto-approved.
3. Repeat steps 7 and 8 above with `/hstack-handoff` and Agy's tool names.
4. Rerun `node ./test/verify-live.mjs` for `L1`, `L3`, `L5`, and `L16`.

## Install and update

### Fresh install

Install `hstack` from GitHub or a local checkout, then start a new Antigravity CLI session.

```sh
agy plugin install https://github.com/hs1662/hstack
agy plugin install .
```

Run `/thinking` inside an Antigravity CLI session to view `thinking` traces.

### Reinstall or update

Reinstall a local `hstack` checkout while preserving `plugin_data/hstack/` (`audit.jsonl`, `config.json`, handoff snapshots).

```sh
agy plugin uninstall hstack
agy plugin install /path/to/hstack
```

Start a new `agy` session after every install or update so hooks, rules, agents, skills, and MCP servers load cleanly.

## Configuration reference

`hstack` reads optional JSON settings from:

```text
$ANTIGRAVITY_APP_DATA_DIR/plugin_data/hstack/config.json
```

When `PLUGIN_DATA` or `HSTACK_DATA_DIR` is set, that directory takes precedence. Default app-data path on Linux is `~/.gemini/antigravity-cli/plugin_data/hstack/config.json`.

### Supported `config.json` keys

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `schemaRegister` | `"neutral" \| "audit"` | `"neutral"` | Selects tool schema and receipt copy register. |
| `auditEscalation` | `"auto" \| "manual" \| "off"` | `"auto"` | Controls `TIER_1` independent auditor escalation. `"auto"` enforces escalation on `TIER_1` edits in `main` sessions; `"manual"` and `"off"` skip automatic escalation. |
| `autonomyMode` | `"smart" \| "manual" \| "off"` | `"smart"` | Controls zero-command autonomous governance. `"smart"` enables prompt routing, circuit breaker, Silent-on-Green/Stop-on-Red, and self-healing handoff; `"manual"` preserves v0.1.0 explicit slash-command behavior; `"off"` disables autonomous preflight/self-healing while keeping completion gates and `TIER_1` audits. |
| `autonomyThresholds.destructiveDeleteLines` | positive integer | `25` | Net deleted lines threshold on `TIER_1` sensitive files (or 40%+ shrink on overwrites) to trip the circuit breaker. |
| `autonomyThresholds.thrashingVerifyFailures` | positive integer | `4` | Total verification failures per turn threshold for self-healing handoff. |
| `autonomyThresholds.thrashingSameFileEdits` | positive integer | `5` | Single-file edit churn threshold (combined with `>= 2` verification failures) for self-healing handoff. |
| `autonomyThresholds.thrashingHighTokens` | positive integer | `150000` | `inputTokens` threshold (combined with `>= 2` consecutive verification failures) for self-healing handoff. |
| `riskThresholds.minCodeFiles` | positive integer | `4` | Minimum modified code files to classify as `TIER_1` (`large_file_count`). |
| `riskThresholds.minChangedLines` | positive integer | `150` | Minimum added plus deleted code lines to classify as `TIER_1` (`large_diff_lines`). |
| `sensitivePatterns` | `string[]` (max 50) | Built-in list | Optional custom case-insensitive regex strings overriding default sensitive path patterns. |
| `pollutionThresholds.inputTokensWarning` | integer | `120000` | Input token threshold for `pollutionAlert`. |
| `pollutionThresholds.failedExecutionsInTurn` | integer | `4` | Failed execution count per turn threshold for `pollutionAlert`. |
| `pollutionThresholds.repeatedFileEditChurn` | integer | `5` | Repeated edits to a single file per turn threshold for `pollutionAlert`. |

Example `config.json`:

```json
{
	"schemaRegister": "neutral",
	"auditEscalation": "auto",
	"autonomyMode": "smart",
	"autonomyThresholds": {
		"destructiveDeleteLines": 25,
		"thrashingVerifyFailures": 4,
		"thrashingSameFileEdits": 5,
		"thrashingHighTokens": 150000
	},
	"riskThresholds": {
		"minCodeFiles": 4,
		"minChangedLines": 150
	},
	"pollutionThresholds": {
		"inputTokensWarning": 120000,
		"failedExecutionsInTurn": 4,
		"repeatedFileEditChurn": 5
	}
}
```

### Environment variables and precedence

Environment variables override `config.json`, which overrides built-in defaults.

1. `HSTACK_SCHEMA_REGISTER` (`"neutral"` or `"audit"`) > `config.json` `schemaRegister` > `"neutral"`.
2. `HSTACK_AUDIT_ESCALATION` (`"auto"`, `"manual"`, or `"off"`) > `config.json` `auditEscalation` > `"auto"`.
3. `HSTACK_AUTONOMY_MODE` (`"smart"`, `"manual"`, or `"off"`) > `config.json` `autonomyMode` > `"smart"`.

## Usage guide

### Adversarial preflight review (`/hstack-preflight`)

In `smart` mode, `hstack` automatically triggers adversarial preflight review on high-risk prompt proposals or destructive edits. You can also invoke `/hstack-preflight` explicitly before refactors or architectural changes when you want code-grounded pushback and a mandatory manual vote.

- `/hstack-preflight [proposal]` (default): builds a neutral 4-item brief, delegates read-only 4-axis review to `hstack-challenger`, summarizes trade-offs in a comparison table, and runs a 4-choice `ask_question` vote before editing. In non-interactive runs (`agy -p`) where `ask_question` returns empty or errors, it prints the comparison table and choices without modifying files.
- `/hstack-preflight plan [proposal]`: design-only review; strictly forbids file edits.
- `/hstack-preflight strict [proposal]`: red-team review instructing `hstack-challenger` to default toward rejecting the proposal unless code evidence holds up.

### Context handoff (`/hstack-handoff`)

Use `/hstack-handoff` to distill and transfer session state without carrying raw conversation bloat.

- `/hstack-handoff save` (default): calls `manage_handoff(action: "save")` to store verified facts, failed approaches, remaining tasks, open risks, and machine evidence as a workspace snapshot.
- `/hstack-handoff load` or `/hstack-handoff load <snapshot_id>`: calls `manage_handoff(action: "load")` to restore the latest or named snapshot and warn if Git HEAD or dirty files changed since saving.
- `/hstack-handoff list`: calls `manage_handoff(action: "list")` to inspect recent snapshots for the current workspace.
- `/hstack-handoff delegate`: saves or loads the latest snapshot and dispatches `hstack-worker` (`invoke_subagent`) with the distilled handoff brief and scoped verification target.

### Audit log summary CLI (`scripts/audit-report.mjs`)

Inspect operational gate metrics across 8 sections from `audit.jsonl`: `[1]` overall summary, `[2]` period reject trend, `[3]` `R1~R9` rule violation/warning distribution (including `R9_PREFLIGHT_UNVOTED`), `[4]` Tier 1 independent audit stats, `[5]` context pollution alerts and unverified scope, `[6]` local scan latency (`ledgerScanMs`, `gitScanMs`), `[7]` adversarial preflight challenge summary (turn-deduplicated count, `auto`/`manual` mode split, verdict distribution, vote completion rate, and `R9_PREFLIGHT_UNVOTED` blocks/warnings), and `[8]` zero-command autonomy events (`circuit_breaker` reason breakdown, `prompt_route`, and `auto_handoff`).

```sh
node ./scripts/audit-report.mjs
node ./scripts/audit-report.mjs --days 7
node ./scripts/audit-report.mjs --since 2026-11-20 --group-by week
node ./scripts/audit-report.mjs --days 7 --json
node ./scripts/audit-report.mjs --file /path/to/audit.jsonl
```

Default file resolution checks `--file`, `$PLUGIN_DATA/audit.jsonl`, `$HSTACK_DATA_DIR/audit.jsonl`, `$ANTIGRAVITY_APP_DATA_DIR/plugin_data/hstack/audit.jsonl`, `~/.gemini/antigravity-cli/plugin_data/hstack/audit.jsonl`, and `resolvePluginDataDir()/audit.jsonl` in order.

## Verification and tests

Run the unit test suite, strict plugin manifest validation on both hosts, and isolated live checks from the repository root.

```sh
env -u PLUGIN_DATA -u PLUGIN_ROOT node --test test/*.test.mjs
agy plugin validate --strict --json .
claude plugin validate --strict --json .
claude --plugin-dir /path/to/hstack
node ./test/verify-live.mjs --models gemini-4-neon-xhigh
```

`test/verify-live.mjs` executes each scenario in an isolated temporary `HOME` and app-data directory so global plugins cannot interfere and cleans up temporary logs on exit.

### Measured baseline and release notes (v0.3.0)

These numbers were measured at `v0.3.0` on `main` (upgraded from the `v0.2.0` baseline of 153 suites / 817 tests).

- Unit and integration suite: `env -u PLUGIN_DATA -u PLUGIN_ROOT node --test test/*.test.mjs` passes **162 suites / 1,136 tests (`fail 0`)**, covering the `hstack:graph` v1 engine and skill walkthroughs (`test/graph-*.test.mjs`), dual-host adapter and Claude Code transcript/hook/MCP session-reference contracts, workspace-scoped snapshot pins (`pin`/`unpin`/`list_pinned`/`clear`), `k=2`/`k=3` language canary with turn-1 `load_failure` separation, Claude `UserPromptSubmit` turn-snapshot binding, UI/`PowerShell` transcript tracking, and all existing governance, analyzer, and hardening suites, including Node `18.20.8` startup and crash-recovery checks.
- Strict manifest validation (both hosts): `agy plugin validate --strict --json .` exits `0` with `"findings": []` and `components: { agents: 3, hooks: 1, mcpServers: 1, rules: 1, sidecars: 0, skills: 3 }`. `claude plugin validate --strict --json .` exits `0` with `"success": true`, `0` errors, and `0` warnings.
- Dual-host live session verification (`hstack:graph` v1 L1–L4 & independent audit): verified end-to-end across Agy `1.5.19` (isolated `HOME`/`PLUGIN_DATA`, real `invoke_subagent(research)` round-trip, forged/missing gate rejections, canary pin handoff and cross-session `manage_handoff` restore with stale-token exit `49`, `mass` `partial`/`complete` fan-in, `null` unobserved telemetry, and v2 exit `69` cutoff) and Claude Code `2.1.332` (`--plugin-dir`, real `Agent(Explore)` round-trip, `hstack-inline` `manage_handoff` cross-session restore with exit `49`, `mass` fan-in, and `69` cutoff), plus `[감사 판정: 통과]` from independent `hstack-auditor` reviews on both hosts.
- Governance live baselines (v0.2.0): Antigravity CLI (`test/verify-live.mjs`, `gemini-4-neon-xhigh`) passed `L1`, `L3`, `L5`, and `L16` `4/4` (`drifted: 0`, `hookcaller` panics `0`), and Claude Code (`claude --plugin-dir`, v2.1.332) verified C1–C4.
- Known limitations:
	1. In Claude Code headless mode (`claude -p`), interactive `AskUserQuestion` selection UI and interactive permission prompts cannot be clicked directly. Claude `AskUserQuestion` answer normalization (`toolUseResult.answers` and `"User has answered your questions: ..."`) is verified in `test/claude-transcript.test.mjs`.
	2. Claude Code writes `PreToolUse` `updatedInput` (including the one-use `_hstackContext` string) into its own session transcript (`hook_success.stdout`). The MCP server deletes the underlying token file immediately on redemption so replaying the recorded token always fails (`isError: true`), and `audit.jsonl` never logs the token.
	3. On platforms without an OS `flock` binary (such as Windows or minimal containers), stale session lock reclamation falls back to an inode-verified `.reclaim` guard file under zero-dependency Node.js 18+.
	4. **v1 write/integration cutoff:** parallel code `write` specs and `integrate` belong to v2 and fail closed in v1 with `ERR_V2_WRITE_INTEGRATION_NOT_ENABLED` (exit code `69`).
	5. **Same-UID worker boundary:** `writeScope` and workspace-fallback directives are not OS sandboxes when workers share the user UID; untrusted workers require separate UID or container isolation.
	6. **Claude Code Bash shell environment:** Claude Code injects `CLAUDE_PLUGIN_ROOT` and `CLAUDE_PLUGIN_DATA` into hooks and MCP servers rather than the Bash tool shell, so graph CLI calls in Claude Code must set them explicitly to match the hook/MCP data directory instead of falling back to `<workspace>/.hstack/graph`.
	7. **Agy auditor read-only enforcement:** unlike Claude Code's host-enforced `tools: Read, Glob, Grep`, Agy `hstack-auditor` enforces read-only behavior at the prompt/hook level; verify pre/post `git status` and `git diff --stat` equivalence when auditing on Agy.

See [Publishing guide](docs/PUBLISHING.md) for releases and [MIT License](LICENSE) for licensing.
