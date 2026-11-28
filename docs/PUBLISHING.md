# Publish hstack to GitHub and Antigravity Marketplace

Return to the [English README](../README.md) or [Korean README](../README.ko.md) for plugin architecture and usage details.

Use this guide to verify the repository before a release, push tags to GitHub, and submit updates to the Antigravity Marketplace. Release `0.4.0` adds **M2: `hstack:graph` v2.0** (engine-isolated v2 write worktrees, private-index sealer, single Git wrapper, `merge-tree` `B=1` two-phase CAS integrator with stale `.lock` reclamation, `land` 4 modes with ignored-overlap protection, `release`, `gc --scope git`, incremental WAL root tracing, and 3-tier `tiers.mjs` tests) alongside the existing Korean guard, completion gate, preflight challenge, snapshot handoff surface, and `hstack:graph` v1 core. Run every check in the pre-publish checklist before tagging or pushing.

## Bundled components

Confirm that `plugin.json` and the repository layout expose these Agy components at the target version (`0.4.0`):

- `rules` (`1`): `rules/AGENTS.md` (pure Korean, zero ASCII letters)
- `hooks` (`1`): `hstack-guard` in `hooks.json` (`PreInvocation`, `PreToolUse`, `PostInvocation`, and `Stop`)
- `mcpServers` (`1`): `gate` in `mcp_config.json` (`scripts/mcp/server.mjs`, exposing eager tools `verify_completion` and `manage_handoff`)
- `agents` (`3`): `agents/hstack-auditor.md`, `agents/hstack-worker.md`, and `agents/hstack-challenger.md`
- `skills` (`3`): `skills/hstack-graph/SKILL.md` (`hstack-graph`), `skills/hstack-handoff/SKILL.md` (`hstack-handoff`), and `skills/hstack-preflight/SKILL.md` (`hstack-preflight`)
- `assets`: `assets/logo.svg` (`256x256` square canvas with rounded badge padding)

Dual-host and graph v2.0 components (`0.4.0`):

- `.claude-plugin/plugin.json` (`version: "0.4.0"`) references every Claude path explicitly, so Agy doesn't flag Claude's default `.mcp.json` or `hooks/hooks.json` locations:
  - `"hooks": "./.claude-plugin/hooks.json"`: `SessionStart`, `UserPromptSubmit`, `PreToolUse`, and `Stop`, all through `scripts/hooks/claude.mjs`
  - `"mcpServers": "./.claude-plugin/mcp.json"`: `gate` sets `HSTACK_HOST=claude` and inherits the host-injected `CLAUDE_PLUGIN_DATA` directory without overriding it, exposed as `mcp__plugin_hstack_gate__verify_completion` and `mcp__plugin_hstack_gate__manage_handoff`
  - `"agents"`: `./.claude-plugin/agents/hstack-auditor.md` and `hstack-challenger.md` (`tools: Read, Glob, Grep`), and `hstack-worker.md` (adds `Edit, Write, Bash`)
  - `skills/`: registered on Claude Code as `hstack:hstack-graph`, `hstack:hstack-handoff`, and `hstack:hstack-preflight`
- `scripts/graph/`: daemonless POSIX graph engine including v1 core (`cli.mjs`, `admission.mjs`, `attempts.mjs`, `state-machine.mjs`, `wal-store.mjs`, `lock.mjs`, `fs-guard.mjs`, `gc.mjs`, `mass.mjs`, `reducer.mjs`, `metrics.mjs`, `host-bridge.mjs`, `patch.mjs`, `incremental.mjs`, `fingerprint.mjs`, `schema.mjs`, `verify-gate.mjs`) and v2.0 write integration (`git.mjs`, `worktree.mjs`, `seal.mjs`, `merge-tree.mjs`, `write-attempts.mjs`, `integrator.mjs`, `land.mjs`)
- `scripts/host/host-adapter.mjs`, `scripts/host/mcp-session.mjs`, `scripts/host/tools.mjs`, `scripts/host/claude-transcript.mjs`, and `scripts/governance/language-canary.mjs`

## Pre-publish validation checklist

Run every required check from the repository root before you push `main` or a release tag.

1. Run the 3-tier test suite (`v0.4.0` baseline: `fast` 347 pass, `full` 1,280 pass across 166 suites, `fault` 77 pass including 64-shard engine checks; previous `v0.3.0` baseline: 162 suites / 1,136 tests including Node `18.20.8` checks).

   ```sh
   env -u PLUGIN_DATA -u PLUGIN_ROOT node test/tiers.mjs fast
   env -u PLUGIN_DATA -u PLUGIN_ROOT node test/tiers.mjs full
   env -u PLUGIN_DATA -u PLUGIN_ROOT node test/tiers.mjs fault
   ```

2. Run strict Antigravity plugin validation and confirm exit code `0` with `"findings": []` and `components: { agents: 3, hooks: 1, mcpServers: 1, rules: 1, sidecars: 0, skills: 3 }`.

   ```sh
   agy plugin validate --strict --json .
   ```

   Then validate the Claude Code manifest and confirm it loads for one session.

   ```sh
   claude plugin validate --strict --json .
   claude --plugin-dir .
   ```

3. Verify that all standalone executable scripts have mode `100755` in the git index (`scripts/prompt-router.mjs` stays `100644` and is invoked via `node ./scripts/prompt-router.mjs` in `hooks.json`).

   ```sh
   git ls-files -s scripts/pre-tool-use.mjs scripts/pre-tool-gate.mjs scripts/post-invocation.mjs scripts/stop.mjs scripts/mcp/server.mjs scripts/audit-report.mjs test/verify-live.mjs
   ```

   If any entry shows `100644`, mark it executable in the working tree and index, then commit the mode change.

   ```sh
   chmod +x scripts/pre-tool-use.mjs scripts/pre-tool-gate.mjs scripts/post-invocation.mjs scripts/stop.mjs scripts/mcp/server.mjs scripts/audit-report.mjs test/verify-live.mjs
   git update-index --chmod=+x scripts/pre-tool-use.mjs scripts/pre-tool-gate.mjs scripts/post-invocation.mjs scripts/stop.mjs scripts/mcp/server.mjs scripts/audit-report.mjs test/verify-live.mjs
   ```

4. Confirm that `assets/logo.svg` uses `viewBox="0 0 256 256"` and outer padding (`x="26" y="26" width="204" height="204"`).
5. Confirm that `"version"` in `plugin.json` and `.claude-plugin/plugin.json`, `SERVER_INFO.version` in `scripts/mcp/server.mjs`, `README.md`, and `README.ko.md` match the target semantic version (`0.4.0`).
6. Confirm that no untracked or temporary files are staged, and that all modules under `rules/`, `agents/`, `skills/`, `scripts/`, and `.claude-plugin/` are tracked, along with every file `.claude-plugin/plugin.json` references.

   ```sh
   git status --short
   git ls-files rules/ agents/ skills/ scripts/ .claude-plugin/
   ```

7. When you change `rules/AGENTS.md`, `scripts/analyzer/`, `scripts/transcript/`, or governance hooks, run the isolated live verification script (`L1`–`L16`) as needed.

   ```sh
   node ./test/verify-live.mjs
   ```

   For `v0.4.0`, live `hstack:graph` v2.0 V1–V5 sessions (isolated `HOME` `invoke_subagent` on Agy `1.5.19` and `--plugin-dir` `Agent` on Claude Code `2.1.332`, `O-H-3` inbox race, `O-L-4` ignored-overlap block, and `ff-only` landing) and read-only `hstack-auditor` reviews passed on both hosts. For `v0.3.0`, live `hstack:graph` v1 L1–L4 sessions passed on both hosts; for governance hooks, `verify-live.mjs` covers Agy (`L1`, `L3`, `L5`, `L16` `4/4 pass` on `gemini-4-neon-xhigh`), and Claude Code verified C1–C4 in isolated runs. Headless runs (`claude -p`) cannot drive interactive `AskUserQuestion` clicks, and Claude Bash shells require explicit `CLAUDE_PLUGIN_ROOT`/`CLAUDE_PLUGIN_DATA` for graph CLI calls.

8. Review local audit telemetry (sections `[1]`–`[8]`, including `[3]` `R1~R9`, `[6]` scan latency, `[7]` preflight mode summary, and `[8]` autonomy events) with the zero-dependency report CLI when inspecting operational metrics.

   ```sh
   node ./scripts/audit-report.mjs
   ```

## Confirm required manifest fields

Verify that `plugin.json` contains every required Antigravity Marketplace field before you publish.

| Field | Current value | Requirement |
| :--- | :--- | :--- |
| `name` | `"hstack"` | Lowercase plugin slug. |
| `displayName` | `"hstack"` | Human-readable title shown in the Marketplace listing. |
| `description` | One-sentence summary | Clear statement of what the plugin does. |
| `version` | `"0.4.0"` | Semantic version matching the GitHub release tag. |
| `logo` | `"assets/logo.svg"` | Relative path to a 1:1 square icon with padding. |
| `license` | `"MIT"` | License identifier matching `LICENSE`. |
| `homepage` | `"https://github.com/hs1662/hstack"` | Public repository URL. |
| `repository` | `"https://github.com/hs1662/hstack"` | Public GitHub repository URL. |
| `suggestedPrompts` | 3 Korean prompts | Example prompts displayed on the Marketplace detail page. |
| `author` | `{ "name": "hs1662", "url": "https://github.com/hs1662" }` | Author name and `https://` profile URL. |

## Push to GitHub and validate remotely

1. Create an annotated tag that matches `"version"` in `plugin.json`.

   ```sh
   git tag -a v0.4.0 -m "Release v0.4.0"
   ```

2. Push `main` and the release tag with a standard fast-forward push.

   ```sh
   git push origin main v0.4.0
   ```

3. Validate the published GitHub repository directly with Antigravity CLI and confirm exit code `0` with `"findings": []`.

   ```sh
   agy plugin validate --strict --json https://github.com/hs1662/hstack
   ```

4. Optional: create a GitHub Release for the tag.

   ```sh
   gh release create v0.4.0 --title "hstack v0.4.0" --generate-notes
   ```

## Submit to the Antigravity Marketplace

1. Open the [Antigravity Marketplace intake form](https://forms.gle/2EX5RFYPoJe1UgxR9).
2. Enter `https://github.com/hs1662/hstack` as the repository URL and match the submitted version to `"version"` in `plugin.json` (`0.4.0`).
3. Confirm that `plugin.json`, `hooks.json`, `mcp_config.json`, `.claude-plugin/` (with every file its manifest references), `rules/AGENTS.md`, `agents/`, `skills/`, `scripts/`, `assets/logo.svg`, `README.md`, and `README.ko.md` are committed on `main` and pass `agy plugin validate --strict --json https://github.com/hs1662/hstack`.
4. Rerun `env -u PLUGIN_DATA -u PLUGIN_ROOT node test/tiers.mjs fast`, `full`, `fault`, `agy plugin validate --strict --json .`, and `claude plugin validate --strict --json .` before you push any follow-up commits.
