# Changelog

## 0.1.0

The first npm release.

Since the release candidate:

- `.harness/policy.json` overrides a rule for one project: `ask`, `off` or `deny`. An override applies
  where its rule fires, so turning one rule off never hides another; the guard's own limits cannot be
  overridden, and a file that is not valid is ignored as a whole. `ah doctor` reports problems in it
  (BUG-2026-022).
- `ah stats` counts denies, asks and overridden calls per rule from `.harness/metrics.jsonl`.
- `ah init` keeps `.harness/metrics.jsonl` out of git through `.git/info/exclude`.
- A deny now tells the agent that the user can set the rule to `ask` in `.harness/policy.json`.
- MCP tools that run commands or write, edit, move or delete local files (Desktop Commander, the
  filesystem server and the like) meet the shell and edit rules, not only the secret checks
  (BUG-2026-023).
- CI also runs on Node 24.
- Moving a protected branch (`git branch -f main`, `git checkout -B main`, `git switch -C main`)
  asks, and `git update-index --assume-unchanged` or `--skip-worktree` on a lint, test or hook
  config is denied (BUG-2026-024).

The candidate:

- `ah guard`: the PreToolUse hook for Claude Code and Codex. 75 rules (46 deny, 29 ask) check
  shell commands (bash, PowerShell and cmd), file edits, reads, searches and MCP calls; anything
  else passes silently. Relative paths are read from the directory a command runs in, `cd` within
  the command included. Each rule traces to a blueprint section or an incident record under
  `.harness/memory/bugs/`. The guard is lexical, has no dependencies, and asks instead of failing
  open when a command takes longer than 2 s to check.
- `ah init`: wires the hook for both agents (`--scope local|project|user`, `--fail-closed`,
  `--ask-fallback warn`) and the `AGENTS.md` block; `--dry-run` and `--remove`. It refuses to wire
  a guard that lets `rm -rf /` through, and a second run changes nothing.
- `ah doctor`: reads every settings file each agent loads, reports switches that turn hooks off,
  stale paths, duplicates and Codex hook trust, then runs each hook the way its agent would with
  three canaries.
- `ah stats`, `ah test-hooks`, `ah bug add|list`, `ah rules`, `ah version`.
- A fixture corpus of 449 `must_block`, 76 `must_ask` and 350 `must_allow` calls, replayed in CI
  on Linux and Windows within a p95 budget of 150 ms (400 ms on Windows). A probe pass before the
  release added 146 of them (BUG-2026-020), and an audit of the candidate 18 more
  (BUG-2026-021).

Known limits: the guard reads the call text, not its effect, so a command built at run time, a
script the agent wrote a moment ago or a symlink can get past it. See "What it is not" in the
README.
