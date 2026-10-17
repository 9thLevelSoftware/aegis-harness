# Changelog

## 0.1.0

The first npm release.

- `ah guard`: the PreToolUse hook for Claude Code and Codex. 74 rules (46 deny, 28 ask) check
  shell commands (bash, PowerShell and cmd), file edits, reads and MCP calls; anything else passes
  silently. Each rule traces to a blueprint section or an incident record under
  `.harness/memory/bugs/`. The guard is lexical, has no dependencies, and asks instead of failing
  open when a command takes longer than 2 s to check.
- `ah init`: wires the hook for both agents (`--scope local|project|user`, `--fail-closed`,
  `--ask-fallback warn`) and the `AGENTS.md` block; `--dry-run` and `--remove`. It refuses to wire
  a guard that lets `rm -rf /` through, and a second run changes nothing.
- `ah doctor`: reads every settings file each agent loads, reports switches that turn hooks off,
  stale paths, duplicates and Codex hook trust, then runs each hook the way its agent would with
  three canaries.
- `ah test-hooks`, `ah bug add|list`, `ah rules`, `ah version`.
- A fixture corpus of 351 `must_block`, 61 `must_ask` and 271 `must_allow` calls, replayed in CI
  on Linux and Windows within a p95 budget of 150 ms (400 ms on Windows).

Known limits: the guard reads the call text, not its effect, so a command built at run time, a
script the agent wrote a moment ago or a symlink can get past it. See "What it is not" in the
README.
