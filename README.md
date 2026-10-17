# @9thlevel/aegis (`ah`)

A PreToolUse guard for coding agents. It reads the tool call Codex or Claude Code is about to make,
decides in under 150 ms, and either stays silent or returns a deny with text the agent can act on.

```
[ah guard] denied by shell.rm-recursive-root: rm targets the filesystem root (/)
Do instead: Nothing in a project needs the filesystem root deleted. Name the specific directory.
(If this is a false positive, tell the user and record it: ah bug add --rule shell.rm-recursive-root --title "<what you were doing>")
```

It is one process, no dependencies, no daemon, no network. It does not plan, orchestrate,
evaluate or remember anything except the incidents that made its rules.

## Status

v0. Not yet published to npm. Used on its own repository. Every rule traces to a blueprint
section or to one of the eighteen records in [`.harness/memory/bugs/`](.harness/memory/bugs/),
which are what nine earlier harness attempts by the same author taught.

## Install

Requires Node 22.18 or later.

```sh
npm install -g @9thlevel/aegis   # when published
# until then, from a checkout:
npm ci && npm run build && npm link
```

## Wiring the hook

`ah init` will do this in step 2. For now, by hand. Use absolute paths to `node` and to
`guard.mjs`: the agent launches hooks without your shell's PATH, and on Windows an npm bin is a
`.cmd` shim that some launchers cannot execute directly (BUG-2026-014). `npm root -g` prints the global `node_modules` directory.

**Claude Code**, in `.claude/settings.json` of the project (or `~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Edit|Write|MultiEdit|NotebookEdit|Read|Agent|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/node",
            "args": ["/absolute/path/to/node_modules/@9thlevel/aegis/dist/guard.mjs", "--agent", "claude"],
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

**Codex**, in `.codex/hooks.json` of the project (or `~/.codex/hooks.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Edit|Write|Agent",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/node /absolute/path/to/node_modules/@9thlevel/aegis/dist/guard.mjs --agent codex",
            "commandWindows": "C:\\absolute\\path\\to\\node.exe C:\\absolute\\path\\to\\node_modules\\@9thlevel\\aegis\\dist\\guard.mjs --agent codex",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

`PowerShell` is in the Claude Code matcher because on Windows Claude Code routes shell commands
through that tool (without Git Bash it does not register `Bash` at all); the guard parses it as
PowerShell on any platform. Git Bash and Cygwin drive spellings (`/c/Users/...`) are resolved against
the Windows project root and home; WSL `/mnt/c/...` is a Linux path. `MultiEdit` is a legacy entry for older installs. An allow prints
nothing, so the per-call cost of a matched tool is one short-lived `node` process.

Project-scoped Codex hooks load only when the `.codex/` directory is trusted, and Codex asks you to
review and trust each non-managed hook definition via `/hooks`. Trust is tied to the hook's hash, so
after any change to the entry (a new `node` path, `--ask-fallback warn`, a different timeout) run
`/hooks` again or re-run the check below; until then the hook is skipped. Hooks are on by default in
current Codex builds; if `features.hooks = false` is in your `config.toml`, nothing here runs.

Check the wiring: ask the agent to run `rm -rf /`. It should be refused with the text shown at the
top of this file.

## What it blocks

Three verdicts. **deny** refuses the call. **ask** pauses for a human in Claude Code; Codex cannot
pause, so there it becomes a deny whose text says why (pass `--ask-fallback warn` to let the call
through with a warning instead). **allow** prints nothing, so the agent's own permission rules still
apply on top.

| family | deny | ask |
| --- | --- | --- |
| shell: destruction | `rm -rf` of `/`, `~`, the project root (also spelled `<root>/*` or `.[!.]*`), `.git`, or anything outside the project (temp directories excepted); `find … -delete` unless a filter narrows it (`-type`, a negated filter, `-name '*'` or a filter placed after `-delete` do not); `mv` of `.git/`, `.harness/` or a hook config away; `dd`/`mkfs` on devices; shutdown; fork bombs; `kill -9 -1` (any signal to pid -1); `chmod -R` on system paths | `rm -rf "$VAR"` and `rm -rf $(pwd)` (temp variables such as `$TMPDIR`, `${TMPDIR:-/tmp}`, `$env:TEMP`, and `${VAR:?unset}/sub` or `$PWD/sub` forms pass), `chmod -R 777 .` or any mode granting write to others, `sudo`, `docker system prune`, `docker volume prune`, `docker compose down -v`, `DROP DATABASE`, `prisma migrate reset` |
| shell: remote code and credentials | `curl \| sh`, `iwr \| iex`, `curl \| python3 -` (an interpreter that runs stdin as code; `curl \| python3 -m json.tool` passes); printing or copying private keys and credential stores, `~/.ssh` or `~/.aws` as a whole included (`~/.ssh/config`, `known_hosts` and `authorized_keys` are not secrets); piping `.env`, keys or `env` to the network; credential literals in a command | `-EncodedCommand`, inline `python`/`node`/`deno`/`perl`/`ruby` code that deletes a tree or shells out to `rm -rf` |
| shell: git | force-push to `main`/`master`/`develop`/`release*`; `--mirror`; `reset --hard`; `checkout .`; `clean -f` with no path (`git clean -f -- dist/` and `git clean -fdX` pass); `stash drop`; `filter-branch`, `replace -d`; `--no-verify`, `HUSKY=0`, `SKIP=`, setting `core.hooksPath` (reading it passes) | force-push to a feature branch, `branch -D`, `checkout -- file`, `checkout -f <branch>`, `switch --discard-changes`, setting `config --global` (`--global --list` passes) |
| shell: writes | redirects, `tee`, `sed -i`, `cp`, `mv`, `rm` aimed at `.harness/`, `.git/` (a stale `*.lock` under `.git/` may be removed), hook configs, linter and test configs, shell rc files and the PowerShell `$PROFILE`, `~/.claude`, `~/.codex`, `~/.ssh`; writing a lockfile by hand (removing one, so the package manager regenerates it, passes) | the same aimed at `.env`, CI files, baselines and snapshots, `/etc` |
| shell: deploy | `terraform destroy`, `gh repo delete`, `aws s3 rb`, `kubectl delete namespace`, and the `az`/`gcloud` deletes of a resource group, project, cluster, database (Firestore included), bucket, storage account, VM or app (one blob, image tag or secret passes) | `npm publish`, `wrangler deploy`, `terraform apply`, `gh pr merge`, `supabase functions deploy`, `az deployment create` (`--dry-run`, `--what-if` and `list`/`get`/`history` forms pass; `--dry-run=none` or `=false` is the real thing) |
| edit: paths | `.harness/`, `.git/`, `.claude/settings*.json`, `.codex/`, `.husky/`, pre-commit and lefthook configs, `biome.json`, eslint and ruff configs, vitest/jest/playwright/pytest configs, lockfiles, home dotfiles, system paths | baselines and snapshots, `tsconfig*.json`, CI workflows, `.env*` (not `.env.example`), key files, files outside the project |
| edit: content | credential literals; file-wide `eslint-disable`, `@ts-nocheck`, `pylint: disable=all`; `.only`, `fit('...')`; `.skip`/`test.fixme` with a title, `@pytest.mark.skip`, `#[ignore]`, `@Disabled`, and an unconditional `t.Skip(`, `pytest.skip(` or `self.skipTest(` (a skip under a visible condition such as `if testing.Short()` or `test.skip(condition, reason)` passes); `"test": "echo ..."` or `\|\| true` in a gate script; `continue-on-error` or `if: false` in CI; `"strict": false` | `@ts-ignore`, bare `# noqa`, `istanbul ignore`, `pragma: no cover`, a changed gate script, any other workflow edit (`if: always()` included), a real-looking token in a test fixture |
| other tools | `Read` of a private key or credential store; a credential literal in any argument of a matched tool | |

`ah rules` prints the full list with each rule's provenance. The authoritative definition is the
fixture corpus: [`fixtures/`](fixtures/README.md) holds about 195 calls that must be denied,
55 that must ask and 190 legitimate neighbours that must pass, and CI runs all of them through the
built guard on Linux and Windows.

## What it is not

A guardrail, not a boundary. The agent runs as you; the guard sees the call text, not its effect.
Codex's own documentation says the same of its hooks: "a useful guardrail, not a complete
enforcement boundary." It cannot see through a script the agent wrote a moment ago, a binary it
compiled, or an interpreter one-liner (a one-liner that visibly deletes a tree or touches hook files
is caught; everything else passes). It does not resolve symlinks. If you need a boundary, use a
container or a separate user; the guard then stops the mistakes, and the boundary stops the rest.

It fails open by default. Malformed input or an internal error exits 1, which Claude Code treats as
a non-blocking hook error, so a broken install never locks you out. To fail closed instead, add
`"onFailure": "block"` to the Claude Code hook entry (Claude Code v2.1.295 or later); under it a
hook that cannot start, times out, or exits with a code other than 0 or 2 blocks the call.

## Recording a false positive

```sh
ah bug add --rule shell.git-discard-changes --title "git checkout . on a throwaway worktree"
```

That writes `.harness/memory/bugs/BUG-2026-NNN.yaml`, the only sanctioned write under `.harness/`.
Fill in what happened, add a `must_allow` fixture, then change the rule. The record comes first;
see [CONTRIBUTING.md](CONTRIBUTING.md).

Every deny and ask is also appended to `.harness/metrics.jsonl` (if `.harness/` exists), one JSON
line each, so you can see what fires in a real project before touching a rule.

## Commands

| command | what |
| --- | --- |
| `ah guard --agent claude\|codex [--root DIR] [--home DIR] [--platform posix\|windows] [--ask-fallback deny\|warn] [--no-log]` | the hook. Reads a PreToolUse payload on stdin. `--no-log` skips the `.harness/metrics.jsonl` line. Env overrides: `AH_PROJECT_ROOT`, `AH_HOME`, `AH_PLATFORM`; `CLAUDE_PROJECT_DIR` is honoured as the root. |
| `ah test-hooks [--budget-ms N] [--json]` | runs the fixture corpus in-process and through `dist/guard.mjs`, reports p50/p95 latency. Also picks up `.harness/hook_tests/` in the current project. |
| `ah bug add\|list` | incident records. |
| `ah rules` | every rule, its verdict and provenance. |

## Development

```sh
npm ci
npm run verify    # build, typecheck, npm test, hygiene scan, then the fixture corpus end to end
                  # through dist/guard.mjs with the p95 budget (150 ms; 400 ms on Windows;
                  # AH_LATENCY_BUDGET_MS overrides). CI runs the same, plus an installed-package
                  # smoke test (npm pack, install, npx ah test-hooks --in-process) on Linux.
```

Tests run with `node --test` on the TypeScript sources directly (Node 22 type stripping); the
guard is bundled with esbuild into a single file with no runtime dependencies.

## License

MIT. Patterns in `src/guard/secrets.ts` were ported from the author's earlier `legion-cli`.
