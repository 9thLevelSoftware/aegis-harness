# @9thlevel/aegis (`ah`)

A PreToolUse guard for coding agents. It reads the tool call Codex or Claude Code is about to make,
decides in under 150 ms, and either stays silent or returns a deny with text the agent can act on.

```
[ah guard] denied by edit.lint-config: .ruff.toml is a linter configuration file.
Do instead: fix the finding in the source file, or ask the user to change the rule.
(If this is a false positive, record it: ah bug add --rule edit.lint-config --title "...")
```

It is one process, no dependencies, no daemon, no network. It does not plan, orchestrate,
evaluate or remember anything except the incidents that made its rules.

## Status

v0. Not yet published to npm. Used on its own repository. Every rule traces to a blueprint
section or to one of the fifteen records in [`.harness/memory/bugs/`](.harness/memory/bugs/),
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
        "matcher": "Bash|Write|Edit|MultiEdit|Read|Agent",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/node",
            "args": ["/absolute/path/to/node_modules/@9thlevel/aegis/dist/guard.mjs", "--agent", "claude"],
            "timeout": 5,
            "onFailure": "block"
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
        "matcher": "Bash|Edit|Write",
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

Project-scoped Codex hooks load only when the `.codex/` directory is trusted, and Codex asks you to
trust non-managed hooks once via `/hooks`. Hooks are on by default in current Codex builds; if
`features.hooks = false` is in your `config.toml`, nothing here runs.

Check the wiring: ask the agent to run `rm -rf /`. It should be refused with the text above.

## What it blocks

Three verdicts. **deny** refuses the call. **ask** pauses for a human in Claude Code; Codex cannot
pause, so there it becomes a deny whose text says why (pass `--ask-fallback warn` to let the call
through with a warning instead). **allow** prints nothing, so the agent's own permission rules still
apply on top.

| family | deny | ask |
| --- | --- | --- |
| shell: destruction | `rm -rf` of `/`, `~`, the project root, `.git`, or anything outside the project; `dd`/`mkfs` on devices; shutdown; fork bombs; `kill -1`; `chmod -R` on system paths | `rm -rf "$VAR"`, `chmod -R 777 .`, `sudo`, `docker system prune`, `DROP DATABASE`, `prisma migrate reset` |
| shell: remote code and credentials | `curl \| sh`, `iwr \| iex`; printing private keys or credential stores; piping `.env`, keys or `env` to the network; credential literals in a command | `-EncodedCommand`, `python -c` with `rmtree` |
| shell: git | force-push to `main`/`master`/`develop`/`release*`; `--mirror`; `reset --hard`; `checkout .`; `clean -f`; `stash drop`; `filter-branch`; `--no-verify`, `HUSKY=0`, `SKIP=`, `core.hooksPath` | force-push to a feature branch, `branch -D`, `checkout -- file`, `config --global` |
| shell: writes | redirects, `tee`, `sed -i`, `cp`, `mv`, `rm` aimed at `.harness/`, `.git/`, hook configs, linter and test configs, lockfiles, shell rc files, `~/.claude`, `~/.codex`, `~/.ssh` | the same aimed at `.env`, CI files, baselines and snapshots, `/etc` |
| shell: deploy | `terraform destroy`, `gh repo delete`, `aws s3 rb`, `kubectl delete namespace` | `npm publish`, `wrangler deploy`, `terraform apply`, `gh pr merge`, `supabase functions deploy` |
| edit: paths | `.harness/`, `.git/`, `.claude/settings*.json`, `.codex/`, `.husky/`, pre-commit and lefthook configs, `biome.json`, eslint and ruff configs, vitest/jest/playwright/pytest configs, lockfiles, home dotfiles, system paths | baselines and snapshots, `tsconfig*.json`, CI workflows, `.env*` (not `.env.example`), key files, files outside the project |
| edit: content | credential literals; file-wide `eslint-disable`, `@ts-nocheck`, `pylint: disable=all`; `.skip`, `.only`, `@pytest.mark.skip`, `#[ignore]`, `test.fixme`; `"test": "echo ..."` or `\|\| true` in a gate script; `continue-on-error` in CI; `"strict": false` | `@ts-ignore`, bare `# noqa`, `istanbul ignore`, `pragma: no cover`, a changed gate script, a real-looking token in a test fixture |
| other tools | `Read` of a private key or credential store; a credential literal in any tool argument | |

`ah rules` prints the full list with each rule's provenance. The authoritative definition is the
fixture corpus: [`fixtures/`](fixtures/README.md) holds about 150 calls that must be denied,
40 that must ask and 120 legitimate neighbours that must pass, and CI runs all of them through the
built guard on Linux and Windows.

## What it is not

A guardrail, not a boundary. The agent runs as you; the guard sees the call text, not its effect.
Codex's own documentation says the same of its hooks: "a useful guardrail, not a complete
enforcement boundary." It cannot see through a script the agent wrote a moment ago, a binary it
compiled, or an interpreter one-liner (those `ask`). It does not resolve symlinks. If you need a
boundary, use a container or a separate user; the guard then stops the mistakes, and the boundary
stops the rest.

It fails open on its own errors (exit 1, which Claude Code treats as non-blocking) so a broken
install never locks you out. Set `"onFailure": "block"` in the Claude Code hook if you prefer
fail-closed.

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
| `ah guard --agent claude\|codex` | the hook. Reads a PreToolUse payload on stdin. |
| `ah test-hooks [--budget-ms N] [--json]` | runs the fixture corpus in-process and through `dist/guard.mjs`, reports p50/p95 latency. Also picks up `.harness/hook_tests/` in the current project. |
| `ah bug add\|list` | incident records. |
| `ah rules` | every rule, its verdict and provenance. |

## Development

```sh
npm ci
npm run verify    # build, typecheck, tests, hygiene scan, fixtures with the latency budget
```

Tests run with `node --test` on the TypeScript sources directly (Node 22 type stripping); the
guard is bundled with esbuild into a single file with no runtime dependencies.

## License

MIT. Patterns in `src/guard/secrets.ts` were ported from the author's earlier `legion-cli`.
