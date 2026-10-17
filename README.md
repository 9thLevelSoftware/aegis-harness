# @9thlevelsoftware/aegis (`ah`)

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

0.1.0, the first npm release ([CHANGELOG.md](CHANGELOG.md)). Used on its own repository. Every
rule traces to a blueprint section or to one of the nineteen records in
[`.harness/memory/bugs/`](.harness/memory/bugs/), which are what nine earlier harness attempts by
the same author taught.

## Install

Requires Node 22.18 or later.

```sh
npm install -g @9thlevelsoftware/aegis
# or, from a checkout:
npm ci && npm run build && npm link
```

## Wiring the hook

```sh
ah init      # Claude Code and Codex, this project, this machine (--agents claude or codex for one)
ah doctor    # checks what each agent will load, then pushes a canary through each hook
```

`ah init` writes one PreToolUse entry per agent with absolute paths to `node` and `guard.mjs`
(agents launch hooks without your shell's PATH, and on Windows an npm bin is a `.cmd` shim:
BUG-2026-014), and a short block between `<!-- ah:begin -->` markers in `AGENTS.md` that tells the
agent what a refusal means. It first runs the guard on `rm -rf /` and will not wire one that lets
it through. Nothing else in those files changes: your hooks keep their place and their text, a
file that is not plain JSON is refused, and a second run is a no-op. `ah init --remove` takes it
all out again; `--dry-run` prints the plan.

| `--scope` | Claude Code | Codex |
| --- | --- | --- |
| `local` (default) | `.claude/settings.local.json` at the repository root (on Windows, in this folder) | `.codex/hooks.json` (in a linked worktree, the main checkout's) |
| `project` | `.claude/settings.json` | `.codex/hooks.json` |
| `user` | `~/.claude/settings.json` | `~/.codex/hooks.json` |

Local files hold this machine's paths, so `ah init` adds them to `.git/info/exclude` and warns
if one is already tracked. Claude Code reads `.claude/settings.json` only from the directory a
session starts in, but `settings.local.json` at the repository root for any session inside it,
except on Windows, where it too is read only in the start directory: a session started in a
subfolder there runs without the hook, so use `--scope user` if you work that way. In a linked
git worktree Claude Code reads `settings.local.json` and Codex reads every `.codex/` file from the
main checkout, never the worktree's, so local scope writes them there. The paths are this
machine's, so a checkout shared between WSL and Windows (`/mnt/c/...`) needs `--scope user` on
each side: one side cannot run the other's `node`.

Codex then needs two things you do in Codex itself: trust the project when it asks, and trust
the ah hook in `/hooks`. Codex keys that trust to the entry's hash and position, so ah appends its
entry after your hooks and keeps it there; after a change to the entry (a new `node` path,
`--ask-fallback warn`) Codex asks again. `ah doctor` says which step is still missing.

`ah doctor` reads every settings file each agent loads and reports whether the hook is bound and
for which tools; switches that turn hooks off (`disableAllHooks`, `allowManagedHooksOnly`, Claude
Code's Windows registry policy, Codex `features.hooks` and `allow_managed_hooks_only`); entries
that make an agent reject a whole file; stale paths; duplicates; workspace and hook trust; and
whether the `AGENTS.md` block is current. For Codex it also asks Codex itself (`codex app-server`; no
model call) which hooks it loads for this folder and whether it trusts ah's, since Codex skips an
entry that changed after you trusted it.
Then it runs each hook's command the way its agent would, with three canaries: `rm -rf /` and an
edit to `.ruff.toml` must be refused and `ls` must pass. It exits 1 when any check fails. The
canary proves the command; the last check is the agent: ask it to run `rm -rf /` and to edit
`.ruff.toml`. Both should be refused with text like the sample at the top of this file.

What `ah init` writes, if you wire by hand (Claude Code, exec form, no shell):

```json
{"matcher": "^(Bash|PowerShell|Monitor|Edit|Write|MultiEdit|NotebookEdit|Read|Grep|Agent|WebFetch|Workflow|mcp__.*)$",
 "hooks": [{"type": "command", "command": "/abs/node", "args": ["/abs/dist/guard.mjs", "--agent", "claude"], "timeout": 5}]}
```

and Codex (`command` runs under `bash -c`; `commandWindows` is for Windows):

```json
{"matcher": "^(Bash|Edit|Write|Agent|mcp__.*)$",
 "hooks": [{"type": "command", "command": "/abs/node /abs/dist/guard.mjs --agent codex", "timeout": 5}]}
```

`PowerShell` is in the Claude Code matcher because on Windows Claude Code routes shell commands
through that tool (without Git Bash it does not register `Bash` at all); the guard parses it as
PowerShell on any platform. `Monitor` runs a shell command in the background, so it gets the
same checks as `Bash`. `Grep` prints the lines it finds, so a search of `~/.ssh` gets the private-key rule that `Read` gets. `mcp__.*` sends MCP tool calls through the guard for the credential-literal
and private-key rules; the matchers are anchored because both agents read them as regexes. Git Bash and Cygwin drive spellings (`/c/Users/...`) are resolved against
the Windows project root and home; WSL `/mnt/c/...` is a Linux path. `MultiEdit` is a legacy entry for older installs. An allow prints
nothing, so the per-call cost of a matched tool is one short-lived `node` process.

## What it blocks

Three verdicts. **deny** refuses the call. **ask** pauses for a human in Claude Code; Codex cannot
pause, so there it becomes a deny whose text says why (pass `--ask-fallback warn` to let the call
through with a warning instead). **allow** prints nothing, so the agent's own permission rules still
apply on top.

| family | deny | ask |
| --- | --- | --- |
| shell: destruction | `rm -rf` of `/`, `~`, the project root (also spelled `<root>/*` or `.[!.]*`), `.git`, or anything outside the project (temp directories excepted); `find … -delete` unless a filter narrows it (`-type`, a negated filter, `-name '*'` or a filter placed after `-delete` do not); `mv` (or `Rename-Item`, `ren`, `rename`) of `.git/`, `.harness/` or a hook config away, or of a directory that holds one (`.claude`, `~/.claude`); `dd`/`mkfs` on devices; shutdown; fork bombs; `kill -9 -1` (any signal to pid -1); `chmod -R` on system paths | `rm -rf "$VAR"` and `rm -rf $(pwd)` (temp variables such as `$TMPDIR`, `${TMPDIR:-/tmp}`, `$env:TEMP`, and `${VAR:?unset}/sub` or `$PWD/sub` forms pass), `chmod -R 777 .` or any mode granting write to others, `sudo`, `docker system prune`, `docker volume prune`, `docker compose down -v`, `DROP DATABASE`, `prisma migrate reset` |
| shell: remote code and credentials | `curl \| sh`, `iwr \| iex`, `curl \| python3 -` (an interpreter that runs stdin as code; `curl \| python3 -m json.tool` passes), and the same without a pipe: `bash <(curl …)`, `source <(curl …)`, `bash -c "$(curl …)"`, `eval "$(curl …)"`, `iex (iwr …)` (`diff <(curl a) <(curl b)` passes); printing or copying private keys and credential stores, `~/.ssh` or `~/.aws` as a whole included, with `cat`, `grep`, `sed`, `awk`, `jq`, `sort`, `diff`, `dd if=`, `openssl` (not `-pubout`), an archive or a `<` redirect (`~/.ssh/config`, `known_hosts`, `authorized_keys`, public keys and certificates such as `ca.pem` are not secrets); piping `.env`, keys or `env` to the network; credential literals in a command; starting a nested agent with hooks off (`claude --bare`, `--safe-mode`, `--setting-sources` without every source, `--settings '{"disableAllHooks":true}'`, `codex --disable hooks`, `-c features.hooks=false`, a fresh `CODEX_HOME`) | `-EncodedCommand`, inline `python`/`node`/`deno`/`perl`/`ruby` code that deletes a tree or shells out to `rm -rf` |
| shell: git | force-push to `main`/`master`/`develop`/`release*`; `--mirror`; `reset --hard`; `checkout .`; `clean -f` with no path (`git clean -f -- dist/` and `git clean -fdX` pass); `stash drop`; `filter-branch`, `replace -d`; `git rm`, `git mv` and `git clean -f -- <path>` on the paths `rm` and `mv` may not touch (`git rm --cached` passes); `--no-verify` on a command that runs hooks (`git grep -e --no-verify` passes), `HUSKY=0`, `SKIP=`, setting or unsetting `core.hooksPath` (reading it passes) | force-push to a feature branch, `branch -D`, `checkout -- file`, `checkout -f <branch>`, `switch --discard-changes`, setting `config --global` (reading a key or `--global --list` passes) |
| shell: writes | redirects (`>&file` included), `tee`, `sed -i` in any spelling, `perl -i`, `awk -i inplace`, `yq -i`, `sponge`, `dd of=`, `curl -o`, `wget -O`, `rsync`, `git --output`, and `cp`, `mv`, `install`, `ln` (into a directory too) and `rm` aimed at `.harness/`, `.git/` (a stale `*.lock` under `.git/` may be removed), hook configs, linter and test configs, shell rc files and the PowerShell `$PROFILE`, `~/.claude`, `~/.codex`, `~/.ssh`; writing a lockfile by hand (removing one, so the package manager regenerates it, passes) | the same aimed at `.env`, CI files, baselines and snapshots, `/etc` (`/dev/stderr`, `/dev/tty` and `/dev/fd/N` pass) |
| shell: deploy | `terraform destroy`, `gh repo delete`, `aws s3 rb`, `kubectl delete namespace` (or `ns/x`), and the `az`/`gcloud` deletes (`gcloud beta` and `alpha` included) of a resource group, project, cluster, database (Firestore included), bucket, storage account, VM or app (one blob, image tag or secret passes) | `npm publish`, `wrangler deploy`, `terraform apply`, `gh pr merge`, `supabase functions deploy`, `az deployment create` (`--dry-run`, `--what-if`, `--help` and `list`/`get`/`history` forms pass, as does `aws s3 sync` from a bucket to a local folder; `--dry-run=none` or `=false` is the real thing) |
| edit: paths | `.harness/`, `.git/`, `.claude/settings*.json`, `.codex/`, `.husky/`, pre-commit and lefthook configs, `biome.json`, eslint and ruff configs, vitest/jest/playwright/pytest configs, lockfiles, home dotfiles, system paths | baselines and snapshots, `tsconfig*.json`, CI workflows, `.env*` (not `.env.example`), key files, files outside the project |
| edit: content | credential literals; file-wide `eslint-disable`, `@ts-nocheck` (in any case), `pylint: disable=all`, `# ruff: noqa`; `.only` (`.only.each` and `it.concurrent.only` too), `fit('...')`; `.skip`/`test.fixme` with a title (`.skip.each` too), `@pytest.mark.skip`, `#[ignore]`, `@Disabled`, and an unconditional `t.Skip(`, `pytest.skip(` or `self.skipTest(` (a skip under a visible condition such as `if testing.Short()` or `test.skip(condition, reason)` passes); `"test": "echo ..."` or `\|\| true` in a gate script; `continue-on-error` or `if: false` in CI; `"strict": false` | `@ts-ignore`, bare `# noqa`, `istanbul ignore`, `pragma: no cover`, a changed gate script, any other workflow edit (`if: always()` included), a real-looking token in a test fixture. A suppression or skip written in prose (`.md`, `.txt`, `.rst`, such as a rule in `CLAUDE.md`) is text and passes |
| other tools | `Read` of a private key or credential store, and `Grep` printing lines from one; a credential literal in any argument of a matched tool | |

Hook files and `.git/` count wherever the agents load them from: in every directory above the
folder a session started in, and in a linked worktree's main checkout, so a session in `sub/`
cannot remove `../.claude/settings.local.json` or `../.git/hooks/pre-commit` either.

Relative paths are read from the directory the command runs in: the agent's working directory
(Claude Code reports it after a `cd`; Codex names a `workdir`), then any `cd`, `pushd`,
`Set-Location`, `env -C` or `sudo -D` earlier in the same command line. After `&&` only the new
directory counts; after `;`, `||` or `&` the `cd` may have failed, so both count, which is why
`cd dist && rm -rf *` passes and `cd dist; rm -rf *` does not. Each such `cd` doubles the places
the rest may run, so past 1024 of them (about nine `cd x; make; cd ..` round trips) the guard asks;
`(cd x && make)` per folder, or `&&` throughout, keeps the count at one. When the session moves to
another project (`/cd`), that project's hook files are the ones protected.

`ah rules` prints the full list with each rule's provenance. The authoritative definition is the
fixture corpus: [`fixtures/`](fixtures/README.md) holds about 430 calls that must be denied,
70 that must ask and 330 legitimate neighbours that must pass, and CI runs all of them through the
built guard on Linux and Windows. Commands inside loops, `if` blocks, functions and PowerShell
`{ }` blocks meet every rule, so a `for` loop that runs `rm -rf "$d"` asks like the bare command.
sh brace expansion is applied first, as bash does it (`mv .ruff.toml{,.bak}`, `.claud{e..e}`,
quoted parts and all); past 1024 words, or 64 groups in one word, the guard asks instead. A here-document is read as the
command's stdin, as bash reads it, so JSON or a commit message in one is text, unless the command
runs its stdin (`bash <<'EOF'`, `cat <<'EOF' | sh`). `$'...'` is decoded (`$'\x2eclaude'` is
`.claude`), and code nested more than eight levels deep asks, as does a command that takes the
guard more than two seconds to read, since a hook that times out lets the call through. A wildcard counts as the protected
path it names (`rm .claude/*`, `rm .eslintrc*`, `rm .g*/hooks/pre-commit`); one that names only
an extension (`rm dist/*.js`) or nothing (`rm -rf src/*`) does not. In Git Bash a wildcard skips
dotfiles, as sh does; in PowerShell and cmd it matches them.

## What it is not

A guardrail, not a boundary. The agent runs as you; the guard sees the call text, not its effect.
Codex's own documentation says the same of its hooks: "a useful guardrail, not a complete
enforcement boundary." It cannot see through a script the agent wrote a moment ago, a binary it
compiled, or an interpreter one-liner (a one-liner that visibly deletes a tree or touches hook files
is caught; everything else passes). It does not resolve symlinks, follow a `cd` to a directory
held in a variable, or read a settings file a nested agent is pointed at (`claude --settings
file.json`). On Codex, a shell the agent opens without a command (`bash`) takes later input
through `write_stdin`, which runs no hook. If you need a boundary, use a
container or a separate user; the guard then stops the mistakes, and the boundary stops the rest.

It fails open by default. Malformed input exits 1, which Claude Code treats as a non-blocking hook
error, so a broken install never locks you out. A call the guard fails on while checking it asks
instead, so a command that trips a bug in the guard cannot switch its checks off. To fail closed instead, run
`ah init --fail-closed` (Claude Code v2.1.295 or later; it sets `"onFailure": "block"`); then a
hook that cannot start, times out, or exits with a code other than 0 or 2 blocks the call. Codex
has no such switch: a hook that cannot start lets the call through.

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
| `ah init [--agents claude,codex] [--scope local\|project\|user] [--fail-closed] [--remove] [--dry-run]` | wires the hook and the `AGENTS.md` block (see [Wiring the hook](#wiring-the-hook)). `ah init --help` for the rest. |
| `ah doctor [--agents claude,codex] [--json]` | checks the wiring and runs the canaries. |
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
                  # smoke test (npm pack, install, npx ah test-hooks --in-process, then
                  # ah init and ah doctor in a scratch project) on Linux.
```

Tests run with `node --test` on the TypeScript sources directly (Node 22 type stripping), one file at a time so the latency tests measure the guard rather than their neighbours; the
guard is bundled with esbuild into a single file with no runtime dependencies.

## License

MIT. Patterns in `src/guard/secrets.ts` were ported from the author's earlier `legion-cli`.
