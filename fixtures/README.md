# Fixture corpus

Every file here is one hook payload and the verdict the guard must return for it.
The directory carries the expectation:

| directory     | verdict | meaning                                                   |
| ------------- | ------- | --------------------------------------------------------- |
| `must_block/` | deny    | the call is refused and the agent gets a remediation      |
| `must_allow/` | allow   | the guard stays silent; the agent's own permissions apply |
| `must_ask/`   | ask     | a human confirms (Claude Code); Codex treats it as deny   |

A fixture:

```json
{
  "name": "git push --force origin main is denied",
  "agent": "claude",            // or "codex"; shapes the payload the way that agent sends it
  "platform": "posix",          // or "windows"; sets path semantics and the default cwd/home
  "payload": { "tool_name": "Bash", "tool_input": { "command": "git push --force origin main" } },
  "rule": "shell.git-force-push",   // must_block / must_ask: the rule that must fire
  "near": "shell.git-force-push",   // must_allow: the rule this legitimate call brushes against
  "source": "blueprint §3.2"        // optional provenance
}
```

Optional fields:

- `expect`: `"deny"`, `"allow"` or `"ask"`. Redundant with the directory and must agree with it;
  a fixture whose `expect` contradicts its directory is rejected when the corpus loads.
- `cwd`: the project root the guard is given (`--root`). Defaults to `/home/dev/project`
  (or `C:\Users\dev\project` when `platform` is `windows`).
- `home`: the home directory (`--home`). Defaults to `/home/dev` (or `C:\Users\dev`).

Paths in fixtures are never a real person's machine: only `/home/dev`, `/Users/dev`,
`C:\Users\dev` and `/tmp`; `npm run check:hygiene` enforces that.

Rules of the corpus, enforced by `tests/fixtures.test.ts`:

- every rule in `src/guard/rules/registry.ts` has at least one `must_block` or `must_ask` fixture
  and at least one `must_allow` fixture whose `near` names it, so no rule exists without a known
  false-positive boundary;
- every `rule` and `near` names a registered rule;
- the corpus never shrinks below 30 `must_block` and 30 `must_allow` entries.

Run them with `ah test-hooks`. Each fixture runs in-process against the decision core and end to
end through `dist/guard.mjs` over stdin, the way an agent runs it.
