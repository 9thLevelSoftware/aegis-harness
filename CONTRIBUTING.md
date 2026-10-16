# Contributing

## Grow by incident

`ah` adds a rule only when something went wrong. The order is fixed:

1. **Record it.** `ah bug add --rule <closest rule or none> --title "<what happened>"` writes
   `.harness/memory/bugs/BUG-YYYY-NNN.yaml`. Fill in `root_cause`, `impact` and `countermeasure`.
   A record with no session, repository or document behind it is speculation and is closed, not fixed.
2. **Write both fixtures.** One under `fixtures/must_block/` (or `must_ask/`) that reproduces the
   incident, and one under `fixtures/must_allow/` for the nearest legitimate call, with `near` set to
   the rule. A rule with no known false-positive boundary cannot merge; `tests/fixtures.test.ts`
   enforces it.
3. **Change the rule.** Register it in `src/guard/rules/registry.ts` with a `provenance` that names
   the record. Implement it in `src/guard/rules/{shell,edit,other}.ts`.
4. **Run `npm run verify`.** Build, typecheck, every test, the hygiene scan and the fixture corpus
   with the latency budget. It is what CI runs.

The same path applies in reverse. A rule that fires on legitimate work gets a record, a `must_allow`
fixture, and then a narrower rule. A rule nobody has seen fire in `.harness/metrics.jsonl` for a
quarter is a candidate for removal.

Things that do not go in without a record: new agents, new subcommands, new directories under
`.harness/`, anything that runs on a timer, anything that needs a network.

## What a rule must be

- **Pure.** `decide(call, context)` reads nothing from disk or the network. The context carries the
  project root, home directory, platform and policy; the rule reads those and the call.
- **Lexical.** Paths are classified from their text against the project root and home directory.
  The guard never resolves symlinks or stats files; an agent that can create a symlink can defeat
  any check that does, and the check would cost the latency budget.
- **Explained.** Every deny and ask carries a `reason` an agent can act on and a `remediation` that
  says what to do instead. The agent reads it, so write it for the agent.
- **Cheap.** CI fails when p95 latency of the bundled guard exceeds 150 ms on Linux
  (400 ms on the Windows runner). No dependencies in `dist/guard.mjs`.

## Docs

The README stays under 300 lines (`tests/docs.test.ts`). There is no `plans/` directory. Design
reasoning lives in the bug records and in commit messages. If a change needs a long explanation,
the explanation is the record and the commit message, not a document.

## Fixtures never name a real machine

Paths in fixtures, tests and docs use `/home/dev`, `/Users/dev` and `C:\Users\dev`.
`npm run check:hygiene` fails on anything else; see BUG-2026-006 for why.

## Commit and PR conventions

Conventional commit subjects (`feat:`, `fix:`, `test:`, `docs:`, `chore:`). A PR that adds or
changes a rule links its bug record in the description. CI must be green on the Linux job before
merge; the Windows job is advisory until it has been green for 30 days.
