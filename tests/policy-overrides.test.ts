/**
 * `.harness/policy.json` overrides and `ah stats` (BUG-2026-022).
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { tally } from "../src/cli/stats.ts";
import { decideAll } from "../src/guard/decide.ts";
import type { Context, RuleOverride } from "../src/guard/model.ts";
import { DEFAULT_POLICY } from "../src/guard/policy.ts";
import { parsePolicyFile } from "../src/guard/policy-file.ts";

const here = dirname(fileURLToPath(import.meta.url));
const guard = resolve(here, "../dist/guard.mjs");
const skip = !existsSync(guard) && "run npm run build first";

const ctx = (overrides?: Record<string, RuleOverride>): Context => ({
  projectRoot: "/home/dev/project",
  homeDir: "/home/dev",
  platform: "posix",
  policy: DEFAULT_POLICY,
  ...(overrides ? { overrides } : {}),
});
const shell = (command: string) => [{ kind: "shell" as const, command }];

test("policy file: off, ask and deny are read; unknown and guard.* rules are skipped and reported", () => {
  const p = parsePolicyFile(JSON.stringify({ rules: { "shell.git-discard-changes": "off", "edit.lint-config": "ask", "shell.deploy-or-publish": "deny", "nope.rule": "off", "guard.time-limit": "off" } }));
  assert.deepEqual({ ...p.overrides }, { "shell.git-discard-changes": "off", "edit.lint-config": "ask", "shell.deploy-or-publish": "deny" });
  assert.equal(p.problems.length, 2);
  assert.match(p.problems.join("\n"), /nope\.rule/);
  assert.match(p.problems.join("\n"), /guard\.time-limit/);
});

test("policy file: a file that is not valid is ignored as a whole, so no rule goes off by a typo", () => {
  for (const text of ["{", "[]", "{}", '{"rules": []}', '{"rules": {"shell.git-discard-changes": "of"}}', '{"rules": {"shell.git-discard-changes": "off", "edit.lint-config": false}}']) {
    const p = parsePolicyFile(text);
    assert.deepEqual({ ...p.overrides }, {}, text);
    assert.equal(p.problems.length, 1, text);
  }
});

test("no overrides: the defaults stand", () => {
  assert.equal(decideAll(shell("git reset --hard"), ctx()).verdict, "deny");
});

test("off lets the rule's calls through and reports it as suppressed", () => {
  const d = decideAll(shell("git reset --hard"), ctx({ "shell.git-discard-changes": "off" }));
  assert.equal(d.verdict, "allow");
  assert.deepEqual(d.suppressed, ["shell.git-discard-changes"]);
});

test("off on one rule never hides another rule in the same command", () => {
  const d = decideAll(shell("git reset --hard && rm -rf /"), ctx({ "shell.git-discard-changes": "off" }));
  assert.equal(d.verdict, "deny");
  assert.equal(d.rule, "shell.rm-recursive-root");
  assert.deepEqual(d.suppressed, ["shell.git-discard-changes"]);
});

test("ask turns a deny into an ask that says why; deny hardens an ask", () => {
  const a = decideAll(shell("git reset --hard"), ctx({ "shell.git-discard-changes": "ask" }));
  assert.equal(a.verdict, "ask");
  assert.match(a.reason ?? "", /deny by default; ask by \.harness\/policy\.json/);
  const d = decideAll(shell("npm publish"), ctx({ "shell.deploy-or-publish": "deny" }));
  assert.equal(d.verdict, "deny");
});

test("the guard's own limits cannot be overridden", () => {
  const d = decideAll(shell(`echo ${"{a,b}".repeat(30)}`), ctx({ "shell.brace-expansion-limit": "off", "guard.time-limit": "off" } as Record<string, RuleOverride>));
  assert.notEqual(d.verdict, "allow");
});

test("overrides do not leak into the next decision", () => {
  decideAll(shell("git reset --hard"), ctx({ "shell.git-discard-changes": "off" }));
  assert.equal(decideAll(shell("git reset --hard"), ctx()).verdict, "deny");
});

test("the hook reads .harness/policy.json from the project and logs an off as firing", { skip }, () => {
  const root = mkdtempSync(join(tmpdir(), "ah-policy-"));
  try {
    mkdirSync(join(root, ".harness"));
    writeFileSync(join(root, ".harness", "policy.json"), JSON.stringify({ rules: { "shell.git-discard-changes": "off" } }));
    const payload = JSON.stringify({ hook_event_name: "PreToolUse", session_id: "t", cwd: root, tool_name: "Bash", tool_input: { command: "git reset --hard" } });
    const r = spawnSync(process.execPath, [guard, "--agent", "claude", "--root", root], { input: payload, encoding: "utf8", env: { ...process.env, AH_NO_LOG: "" } });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, "");
    const log = readFileSync(join(root, ".harness", "metrics.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(log.length, 1);
    assert.equal(log[0].verdict, "off");
    assert.equal(log[0].rule, "shell.git-discard-changes");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("stats: counts per rule and verdict, skips other lines, honours since", () => {
  const line = (ts: string, verdict: string, rule: string) => JSON.stringify({ ts, event: "ah.guard.decision", verdict, rule });
  const text = [
    line("2026-11-01T10:00:00.000Z", "deny", "shell.git-discard-changes"),
    line("2026-11-08T10:00:00.000Z", "deny", "shell.git-discard-changes"),
    line("2026-11-08T11:00:00.000Z", "off", "shell.git-discard-changes"),
    line("2026-11-09T10:00:00.000Z", "ask", "shell.deploy-or-publish"),
    "not json",
    JSON.stringify({ event: "something.else" }),
  ].join("\n");
  const all = tally(text, "m");
  assert.equal(all.total, 4);
  assert.equal(all.skipped, 2);
  assert.deepEqual(all.rules[0], { rule: "shell.git-discard-changes", deny: 2, ask: 0, off: 1, last: "2026-11-08T11:00:00.000Z" });
  assert.ok(all.silent.includes("shell.rm-recursive-root"));
  assert.ok(!all.silent.includes("shell.deploy-or-publish"));
  const recent = tally(text, "m", "2026-11-05T00:00:00.000Z");
  assert.equal(recent.total, 3);
  assert.equal(recent.first, "2026-11-08T10:00:00.000Z");
});
