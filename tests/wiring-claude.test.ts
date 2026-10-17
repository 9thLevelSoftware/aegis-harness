/**
 * Claude Code specifics: the entry ah writes is exec form and schema-valid,
 * carries over what a person set, never silently drops fail-closed, and the
 * matcher logic agrees with Claude Code's (exact list vs regex, aliases).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { atLeast, CLAUDE_MATCHER, CLAUDE_REQUIRED_TOOLS, claudeGroup, claudeMatcherCovers, parseVersion } from "../src/wiring/claude.ts";
import type { Machine } from "../src/wiring/project.ts";

const m: Machine = { root: "/home/dev/project", home: "/home/dev", os: "linux", env: {}, nodePath: "/usr/bin/node", guardPath: "/home/dev/.npm-global/lib/node_modules/@9thlevel/aegis/dist/guard.mjs" };

test("the canonical entry is exec form with a timeout and nothing Claude Code would reject", () => {
  const g = claudeGroup(m, {}, []);
  assert.deepEqual(g, { matcher: CLAUDE_MATCHER, hooks: [{ type: "command", command: "/usr/bin/node", args: [m.guardPath, "--agent", "claude"], timeout: 5 }] });
});

test("--fail-closed adds onFailure block; an existing block is never dropped", () => {
  assert.equal((claudeGroup(m, { failClosed: true }, []).hooks as Record<string, unknown>[])[0].onFailure, "block");
  const kept = claudeGroup(m, {}, [{ command: "/old/node", args: ["/old/dist/guard.mjs", "--agent", "claude"], onFailure: "block", timeout: 12, statusMessage: "guard" }]);
  assert.deepEqual((kept.hooks as Record<string, unknown>[])[0], { type: "command", command: "/usr/bin/node", args: [m.guardPath, "--agent", "claude"], timeout: 12, onFailure: "block", statusMessage: "guard" });
});

test("keys that would weaken the hook are not carried over", () => {
  const g = claudeGroup(m, {}, [{ command: "/n", args: ["/p/dist/guard.mjs", "--agent", "claude", "--no-log"], async: true, if: "Bash(git *)", once: true, timeout: -1 }]);
  assert.deepEqual((g.hooks as Record<string, unknown>[])[0], { type: "command", command: "/usr/bin/node", args: [m.guardPath, "--agent", "claude", "--no-log"], timeout: 5 });
});

test("matcher coverage follows Claude Code's rules", () => {
  for (const t of CLAUDE_REQUIRED_TOOLS) assert.ok(claudeMatcherCovers(CLAUDE_MATCHER, t), t);
  assert.ok(claudeMatcherCovers(undefined, "Bash"));
  assert.ok(claudeMatcherCovers("*", "Read"));
  assert.ok(claudeMatcherCovers("", "Read"));
  assert.ok(claudeMatcherCovers("Bash, Edit", "Edit"), "comma list");
  assert.ok(claudeMatcherCovers("Task", "Agent"), "legacy alias");
  assert.equal(claudeMatcherCovers("Bash", "PowerShell"), false);
  assert.equal(claudeMatcherCovers("bash", "Bash"), false, "case-sensitive");
  assert.ok(claudeMatcherCovers("Edit.*", "Edit"), "regex");
  assert.ok(claudeMatcherCovers("^(Bash|Write)$", "Write"));
  assert.equal(claudeMatcherCovers("^Bash$", "Bash2"), false);
  assert.equal(claudeMatcherCovers("(", "Bash"), false, "a broken regex matches nothing");
  assert.equal(claudeMatcherCovers(["Bash"], "Bash"), false);
});

test("version parsing and comparison", () => {
  assert.deepEqual(parseVersion("2.1.302 (Claude Code)"), [2, 1, 302]);
  assert.equal(parseVersion("claude"), null);
  assert.equal(atLeast([2, 1, 302], "2.1.295"), true);
  assert.equal(atLeast([2, 1, 295], "2.1.295"), true);
  assert.equal(atLeast([2, 1, 99], "2.1.139"), false);
  assert.equal(atLeast([3, 0, 0], "2.1.139"), true);
  assert.equal(atLeast(null, "2.1.139"), null);
});
