/**
 * How `ah doctor` reads a hook's answer: what each agent does with it, per
 * Claude Code 2.1.302 and Codex 0.163.0 run against test hooks (BUG-2026-019).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { verdictOf } from "../src/wiring/canary.ts";

const out = (o: unknown) => JSON.stringify(o);
const decision = (permissionDecision: string, permissionDecisionReason?: string) => out({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision, permissionDecisionReason } });

test("Claude Code: exit 2 and deny block, ask pauses, silence and allow pass", () => {
  assert.equal(verdictOf(2, "", "no"), "deny");
  assert.equal(verdictOf(0, decision("deny", "r")), "deny");
  assert.equal(verdictOf(0, decision("ask", "r")), "ask");
  assert.equal(verdictOf(0, ""), "allow");
  assert.equal(verdictOf(0, decision("allow")), "allow");
  assert.equal(verdictOf(1, ""), null, "exit 1 is a hook error");
  assert.equal(verdictOf(0, "not json"), null);
});

test("Codex runs the call on anything but a reasoned refusal", () => {
  assert.equal(verdictOf(0, decision("deny", "because"), "", "codex"), "deny");
  assert.equal(verdictOf(0, out({ decision: "block", reason: "because" }), "", "codex"), "deny");
  assert.equal(verdictOf(2, "", "because", "codex"), "deny");
  assert.equal(verdictOf(2, "", "", "codex"), "allow", "exit 2 with nothing on stderr");
  assert.equal(verdictOf(0, decision("deny"), "", "codex"), "allow", "a deny without a reason");
  assert.equal(verdictOf(0, decision("ask", "r"), "", "codex"), "allow", "Codex cannot ask");
  assert.equal(verdictOf(0, "not json", "", "codex"), "allow");
});

test("a decision neither agent defines is unreadable, not a pass", () => {
  assert.equal(verdictOf(0, decision("defer")), null);
  assert.equal(verdictOf(0, decision("Deny", "r"), "", "codex"), null);
});
