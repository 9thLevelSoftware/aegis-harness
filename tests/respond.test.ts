import assert from "node:assert/strict";
import { test } from "node:test";
import { render } from "../src/guard/respond.ts";

test("allow renders as silence so the agent's own permissions still apply", () => {
  assert.deepEqual(render({ verdict: "allow" }, "claude"), { stdout: "", exitCode: 0 });
  assert.deepEqual(render({ verdict: "allow" }, "codex"), { stdout: "", exitCode: 0 });
});

test("deny renders the documented permissionDecision JSON", () => {
  const r = render({ verdict: "deny", rule: "shell.rm-recursive-root", reason: "rm -rf /", remediation: "Do not." }, "claude");
  const j = JSON.parse(r.stdout);
  assert.equal(j.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(j.hookSpecificOutput.permissionDecision, "deny");
  assert.match(j.hookSpecificOutput.permissionDecisionReason, /shell\.rm-recursive-root/);
  assert.match(j.hookSpecificOutput.permissionDecisionReason, /Do instead: Do not\./);
});

test("the false-positive hint is a complete ah bug add command", () => {
  const r = render({ verdict: "deny", rule: "edit.lint-config", reason: "x", remediation: "y" }, "claude");
  assert.match(JSON.parse(r.stdout).hookSpecificOutput.permissionDecisionReason, /ah bug add --rule edit\.lint-config --title "<what you were doing>"\)$/);
});

test("ask is ask for Claude Code and deny-with-explanation for Codex by default", () => {
  const d = { verdict: "ask" as const, rule: "shell.privilege-escalation", reason: "sudo", remediation: "Ask." };
  assert.equal(JSON.parse(render(d, "claude").stdout).hookSpecificOutput.permissionDecision, "ask");
  const codex = JSON.parse(render(d, "codex").stdout);
  assert.equal(codex.hookSpecificOutput.permissionDecision, "deny");
  assert.match(codex.hookSpecificOutput.permissionDecisionReason, /Codex cannot pause/);
  const warn = JSON.parse(render(d, "codex", "warn").stdout);
  assert.equal(warn.hookSpecificOutput.permissionDecision, undefined);
  assert.ok(warn.systemMessage);
});

test("on Claude Code an ask carries the agent-facing explanation in additionalContext and a short sentence for the user", () => {
  // Claude Code shows permissionDecisionReason for an ask only to the user; additionalContext reaches the agent.
  const d = { verdict: "ask" as const, rule: "shell.privilege-escalation", reason: "apt-get install runs with elevated privileges", remediation: "Ask the user to run it." };
  const h = JSON.parse(render(d, "claude").stdout).hookSpecificOutput;
  assert.equal(h.permissionDecisionReason, "[ah guard] shell.privilege-escalation: apt-get install runs with elevated privileges");
  assert.match(h.additionalContext, /^\[ah guard\] held for a human by shell\.privilege-escalation: apt-get install runs with elevated privileges\n/);
  assert.match(h.additionalContext, /Do instead: Ask the user to run it\./);
  assert.match(h.additionalContext, /ah bug add --rule shell\.privilege-escalation --title "<what you were doing>"/);
  // deny format unchanged: the rule is still parsed from "by <rule>:" in the reason
  const deny = JSON.parse(render({ ...d, verdict: "deny" }, "claude").stdout).hookSpecificOutput;
  assert.match(deny.permissionDecisionReason, /^\[ah guard\] denied by shell\.privilege-escalation: /);
  assert.equal(deny.additionalContext, undefined);
});
