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
