import assert from "node:assert/strict";
import { test } from "node:test";
import { commandText, normalizeHookPayload, parseApplyPatch } from "../src/guard/normalize.ts";

test("Claude Code Bash, Write, Edit and MultiEdit map to calls", () => {
  assert.deepEqual(normalizeHookPayload({ hook_event_name: "PreToolUse", session_id: "s", tool_name: "Bash", tool_input: { command: "ls" } }).calls, [{ kind: "shell", command: "ls" }]);
  assert.deepEqual(normalizeHookPayload({ session_id: "s", tool_name: "Write", tool_input: { file_path: "a.ts", content: "x" } }).calls, [{ kind: "write", path: "a.ts", content: "x" }]);
  const multi = normalizeHookPayload({ session_id: "s", tool_name: "MultiEdit", tool_input: { file_path: "a.ts", edits: [{ old_string: "a", new_string: "b" }, { old_string: "c", new_string: "d" }] } });
  assert.equal(multi.calls.length, 2);
});

test("Codex is detected from its payload fields and argv arrays are joined", () => {
  const ev = normalizeHookPayload({ hook_event_name: "PreToolUse", turn_id: "t", model: "m", tool_name: "Bash", tool_input: { command: ["bash", "-lc", "git status"] } });
  assert.equal(ev.agent, "codex");
  assert.deepEqual(ev.calls, [{ kind: "shell", command: "git status" }]);
  assert.equal(commandText(["rm", "-rf", "a b"]), "rm -rf 'a b'");
});

test("apply_patch envelopes become edits and writes", () => {
  const calls = parseApplyPatch("*** Begin Patch\n*** Add File: a.py\n+print(1)\n*** Update File: b.py\n@@\n-x = 1\n+x = 2\n y = 3\n*** Delete File: c.py\n*** End Patch");
  assert.deepEqual(calls[0], { kind: "write", path: "a.py", content: "print(1)" });
  assert.deepEqual(calls[1], { kind: "edit", path: "b.py", oldText: "x = 1\ny = 3", newText: "x = 2\ny = 3" });
  assert.equal(calls[2].kind, "edit");
  assert.equal((calls[2] as { path: string }).path, "c.py");
});

test("unknown tools become 'other' calls", () => {
  const ev = normalizeHookPayload({ session_id: "s", tool_name: "mcp__linear__create_issue", tool_input: { title: "x" } });
  assert.equal(ev.calls[0].kind, "other");
});
