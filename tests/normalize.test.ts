import assert from "node:assert/strict";
import { test } from "node:test";
import { applyPatchViaShell, commandText, normalizeHookPayload, parseApplyPatch } from "../src/guard/normalize.ts";
import { buildContext } from "../src/guard/main.ts";

test("Claude Code Bash, PowerShell, Write, Edit and legacy MultiEdit map to calls", () => {
  assert.deepEqual(normalizeHookPayload({ hook_event_name: "PreToolUse", session_id: "s", tool_name: "Bash", tool_input: { command: "ls" } }).calls, [{ kind: "shell", command: "ls" }]);
  assert.deepEqual(normalizeHookPayload({ session_id: "s", tool_name: "PowerShell", tool_input: { command: "Remove-Item -Recurse -Force .\\dist" } }).calls, [{ kind: "shell", command: "Remove-Item -Recurse -Force .\\dist" }]);
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

test("the shell dialect follows the PowerShell tool on any platform, and the agent otherwise", () => {
  const env = {};
  const ps = normalizeHookPayload({ session_id: "s", tool_name: "PowerShell", tool_input: { command: "ls" } });
  assert.equal(buildContext(ps, { agent: "claude", platform: "windows", root: "C:\\Users\\dev\\project", home: "C:\\Users\\dev" }, env).shellDialect, "powershell");
  assert.equal(buildContext(ps, { agent: "claude", platform: "posix", root: "/home/dev/project", home: "/home/dev" }, env).shellDialect, "powershell");
  const bash = normalizeHookPayload({ session_id: "s", tool_name: "Bash", tool_input: { command: "ls" } });
  assert.equal(buildContext(bash, { agent: "claude", platform: "windows", root: "C:\\Users\\dev\\project", home: "C:\\Users\\dev" }, env).shellDialect, "posix");
  assert.equal(buildContext(bash, { agent: "codex", platform: "windows", root: "C:\\Users\\dev\\project", home: "C:\\Users\\dev" }, env).shellDialect, "powershell");
});

const PATCH = "*** Begin Patch\n*** Update File: .eslintrc.json\n@@\n-  \"rules\": {}\n+  \"rules\": { \"no-console\": \"off\" }\n*** End Patch";

test("a Codex apply_patch that arrives through the shell tool is parsed as edits, in every shape", () => {
  const codex = (command: unknown) => normalizeHookPayload({ turn_id: "t", model: "m", tool_name: "shell", tool_input: { command } }).calls;
  const edit = { kind: "edit", path: ".eslintrc.json", oldText: '  "rules": {}', newText: '  "rules": { "no-console": "off" }' };
  // Bare argv: nothing but the patch runs. `env` execs through.
  assert.deepEqual(codex(["apply_patch", PATCH]), [edit]);
  assert.deepEqual(codex(["/tmp/codex-arg0-abc123/apply_patch", PATCH]), [edit]);
  assert.deepEqual(codex(["env", "FOO=1", "apply_patch", PATCH]), [edit]);
  assert.deepEqual(codex(["/usr/bin/env", "-i", "apply_patch", PATCH]), [edit]);
  // Through a shell: the edit, plus the command line with the patch body cut out, so the shell rules see what else runs.
  const skeleton = "apply_patch <<'EOF'\n\nEOF";
  assert.deepEqual(codex(`apply_patch <<'EOF'\n${PATCH}\nEOF`), [edit, { kind: "shell", command: skeleton }]);
  assert.deepEqual(codex(`bash -lc "apply_patch <<'EOF'\n${PATCH}\nEOF"`), [edit, { kind: "shell", command: skeleton }]);
  assert.deepEqual(codex(["bash", "-lc", `apply_patch <<'EOF'\n${PATCH}\nEOF`]), [edit, { kind: "shell", command: skeleton }]);
  assert.deepEqual(codex(["bash", "-c", "--", `apply_patch <<'EOF'\n${PATCH}\nEOF`]), [edit, { kind: "shell", command: skeleton }]);
  assert.equal(commandText(["bash", "-c", "--", "git status"]), "git status");
  assert.deepEqual(codex(`apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: src/new.ts\n+export const x = 1;\n*** End Patch\nEOF`), [{ kind: "write", path: "src/new.ts", content: "export const x = 1;" }, { kind: "shell", command: skeleton }]);
  // A trailing or leading command is kept for the shell rules (BUG-2026-018).
  assert.deepEqual(codex(`apply_patch <<'EOF'\n${PATCH}\nEOF\nrm -rf /`), [edit, { kind: "shell", command: `${skeleton}\nrm -rf /` }]);
  assert.deepEqual(codex(`cd /home/dev/project && apply_patch <<'EOF'\n${PATCH}\nEOF`), [edit, { kind: "shell", command: `cd /home/dev/project && ${skeleton}` }]);
  assert.deepEqual(codex(`FOO=1 apply_patch '${PATCH}' && rm -rf /`), [edit, { kind: "shell", command: "FOO=1 apply_patch '' && rm -rf /" }]);
  // not apply_patch: ordinary commands still become shell calls
  assert.equal(applyPatchViaShell("echo '*** Begin Patch' > notes.txt"), undefined);
  assert.equal(applyPatchViaShell(["git", "apply", "patch.diff"]), undefined);
  assert.equal(applyPatchViaShell("apply_patch --help"), undefined);
  assert.equal(applyPatchViaShell("cat <<'EOF'\n*** Begin Patch\n*** End Patch\nEOF"), undefined);
  assert.deepEqual(codex(["bash", "-lc", "git status"]), [{ kind: "shell", command: "git status" }]);
});

test("Claude Code's Monitor runs its command as a Bash call, in the POSIX dialect on Windows too (BUG-2026-019)", () => {
  const monitor = normalizeHookPayload({ session_id: "s", tool_name: "Monitor", tool_input: { command: "tail -f dist/server.log", description: "watch the server" } });
  assert.deepEqual(monitor.calls, [{ kind: "shell", command: "tail -f dist/server.log" }]);
  assert.equal(buildContext(monitor, { agent: "claude", platform: "windows", root: "C:\\Users\\dev\\project", home: "C:\\Users\\dev" }, {}).shellDialect, "posix");
  // Without a command string there is nothing to run; it is judged like any other tool.
  assert.equal(normalizeHookPayload({ session_id: "s", tool_name: "Monitor", tool_input: { task_id: "x" } }).calls[0].kind, "other");
});

test("unknown tools become 'other' calls", () => {
  const ev = normalizeHookPayload({ session_id: "s", tool_name: "mcp__linear__create_issue", tool_input: { title: "x" } });
  assert.equal(ev.calls[0].kind, "other");
});
