/**
 * Recognising ah's own hook entries: what `ah init` writes, what the README
 * told people to write by hand, and nothing else.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { carriedOptions, isOwnedEntry, splitWords } from "../src/wiring/owned.ts";

test("splitWords groups quotes and keeps Windows backslashes", () => {
  assert.deepEqual(splitWords(`"C:\\Program Files\\nodejs\\node.exe" "C:\\Users\\dev\\a b\\dist\\guard.mjs" --agent codex`), [
    "C:\\Program Files\\nodejs\\node.exe",
    "C:\\Users\\dev\\a b\\dist\\guard.mjs",
    "--agent",
    "codex",
  ]);
  assert.deepEqual(splitWords(`'/opt/node 22/bin/node' ''  x`), ["/opt/node 22/bin/node", "", "x"]);
});

test("the exec form, the shell form, the Windows form and `ah guard` are ah's", () => {
  const owned = [
    { type: "command", command: "/usr/local/bin/node", args: ["/home/dev/.npm-global/lib/node_modules/@9thlevel/aegis/dist/guard.mjs", "--agent", "claude"], timeout: 5 },
    { type: "command", command: "/usr/bin/node /home/dev/project/node_modules/@9thlevel/aegis/dist/guard.mjs --agent codex" },
    { type: "command", command: "x", commandWindows: `"C:\\Program Files\\nodejs\\node.exe" C:\\Users\\dev\\AppData\\Roaming\\npm\\node_modules\\@9thlevel\\aegis\\dist\\guard.mjs --agent codex` },
    { type: "command", command: "ah guard --agent claude" },
    { type: "command", command: "npx ah guard --agent claude" },
    { type: "command", command: "& 'C:\\Users\\dev\\AppData\\Roaming\\npm\\ah.cmd' guard --agent codex" },
  ];
  for (const e of owned) assert.ok(isOwnedEntry(e), JSON.stringify(e));
});

test("other hooks are the user's, even when they mention guard.mjs or ah", () => {
  const theirs = [
    { type: "command", command: "npx prettier --check" },
    { type: "command", command: "node scripts/guard.mjs" },
    { type: "command", command: "/usr/bin/node /home/dev/x/dist/guard.mjs" },
    { type: "command", command: "echo ah guard" },
    { type: "command", command: "ah doctor" },
    { type: "http", url: "https://example.invalid/hook" },
    "not an object",
    null,
    ["array"],
  ];
  for (const e of theirs) assert.equal(isOwnedEntry(e), false, JSON.stringify(e));
});

test("hand-added guard options are carried over", () => {
  assert.deepEqual(carriedOptions({ command: "/n", args: ["/p/dist/guard.mjs", "--agent", "codex", "--ask-fallback", "warn", "--no-log"] }), { askFallback: "warn", noLog: true });
  assert.deepEqual(carriedOptions({ command: "/n /p/dist/guard.mjs --agent codex --ask-fallback=deny" }), { askFallback: "deny" });
  assert.deepEqual(carriedOptions({ command: "/n /p/dist/guard.mjs --agent codex --root /tmp" }), {});
});
