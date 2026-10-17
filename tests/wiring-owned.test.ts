/**
 * Recognising ah's own hook entries: what `ah init` writes, what the README
 * told people to write by hand, and nothing else.
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { carriedOptions, isOwnedEntry, looksLikeGuard, splitWords } from "../src/wiring/owned.ts";

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
    { type: "command", command: "/usr/bin/node /home/dev/a/dist/guard.mjs --agent codex", commandWindows: `"C:\\Program Files\\nodejs\\node.exe" C:\\Users\\dev\\AppData\\Roaming\\npm\\node_modules\\@9thlevel\\aegis\\dist\\guard.mjs --agent codex` },
    { type: "command", command: "/usr/bin/node '/home/dev/My Tools/dist/guard.mjs' --agent codex --root /srv/app --no-log", commandWindows: "& 'C:\\Users\\dev\\my tools\\node.exe' 'C:\\Users\\dev\\My Tools\\dist\\guard.mjs' --agent codex" },
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
    // Another vendor's guard.mjs, and the user's own wrappers around ah's: replacing them would drop their parts.
    { type: "command", command: "node", args: ["/opt/acme-policy/dist/guard.mjs", "--agent", "claude-code", "--policy", "strict"] },
    { type: "command", command: "/usr/bin/node /x/dist/guard.mjs --agent codex && python3 /home/dev/checks/secrets_scan.py" },
    { type: "command", command: "hook-audit --log f -- node /x/dist/guard.mjs --agent codex" },
    { type: "command", command: "AH_PROJECT_ROOT=/srv/app node /x/dist/guard.mjs --agent codex" },
    { type: "command", command: "node --no-warnings /x/dist/guard.mjs --agent claude" },
    { type: "command", command: "/usr/bin/node /x/dist/guard.mjs --agent codex", commandWindows: "C:\\x\\wrap.cmd" },
    { type: "prompt", command: "node /x/dist/guard.mjs --agent claude" },
    { type: "http", url: "https://example.invalid/hook" },
    "not an object",
    null,
    ["array"],
  ];
  for (const e of theirs) assert.equal(isOwnedEntry(e), false, JSON.stringify(e));
});

test("hand-added guard options are carried over", () => {
  assert.deepEqual(carriedOptions({ command: "/usr/bin/node", args: ["/p/dist/guard.mjs", "--agent", "codex", "--ask-fallback", "warn", "--no-log"] }), { askFallback: "warn", noLog: true });
  assert.deepEqual(carriedOptions({ command: "/usr/bin/node /p/dist/guard.mjs --agent codex --ask-fallback=deny" }), { askFallback: "deny" });
  assert.deepEqual(carriedOptions({ command: "/usr/bin/node /p/dist/guard.mjs --agent codex --root /srv/app --home=/home/dev" }), { extra: ["--root", "/srv/app", "--home", "/home/dev"] });
});

test("an entry that mentions the guard but is not ah's is reported, not adopted", () => {
  assert.ok(looksLikeGuard({ type: "command", command: "/usr/bin/node /x/dist/guard.mjs --agent codex && python3 scan.py" }));
  assert.ok(looksLikeGuard({ type: "command", command: "npx ah guard --agent claude | tee log" }));
  assert.equal(looksLikeGuard({ type: "command", command: "/usr/bin/node /x/dist/guard.mjs --agent codex" }), false, "ah's own entry");
  assert.equal(looksLikeGuard({ type: "command", command: "npx prettier --check" }), false);
});

test("a guard.mjs that another package ships is not ah's", () => {
  const dir = mkdtempSync(join(tmpdir(), "ah-owned-"));
  mkdirSync(join(dir, "dist"));
  writeFileSync(join(dir, "dist", "guard.mjs"), "");
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "acme-guard" }));
  const entry = { type: "command", command: "node", args: [join(dir, "dist", "guard.mjs"), "--agent", "claude"] };
  assert.equal(isOwnedEntry(entry), false);
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@9thlevel/aegis" }));
  assert.ok(isOwnedEntry(entry));
  rmSync(dir, { recursive: true, force: true });
});
