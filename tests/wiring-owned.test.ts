/**
 * Recognising ah's own hook entries: what `ah init` writes, what the README
 * told people to write by hand, and nothing else.
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { claudeGroup } from "../src/wiring/claude.ts";
import { codexGroup } from "../src/wiring/codex.ts";
import { planHooks } from "../src/wiring/hooks-json.ts";
import { carriedOptions, entryWords, guardArgs, isOwnedEntry, looksLikeGuard, splitWords } from "../src/wiring/owned.ts";
import type { Machine } from "../src/wiring/project.ts";

test("splitWords groups quotes and keeps Windows backslashes", () => {
  assert.deepEqual(splitWords(`"C:\\Program Files\\nodejs\\node.exe" "C:\\Users\\dev\\a b\\dist\\guard.mjs" --agent codex`), [
    "C:\\Program Files\\nodejs\\node.exe",
    "C:\\Users\\dev\\a b\\dist\\guard.mjs",
    "--agent",
    "codex",
  ]);
  assert.deepEqual(splitWords(`'/opt/node 22/bin/node' ''  x`), ["/opt/node 22/bin/node", "", "x"]);
});

test("splitWords reads a quote inside quotes the way the shell each form is written for does", () => {
  assert.deepEqual(splitWords(`'/home/dev/O'\\''Brien/bin/node' x`), ["/home/dev/O'Brien/bin/node", "x"], "POSIX: '\\''");
  assert.deepEqual(splitWords(`& 'C:\\Users\\dev\\O''Brien\\node.exe' x`), ["&", "C:\\Users\\dev\\O'Brien\\node.exe", "x"], "PowerShell, after its & call operator: ''");
  assert.deepEqual(splitWords(`'it''s'`), ["its"], "POSIX: two quoted strings side by side");
  assert.deepEqual(splitWords(`'it''s'`, "powershell"), ["it's"]);
  assert.deepEqual(splitWords("& 'a\u2019\u2019b\u2018\u2018' \u2018c d\u201B", "powershell"), ["&", "a\u2019b\u2018", "c d"], "PowerShell: U+2018 to U+201B are single quotes too");
  assert.deepEqual(splitWords("& 'a\u2018' b'"), ["&", "a' b"], "PowerShell: any two of them make one");
  assert.deepEqual(splitWords('& \u201Ca b\u201D "c""d\u201C\u201C" \u201Ee f\u201C', "powershell"), ["&", "a b", 'c"d\u201C', "e f"], "and U+201C to U+201E are double quotes");
  assert.deepEqual(splitWords('"a\u201D b"'), ["a\u201D b"], "POSIX: a typographic quote is a letter");
  assert.deepEqual(splitWords("'a\u2019b' c"), ["a\u2019b", "c"], "POSIX: a typographic quote is a letter");
  assert.deepEqual(splitWords('C:"\\Users\\dev\\my tools\\node.exe" "C:\\a b\\guard.mjs" --agent codex'), ["C:\\Users\\dev\\my tools\\node.exe", "C:\\a b\\guard.mjs", "--agent", "codex"]);
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

function prng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test("property: every command ah writes reads back to its node, guard and options, and stays ah's", () => {
  const r = prng(20261017);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
  const odd = [" ", "'", "''", "\\'", '"', "$", "$(x)", "`", "%", "%PATH%", "!", "^", "&", ";", ",", "=", "(x)", "@", "~1", "#", "-", "é", "日本", "😀", "\u2018", "\u2019", "\u201A", "\u201B", "\u201C", "\u201D", "\u201E"];
  const name = () => {
    let s = pick(["a", "dev", "My"]);
    for (let n = 1 + Math.floor(r() * 3); n > 0; n--) s += pick(odd) + pick(["", "b", "x y"]);
    return s;
  };
  const look = { short: (p: string) => p };
  const forms = new Set<string>();
  for (let i = 0; i < 3000; i++) {
    const os = pick(["linux", "darwin", "win32"] as const);
    const win = os === "win32";
    const nodePath = win ? pick([`C:\\Users\\dev\\${name()}\\node.exe`, `\\\\srv\\${name()}\\node.exe`, "C:\\nodejs\\node.exe"]) : pick([`/home/dev/${name()}/bin/node`, "/usr/bin/node"]);
    const guardPath = win ? `C:\\Users\\dev\\${name()}\\dist\\guard.mjs` : `/Users/dev/${name()}/dist/guard.mjs`;
    const m = { root: win ? "C:\\Users\\dev\\project" : "/home/dev/project", home: win ? "C:\\Users\\dev" : "/home/dev", os, env: {}, nodePath, guardPath } as unknown as Machine;
    const extra = [...(r() < 0.4 ? ["--root", win ? `C:\\Users\\dev\\${name()}` : `/home/dev/${name()}`] : []), ...(r() < 0.3 ? ["--home", name()] : []), ...(r() < 0.2 ? ["--platform", "windows"] : [])];
    const warn = r() < 0.5;
    const noLog = r() < 0.5;
    // A hand-wired entry that carries the extra options, the way `ah init` finds one.
    const handWired = { type: "command", command: "/usr/bin/node", args: ["/x/dist/guard.mjs", "--agent", "codex", ...extra] };
    const group = codexGroup(m, { askFallback: warn ? "warn" : undefined, noLog: noLog || undefined }, [handWired], look);
    const entry = (group.hooks as Record<string, unknown>[])[0];
    const why = `case ${i} ${JSON.stringify(entry)}`;
    const args = ["--agent", "codex", ...extra, ...(warn ? ["--ask-fallback", "warn"] : []), ...(noLog ? ["--no-log"] : [])];
    const read = entryWords(entry);
    assert.equal(read.length, win ? 2 : 1, why);
    read.forEach((words, f) => {
      const slash = (p: string) => (f === 0 && win ? p.replace(/\\/g, "/") : p);
      const w = words.filter((x) => x !== "&");
      assert.deepEqual(w, [slash(nodePath), slash(guardPath), ...args], why);
      assert.deepEqual(guardArgs(words), args, why);
    });
    if (win) {
      const cw = entry.commandWindows as string;
      forms.add(cw.startsWith("& ") ? "powershell" : cw.startsWith('C:"') ? "node quoted" : cw.includes(' "') ? "guard quoted" : "bare");
      // ah doctor reads the Windows form with splitWords' own default.
      assert.deepEqual(splitWords(cw), read[1], why);
    }
    assert.ok(isOwnedEntry(entry), why);
    assert.deepEqual(carriedOptions(entry), { ...(warn ? { askFallback: "warn" } : {}), ...(noLog ? { noLog: true } : {}), ...(extra.length > 0 ? { extra } : {}) }, why);
    // A second `ah init` finds the entry and leaves it as it is; --remove takes it out.
    const file = { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "lint" }] }, group] } };
    assert.equal(planHooks(file, "hooks.json", (found) => codexGroup(m, {}, found, look), { placement: "keep-indexes" }).action, "unchanged", why);
    assert.deepEqual(planHooks(file, "hooks.json", () => null).value, { hooks: { PreToolUse: [file.hooks.PreToolUse[0]] } }, why);
    // The Claude Code entry, built from the same carried options.
    const claudeWanted = claudeGroup(m, { noLog: noLog || undefined }, [entry]);
    const claude = (claudeWanted.hooks as Record<string, unknown>[])[0];
    assert.ok(isOwnedEntry(claude), why);
    assert.deepEqual(entryWords(claude), [[nodePath, guardPath, "--agent", "claude", ...extra, ...(noLog ? ["--no-log"] : [])]], why);
    assert.equal(planHooks({ hooks: { PreToolUse: [claudeWanted] } }, "settings.json", (found) => claudeGroup(m, {}, found)).action, "unchanged", why);
  }
  assert.deepEqual([...forms].sort(), ["bare", "guard quoted", "node quoted", "powershell"], "every Windows form came up");
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
