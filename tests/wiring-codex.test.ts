/**
 * Codex wiring helpers, per what Codex 0.163.0 did with test files
 * (BUG-2026-019): how a matcher selects a tool, and the command ah writes.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { CODEX_MATCHER, CODEX_REQUIRED_TOOLS, codexCommand, codexMatcherCovers, posixQuote, powershellQuote, windowsDoubleQuote } from "../src/wiring/codex.ts";
import { splitWords } from "../src/wiring/owned.ts";
import type { Machine } from "../src/wiring/project.ts";

const apply = CODEX_REQUIRED_TOOLS[1].names;

test("a matcher of plain names is a list of exact names; anything else is a regex search", () => {
  assert.ok(codexMatcherCovers(CODEX_MATCHER, ["Bash"]));
  assert.ok(codexMatcherCovers(CODEX_MATCHER, apply), "Edit and Write select apply_patch");
  assert.equal(codexMatcherCovers("Bas", ["Bash"]), false, "Codex: Bas does not match Bash");
  assert.equal(codexMatcherCovers("Ba|Zzz", ["Bash"]), false);
  assert.equal(codexMatcherCovers("bash", ["Bash"]), false, "case-sensitive");
  assert.ok(codexMatcherCovers("Ba.h", ["Bash"]));
  assert.ok(codexMatcherCovers("^Bash$", ["Bash"]));
  assert.ok(codexMatcherCovers("*", ["Bash"]));
  assert.ok(codexMatcherCovers(undefined, ["Bash"]));
  assert.equal(codexMatcherCovers("Bash", apply), false, "Bash alone skips apply_patch");
});

test("the command quotes what bash and zsh would split, and nothing else", () => {
  assert.equal(posixQuote("/usr/local/bin/node"), "/usr/local/bin/node");
  assert.equal(posixQuote("/Users/dev/My Tools/node"), "'/Users/dev/My Tools/node'");
  assert.equal(posixQuote("/home/dev/it's/node"), `'/home/dev/it'\\''s/node'`);
  const m = { root: "/home/dev/project", home: "/home/dev", os: "linux", env: {}, nodePath: "/home/dev/.nvm/versions/node/v22.18.0/bin/node", guardPath: "/home/dev/My Tools/aegis/dist/guard.mjs" } as unknown as Machine;
  assert.equal(codexCommand(m, ["--agent", "codex"]).command, "/home/dev/.nvm/versions/node/v22.18.0/bin/node '/home/dev/My Tools/aegis/dist/guard.mjs' --agent codex");
});

test("commandWindows runs in cmd.exe and PowerShell alike whenever it can", () => {
  const win = (nodePath: string, guardPath: string) => ({ root: "C:\\Users\\dev\\project", home: "C:\\Users\\dev", os: "win32", env: {}, nodePath, guardPath }) as unknown as Machine;
  const noShort = (p: string) => p;
  const args = ["--agent", "codex"];
  const plain = codexCommand(win("C:\\nodejs\\node.exe", "C:\\Users\\dev\\npm\\guard.mjs"), args, { short: noShort });
  assert.equal(plain.commandWindows, "C:\\nodejs\\node.exe C:\\Users\\dev\\npm\\guard.mjs --agent codex");
  const short = codexCommand(win("C:\\Program Files\\nodejs\\node.exe", "C:\\x\\guard.mjs"), args, { short: (p) => p.replace("Program Files", "PROGRA~1") });
  assert.equal(short.commandWindows, "C:\\PROGRA~1\\nodejs\\node.exe C:\\x\\guard.mjs --agent codex");
  const quoted = codexCommand(win("C:\\nodejs\\node.exe", "C:\\Users\\dev\\ah with space\\guard.mjs"), args, { short: noShort });
  assert.equal(quoted.commandWindows, 'C:\\nodejs\\node.exe "C:\\Users\\dev\\ah with space\\guard.mjs" --agent codex', "a quoted argument after a bare first word runs in both");
  const spacedNode = codexCommand(win("C:\\Users\\dev\\my tools\\node.exe", "C:\\Users\\dev\\ah with space\\guard.mjs"), args, { short: noShort });
  assert.equal(spacedNode.commandWindows, 'C:"\\Users\\dev\\my tools\\node.exe" "C:\\Users\\dev\\ah with space\\guard.mjs" --agent codex', "a line that starts with a quote is a string to PowerShell; a quote after the drive groups in both");
  assert.match(spacedNode.windowsNote ?? "", /node path in double quotes after its drive.*both run it/);
  const unc = codexCommand(win("\\\\srv\\tools\\node 22\\node.exe", "C:\\x\\guard.mjs"), args, { short: noShort });
  assert.equal(unc.commandWindows, "& '\\\\srv\\tools\\node 22\\node.exe' 'C:\\x\\guard.mjs' --agent codex", "cmd.exe splits a first word with quotes at its first space unless it starts with a drive");
  const comma = codexCommand(win("C:\\Users\\dev\\a,b\\node.exe", "C:\\Users\\dev\\a,b\\guard.mjs"), [...args, "--root", "C:\\Users\\dev\\a,b"], { short: noShort });
  assert.equal(comma.commandWindows, 'C:"\\Users\\dev\\a,b\\node.exe" "C:\\Users\\dev\\a,b\\guard.mjs" --agent codex --root "C:\\Users\\dev\\a,b"', "a bare a,b is an array to PowerShell");
  const dollar = codexCommand(win("C:\\nodejs\\node.exe", "C:\\Users\\dev\\a b$c\\guard.mjs"), args, { short: noShort });
  assert.match(dollar.commandWindows ?? "", /^& /, "PowerShell would expand $c inside double quotes");
  assert.match(dollar.windowsNote ?? "", /cmd\.exe cannot run/);
  const percent = codexCommand(win("C:\\Users\\dev\\100% b\\node.exe", "C:\\x\\guard.mjs"), args, { short: noShort });
  assert.equal(percent.commandWindows, "& 'C:\\Users\\dev\\100% b\\node.exe' 'C:\\x\\guard.mjs' --agent codex", "cmd.exe expands %...% inside double quotes");
});

test("commandWindows always runs the node path it was given, never a bare node that cmd.exe looks for in the current directory first", () => {
  const win = (nodePath: string) => ({ root: "C:\\Users\\dev\\project", home: "C:\\Users\\dev", os: "win32", env: {}, nodePath, guardPath: "C:\\Users\\dev\\ah\\dist\\guard.mjs" }) as unknown as Machine;
  const short = (p: string) => p.replace("Program Files", "PROGRA~1");
  const cases: [string, ((p: string) => string) | undefined, string][] = [
    ["C:\\nodejs\\node.exe", undefined, "C:\\nodejs\\node.exe"],
    ["C:\\Program Files\\nodejs\\node.exe", short, "C:\\PROGRA~1\\nodejs\\node.exe"],
    ["C:\\Program Files\\nodejs\\node.exe", (p) => p, "C:\\Program Files\\nodejs\\node.exe"],
    ["C:\\Users\\dev\\O'Brien tools\\node.exe", (p) => p, "C:\\Users\\dev\\O'Brien tools\\node.exe"],
    ["C:\\Users\\dev\\it\u2019s $x\\node.exe", (p) => p, "C:\\Users\\dev\\it\u2019s $x\\node.exe"],
    ["\\\\srv\\tools\\node 22\\node.exe", (p) => p, "\\\\srv\\tools\\node 22\\node.exe"],
  ];
  for (const [nodePath, look, want] of cases) {
    const c = codexCommand(win(nodePath), ["--agent", "codex"], { short: look ?? ((p) => p) });
    const words = splitWords(c.commandWindows ?? "", "powershell").filter((w) => w !== "&");
    assert.equal(words[0], want, c.commandWindows);
    assert.match(words[0], /^([A-Za-z]:\\|\\\\)/, c.commandWindows);
    assert.doesNotMatch(c.windowsNote ?? "", /PATH/, c.commandWindows);
  }
});

test("PowerShell single quotes double every single-quote character, and double quotes are not used when a double-quote character is in the word", () => {
  assert.equal(powershellQuote("C:\\Users\\dev\\O'Brien\\node.exe"), "'C:\\Users\\dev\\O''Brien\\node.exe'");
  assert.equal(powershellQuote("a\u2018b\u2019c\u201Ad\u201Be'"), "'a\u2018\u2018b\u2019\u2019c\u201A\u201Ad\u201B\u201Be'''");
  assert.equal(powershellQuote("\u201C$x\u201D `n"), "'\u201C$x\u201D `n'", "nothing else is special in single quotes");
  for (const q of ['"', "\u201C", "\u201D", "\u201E"]) assert.equal(windowsDoubleQuote(`C:\\a${q}b c`), null, `PowerShell ends a double-quoted string at ${q}`);
  assert.equal(windowsDoubleQuote("C:\\it\u2019s b"), '"C:\\it\u2019s b"', "a single-quote character is a letter inside double quotes");
  const win = (guardPath: string) => ({ root: "C:\\Users\\dev\\project", home: "C:\\Users\\dev", os: "win32", env: {}, nodePath: "C:\\nodejs\\node.exe", guardPath }) as unknown as Machine;
  const typographic = codexCommand(win("C:\\Users\\dev\\it\u2019s $x\\guard.mjs"), ["--agent", "codex"], { short: (p) => p });
  assert.equal(typographic.commandWindows, "& 'C:\\nodejs\\node.exe' 'C:\\Users\\dev\\it\u2019\u2019s $x\\guard.mjs' --agent codex");
  const doubleQuote = codexCommand(win("C:\\Users\\dev\\\u201Cah\u201D b\\guard.mjs"), ["--agent", "codex"], { short: (p) => p });
  assert.equal(doubleQuote.commandWindows, "& 'C:\\nodejs\\node.exe' 'C:\\Users\\dev\\\u201Cah\u201D b\\guard.mjs' --agent codex");
});

test("an option that PowerShell reads specially at its start is quoted in both Windows forms", () => {
  const win = (guardPath: string) => ({ root: "C:\\Users\\dev\\project", home: "C:\\Users\\dev", os: "win32", env: {}, nodePath: "C:\\nodejs\\node.exe", guardPath }) as unknown as Machine;
  const both = (args: string[]) => [codexCommand(win("C:\\ah\\dist\\guard.mjs"), args, { short: (p) => p }), codexCommand(win("C:\\Users\\dev\\it$x\\dist\\guard.mjs"), args, { short: (p) => p })].map((c) => c.commandWindows ?? "");
  // @x splats (and @x.y does not parse), ~ may be the home folder, -x is a parameter that PowerShell splits at . or : (node gets -x .y).
  for (const v of ["@x.y", "@home", "@", "~", "~\\x", "-x.y", "-x:y", "-", "--", "-1.5"]) {
    const [cmd, ps] = both(["--agent", "codex", "--root", v]);
    assert.equal(cmd, `C:\\nodejs\\node.exe C:\\ah\\dist\\guard.mjs --agent codex --root "${v}"`);
    assert.equal(ps, `& 'C:\\nodejs\\node.exe' 'C:\\Users\\dev\\it$x\\dist\\guard.mjs' --agent codex --root '${v}'`);
    for (const c of [cmd, ps]) assert.deepEqual(splitWords(c, "powershell").slice(-2), ["--root", v], c);
  }
  const [cmd, ps] = both(["--agent", "codex", "--root", "C:\\a@b~c", "--home", "x-y.z", "--ask-fallback", "warn", "--no-log"]);
  assert.equal(cmd, "C:\\nodejs\\node.exe C:\\ah\\dist\\guard.mjs --agent codex --root C:\\a@b~c --home x-y.z --ask-fallback warn --no-log", "the guard's own flags, and @ ~ - after the start, stay bare");
  assert.equal(ps, "& 'C:\\nodejs\\node.exe' 'C:\\Users\\dev\\it$x\\dist\\guard.mjs' --agent codex --root C:\\a@b~c --home x-y.z --ask-fallback warn --no-log");
});
