/**
 * The JSON editor `ah init` writes settings through: only what changed is
 * written fresh, everything else keeps its exact text, and removing what was
 * added gives back the original bytes.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { detectStyle } from "../src/wiring/files.ts";
import { editJson } from "../src/wiring/json-edit.ts";

const edit = (text: string, f: (v: any) => unknown) => editJson(text, f(JSON.parse(text.replace(/^﻿/, ""))), detectStyle(text));
const group = { matcher: "Bash", hooks: [{ type: "command", command: "node guard.mjs" }] };

test("adding a key keeps the rest of the file byte for byte, and taking it out restores it", () => {
  const original = '{\n    "permissions": {\n        "allow": ["Bash(ls)"]\n    },\n    "hooks": {\n        "PostToolUse": [{"matcher": "Write", "hooks": []}]\n    }\n}\n';
  const added = edit(original, (v) => ({ ...v, hooks: { ...v.hooks, PreToolUse: [group] } }));
  assert.ok(added.startsWith('{\n    "permissions": {\n        "allow": ["Bash(ls)"]\n    },\n    "hooks": {\n        "PostToolUse": [{"matcher": "Write", "hooks": []}],\n        "PreToolUse": [\n            {\n                "matcher": "Bash",'), added);
  assert.deepEqual(JSON.parse(added).hooks.PreToolUse, [group]);
  const removed = edit(added, (v) => {
    const { PreToolUse: _, ...rest } = v.hooks;
    return { ...v, hooks: rest };
  });
  assert.equal(removed, original);
});

test("an appended array element copies its neighbours' indentation; the others keep their text", () => {
  const original = '{\n  "hooks": {\n    "PreToolUse": [\n      { "matcher": "^Bash$", "hooks": [ { "type": "command", "command": "python3 check.py" } ] }\n    ]\n  }\n}\n';
  const out = edit(original, (v) => ({ hooks: { PreToolUse: [...v.hooks.PreToolUse, group] } }));
  assert.ok(out.includes('      { "matcher": "^Bash$", "hooks": [ { "type": "command", "command": "python3 check.py" } ] },\n      {\n        "matcher": "Bash",'), out);
  assert.equal(edit(out, (v) => ({ hooks: { PreToolUse: v.hooks.PreToolUse.slice(0, 1) } })), original);
});

test("an element edited in place keeps its place and the unchanged parts of its text", () => {
  const original = '[\n  {"a": 1,   "b": [1, 2]},\n  {"c": 3}\n]';
  const out = edit(original, (v) => [{ ...v[0], b: [1, 2, 3] }, v[1]]);
  assert.equal(out, '[\n  {"a": 1,   "b": [1, 2, 3]},\n  {"c": 3}\n]');
});

test("an empty object or array gets lines when the file has them, and none when it is on one line", () => {
  assert.equal(edit('{\n  "hooks": {}\n}\n', () => ({ hooks: { PreToolUse: [] } })), '{\n  "hooks": {\n    "PreToolUse": []\n  }\n}\n');
  assert.equal(edit('{"hooks":{}}', () => ({ hooks: { PreToolUse: [1] } })), '{"hooks":{"PreToolUse":[1]}}');
  assert.equal(edit("{}\n", () => ({ a: { b: 1 } })), '{\n  "a": {\n    "b": 1\n  }\n}\n');
  assert.equal(edit('{\n  "a": 1\n}\n', () => ({})), "{}\n");
});

test("tabs, CRLF and a byte-order mark carry into what is added", () => {
  const original = '﻿{\r\n\t"model": "x"\r\n}\r\n';
  const out = edit(original, (v) => ({ ...v, hooks: { PreToolUse: [] } }));
  assert.equal(out, '﻿{\r\n\t"model": "x",\r\n\t"hooks": {\r\n\t\t"PreToolUse": []\r\n\t}\r\n}\r\n');
});

test("number spelling and escapes in untouched values survive", () => {
  const original = '{"n": 1.50, "s": "\\u00e9", "x": 1}';
  assert.equal(edit(original, (v) => ({ ...v, x: 2 })), '{"n": 1.50, "s": "\\u00e9", "x": 2}');
});

test("a replaced element whose keys were in another order is written fresh in its place, and nothing else moves", () => {
  // An ah group written by hand as {"hooks": ..., "matcher": ...} used to reformat the whole file.
  const inline = '{\n  "n": 1.0,\n  "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "node /x/dist/guard.mjs --agent claude"}], "matcher": "Bash"}]},\n  "big": 12345678901234567890\n}\n';
  assert.equal(
    edit(inline, (v) => ({ ...v, hooks: { PreToolUse: [group] } })),
    '{\n  "n": 1.0,\n  "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "node guard.mjs"}]}]},\n  "big": 12345678901234567890\n}\n',
  );
  const lines = '{\n  "env": {"RATIO": 1.50},\n  "hooks": {\n    "PreToolUse": [\n      { "hooks": [ { "type": "command", "command": "node /x/dist/guard.mjs --agent claude" } ], "matcher": "Bash" }\n    ]\n  }\n}\n';
  assert.equal(
    edit(lines, (v) => ({ ...v, hooks: { PreToolUse: [group] } })),
    '{\n  "env": {"RATIO": 1.50},\n  "hooks": {\n    "PreToolUse": [\n      {\n        "matcher": "Bash",\n        "hooks": [\n          {\n            "type": "command",\n            "command": "node guard.mjs"\n          }\n        ]\n      }\n    ]\n  }\n}\n',
  );
  const hug = '{\n  "PreToolUse": [{\n    "hooks": [],\n    "matcher": "Bash"\n  }]\n}\n';
  assert.equal(edit(hug, () => ({ PreToolUse: [group] })), '{\n  "PreToolUse": [{\n    "matcher": "Bash",\n    "hooks": [\n      {\n        "type": "command",\n        "command": "node guard.mjs"\n      }\n    ]\n  }]\n}\n');
});

test("a user's entry keeps its text when ah's entry beside it, keys in another order, is lifted out", () => {
  const original = '{\n  "hooks": {\n    "PreToolUse": [\n      {\n        "matcher": "Bash",\n        "hooks": [\n          { "type": "command", "timeout": 30.0, "command": "python3 audit.py" },\n          { "command": "node /x/dist/guard.mjs --agent claude", "type": "command" }\n        ]\n      }\n    ]\n  }\n}\n';
  const out = edit(original, (v) => ({ hooks: { PreToolUse: [group, { matcher: "Bash", hooks: [v.hooks.PreToolUse[0].hooks[0]] }] } }));
  assert.equal(
    out,
    '{\n  "hooks": {\n    "PreToolUse": [\n      {\n        "matcher": "Bash",\n        "hooks": [\n          {\n            "type": "command",\n            "command": "node guard.mjs"\n          }\n        ]\n      },\n      {\n        "matcher": "Bash",\n        "hooks": [\n          { "type": "command", "timeout": 30.0, "command": "python3 audit.py" }\n        ]\n      }\n    ]\n  }\n}\n',
  );
});

test("members whose keys changed order, and elements that moved, keep their text", () => {
  assert.equal(edit('{"a": 1.0, "b": 2}', () => ({ b: 2, a: 1 })), '{"b": 2, "a": 1.0}');
  assert.equal(edit('{\n  "x": {"a": 1.0, "b": [2.50]},\n  "y": 1\n}\n', () => ({ x: { b: [2.5], a: 1, c: 3 }, y: 1 })), '{\n  "x": {"b": [2.50], "a": 1.0, "c": 3},\n  "y": 1\n}\n');
  assert.equal(edit("[1.0, 2.50, 3]", () => [2.5, 1, 4]), "[2.50, 1.0, 4]");
});

test("whitespace before a comma, comma-first lines and `{ }` survive adding and removing a key", () => {
  const add = (t: string) => edit(t, (v) => ({ ...v, hooks: { PreToolUse: [] } }));
  const remove = (t: string) =>
    edit(t, (v) => {
      const { hooks: _, ...rest } = v;
      return rest;
    });
  const cases: [string, string][] = [
    ['{\n  "a": 1 ,\n  "b": 2\n}\n', '{\n  "a": 1 ,\n  "b": 2 ,\n  "hooks": {\n    "PreToolUse": []\n  }\n}\n'],
    ['{\n  "a": 1\n, "b": 2\n}\n', '{\n  "a": 1\n, "b": 2\n, "hooks": {\n    "PreToolUse": []\n  }\n}\n'],
    ["{ }\n", '{ "hooks": {"PreToolUse": []} }\n'],
    ['{ "a": 1 }\n', '{ "a": 1, "hooks": {"PreToolUse": []} }\n'],
    ['{"a": 1}', '{"a": 1, "hooks": {"PreToolUse": []}}'],
  ];
  for (const [original, added] of cases) {
    assert.equal(add(original), added, original);
    assert.equal(remove(added), original, original);
  }
});

test("integer-like keys, which JSON.parse lists first, keep their place in the text", () => {
  const original = '{\n  "b": 1,\n  "1": 2.0\n}\n';
  const added = edit(original, (v) => ({ ...v, hooks: {} }));
  assert.equal(added, '{\n  "b": 1,\n  "1": 2.0,\n  "hooks": {}\n}\n');
  assert.equal(
    edit(added, (v) => {
      const { hooks: _, ...rest } = v;
      return rest;
    }),
    original,
  );
});

test("what it cannot map is reformatted rather than guessed at", () => {
  const dup = '{"a": 1, "a": 2}';
  assert.equal(editJson(dup, { a: 3 }, detectStyle(dup)), '{\n  "a": 3\n}\n');
  assert.equal(editJson(undefined, { a: 1 }, detectStyle("")), '{\n  "a": 1\n}\n');
  assert.equal(editJson("  \n", { a: 1 }, detectStyle("  \n")), '{\n  "a": 1\n}\n');
});

test("text that is not JSON falls back to a plain reformat at once", () => {
  for (const bad of ['{"a": "x', '{"a": 1', "[1, 2", '{"a": 1}}']) {
    const t = performance.now();
    assert.equal(editJson(bad, { a: 1 }, detectStyle(bad)), '{\n  "a": 1\n}\n', bad);
    assert.ok(performance.now() - t < 100, bad);
  }
});
