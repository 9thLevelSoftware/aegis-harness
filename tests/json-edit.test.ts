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

test("what it cannot edit in place is reformatted rather than guessed at", () => {
  const dup = '{"a": 1, "a": 2}';
  assert.equal(editJson(dup, { a: 3 }, detectStyle(dup)), '{\n  "a": 3\n}\n');
  const reordered = '{"a": 1, "b": 2}';
  assert.equal(editJson(reordered, { b: 2, a: 1 }, detectStyle(reordered)), '{\n  "b": 2,\n  "a": 1\n}\n');
  assert.equal(editJson(undefined, { a: 1 }, detectStyle("")), '{\n  "a": 1\n}\n');
  assert.equal(editJson("  \n", { a: 1 }, detectStyle("  \n")), '{\n  "a": 1\n}\n');
});
