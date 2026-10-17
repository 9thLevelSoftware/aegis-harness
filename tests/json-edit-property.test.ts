/**
 * editJson over random settings files with random formatting (indent styles,
 * one-line and spread-out containers, CRLF, BOM, space before commas,
 * comma-first, `[{` hugging, number spellings, escapes) and random edits of
 * the kind `ah init` makes through planHooks. Seeded, so a failure names the
 * case that reproduces it.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { detectStyle } from "../src/wiring/files.ts";
import { HookShapeError, planHooks } from "../src/wiring/hooks-json.ts";
import { editJson } from "../src/wiring/json-edit.ts";

type Obj = Record<string, unknown>;

function rng(seed: number): () => number {
  let s = seed;
  return () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface Fmt {
  eol: string;
  unit: string;
  colon: string;
  /** `, "b"` at the start of the line instead of a comma at the end. */
  commaFirst: boolean;
  /** Odd spacing near commas: `1 ,`, `,  ⏎`, blank lines. */
  loose: boolean;
}

type Layout = "lines" | "inline" | "compact" | "hug";

const GUARD = "/opt/ah/dist/guard.mjs";
const NODE = "/usr/bin/node";

function generator(seed: number) {
  const rnd = rng(seed);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)];
  const chance = (p: number) => rnd() < p;

  const str = (s: string) => {
    let out = '"';
    for (const ch of s) {
      if (ch === '"' || ch === "\\") out += "\\" + ch;
      else if (ch === "\n") out += "\\n";
      else if (ch === "/" && chance(0.4)) out += "\\/";
      else if (ch === "é" && chance(0.5)) out += "\\u00e9";
      else if (ch === "😀" && chance(0.5)) out += "\\ud83d\\ude00";
      else out += ch;
    }
    return out + '"';
  };
  const scalar = () =>
    chance(0.4)
      ? str(pick(["x", "a/b", "é", "😀", 'q"q', "back\\slash", "line\nbreak", "", "Bash(ls)"]))
      : pick(["1", "1.0", "1.50", "30.0", "1e3", "1E+2", "-0", "0.10", "12345678901234567890", "-12.5e-1", "true", "false", "null", "7"]);

  /** A container's text from its items' texts; `indent` is the indentation of the line it opens on. */
  function join(f: Fmt, open: string, close: string, parts: string[], indent: string, layout: Layout): string {
    if (parts.length === 0) return open + (chance(0.3) ? " " : "") + close;
    if (layout === "compact") return open + parts.join(",") + close;
    if (layout === "hug") return open + parts.join(", ") + close;
    if (layout === "inline") {
      const pad = chance(0.5) ? " " : "";
      return open + pad + parts.join(f.loose && chance(0.3) ? " , " : ", ") + pad + close;
    }
    const inner = indent + f.unit;
    let s = open + f.eol + inner + parts[0];
    for (const p of parts.slice(1)) {
      if (f.commaFirst) s += f.eol + indent + ", " + p;
      else {
        const before = f.loose && chance(0.3) ? " " : "";
        const after = f.loose && chance(0.2) ? "  " : "";
        const blank = f.loose && chance(0.2) ? f.eol : "";
        s += before + "," + after + blank + f.eol + inner + p;
      }
    }
    return s + f.eol + indent + close;
  }

  const layoutFor = (top: boolean): Layout => (top ? (chance(0.85) ? "lines" : pick(["inline", "compact"] as const)) : pick(["lines", "lines", "inline", "compact"] as const));
  const childIndent = (f: Fmt, indent: string, layout: Layout) => (layout === "lines" ? indent + f.unit : indent);
  const colonFor = (f: Fmt, layout: Layout) => (layout === "compact" ? ":" : f.colon);

  function object(f: Fmt, indent: string, fields: [string, (indent: string, layout: Layout) => string][], layout = layoutFor(false)): { text: string; parts: string[] } {
    const ci = childIndent(f, indent, layout);
    const parts = fields.map(([k, v]) => str(k) + colonFor(f, layout) + v(ci, layout));
    return { text: join(f, "{", "}", parts, indent, layout), parts };
  }

  function array(f: Fmt, indent: string, els: ((indent: string, layout: Layout) => string)[], layout = layoutFor(false)): { text: string; parts: string[] } {
    const ci = childIndent(f, indent, layout);
    const parts = els.map((e) => e(ci, layout));
    return { text: join(f, "[", "]", parts, indent, layout), parts };
  }

  function value(f: Fmt, depth: number): (indent: string, outer: Layout) => string {
    if (depth > 3 || chance(0.45)) {
      const t = scalar();
      return () => t;
    }
    // Inside a one-line container everything stays on that line.
    const inner = (outer: Layout): Layout | undefined => (outer === "lines" || outer === "hug" ? undefined : outer);
    if (chance(0.5)) {
      const els = Array.from({ length: Math.floor(rnd() * 4) }, () => value(f, depth + 1));
      return (indent, outer) => array(f, indent, els, inner(outer)).text;
    }
    const keys = [...new Set(Array.from({ length: Math.floor(rnd() * 4) }, () => pick(["a", "b", "allow", "deny", "x/y", "é", "1", "10"])))];
    const fields = keys.map((k): [string, (indent: string, layout: Layout) => string] => [k, value(f, depth + 1)]);
    return (indent, outer) => object(f, indent, fields, inner(outer)).text;
  }

  let serial = 100;
  function entry(f: Fmt, ah: boolean): (indent: string, outer: Layout) => string {
    const fields: [string, string][] = [["type", str("command")]];
    if (ah) {
      if (chance(0.5)) {
        fields.push(["command", str(NODE)]);
        fields.push(["args", `[${[GUARD, "--agent", "claude", ...(chance(0.3) ? ["--no-log"] : [])].map(str).join(", ")}]`]);
      } else fields.push(["command", str(`${NODE} ${pick(["/old/dist/guard.mjs", GUARD])} --agent ${pick(["claude", "codex"])}`)]);
      if (chance(0.6)) fields.push(["timeout", pick(["5", "10", "5.0"])]);
    } else {
      fields.push(["command", str(pick(["npx prettier --write", "python3 check.py", "echo é", "node scripts/guard.mjs"]))]);
      if (chance(0.6)) fields.push(["timeout", pick(["30", "1.0", `${serial++}.0`])]);
    }
    if (chance(0.2)) fields.reverse(); // written by hand, keys in another order
    const typed = fields.map(([k, t]): [string, (indent: string, layout: Layout) => string] => [k, () => t]);
    return (indent, outer) => object(f, indent, typed, outer === "lines" || outer === "hug" ? undefined : outer).text;
  }

  /** A matcher group; the text of each of its user entries goes into `users`. */
  function group(f: Fmt, kind: "user" | "ah" | "mixed", users: string[]): (indent: string, outer: Layout) => string {
    const mine = Array.from({ length: kind === "ah" ? 1 + (chance(0.2) ? 1 : 0) : 1 + Math.floor(rnd() * 2) }, () => kind === "ah");
    if (kind === "mixed") mine.splice(Math.floor(rnd() * (mine.length + 1)), 0, true);
    const els = mine.map((ah) => entry(f, ah));
    const matcher = str(pick(["Bash", "^Bash$", "Write|Edit", "*", "", "Bash|Edit"]));
    const fields: [string, (indent: string, layout: Layout) => string][] = [
      ["matcher", () => matcher],
      [
        "hooks",
        (indent, layout) => {
          const a = array(f, indent, els, layout === "lines" || layout === "hug" ? undefined : layout);
          users.push(...a.parts.filter((_, k) => !mine[k]));
          return a.text;
        },
      ],
    ];
    if (chance(0.2)) fields.reverse();
    return (indent, outer) => object(f, indent, fields, outer === "lines" || outer === "hug" ? undefined : outer).text;
  }

  /** A settings file, with the text of each top-level member, of each PreToolUse group and of each user entry. */
  return function doc(): { text: string; members: Map<string, string>; groups: string[]; users: string[] } {
    const users: string[] = [];
    const f: Fmt = { eol: chance(0.25) ? "\r\n" : "\n", unit: pick(["  ", "    ", "\t", " "]), colon: pick([": ", ":", " : "]), commaFirst: chance(0.08), loose: chance(0.3) };
    const top: [string, (indent: string, layout: Layout) => string][] = [];
    for (const k of new Set(Array.from({ length: Math.floor(rnd() * 4) }, () => pick(["permissions", "env", "model", "$schema", "statusLine", "é", "1", "__proto__"])))) top.push([k, value(f, 1)]);
    let groups: string[] = [];
    if (chance(0.75)) {
      const events: [string, (indent: string, layout: Layout) => string][] = [];
      if (chance(0.4)) events.push(["PostToolUse", (indent) => array(f, indent, [group(f, "user", users)]).text]);
      if (chance(0.85)) {
        const gs = Array.from({ length: Math.floor(rnd() * 4) }, () => group(f, pick(["user", "user", "ah", "mixed", "mixed"] as const), users));
        const layout: Layout = chance(0.2) ? "hug" : "lines";
        events.push(["PreToolUse", (indent) => {
          const a = array(f, indent, gs, layout);
          groups = a.parts;
          return a.text;
        }]);
      }
      if (chance(0.3)) events.push(["Stop", () => "[]"]);
      if (chance(0.5)) events.reverse();
      top.splice(Math.floor(rnd() * (top.length + 1)), 0, ["hooks", (indent, layout) => object(f, indent, events, layout === "lines" ? undefined : layout).text]);
    }
    const root = object(f, "", top, layoutFor(true));
    const members = new Map(top.map(([k], i) => [k, root.parts[i]]));
    const text = (chance(0.1) ? "﻿" : "") + (chance(0.1) ? f.eol : "") + root.text + pick([f.eol, "", f.eol + f.eol, " " + f.eol]);
    return { text, members, groups, users };
  };
}

const parse = (t: string): Obj => JSON.parse(t.replace(/^﻿/, ""));
const S = (v: unknown) => JSON.stringify(v);
const canonical = (agent: "claude" | "codex") => () =>
  agent === "claude"
    ? { matcher: "Bash|Edit", hooks: [{ type: "command", command: NODE, args: [GUARD, "--agent", "claude"], timeout: 5 }] }
    : { matcher: "Bash|Edit|Write|Agent", hooks: [{ type: "command", command: `${NODE} ${GUARD} --agent codex`, timeout: 5 }] };

type Op = (v: Obj) => Obj;
const ops: Record<string, Op> = {
  "add for claude": (v) => planHooks(v, "f", canonical("claude")).value,
  "add for codex": (v) => planHooks(v, "f", canonical("codex"), { placement: "keep-indexes" }).value,
  remove: (v) => planHooks(v, "f", () => null).value,
  "drop the hooks key": (v) => {
    const { hooks: _, ...rest } = v;
    return rest;
  },
  "set hooks.PreToolUse": (v) => ({ ...v, hooks: { ...(v.hooks as Obj | undefined), PreToolUse: [canonical("claude")()] } }),
};
const undo: Record<string, Op | undefined> = { "add for claude": ops.remove, "add for codex": ops.remove, "set hooks.PreToolUse": ops["drop the hooks key"] };

const edit = (text: string, value: unknown) => editJson(text, value, detectStyle(text));
/** Every hook entry in a settings value, as JSON. */
const entriesOf = (v: Obj): string[] =>
  Object.values((v.hooks as Obj | undefined) ?? {}).flatMap((gs) => (Array.isArray(gs) ? gs : []).flatMap((g) => ((g as Obj).hooks as unknown[] | undefined) ?? []).map(S));

test("random settings files keep every byte the edit did not change", () => {
  const doc = generator(20261017);
  const pick = rng(7);
  const names = Object.keys(ops);
  let roundTrips = 0;
  let split = 0;
  for (let n = 0; n < 2500; n++) {
    const d = doc();
    const before = parse(d.text);
    const name = names[Math.floor(pick() * names.length)];
    const where = `case ${n} (${name}) on ${JSON.stringify(d.text)}`;
    let target: Obj;
    try {
      target = ops[name](before);
    } catch (err) {
      if (err instanceof HookShapeError) continue;
      throw err;
    }
    const out = edit(d.text, target);
    assert.equal(S(parse(out)), S(target), `${where}: parses to the target`);
    for (const [k, text] of d.members) {
      if (Object.hasOwn(target, k) && S(before[k]) === S(target[k])) assert.ok(out.includes(text), `${where}: member ${k} keeps its text\n${JSON.stringify(out)}`);
    }
    const pre = (target.hooks as Obj | undefined)?.PreToolUse;
    const kept = (((before.hooks as Obj | undefined)?.PreToolUse as unknown[] | undefined) ?? []).map((g) => Array.isArray(pre) && pre.some((x) => S(x) === S(g)));
    kept.forEach((k, i) => {
      if (k) assert.ok(out.includes(d.groups[i]), `${where}: group ${i} keeps its text\n${JSON.stringify(out)}`);
    });
    // A person's entry keeps its text wherever its value is still listed, also when ah's entry was lifted out of its group.
    const left = new Set(entriesOf(target));
    const values = d.users.map((t) => S(JSON.parse(t)));
    d.users.forEach((t, k) => {
      if (values.indexOf(values[k]) !== values.lastIndexOf(values[k]) || !left.has(values[k])) return;
      assert.ok(out.includes(t), `${where}: user entry ${t} keeps its text\n${JSON.stringify(out)}`);
      const home = d.groups.findIndex((g) => g.includes(t));
      if (home >= 0 && !kept[home]) split++;
    });
    assert.equal(edit(out, ops[name](parse(out))), out, `${where}: doing it again changes nothing`);
    const back = undo[name]?.(parse(out));
    if (back && S(back) === S(before)) {
      assert.equal(edit(out, back), d.text, `${where}: undoing it gives back the original\n${JSON.stringify(out)}`);
      roundTrips++;
    }
  }
  assert.ok(roundTrips > 500, `only ${roundTrips} round trips were checked`);
  assert.ok(split > 100, `only ${split} entries in changed groups were checked`);
});

test("an edit to one of several equal elements spelled differently stays on that element", () => {
  const rnd = rng(31);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)];
  for (let n = 0; n < 1500; n++) {
    const lines = rnd() < 0.5;
    const build = (els: string[]) => (lines ? `{\n  "allow": [\n    ${els.join(",\n    ")}\n  ]\n}\n` : `{"allow": [${els.join(", ")}]}`);
    const els = Array.from({ length: 2 + Math.floor(rnd() * 4) }, () => `{"tool": ${pick(['"Bash"', '"B\\u0061sh"'])}, "timeout": ${pick(["30", "30.0", "3e1"])}}`);
    const text = build(els);
    const before = parse(text) as { allow: Obj[] };
    const x = Math.floor(rnd() * els.length);
    const allow = before.allow.slice();
    const change = pick(["note", "timeout", "remove", "insert"]);
    if (change === "note") allow[x] = { ...allow[x], note: "x" };
    else if (change === "timeout") allow[x] = { ...allow[x], timeout: 31 };
    else if (change === "remove") allow.splice(x, 1);
    else allow.splice(x, 0, { tool: "Bash", timeout: 30 });
    const where = `case ${n} (${change} ${x}) on ${JSON.stringify(text)}`;
    const out = edit(text, { allow });
    assert.equal(S(parse(out)), S({ allow }), `${where}: parses to the target`);
    if (change === "remove") {
      // All are equal, so any one of them may go; the rest keep their text.
      assert.ok(els.some((_, k) => out === build(els.filter((_, i) => i !== k))), `${where}: the others keep their text\n${JSON.stringify(out)}`);
    } else {
      let at = 0;
      els.forEach((t, k) => {
        if (k === x && change !== "insert") return;
        const found = out.indexOf(t, at);
        assert.ok(found >= 0, `${where}: element ${k} keeps its text, in order\n${JSON.stringify(out)}`);
        at = found + t.length;
      });
    }
    assert.equal(edit(out, { allow }), out, `${where}: doing it again changes nothing`);
    // Taking out what was added gives back the bytes; a changed value's old spelling is gone.
    if (change === "note" || change === "insert") assert.equal(edit(out, before), text, `${where}: undoing it gives back the original\n${JSON.stringify(out)}`);
  }
});
