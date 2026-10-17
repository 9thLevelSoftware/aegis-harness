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
      if (chance(0.4)) fields.push(["timeout", pick(["30", "1.0"])]);
    }
    if (chance(0.2)) fields.reverse(); // written by hand, keys in another order
    const typed = fields.map(([k, t]): [string, (indent: string, layout: Layout) => string] => [k, () => t]);
    return (indent, outer) => object(f, indent, typed, outer === "lines" || outer === "hug" ? undefined : outer).text;
  }

  function group(f: Fmt, kind: "user" | "ah" | "mixed"): (indent: string, outer: Layout) => string {
    const els = Array.from({ length: kind === "ah" ? 1 + (chance(0.2) ? 1 : 0) : 1 + Math.floor(rnd() * 2) }, () => entry(f, kind === "ah"));
    if (kind === "mixed") els.splice(Math.floor(rnd() * (els.length + 1)), 0, entry(f, true));
    const matcher = str(pick(["Bash", "^Bash$", "Write|Edit", "*", ""]));
    const fields: [string, (indent: string, layout: Layout) => string][] = [
      ["matcher", () => matcher],
      ["hooks", (indent, layout) => array(f, indent, els, layout === "lines" || layout === "hug" ? undefined : layout).text],
    ];
    if (chance(0.2)) fields.reverse();
    return (indent, outer) => object(f, indent, fields, outer === "lines" || outer === "hug" ? undefined : outer).text;
  }

  /** A settings file, with the text of each top-level member and of each PreToolUse group. */
  return function doc(): { text: string; members: Map<string, string>; groups: string[] } {
    const f: Fmt = { eol: chance(0.25) ? "\r\n" : "\n", unit: pick(["  ", "    ", "\t", " "]), colon: pick([": ", ":", " : "]), commaFirst: chance(0.08), loose: chance(0.3) };
    const top: [string, (indent: string, layout: Layout) => string][] = [];
    for (const k of new Set(Array.from({ length: Math.floor(rnd() * 4) }, () => pick(["permissions", "env", "model", "$schema", "statusLine", "é", "1", "__proto__"])))) top.push([k, value(f, 1)]);
    let groups: string[] = [];
    if (chance(0.75)) {
      const events: [string, (indent: string, layout: Layout) => string][] = [];
      if (chance(0.4)) events.push(["PostToolUse", (indent) => array(f, indent, [group(f, "user")]).text]);
      if (chance(0.85)) {
        const gs = Array.from({ length: Math.floor(rnd() * 4) }, () => group(f, pick(["user", "user", "ah", "mixed"] as const)));
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
    return { text, members, groups };
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

test("random settings files keep every byte the edit did not change", () => {
  const doc = generator(20261017);
  const pick = rng(7);
  const names = Object.keys(ops);
  let roundTrips = 0;
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
    if (Array.isArray(pre)) {
      ((before.hooks as Obj | undefined)?.PreToolUse as unknown[] | undefined)?.forEach((g, i) => {
        if (pre.some((x) => S(x) === S(g))) assert.ok(out.includes(d.groups[i]), `${where}: group ${i} keeps its text\n${JSON.stringify(out)}`);
      });
    }
    assert.equal(edit(out, ops[name](parse(out))), out, `${where}: doing it again changes nothing`);
    const back = undo[name]?.(parse(out));
    if (back && S(back) === S(before)) {
      assert.equal(edit(out, back), d.text, `${where}: undoing it gives back the original\n${JSON.stringify(out)}`);
      roundTrips++;
    }
  }
  assert.ok(roundTrips > 500, `only ${roundTrips} round trips were checked`);
});
