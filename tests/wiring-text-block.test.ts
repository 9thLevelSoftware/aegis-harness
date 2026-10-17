/**
 * The managed block against the files people actually have: marker lines in
 * fenced code are the user's examples, each user line keeps its own line
 * ending, and --remove gives back the exact bytes init started from (no final
 * newline, trailing blank or whitespace lines, a block moved to the top, an
 * empty file). The property test at the end checks all of it over random
 * markdown from a fixed seed.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { AGENTS_BLOCK_BODY } from "../src/wiring/agents-md.ts";
import { blockEndByte, BLOCK_BEGIN, BLOCK_END, BlockError, fencedLines, readBlock, removeBlock, upsertBlock } from "../src/wiring/text-block.ts";

const body = ["## Guard", "", "- one"];
const block = (eol = "\n") => [BLOCK_BEGIN, ...body, BLOCK_END].join(eol);
const BOM = "﻿";

test("marker lines inside fenced code are the user's, not ah's block", () => {
  const example = ["# Project", "", "Tools wrap their section like this:", "", "```markdown", "<!-- ah:begin -->", "(tool-owned lines)", "<!-- ah:end -->", "```", "", "## Build", ""].join("\n");
  const e = upsertBlock(example, body, "AGENTS.md");
  assert.equal(e.action, "appended");
  assert.equal(e.text, `${example}\n${block()}\n`);
  assert.deepEqual(readBlock(e.text!, "AGENTS.md"), body);
  assert.equal(upsertBlock(e.text, body, "AGENTS.md").action, "unchanged");
  assert.equal(removeBlock(e.text, "AGENTS.md").text, example);
  assert.equal(removeBlock(example, "AGENTS.md").action, "absent");
  for (const lone of ["# P\n\n```\n<!-- ah:begin -->\n```\n", "~~~\n<!-- ah:end -->\n~~~\n"]) assert.equal(upsertBlock(lone, body, "AGENTS.md").action, "appended", lone);
});

test("a fence closes only on the same character, at least as long, with nothing after it", () => {
  const cases: [string[], boolean[]][] = [
    [["````md", "```", "<!-- ah:begin -->", "````"], [true, true, true, true]],
    [["~~~", "```", "x", "~~~~~", "y"], [true, true, true, true, false]],
    [["```", "```js", "x", "```  "], [true, true, true, true]],
    [["  - item", "    ```", "    x", "    ```"], [false, true, true, true]],
    [["```a`b", "x", "```"], [false, false, false]],
    [["~~~a`b", "x", "~~~"], [true, true, true]],
    [["``", "x", "``"], [false, false, false]],
  ];
  for (const [lines, want] of cases) assert.deepEqual(fencedLines(lines, false), want, lines.join(" | "));
  assert.deepEqual(fencedLines(["a", "```", "b"], false), [false, false, false]);
  assert.deepEqual(fencedLines(["a", "```", "b"], true), [false, true, true]);
});

test("a fence that never closes does not hide the block, so a second run appends nothing", () => {
  const user = "# P\n\n```sh\nmake\n";
  const once = upsertBlock(user, body, "AGENTS.md");
  assert.equal(once.action, "appended");
  assert.equal(upsertBlock(once.text, body, "AGENTS.md").action, "unchanged");
  assert.equal(removeBlock(once.text, "AGENTS.md").text, user);
});

test("a real block next to a fenced example is found, replaced and removed alone", () => {
  const user = "# P\n\n~~~~\n<!-- ah:begin -->\n~~~\n<!-- ah:end -->\n~~~~\n";
  const once = upsertBlock(user, body, "AGENTS.md").text!;
  const changed = upsertBlock(once, ["- two"], "AGENTS.md");
  assert.equal(changed.action, "replaced");
  assert.equal(changed.text, `${user}\n${[BLOCK_BEGIN, "- two", BLOCK_END].join("\n")}\n`);
  assert.equal(removeBlock(changed.text, "AGENTS.md").text, user);
  assert.throws(() => upsertBlock(`${once}${BLOCK_BEGIN}\n`, body, "AGENTS.md"), BlockError);
});

test("each user line keeps its own line ending; ah's lines take the usual one", () => {
  const user = "# Project\r\n\r\nRule one.\r\nRule two (added on Linux).\nRule three.\r\n";
  const e = upsertBlock(user, body, "AGENTS.md");
  assert.equal(e.text, `${user}\r\n${block("\r\n")}\r\n`);
  assert.equal(removeBlock(e.text, "AGENTS.md").text, user);
  const lf = "a\nb\r\nc\n";
  assert.equal(upsertBlock(lf, body, "AGENTS.md").text, `${lf}\n${block()}\n`);
  const replaced = upsertBlock(`x\r\nz\r\n\r\n${BLOCK_BEGIN}\nold\r\n${BLOCK_END}\ny\n`, body, "AGENTS.md").text;
  assert.equal(replaced, `x\r\nz\r\n\r\n${BLOCK_BEGIN}\n${body.join("\r\n")}\r\n${BLOCK_END}\ny\n`);
});

test("a last line without a line break gets one and gets it back", () => {
  const e = upsertBlock("# Project\nUse pnpm.", body, "AGENTS.md");
  assert.equal(e.text, `# Project\nUse pnpm.\n\n${block()}`);
  assert.equal(removeBlock(e.text, "AGENTS.md").text, "# Project\nUse pnpm.");
  const crlf = upsertBlock("a\r\nb", body, "AGENTS.md").text;
  assert.equal(crlf, `a\r\nb\r\n\r\n${block("\r\n")}`);
  assert.equal(removeBlock(crlf, "AGENTS.md").text, "a\r\nb");
});

test("a block at the top comes out with the blank line after it", () => {
  const big = "# Big\n" + "x".repeat(100).concat("\n").repeat(400);
  const top = upsertBlock(big, body, "AGENTS.md", "start");
  assert.equal(top.action, "prepended");
  assert.equal(top.text, `${block()}\n\n${big}`);
  assert.equal(removeBlock(top.text, "AGENTS.md").text, big);
  const moved = upsertBlock(upsertBlock(`${BOM}${big}`, body, "AGENTS.md").text, body, "AGENTS.md", "start");
  assert.equal(moved.action, "replaced");
  assert.equal(moved.text, `${BOM}${block()}\n\n${big}`);
  assert.equal(removeBlock(moved.text, "AGENTS.md").text, `${BOM}${big}`);
  assert.equal(blockEndByte(moved.text!, "AGENTS.md"), Buffer.byteLength(BOM + block(), "utf8"));
});

test("an existing empty file is appended to and comes back empty; only a file ah created is deleted", () => {
  for (const empty of ["", BOM]) {
    const e = upsertBlock(empty, body, "AGENTS.override.md");
    assert.equal(e.action, "appended");
    assert.equal(e.text, `${empty}\n${block()}\n`);
    assert.deepEqual(removeBlock(e.text, "AGENTS.override.md"), { text: empty, action: "removed" });
  }
  const made = upsertBlock(null, body, "AGENTS.md");
  assert.deepEqual(removeBlock(made.text, "AGENTS.md"), { text: null, action: "removed" });
  assert.deepEqual(removeBlock(made.text!.replace(/\n/g, "\r\n"), "AGENTS.md"), { text: "", action: "removed" });
  assert.deepEqual(removeBlock(`${BOM}${made.text}`, "AGENTS.md"), { text: BOM, action: "removed" });
  assert.deepEqual(removeBlock(`<!-- ah:begin -->\n${body.join("\n")}\n${BLOCK_END}\n`, "AGENTS.md"), { text: "", action: "removed" });
});

// ---------------------------------------------------------------------------
// Property: over random markdown, init writes the user's bytes plus ah's lines
// and nothing else, a re-run changes nothing, and --remove gives the input back.

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

const PLAIN = ["# Title", "", "", "text", "  ", "\t", "\ttab", "a\rb", "- item", "Write `<!-- ah:begin -->` to start one.", "``not a fence``"];

function markdown(r: () => number): string {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
  const mode = pick(["lf", "crlf", "mixed"]);
  const eol = () => (mode === "lf" ? "\n" : mode === "crlf" ? "\r\n" : pick(["\n", "\r\n"]));
  const lines: string[] = [];
  for (let n = Math.floor(r() * 7), k = 0; k < n; k++) {
    if (r() < 0.7) {
      lines.push(pick(PLAIN));
      continue;
    }
    // Fenced code holding marker lines and fence-like lines that do not close it.
    const ch = pick(["`", "~"]);
    const len = 3 + Math.floor(r() * 3);
    const indent = pick(["", "  ", "    "]);
    const other = ch === "`" ? "~" : "`";
    lines.push(indent + ch.repeat(len) + pick(["", "markdown", " md", ch === "~" ? "a`b" : "x"]));
    for (let m = Math.floor(r() * 4), j = 0; j < m; j++) lines.push(pick([BLOCK_BEGIN, BLOCK_END, "<!-- ah:begin -->", "  <!--ah:end-->", "text", "", ch.repeat(len - 1), other.repeat(len + 1), `${ch.repeat(len)}js`]));
    lines.push(indent + ch.repeat(len + Math.floor(r() * 2)) + pick(["", "  "]));
  }
  if (r() < 0.1) lines.push(pick(["```", "~~~~ unclosed"]), "text");
  let t = r() < 0.15 ? BOM : "";
  lines.forEach((l, i) => {
    t += l;
    if (i < lines.length - 1 || r() < 0.7) t += eol();
  });
  return t;
}

function usualEol(t: string): string {
  return (t.match(/\r\n/g) ?? []).length > (t.match(/(?<!\r)\n/g) ?? []).length ? "\r\n" : "\n";
}

test("property: upsert then remove is the identity on random markdown, start and end", () => {
  const r = prng(20261017);
  const other = ["## Guard", "- changed"];
  for (let i = 0; i < 4000; i++) {
    const t = markdown(r);
    const where = r() < 0.5 ? "end" : "start";
    const why = `case ${i} ${where} ${JSON.stringify(t)}`;
    const e = usualEol(t);
    const bom = t.startsWith(BOM) ? BOM : "";
    const ours = [BLOCK_BEGIN, ...AGENTS_BLOCK_BODY, BLOCK_END].join(e);
    const open = t.length > bom.length && !t.endsWith("\n");
    const want = where === "end" ? `${t}${open ? e : ""}${e}${ours}${open ? "" : e}` : `${bom}${ours}${e}${e}${t.slice(bom.length)}`;
    const up = upsertBlock(t, AGENTS_BLOCK_BODY, "f", where);
    assert.equal(up.action, where === "end" ? "appended" : "prepended", why);
    assert.equal(up.text, want, why);
    assert.deepEqual(readBlock(up.text!, "f"), AGENTS_BLOCK_BODY, why);
    assert.equal(upsertBlock(up.text, AGENTS_BLOCK_BODY, "f", where).action, "unchanged", why);
    assert.equal(removeBlock(up.text, "f").text, t, why);
    const end = where === "end" ? up.text!.lastIndexOf(BLOCK_END) : up.text!.indexOf(BLOCK_END);
    assert.equal(blockEndByte(up.text!, "f"), Buffer.byteLength(up.text!.slice(0, end + BLOCK_END.length), "utf8"), why);
    const changed = upsertBlock(up.text, other, "f", where);
    assert.equal(changed.action, "replaced", why);
    assert.equal(removeBlock(changed.text, "f").text, t, why);
    if (where === "end") {
      const moved = upsertBlock(up.text, AGENTS_BLOCK_BODY, "f", "start");
      assert.equal(moved.text, upsertBlock(t, AGENTS_BLOCK_BODY, "f", "start").text, why);
      assert.equal(removeBlock(moved.text, "f").text, t, why);
    }
  }
  assert.equal(removeBlock(upsertBlock(null, AGENTS_BLOCK_BODY, "f").text, "f").text, null);
});
