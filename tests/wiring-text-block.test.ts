/**
 * The managed block against the files people actually have: marker lines in
 * code (as CommonMark reads it) are the user's examples, each user line keeps
 * its own line ending, and --remove gives back the exact bytes init started
 * from (no final newline, a last line ending in a CR, trailing blank or
 * whitespace lines, a block moved to the top, an empty file). A block that
 * would land in code goes at the top, and ah's own marker found only in code
 * is refused, so a fence can neither swallow ah's text nor make it add a
 * second block. The property tests at the end check all of it over random
 * markdown from fixed seeds.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { AGENTS_BLOCK_BODY } from "../src/wiring/agents-md.ts";
import { blockEndByte, BLOCK_BEGIN, BLOCK_END, BlockError, lineKinds, readBlock, removeBlock, upsertBlock } from "../src/wiring/text-block.ts";

const body = ["## Guard", "", "- one"];
const block = (eol = "\n") => [BLOCK_BEGIN, ...body, BLOCK_END].join(eol);
const BOM = "﻿";
const fenced = (t: string) => `\`\`\`markdown\n${t}\n\`\`\`\n`;

test("marker lines inside fenced code are the user's, not ah's block", () => {
  const example = ["# Project", "", "Tools wrap their section like this:", "", "```markdown", "<!-- ah:begin -->", "(tool-owned lines)", "<!-- ah:end -->", "```", "", "## Build", ""].join("\n");
  const e = upsertBlock(example, body, "AGENTS.md");
  assert.equal(e.action, "appended");
  assert.equal(e.text, `${example}\n${block()}\n`);
  assert.deepEqual(readBlock(e.text!, "AGENTS.md"), body);
  assert.equal(upsertBlock(e.text, body, "AGENTS.md").action, "unchanged");
  assert.equal(removeBlock(e.text, "AGENTS.md").text, example);
  assert.equal(removeBlock(example, "AGENTS.md").action, "absent");
  for (const lone of ["# P\n\n```\n<!-- ah:begin -->\n```\n", "~~~\n<!-- ah:end -->\n~~~\n", "Like this:\n\n    <!-- ah:begin -->\n    <!-- ah:end -->\n"]) assert.equal(upsertBlock(lone, body, "AGENTS.md").action, "appended", lone);
});

test("lines are code, comment or text by CommonMark's block rules", () => {
  const kinds = (lines: string[]): string => lineKinds(lines).map((k) => ({ text: "t", code: "c", comment: "h" })[k]).join("");
  const cases: [string[], string][] = [
    [["````md", "```", "<!-- ah:begin -->", "````"], "cccc"],
    [["~~~", "```", "x", "~~~~~", "y"], "cccct"],
    [["```", "```js", "x", "```  "], "cccc"],
    [["```a`b", "x", "```"], "ttc"],
    [["~~~a`b", "x", "~~~"], "ccc"],
    [["``", "x", "``"], "ttt"],
    [["a", "```", "b"], "tcc"],
    [["```", "    ```", "x"], "ccc"],
    // Four columns in is indented code (or a paragraph's next line), never a fence.
    [["Use:", "", "    ```ts", "", "Done."], "ttctt"],
    [["text", "    ```"], "tt"],
    [["\t```", "x"], "ct"],
    // Fences in list items: on the item's line, at its content column, and ending with the item.
    [["  - item", "    ```", "    x", "    ```"], "tccc"],
    [["- ```", "  <!-- ah:begin -->", "  ```", "<!-- ah:end -->"], "ccch"],
    [["- ```", "  x", "<!-- ah:begin -->", "  ```"], "cchc"],
    [["10. ```", "    x", "    ```", "x"], "ccct"],
    [["- item", "lazy", "    ```", "  <!-- ah:begin -->", "    ```"], "ttccc"],
    [["- item", "", "    ```", "<!-- ah:end -->"], "ttch"],
    // An HTML comment hides what looks like a fence; a block quote holds no marker line.
    [["<!--", "```", "-->", "<!-- ah:begin -->", "```"], "hhhhc"],
    [["> ```", "> <!-- ah:begin -->", "> ```"], "ttt"],
  ];
  for (const [lines, want] of cases) assert.equal(kinds(lines), want, lines.join(" | "));
});

test("four spaces in is indented code: it hides neither the block nor the user's later code", () => {
  const user = "# Conventions\n\nOpen every code block with its language:\n\n    ```ts\n\nNever leave it bare.\n";
  const once = upsertBlock(user, body, "AGENTS.md");
  assert.equal(once.action, "appended");
  const tail = "\n## Commands\n\n```sh\nnpm test\n```\n";
  const later = once.text + tail;
  assert.deepEqual(readBlock(later, "AGENTS.md"), body);
  assert.equal(upsertBlock(later, body, "AGENTS.md").action, "unchanged");
  assert.equal(removeBlock(later, "AGENTS.md").text, user + tail);
});

test("a file that ends inside a code fence that never closes gets the block at the top", () => {
  const user = "# Build\n\n```sh\nmake\n";
  const once = upsertBlock(user, body, "AGENTS.md");
  assert.equal(once.action, "prepended");
  assert.equal(once.text, `${block()}\n\n${user}`);
  assert.equal(upsertBlock(once.text, body, "AGENTS.md").action, "unchanged");
  const tail = "\n## Test\n\n```sh\nnpm test\n```\n";
  assert.equal(upsertBlock(once.text + tail, body, "AGENTS.md").action, "unchanged", "a code block added below cannot reach it");
  assert.equal(removeBlock(once.text + tail, "AGENTS.md").text, user + tail);
  // Markers in that fence are the user's example: kept by init, kept by --remove.
  const example = "# P\n\nExample of a managed section:\n\n```markdown\n<!-- ah:begin -->\nmy example\n<!-- ah:end -->\n";
  const e = upsertBlock(example, body, "AGENTS.md");
  assert.equal(e.action, "prepended");
  assert.equal(e.text, `${block()}\n\n${example}`);
  assert.equal(removeBlock(example, "AGENTS.md").action, "absent");
  assert.equal(removeBlock(e.text, "AGENTS.md").text, example);
});

test("ah's own begin marker inside code with no block outside is refused, not hidden or doubled", () => {
  const once = upsertBlock("# P\n", body, "AGENTS.md").text!;
  const opened = once.replace("# P\n", "# P\n```sh\nmake\n");
  for (const t of [opened, `${opened}\n\`\`\`\nx\n\`\`\`\n`, fenced(block())]) {
    assert.throws(() => upsertBlock(t, body, "AGENTS.md"), /begin marker inside a code block \(line \d+\)/, t);
    assert.throws(() => upsertBlock(t, body, "AGENTS.md", "start"), BlockError);
    assert.throws(() => removeBlock(t, "AGENTS.md"), BlockError);
    assert.throws(() => readBlock(t, "AGENTS.md"), BlockError);
  }
  // Next to a real block, a pasted copy of ah's markers is only an example.
  const pasted = `# P\n\n${fenced(block())}`;
  const real = `${pasted}\n${block()}\n`;
  assert.equal(upsertBlock(real, body, "AGENTS.md").action, "unchanged");
  assert.equal(removeBlock(real, "AGENTS.md").text, pasted);
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
  // An end marker with no break and no blank line before the block was not ah's doing: the line above keeps its break.
  assert.equal(removeBlock(`a\n${block()}`, "AGENTS.md").text, "a\n");
});

test("a last line that ends in a CR keeps it: the break ah adds is CRLF, which the CR cannot merge into", () => {
  for (const [t, eol] of [["# Project\nUse pnpm.\r", "\n"], ["a\rb\r", "\n"], ["x\r\ny\r\nz\r", "\r\n"], ["# Notes\n<!-- ah:begin -->\r", "\n"]]) {
    const why = JSON.stringify(t);
    const e = upsertBlock(t, body, "AGENTS.md");
    assert.equal(e.action, "appended", why);
    assert.equal(e.text, `${t}\r\n${eol}${block(eol)}`, why);
    assert.equal(upsertBlock(e.text, body, "AGENTS.md").action, "unchanged", why);
    assert.equal(removeBlock(e.text, "AGENTS.md").text, t, why);
  }
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
// Properties: over random markdown, init writes the user's bytes plus ah's
// lines and nothing else, a re-run changes nothing, and --remove gives the
// input back.

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

function usualEol(t: string): string {
  return (t.match(/\r\n/g) ?? []).length > (t.match(/(?<!\r)\n/g) ?? []).length ? "\r\n" : "\n";
}

/** What upsertBlock must write: after `t` (a last line without a break gets one), or before it. */
function expected(t: string, where: "end" | "start"): string {
  const e = usualEol(t);
  const bom = t.startsWith(BOM) ? BOM : "";
  const ours = [BLOCK_BEGIN, ...AGENTS_BLOCK_BODY, BLOCK_END].join(e);
  const open = t.length > bom.length && !t.endsWith("\n");
  const brk = t.endsWith("\r") ? "\r\n" : e;
  return where === "end" ? `${t}${open ? brk : ""}${e}${ours}${open ? "" : e}` : `${bom}${ours}${e}${e}${t.slice(bom.length)}`;
}

/** What holds for any file upsertBlock accepts: the block reads back, a re-run, a new body or a move changes nothing else, --remove undoes it. */
function roundTrips(t: string, where: "end" | "start", why: string): void {
  const up = upsertBlock(t, AGENTS_BLOCK_BODY, "f", where);
  const text = up.text!;
  const added = up.action === "appended" || up.action === "prepended";
  const back = added ? t : removeBlock(t, "f").text;
  assert.deepEqual(readBlock(text, "f"), AGENTS_BLOCK_BODY, why);
  assert.equal(upsertBlock(text, AGENTS_BLOCK_BODY, "f", where).action, "unchanged", why);
  assert.equal(removeBlock(text, "f").text, back, why);
  assert.equal(removeBlock(upsertBlock(text, ["## Guard", "- changed"], "f", where).text, "f").text, back, why);
  assert.equal(removeBlock(upsertBlock(text, AGENTS_BLOCK_BODY, "f", "start").text, "f").text, back, why);
  if (added) {
    const begin = up.action === "appended" ? text.lastIndexOf(BLOCK_BEGIN) : text.indexOf(BLOCK_BEGIN);
    assert.equal(blockEndByte(text, "f"), Buffer.byteLength(text.slice(0, text.indexOf(BLOCK_END, begin) + BLOCK_END.length), "utf8"), why);
  }
}

const PLAIN = ["# Title", "", "", "text", "  ", "\t", "\ttab", "a\rb", "- item", "  - nested", "1. step", "> quote", "<!-- note -->", "Write `<!-- ah:begin -->` to start one.", "``not a fence``"];

/** Markdown whose code blocks are known: each closes, or the last one never does (`unclosed`). */
function markdown(r: () => number): { t: string; unclosed: boolean } {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
  const mode = pick(["lf", "crlf", "mixed"]);
  const eol = () => (mode === "lf" ? "\n" : mode === "crlf" ? "\r\n" : pick(["\n", "\r\n"]));
  const lines: string[] = [];
  for (let n = Math.floor(r() * 7), k = 0; k < n; k++) {
    const kind = r();
    if (kind < 0.6) {
      lines.push(pick(PLAIN));
    } else if (kind < 0.85) {
      // A fence (at the top level or in a list item) holding marker lines and fence-like lines that do not close it.
      const ch = pick(["`", "~"]);
      const len = 3 + Math.floor(r() * 3);
      const item = r() < 0.25;
      const indent = item ? "  " : pick(["", " ", "  ", "   "]);
      const other = ch === "`" ? "~" : "`";
      lines.push((item ? "- " : indent) + ch.repeat(len) + pick(["", "markdown", " md", ch === "~" ? "a`b" : "x"]));
      for (let m = Math.floor(r() * 4), j = 0; j < m; j++) {
        const l = pick(["<!-- ah:begin -->", "  <!--ah:end-->", "<!-- ah:end -->", "text", "", ch.repeat(len - 1), other.repeat(len + 1), `${ch.repeat(len)}js`]);
        lines.push(l === "" ? "" : indent + l);
      }
      lines.push(indent + ch.repeat(len + Math.floor(r() * 2)) + pick(["", "  "]));
    } else if (kind < 0.93) {
      // Indented code that looks like a fence and markers.
      lines.push("", "    ```ts", "    <!-- ah:begin -->", "    x", "    <!-- ah:end -->", "", "# After");
    } else {
      lines.push("<!--", pick(["```", "~~~~ x"]), "-->");
    }
  }
  const unclosed = r() < 0.1;
  if (unclosed) lines.push("# Tail", pick(["```", "~~~~ unclosed"]), "text");
  let t = r() < 0.15 ? BOM : "";
  lines.forEach((l, i) => {
    t += l;
    if (i < lines.length - 1 || r() < 0.7) t += eol();
  });
  return { t, unclosed };
}

test("property: upsert writes exactly the user's bytes plus ah's lines, and remove gives them back", () => {
  const r = prng(20261017);
  for (let i = 0; i < 3000; i++) {
    const { t, unclosed } = markdown(r);
    const where = r() < 0.5 ? "end" : "start";
    const why = `case ${i} ${where} ${JSON.stringify(t)}`;
    const at = where === "end" && !unclosed ? "end" : "start";
    const up = upsertBlock(t, AGENTS_BLOCK_BODY, "f", where);
    assert.equal(up.action, at === "end" ? "appended" : "prepended", why);
    assert.equal(up.text, expected(t, at), why);
    roundTrips(t, where, why);
  }
  assert.equal(removeBlock(upsertBlock(null, AGENTS_BLOCK_BODY, "f").text, "f").text, null);
});

const WILD = [
  ...PLAIN, "```", "````", "~~~", "```md", "~~~ x`y", "    ```", "\t```", "- ```", "  ```", "1. ```", "   ```", "  - ```", "<!--", "-->", "lazy",
  "<!-- ah:begin -->", "<!--ah:end-->", "  <!-- ah:begin -->", "    <!-- ah:end -->", BLOCK_BEGIN, BLOCK_END, "> ```", "x\r", "\r", "日本語", " ",
];

test("property: on any text, upsert either refuses a file with markers or round-trips", () => {
  const r = prng(4242);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
  let refused = 0;
  for (let i = 0; i < 2500; i++) {
    const lines = Array.from({ length: Math.floor(r() * 9) }, () => pick(WILD));
    let t = r() < 0.15 ? BOM : "";
    lines.forEach((l, k) => {
      t += l;
      if (k < lines.length - 1 || r() < 0.6) t += pick(["\n", "\r\n", "\n", "\r"]);
    });
    for (const where of ["end", "start"] as const) {
      const why = `case ${i} ${where} ${JSON.stringify(t)}`;
      let up;
      try {
        up = upsertBlock(t, AGENTS_BLOCK_BODY, "f", where);
      } catch (err) {
        assert.ok(err instanceof BlockError, why);
        assert.match(t, /ah:(begin|end)/, `only a file with marker text is refused: ${why}`);
        refused++;
        continue;
      }
      if (up.action === "appended" || up.action === "prepended") assert.equal(up.text, expected(t, up.action === "appended" ? "end" : "start"), why);
      if (where === "start") assert.notEqual(up.action, "appended", why);
      roundTrips(t, where, why);
    }
  }
  assert.ok(refused < 2500, `refused ${refused} of 5000`);
});
