/**
 * A block of text that `ah init` owns inside a file somebody else owns
 * (AGENTS.md, CLAUDE.md). Everything outside the markers is the user's and is
 * returned byte for byte, each line with its own line ending; only the lines
 * between the markers are rewritten, and the lines ah adds take the file's
 * usual ending. The byte-order mark is kept. Marker lines inside code, read
 * the way CommonMark reads it, are the user's examples, not ah's block.
 * Removing the block undoes exactly what adding it did, without remembering
 * anything, and upsertBlock checks that before it returns: see upsertBlock.
 */

/** `<!-- ah:begin ... -->` on a line of its own; anything after `ah:begin` is free text. */
const BEGIN_LINE = /^[ \t]*<!--[ \t]*ah:begin\b[^\r\n]*-->[ \t]*$/;
const END_LINE = /^[ \t]*<!--[ \t]*ah:end\b[^\r\n]*-->[ \t]*$/;

export const BLOCK_BEGIN = "<!-- ah:begin (managed by `ah init`; edits between these markers are replaced) -->";
export const BLOCK_END = "<!-- ah:end -->";

export type BlockAction = "created" | "appended" | "prepended" | "replaced" | "unchanged" | "removed" | "absent";

export interface BlockEdit {
  /** The new file content, or null when the file should be deleted (it held nothing but the block). */
  text: string | null;
  action: BlockAction;
}

export class BlockError extends Error {}

type Eol = "" | "\n" | "\r\n";

interface Line {
  text: string;
  /** Empty only on a last line that has no line break. */
  eol: Eol;
}

interface Parsed {
  bom: string;
  /** The ending most of the file's lines have: the one ah's lines get. */
  eol: "\n" | "\r\n";
  lines: Line[];
}

function parse(text: string): Parsed {
  const bom = text.startsWith("﻿") ? "﻿" : "";
  const lines: Line[] = [];
  let crlf = 0;
  for (let i = bom.length; i < text.length; ) {
    const nl = text.indexOf("\n", i);
    if (nl === -1) {
      lines.push({ text: text.slice(i), eol: "" });
      break;
    }
    const cr = nl > i && text[nl - 1] === "\r";
    if (cr) crlf++;
    lines.push({ text: text.slice(i, cr ? nl - 1 : nl), eol: cr ? "\r\n" : "\n" });
    i = nl + 1;
  }
  const lf = lines.filter((l) => l.eol === "\n").length;
  return { bom, eol: crlf > lf ? "\r\n" : "\n", lines };
}

function render(bom: string, lines: readonly Line[]): string {
  return bom + lines.map((l) => l.text + l.eol).join("");
}

/** A file that holds nothing but this block: what upsertBlock writes when there is no file. */
function created(body: readonly string[]): string {
  return [BLOCK_BEGIN, ...body, BLOCK_END].map((l) => `${l}\n`).join("");
}

/** Leading whitespace of `s` from index `at`, column `col`: where the text starts and its column (a tab runs to the next multiple of four). */
function lead(s: string, at: number, col: number): { at: number; col: number } {
  for (; at < s.length; at++) {
    if (s[at] === " ") col++;
    else if (s[at] === "\t") col += 4 - (col % 4);
    else break;
  }
  return { at, col };
}

/** Three or more backticks or tildes; the rest of the line is the info string. */
const FENCE = /^(`{3,}|~{3,})([^]*)$/;
const ITEM = /^(?:[-+*]|\d{1,9}[.)])(?=[ \t]|$)/;
/** Lines that start a block of their own, so they never continue a paragraph lazily. */
const INTERRUPTS = /^(?:`{3,}|~{3,}|<!--|>|#{1,6}(?:[ \t]|$)|(?:[-+*]|\d{1,9}[.)])(?:[ \t]|$)|(?:[-*_][ \t]*){3,}$)/;
const NOT_PARAGRAPH = /^(?:#{1,6}(?:[ \t]|$)|(?:[-*_][ \t]*){3,}$)/;

export type LineKind = "text" | "code" | "comment";

/**
 * What each markdown line is, by CommonMark's block rules: code (fenced, or
 * indented four columns past its list item), an HTML comment, or text. A fence
 * closes on a line of the same character, at least as long, with nothing else
 * on it, or when its list item ends; one that never closes runs to the end, so
 * whether a line is code depends only on the lines above it. Block quotes are
 * text: no marker line can start with `>`. In `lines` a lone CR ends a line.
 */
export function lineKinds(lines: readonly string[]): LineKind[] {
  const kinds: LineKind[] = [];
  const items: number[] = []; // the content column of each open list item, innermost last
  let fence: { ch: string; len: number; col: number } | null = null;
  let comment: number | null = null; // the content column of the list item an open comment is in
  let para = false; // the line before is paragraph text, which a less indented line can continue
  for (const s of lines) {
    let { at, col } = lead(s, 0, 0);
    const blank = at === s.length;
    if (fence !== null && (blank || col >= fence.col)) {
      kinds.push("code");
      if (!blank && col - fence.col <= 3 && closes(s.slice(at), fence.ch, fence.len)) fence = null;
      continue;
    }
    if (comment !== null && (blank || col >= comment)) {
      kinds.push("comment");
      if (s.includes("-->")) comment = null;
      continue;
    }
    // A fence or comment still open here ends with its list item.
    fence = null;
    comment = null;
    if (blank) {
      kinds.push("text");
      para = false;
      continue;
    }
    if (para && col < (items.at(-1) ?? 0) && !INTERRUPTS.test(s.slice(at))) {
      kinds.push("text");
      continue;
    }
    while (items.length > 0 && col < items[items.length - 1]) items.pop();
    let box = items.at(-1) ?? 0;
    let m: RegExpExecArray | null;
    while (col - box <= 3 && (m = ITEM.exec(s.slice(at))) !== null) {
      const end = col + m[0].length;
      const next = lead(s, at + m[0].length, end);
      box = next.at === s.length || next.col - end > 4 ? end + 1 : next.col;
      items.push(box);
      para = false;
      ({ at, col } = next);
    }
    const rest = s.slice(at);
    let f: RegExpExecArray | null;
    if (rest === "") {
      kinds.push("text");
      para = false;
    } else if (col - box >= 4) {
      kinds.push(para ? "text" : "code"); // indented code cannot interrupt a paragraph
    } else if ((f = FENCE.exec(rest)) !== null && !(f[1][0] === "`" && f[2].includes("`"))) {
      fence = { ch: f[1][0], len: f[1].length, col: box };
      kinds.push("code");
      para = false;
    } else if (rest.startsWith("<!--")) {
      if (!rest.includes("-->")) comment = box;
      kinds.push("comment");
      para = false;
    } else {
      kinds.push("text");
      para = !NOT_PARAGRAPH.test(rest);
    }
  }
  return kinds;
}

function closes(rest: string, ch: string, len: number): boolean {
  let n = 0;
  while (rest[n] === ch) n++;
  return n >= len && /^[ \t]*$/.test(rest.slice(n));
}

/** The kind of each of ah's lines, whose text may hold a lone CR: markdown ends a line there, so each takes its first piece's kind. */
function kindsOf(lines: readonly string[]): LineKind[] {
  const pieces: string[] = [];
  const first: number[] = [];
  for (const l of lines) {
    first.push(pieces.length);
    pieces.push(...l.split("\r"));
  }
  const kinds = lineKinds(pieces);
  return first.map((i) => kinds[i]);
}

/**
 * Line indexes of the managed block, or null when there is none. Throws on a
 * malformed block, and when ah's own begin marker is inside code with no
 * block outside it: that may be ah's block under a fence the user left open
 * above it, or an example, and a wrong guess either loses the user's text or
 * adds a second block.
 */
export function locateBlock(lines: readonly string[], file: string): { begin: number; end: number } | null {
  const kinds = kindsOf(lines);
  const begins = lines.flatMap((l, i) => (kinds[i] !== "code" && BEGIN_LINE.test(l) ? [i] : []));
  const ends = lines.flatMap((l, i) => (kinds[i] !== "code" && END_LINE.test(l) ? [i] : []));
  if (begins.length === 0 && ends.length === 0) {
    const hidden = lines.findIndex((l, i) => kinds[i] === "code" && l.trim() === BLOCK_BEGIN);
    if (hidden !== -1) {
      throw new BlockError(`${file} has ah's begin marker inside a code block (line ${hidden + 1}) and no block outside one. If it is ah's block, close the code fence above it; if it is an example, shorten its marker to <!-- ah:begin -->. Then re-run.`);
    }
    return null;
  }
  if (begins.length !== 1 || ends.length !== 1 || ends[0] < begins[0]) {
    throw new BlockError(`${file} has ${begins.length} ah:begin and ${ends.length} ah:end marker(s) outside code blocks; expected one of each, in that order. Fix the markers by hand (or delete both) and re-run.`);
  }
  return { begin: begins[0], end: ends[0] };
}

function locate(p: Parsed, file: string): { begin: number; end: number } | null {
  return locateBlock(p.lines.map((l) => l.text), file);
}

/** The lines strictly between the markers, or null when the file has no block. */
export function readBlock(text: string, file: string): string[] | null {
  const p = parse(text);
  const at = locate(p, file);
  return at ? p.lines.slice(at.begin + 1, at.end).map((l) => l.text) : null;
}

/** `text` reads back as a block holding `body`, and taking the block out gives `back`. */
function holds(text: string, body: readonly string[], file: string, back: string | null): boolean {
  try {
    const b = readBlock(text, file);
    return b !== null && b.length === body.length && b.every((l, i) => l === body[i]) && removeBlock(text, file).text === back;
  } catch (err) {
    if (err instanceof BlockError) return false;
    throw err;
  }
}

/**
 * Put `body` (lines, no markers) into the file's managed block: create the
 * file, add a block to it, or replace the existing block's lines.
 *
 * A new block goes after the user's text, trailing blank lines and all, behind
 * one blank line; or, with `where` "start", before it with one blank line
 * after. A last line without a line break gets one (CRLF after a CR of its
 * own, which an LF would swallow), and then the end marker has none, so
 * removeBlock knows to take the break out again. An existing empty file gets
 * the blank line too, so it is never mistaken for a file `ah init` created.
 * Every result is read back first: the block must be found with `body` in it
 * and removeBlock must give the original back. A file that ends inside a code
 * block that never closes fails that at the end, so its block goes at the
 * start.
 */
export function upsertBlock(original: string | null, body: readonly string[], file: string, where: "end" | "start" = "end"): BlockEdit {
  if (original === null) return { text: created(body), action: "created" };
  const p = parse(original);
  const at = locate(p, file);
  const ours = (texts: readonly string[]): Line[] => texts.map((text) => ({ text, eol: p.eol }));
  if (at && where === "start" && at.begin > 0) {
    // Move it: Codex reads only the first 32 KiB of a project's instructions.
    return { ...upsertBlock(removeBlock(original, file).text, body, file, "start"), action: "replaced" };
  }
  if (at) {
    const current = p.lines.slice(at.begin + 1, at.end);
    if (current.length === body.length && current.every((l, i) => l.text === body[i])) return { text: original, action: "unchanged" };
    const text = render(p.bom, [...p.lines.slice(0, at.begin + 1), ...ours(body), ...p.lines.slice(at.end)]);
    if (!holds(text, body, file, removeBlock(original, file).text)) throw new BlockError(`${file}: ah's new block would not read back from the file. Nothing was changed.`);
    return { text, action: "replaced" };
  }
  const block = ours([BLOCK_BEGIN, ...body, BLOCK_END]);
  const blank: Line = { text: "", eol: p.eol };
  const start = render(p.bom, [...block, blank, ...p.lines]);
  const user = [...p.lines];
  const last = user.at(-1);
  if (last !== undefined && last.eol === "") {
    user[user.length - 1] = { text: last.text, eol: last.text.endsWith("\r") ? "\r\n" : p.eol };
    block[block.length - 1] = { text: BLOCK_END, eol: "" };
  }
  const end = render(p.bom, [...user, blank, ...block]);
  const tries: [string, BlockAction][] = where === "end" ? [[end, "appended"], [start, "prepended"]] : [[start, "prepended"]];
  for (const [text, action] of tries) if (holds(text, body, file, original)) return { text, action };
  throw new BlockError(`${file}: ah's block would not read back from the file at its ${where === "end" ? "end or its start" : "start"}. Nothing was changed.`);
}

/**
 * Take the managed block out again with the blank line upsertBlock put beside
 * it: before a block further down, after a block at the top. A block after
 * that blank line whose end marker has no line break is one upsertBlock gave
 * the user's last line a break for, so the break comes off. The file is to be
 * deleted only when it is exactly what upsertBlock creates from nothing.
 */
export function removeBlock(original: string | null, file: string): BlockEdit {
  if (original === null) return { text: null, action: "absent" };
  const p = parse(original);
  const at = locate(p, file);
  if (!at) return { text: original, action: "absent" };
  if (at.begin === 0 && at.end === p.lines.length - 1 && original === created(p.lines.slice(1, -1).map((l) => l.text))) return { text: null, action: "removed" };
  let from = at.begin;
  let to = at.end + 1;
  if (from === 0) {
    if (p.lines[to]?.text === "") to++;
  } else if (p.lines[from - 1].text === "") from--;
  const lines = [...p.lines.slice(0, from), ...p.lines.slice(to)];
  const last = lines.at(-1);
  if (p.lines[at.end].eol === "" && from < at.begin && last !== undefined) lines[lines.length - 1] = { text: last.text, eol: "" };
  return { text: render(p.bom, lines), action: "removed" };
}

/** Bytes (UTF-8) from the start of the file to the end of the block's end marker, or null without a block. */
export function blockEndByte(text: string, file: string): number | null {
  const p = parse(text);
  const at = locate(p, file);
  if (!at) return null;
  return Buffer.byteLength(render(p.bom, p.lines.slice(0, at.end)) + p.lines[at.end].text, "utf8");
}
