/**
 * A block of text that `ah init` owns inside a file somebody else owns
 * (AGENTS.md, CLAUDE.md). Everything outside the markers is the user's and is
 * returned byte for byte, each line with its own line ending; only the lines
 * between the markers are rewritten, and the lines ah adds take the file's
 * usual ending. The byte-order mark is kept. Marker lines inside fenced code
 * are the user's examples, not ah's block. Removing the block undoes exactly
 * what adding it did, without remembering anything: see upsertBlock.
 */

/** `<!-- ah:begin ... -->` on a line of its own; anything after `ah:begin` is free text. */
const BEGIN_LINE = /^[ \t]*<!--[ \t]*ah:begin\b[^\n]*-->[ \t]*$/;
const END_LINE = /^[ \t]*<!--[ \t]*ah:end\b[^\n]*-->[ \t]*$/;

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

/** Three or more backticks or tildes; the rest of the line is the info string. */
const FENCE = /^[ \t]*(`{3,}|~{3,})(.*)$/;

/**
 * Which lines are fenced code, fences included, by CommonMark's rule: a fence
 * closes on a line of the same character, at least as long, with nothing else
 * on it. Indentation is not limited to three spaces, since a fence nested in a
 * list item sits deeper. A fence that never closes runs to the end of the text
 * when `unclosedRunsToEnd`; otherwise it is text, so that a stray fence cannot
 * hide ah's block below it and make every run append another one.
 */
export function fencedLines(lines: readonly string[], unclosedRunsToEnd: boolean): boolean[] {
  const out = lines.map(() => false);
  for (let i = 0; i < lines.length; i++) {
    const open = FENCE.exec(lines[i]);
    if (!open || (open[1][0] === "`" && open[2].includes("`"))) continue;
    const close = new RegExp(`^[ \\t]*${open[1][0]}{${open[1].length},}[ \\t]*$`);
    let j = i + 1;
    while (j < lines.length && !close.test(lines[j])) j++;
    if (j === lines.length && !unclosedRunsToEnd) continue;
    for (let k = i; k <= j && k < lines.length; k++) out[k] = true;
    i = j;
  }
  return out;
}

/** Line indexes of the managed block, or null when there is none. Throws on a malformed block. */
export function locateBlock(lines: readonly string[], file: string): { begin: number; end: number } | null {
  const code = fencedLines(lines, false);
  const begins = lines.flatMap((l, i) => (!code[i] && BEGIN_LINE.test(l) ? [i] : []));
  const ends = lines.flatMap((l, i) => (!code[i] && END_LINE.test(l) ? [i] : []));
  if (begins.length === 0 && ends.length === 0) return null;
  if (begins.length !== 1 || ends.length !== 1 || ends[0] < begins[0]) {
    throw new BlockError(`${file} has ${begins.length} ah:begin and ${ends.length} ah:end marker(s) outside fenced code; expected one of each, in that order. Fix the markers by hand (or delete both) and re-run.`);
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

/**
 * Put `body` (lines, no markers) into the file's managed block: create the
 * file, add a block to it, or replace the existing block's lines.
 *
 * A new block goes after the user's text, trailing blank lines and all, behind
 * one blank line; or, with `where` "start", before it with one blank line
 * after. A last line without a line break gets one, and then the end marker
 * has none, so removeBlock knows to take the break out again. An existing
 * empty file gets the blank line too, so it is never mistaken for a file
 * `ah init` created.
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
    return { text: render(p.bom, [...p.lines.slice(0, at.begin + 1), ...ours(body), ...p.lines.slice(at.end)]), action: "replaced" };
  }
  const block = ours([BLOCK_BEGIN, ...body, BLOCK_END]);
  const blank: Line = { text: "", eol: p.eol };
  if (where === "start") return { text: render(p.bom, [...block, blank, ...p.lines]), action: "prepended" };
  const user = [...p.lines];
  const last = user.at(-1);
  if (last !== undefined && last.eol === "") {
    user[user.length - 1] = { text: last.text, eol: p.eol };
    block[block.length - 1] = { text: BLOCK_END, eol: "" };
  }
  return { text: render(p.bom, [...user, blank, ...block]), action: "appended" };
}

/**
 * Take the managed block out again with the blank line upsertBlock put beside
 * it: before a block further down, after a block at the top. An end marker
 * with no line break means upsertBlock gave the user's last line one, so it
 * comes off. The file is to be deleted only when it is exactly what
 * upsertBlock creates from nothing.
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
  if (p.lines[at.end].eol === "" && last !== undefined) lines[lines.length - 1] = { text: last.text, eol: "" };
  return { text: render(p.bom, lines), action: "removed" };
}

/** Bytes (UTF-8) from the start of the file to the end of the block's end marker, or null without a block. */
export function blockEndByte(text: string, file: string): number | null {
  const p = parse(text);
  const at = locate(p, file);
  if (!at) return null;
  return Buffer.byteLength(render(p.bom, p.lines.slice(0, at.end)) + p.lines[at.end].text, "utf8");
}
