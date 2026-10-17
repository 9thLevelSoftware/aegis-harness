/**
 * A block of text that `ah init` owns inside a file somebody else owns
 * (AGENTS.md, CLAUDE.md). Everything outside the markers is the user's and is
 * returned byte for byte; only the lines between the markers are rewritten.
 * The file's line endings and byte-order mark are kept.
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

interface Split {
  bom: string;
  eol: "\n" | "\r\n";
  lines: string[];
  /** The text ended with a line break. */
  trailing: boolean;
}

function split(text: string): Split {
  const bom = text.startsWith("﻿") ? "﻿" : "";
  const body = bom ? text.slice(1) : text;
  const crlf = (body.match(/\r\n/g) ?? []).length;
  const lf = (body.match(/(?<!\r)\n/g) ?? []).length;
  const eol = crlf > lf ? "\r\n" : "\n";
  const trailing = /\r?\n$/.test(body);
  const lines = body === "" ? [] : body.replace(/\r?\n$/, "").split(/\r?\n/);
  return { bom, eol, lines, trailing };
}

function join(s: Split, lines: string[], trailing = s.trailing): string {
  if (lines.length === 0) return s.bom;
  return s.bom + lines.join(s.eol) + (trailing ? s.eol : "");
}

/** Line indexes of the managed block, or null when there is none. Throws on a malformed block. */
export function locateBlock(lines: readonly string[], file: string): { begin: number; end: number } | null {
  const begins = lines.flatMap((l, i) => (BEGIN_LINE.test(l) ? [i] : []));
  const ends = lines.flatMap((l, i) => (END_LINE.test(l) ? [i] : []));
  if (begins.length === 0 && ends.length === 0) return null;
  if (begins.length !== 1 || ends.length !== 1 || ends[0] < begins[0]) {
    throw new BlockError(`${file} has ${begins.length} ah:begin and ${ends.length} ah:end marker(s); expected one of each, in that order. Fix the markers by hand (or delete both) and re-run.`);
  }
  return { begin: begins[0], end: ends[0] };
}

/** The lines strictly between the markers, or null when the file has no block. */
export function readBlock(text: string, file: string): string[] | null {
  const s = split(text);
  const at = locateBlock(s.lines, file);
  return at ? s.lines.slice(at.begin + 1, at.end) : null;
}

/**
 * Put `body` (lines, no markers) into the file's managed block: create the
 * file, append a block to it, or replace the existing block's lines.
 */
export function upsertBlock(original: string | null, body: readonly string[], file: string, where: "end" | "start" = "end"): BlockEdit {
  const block = [BLOCK_BEGIN, ...body, BLOCK_END];
  if (original === null) return { text: block.join("\n") + "\n", action: "created" };
  const s = split(original);
  const at = locateBlock(s.lines, file);
  if (at && where === "start" && at.begin > 0) {
    // Move it: Codex reads only the first 32 KiB of a project's instructions.
    const without = removeBlock(original, file).text ?? "";
    return { ...upsertBlock(without === "" ? null : without, body, file, "start"), action: "replaced" };
  }
  if (!at && where === "start") {
    const lines = [...block, ...(s.lines.length > 0 ? ["", ...s.lines] : [])];
    return { text: join(s, lines, s.lines.length > 0 ? s.trailing : true), action: s.lines.length > 0 ? "prepended" : "created" };
  }
  if (at) {
    const current = s.lines.slice(at.begin, at.end + 1);
    const next = [s.lines[at.begin], ...body, s.lines[at.end]];
    if (current.length === next.length && current.every((l, i) => l === next[i])) return { text: original, action: "unchanged" };
    const lines = [...s.lines.slice(0, at.begin), ...next, ...s.lines.slice(at.end + 1)];
    return { text: join(s, lines), action: "replaced" };
  }
  const lines = [...s.lines];
  while (lines.length > 0 && lines[lines.length - 1].trim() === "") lines.pop();
  if (lines.length > 0) lines.push("");
  lines.push(...block);
  return { text: join(s, lines, true), action: lines.length === block.length ? "created" : "appended" };
}

/** Take the managed block out again, with the blank separator line `upsertBlock` added before it. */
export function removeBlock(original: string | null, file: string): BlockEdit {
  if (original === null) return { text: null, action: "absent" };
  const s = split(original);
  const at = locateBlock(s.lines, file);
  if (!at) return { text: original, action: "absent" };
  let from = at.begin;
  if (from > 0 && s.lines[from - 1].trim() === "" && at.end === s.lines.length - 1) from--;
  const lines = [...s.lines.slice(0, from), ...s.lines.slice(at.end + 1)];
  if (lines.every((l) => l.trim() === "")) return { text: null, action: "removed" };
  return { text: join(s, lines), action: "removed" };
}

/** Bytes (UTF-8) from the start of the file to the end of the block's end marker, or null without a block. */
export function blockEndByte(text: string, file: string): number | null {
  const s = split(text);
  const at = locateBlock(s.lines, file);
  if (!at) return null;
  return Buffer.byteLength(s.bom + s.lines.slice(0, at.end + 1).join(s.eol), "utf8");
}
