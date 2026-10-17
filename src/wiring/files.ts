/**
 * Reading and writing the files `ah init` touches without damaging them:
 * JSON keeps its key order, indentation and line endings; a write goes to a
 * temporary file and is renamed into place; a symlinked file (dotfile repos
 * link ~/.claude/settings.json) is written through to its target; the
 * target's permission bits are kept.
 */
import { chmodSync, lstatSync, mkdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export interface TextFile {
  path: string;
  /** null when the file does not exist. */
  text: string | null;
}

export function readText(path: string): TextFile {
  try {
    return { path, text: readFileSync(path, "utf8") };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT" || (err as NodeJS.ErrnoException).code === "ENOTDIR") return { path, text: null };
    throw err;
  }
}

export interface JsonStyle {
  indent: string | number;
  eol: "\n" | "\r\n";
  bom: boolean;
}

export type JsonRead =
  | { ok: true; exists: false; style: JsonStyle }
  | { ok: true; exists: true; value: unknown; style: JsonStyle; text: string }
  | { ok: false; exists: true; error: string; text: string };

const DEFAULT_STYLE: JsonStyle = { indent: 2, eol: "\n", bom: false };

export function detectStyle(text: string): JsonStyle {
  const bom = text.startsWith("﻿");
  const crlf = (text.match(/\r\n/g) ?? []).length;
  const lf = (text.match(/(?<!\r)\n/g) ?? []).length;
  const indentMatch = /\n([ \t]+)\S/.exec(text);
  const indent = indentMatch ? (indentMatch[1].startsWith("\t") ? "\t" : indentMatch[1].length) : 2;
  return { indent, eol: crlf > lf ? "\r\n" : "\n", bom };
}

/**
 * Parse a JSON settings file. An empty or whitespace-only file counts as `{}`.
 * Anything else that is not plain JSON (comments, trailing commas) is an
 * error: `ah` will not rewrite a file it cannot read back exactly.
 */
export function readJson(path: string): JsonRead {
  const f = readText(path);
  if (f.text === null) return { ok: true, exists: false, style: DEFAULT_STYLE };
  const body = f.text.replace(/^﻿/, "");
  if (body.trim() === "") return { ok: true, exists: true, value: {}, style: detectStyle(f.text), text: f.text };
  try {
    return { ok: true, exists: true, value: JSON.parse(body), style: detectStyle(f.text), text: f.text };
  } catch (err) {
    return { ok: false, exists: true, error: (err as Error).message, text: f.text };
  }
}

export function formatJson(value: unknown, style: JsonStyle): string {
  const body = JSON.stringify(value, null, style.indent) + "\n";
  return (style.bom ? "﻿" : "") + (style.eol === "\r\n" ? body.replace(/\n/g, "\r\n") : body);
}

/** The file a write to `path` should land in: the symlink's target when `path` is a symlink. */
export function writeTarget(path: string): string {
  let link = false;
  try {
    link = lstatSync(path).isSymbolicLink();
  } catch {
    return path; // missing: write a new file at `path`
  }
  if (!link) return path;
  try {
    return realpathSync(path);
  } catch {
    throw new Error(`${path} is a symlink to a file that does not exist; fix or remove the link and re-run`);
  }
}

/** Write `text` to `path` atomically, creating parent directories, keeping the old file's mode. */
export function writeAtomic(path: string, text: string): void {
  const target = writeTarget(path);
  mkdirSync(dirname(target), { recursive: true });
  let mode: number | undefined;
  try {
    mode = statSync(target).mode & 0o777;
  } catch {
    mode = undefined;
  }
  const tmp = join(dirname(target), `.${baseName(target)}.ah-${process.pid}.tmp`);
  try {
    writeFileSync(tmp, text, mode === undefined ? undefined : { mode });
    if (mode !== undefined) chmodSync(tmp, mode);
    renameSync(tmp, target);
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
}

/**
 * Delete a file `ah init --remove` emptied. A symlink is never deleted, and
 * neither is its target: the link belongs to somebody's dotfiles, so the
 * target is emptied instead.
 */
export function removeFile(path: string): void {
  let link: boolean;
  try {
    link = lstatSync(path).isSymbolicLink();
  } catch {
    return;
  }
  if (link) writeAtomic(path, "");
  else unlinkSync(path);
}

function baseName(p: string): string {
  return p.split(/[\\/]/).pop() ?? p;
}
