/**
 * Where the guard's instructions go so each agent reads them.
 *
 * AGENTS.md at the project root gets the managed block. Claude Code
 * reads AGENTS.md only when there is no CLAUDE.md, .claude/CLAUDE.md or
 * CLAUDE.local.md at the project root or in any directory above it
 * (~/.claude/CLAUDE.md aside). When one of those exists, the same block goes
 * into the root's file, or into a new CLAUDE.md at the root when the only ones
 * are further up, unless the root's file is AGENTS.md itself or imports it
 * (`@AGENTS.md` beside it, `@../AGENTS.md` in .claude/CLAUDE.md). Importing
 * AGENTS.md wholesale would change what Claude Code reads beyond ah's few
 * lines, so ah never adds the import itself. A root file that git has as a
 * symlink but checked out as a plain file holding the link's target (Git for
 * Windows' default) is never written into: see rootTextLinks. When AGENTS.md
 * is one, Codex gets the block in an AGENTS.override.md made for that checkout
 * alone, and Claude Code in the root's CLAUDE.md, or else in a new
 * CLAUDE.local.md (see claudeMdState).
 */
import { realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { agentsBlockLines, AGENTS_BLOCK_BODY } from "./agents-md.ts";
import { readText } from "./files.ts";
import { symlinkCheckedOutAsText } from "./project.ts";
import { blockEndByte, readBlock, removeBlock, upsertBlock, type BlockEdit } from "./text-block.ts";

export interface InstructionEdit {
  path: string;
  original: string | null;
  edit: BlockEdit;
  why: string;
  /**
   * ah made the file to stand in for a text link (see rootTextLinks): it is
   * for this checkout alone and stays out of git. Set too when --remove
   * deletes such a file.
   */
  local?: boolean;
}

export const CLAUDE_MD_CANDIDATES = ["CLAUDE.md", join(".claude", "CLAUDE.md"), "CLAUDE.local.md"];

function same(a: string, b: string): boolean {
  try {
    return realpathSync(a) === realpathSync(b);
  } catch {
    return false;
  }
}

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

/**
 * An @-import as Claude Code reads one: the path runs to whitespace, `\ ` is
 * a space in it, and any other backslash ends it, so only `/` paths count,
 * which it follows on every OS.
 */
const IMPORT = /(?:^|\s)@((?:[^\s\\]|\\ )+)/g;

/**
 * `text`, the content of `file`, imports `agents`. Claude Code cuts a
 * `#fragment` off the path and resolves it against the directory of the file
 * it is in (a leading ~/ is the home directory), so `@AGENTS.md` in
 * .claude/CLAUDE.md is .claude/AGENTS.md; the root's is `@../AGENTS.md` there.
 */
export function importsAgentsMd(text: string, file: string, agents: string, home: string = homedir()): boolean {
  const want = resolve(agents);
  const names = (spec: string): boolean => {
    const p = spec.split("#")[0].replaceAll("\\ ", " ");
    if (!/^(?:\.\/|~\/|\/.|[\w.-])/.test(p)) return false;
    const t = p.trim();
    const abs = t.startsWith("~/") ? resolve(home, t.slice(2)) : resolve(dirname(file), t);
    return abs === want || same(abs, want);
  };
  return importText(text).some((t) => [...t.matchAll(IMPORT)].some((m) => names(m[1])));
}

/** A block quote, or a list item whose content starts `col` columns in. */
interface Box {
  /** null for a quote. */
  col: number | null;
  /** Item: its first line was blank, or a blank line has been in it since. */
  blank: boolean;
  /** No lazy line comes after its last line: in an item, code, a fence, a heading or a rule; in a quote, a blank line or code. */
  stop: boolean;
  /** Item: nothing has followed its first line yet. */
  first: boolean;
  /** Quote: its last line was a lazy one. */
  lazy: boolean;
}

/** A block Claude Code does not read for imports: HTML (of a comment, what is left once the comments are out), or a link reference definition. */
interface Skipped {
  /** What ends it; null for a blank line. */
  end: RegExp | null;
  /** The lines of an HTML comment block. */
  lines: string[] | null;
  /** It ends on the line it starts on. */
  closed: boolean;
}

const BLANK = /^[ \t]*$/;
const QUOTE = /^ {0,3}>[ \t]?/;
const HR = /^ {0,3}(?:(?:-[ \t]*){3,}|(?:_[ \t]*){3,}|(?:\*[ \t]*){3,})$/;
const SETEXT = /^ {0,3}(?:=+|-+)[ \t]*$/;
const HEADING = /^ {0,3}#{1,6}(?:\s|$)/;
/** A list's first item: marked wants text after the space, or nothing at all, after the marker. Later items need neither. */
const BULLET = /^( {0,3}(?:[*+-]|\d{1,9}[.)]))((?:[ \t].+)?)$/;
const BULLET_ANY = /^( {0,3}(?:[*+-]|\d{1,9}[.)]))((?:[ \t].*)?)$/;
const FENCE_OPEN = /^ {0,3}(`{3,}(?=[^`]*$)|~{3,})/;
const DEF = /^ {0,3}\[(?:\\.|[^[\]\\])+\]:/;
const BLOCK_TAGS = "address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|meta|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul";
const BLOCK_TAG = new RegExp(`^</?(?:${BLOCK_TAGS})(?:[\\s/>]|$)`, "i");
/** What ends a paragraph for marked's quote, which takes every other line lazily. */
const PARA_END = new RegExp(`^(?: {0,3}(?:#{1,6}(?:\\s|$)|>|\`{3,}[^\`]*$|~{3,}|(?:[*+-]|1[.)]) |(?:(?:-[ \\t]*){3,}|(?:_[ \\t]*){3,}|(?:\\*[ \\t]*){3,})$)|</?(?:${BLOCK_TAGS})(?: +|$|/?>)|<(?:script|pre|style|textarea|!--))`);
const LONE_TAG = /^(?:<[a-z][\w-]*(?:\s(?:[^<>"']|"[^"]*"|'[^']*')*)?\/?>|<\/[a-z][\w-]*\s*>)[ \t]*$/i;
const INLINE_HTML = /^(?:<!--(?:-?>|[\s\S]*?-->)|<\/?[a-z][\w:-]*(?:\s(?:[^<>"']|"[^"]*"|'[^']*')*)?\/?>|<\?[\s\S]*?\?>|<![a-z][^>]*>|<!\[CDATA\[[\s\S]*?\]\]>)/i;
const LINK = /^(!?)\[((?:\\.|[^[\]\\])*)\]\((?:\\.|[^()\\]|\([^()]*\))*\)/;

function width(s: string): number {
  return s.replace(/\t/g, "    ").search(/[^ ]/);
}

/** The HTML block `s` starts, if any; a tag alone on its line counts only where `lone`. */
function htmlStart(s: string, lone: boolean): Skipped | null {
  const t = /^ {0,3}(<.*)$/.exec(s)?.[1];
  if (t === undefined) return null;
  const block = (end: RegExp | null, from: number): Skipped => ({ end, lines: null, closed: end !== null && end.test(t.slice(from)) });
  const raw = /^<(script|pre|style|textarea)(?:[\s>]|$)/i.exec(t);
  if (raw !== null) return block(new RegExp(`</${raw[1]}>`, "i"), raw[0].length);
  if (t.startsWith("<!--")) return { end: /-->/, lines: [], closed: /^<!--(?:-?>|[\s\S]*?-->)/.test(t) };
  if (t.startsWith("<?")) return block(/\?>/, 2);
  if (t.startsWith("<![CDATA[")) return block(/\]\]>/, 9);
  if (/^<![a-z]/i.test(t)) return block(/>/, 2);
  return BLOCK_TAG.test(t) || (lone && LONE_TAG.test(t)) ? block(null, 0) : null;
}

/** `s` ends the paragraph above it. In a list item every line is tried as a new block. */
function interrupts(s: string, inItem: boolean): boolean {
  return BLANK.test(s) || HR.test(s) || HEADING.test(s) || /^ {0,3}>/.test(s) || FENCE_OPEN.test(s) || htmlStart(s, inItem) !== null || (inItem ? /^ {0,3}(?:[*+-]|\d{1,9}[.)])(?:[ \t]|$)/ : /^ {0,3}(?:[*+-]|1[.)]) /).test(s);
}

/** The line, indented less than an item's content at `col`, starts a fence, heading, HTML, item or rule, which ends the item. */
function endsItem(s: string, col: number): boolean {
  return new RegExp(`^ {0,${Math.min(3, col - 1)}}(?:\`\`\`|~~~|#|<(?:[a-z].*>|!--)|(?:[*+-]|\\d{1,9}[.)])(?:[ \\t]|$)|(?:(?:- *){3,}|(?:_ *){3,}|(?:\\* *){3,})$)`, "i").test(s);
}

/** The line, in an item at `col`, is one after which marked takes no lazy line. */
function stopsLazy(s: string, col: number): boolean {
  return width(s) >= 4 || new RegExp(`^ {0,${Math.min(3, col - 1)}}(?:\`\`\`|~~~|#|(?:(?:- *){3,}|(?:_ *){3,}|(?:\\* *){3,})$)`).test(s);
}

/** A paragraph's text as Claude Code reads it for imports: code spans, inline HTML, link targets and images out; an escaped character splits the text. */
function inline(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; ) {
    const rest = text.slice(i);
    const c = text[i];
    let m: RegExpExecArray | null;
    if (c === "\\" && /^\\[!-/:-@[-`{-~]/.test(rest)) {
      out += " ";
      i += 2;
    } else if (c === "`") {
      const run = /^`+/.exec(rest)![0];
      const close = new RegExp(`(?<!\`)${run}(?!\`)`, "g");
      close.lastIndex = run.length;
      const end = close.exec(rest);
      out += end === null ? run : " ";
      i += end === null ? run.length : end.index + run.length;
    } else if (c === "<" && (m = INLINE_HTML.exec(rest)) !== null) {
      out += " ";
      i += m[0].length;
    } else if ((c === "[" || c === "!") && (m = LINK.exec(rest)) !== null) {
      out += m[1] === "!" ? " " : ` ${inline(m[2])} `;
      i += m[0].length;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

/**
 * The text Claude Code looks for @-imports in. It lexes the file as Markdown
 * (marked, without GFM) and reads the text of paragraphs and headings, and of
 * an HTML comment block what is left once the comments are out. Fenced and
 * indented code, code spans, other HTML and front matter it skips. This
 * follows marked through block quotes and list items, lazy lines included,
 * though not into every way the two nest: a quote's lazy lines that marked
 * hands on to a list inside it can still part them. Elsewhere, where they
 * could part, less is read here, so the block goes in twice rather than nowhere.
 */
function importText(text: string): string[] {
  const out: string[] = [];
  const boxes: Box[] = [];
  let para: string[] | null = null;
  let fence: RegExp | null = null;
  let skip: Skipped | null = null;
  const flush = (): void => {
    if (para !== null) out.push(inline(para.join("\n")));
    para = null;
  };
  const endSkip = (): void => {
    if (skip?.lines) out.push(skip.lines.join("\n").replace(/<!--[\s\S]*?-->/g, ""));
    skip = null;
  };
  const body = text.replace(/^﻿/, "").replace(/^---\s*\n[\s\S]*?---\s*\n?/, "");
  for (const line of body.split(/\r\n|\r|\n/)) {
    let s = line;
    // A lazy line is outside a box it is still in. marked's quote takes one
    // that could carry on a paragraph, if its last line had text, and hands it
    // to the list or quote inside; a list item takes one that starts no block,
    // unless a blank line or a line that stops it came first.
    let lazy = false;
    let sibling = false;
    for (let n = 0; n < boxes.length; n++) {
      const b = boxes[n];
      const q = b.col === null ? QUOTE.exec(s) : null;
      const blank = BLANK.test(s);
      let inside = true;
      if (q !== null) {
        s = s.slice(q[0].length);
        b.stop = BLANK.test(s);
        b.lazy = false;
      } else if (b.col === null) {
        inside = lazy = !b.stop && !blank && !PARA_END.test(s) && (n + 1 < boxes.length || fence === null);
        // Lazy lines after quoted ones are lexed afresh, so HTML from the quoted lines ends there.
        if (inside && n + 1 === boxes.length && !b.lazy) skip = null;
        b.lazy = true;
      } else if (blank || width(s) >= b.col) {
        s = blank ? "" : s.replace(/\t/g, "    ").slice(b.col);
        // An item that starts blank ends at a blank line right after it.
        inside = !(blank && b.first && b.blank);
        b.stop = !blank && stopsLazy(s, b.col);
      } else {
        inside = lazy = !endsItem(s, b.col) && !b.blank && !b.stop;
        sibling = !inside && BULLET_ANY.test(s);
        b.stop = stopsLazy(s.replace(/\t/g, "    ").slice(b.col), b.col);
      }
      if (b.col !== null) {
        b.blank ||= blank;
        b.first = false;
      }
      if (!inside) {
        boxes.length = n;
        lazy = false;
        flush();
        fence = null;
        skip = null;
      }
    }
    const inner = boxes.at(-1);
    if (fence !== null) {
      if (!lazy && fence.test(s)) fence = null;
      // A quote whose last line is code takes no lazy line.
      if (inner?.col === null) inner.stop = true;
      continue;
    }
    if (skip !== null) {
      skip.lines?.push(s);
      if (skip.end === null ? BLANK.test(s) : skip.end.test(s)) endSkip();
      continue;
    }
    if (para !== null) {
      // A setext underline makes the paragraph a heading, which nothing carries on.
      const underline = !lazy && SETEXT.test(s);
      if (!underline && (width(s) >= 4 || !interrupts(s, lazy || (inner !== undefined && inner.col !== null)))) {
        para.push(s);
        continue;
      }
      if (underline) para.push(s);
      flush();
      if (underline) continue;
    }
    for (;;) {
      if (width(s) >= 4 || HR.test(s)) break;
      const q = QUOTE.exec(s);
      if (q !== null) {
        s = s.slice(q[0].length);
        boxes.push({ col: null, blank: false, stop: BLANK.test(s), first: false, lazy: false });
        continue;
      }
      const m = (sibling ? BULLET_ANY : BULLET).exec(s);
      sibling = false;
      if (m === null) break;
      // Where marked starts the item's content: a tab counts as text there, and 5+ spaces as one, then code.
      const empty = BLANK.test(m[2]);
      const w = m[2].search(/[^ ]/);
      const col = m[1].length + (empty || w > 4 ? 1 : w);
      const first = m[2].replace(/^\t+/, (t) => "   ".repeat(t.length));
      boxes.push({ col, blank: empty, stop: !empty && stopsLazy(first, col), first: true, lazy: false });
      s = empty ? "" : first.slice(col - m[1].length);
    }
    if (BLANK.test(s) || width(s) >= 4) {
      const b = boxes.at(-1);
      if (b?.col === null) b.stop = true;
      continue;
    }
    const f = FENCE_OPEN.exec(s);
    if (f !== null) {
      fence = new RegExp(`^ {0,3}${f[1]}[~\`]* *$`);
      continue;
    }
    skip = htmlStart(s, true) ?? (DEF.test(s) ? { end: null, lines: null, closed: false } : null);
    if (skip !== null) {
      skip.lines?.push(s);
      if (skip.closed) endSkip();
      continue;
    }
    if (HEADING.test(s)) out.push(inline(s));
    else if (!HR.test(s)) para = [s];
  }
  flush();
  return out;
}

export interface ClaudeMdFile {
  dir: string;
  path: string;
}

export interface TextLink {
  path: string;
  /** What git says it links to: all the checkout wrote into the file. */
  target: string;
}

export interface ClaudeMdState {
  /** CLAUDE.md-style files that exist at the root. */
  present: string[];
  /**
   * The file the block must go in, or null when Claude Code already reads
   * AGENTS.md, or when every file it could go in is one of `textLinks`.
   */
  target: string | null;
  reason: string;
  /**
   * Every CLAUDE.md-style file at the root and above it, nearest first. Any
   * one of them stops Claude Code reading AGENTS.md by itself.
   */
  suppressing: ClaudeMdFile[];
  /**
   * Files in `present` that git has as symlinks but that are checked out as
   * plain files holding the link's target (core.symlinks=false, Git for
   * Windows' default). Claude Code reads that one line, not the file it
   * names, so a CLAUDE.md linked to AGENTS.md still keeps AGENTS.md out.
   */
  textLinks: TextLink[];
}

/**
 * The instruction files at `root` that git has as symlinks but that are
 * checked out as plain files holding the link's target (core.symlinks=false,
 * Git for Windows' default). An agent reads that one line, not the file it
 * names, and git takes any edit for a new target, so ah writes into none of
 * them: a block an older ah left in one comes out.
 */
export function rootTextLinks(root: string): TextLink[] {
  return ["AGENTS.md", "AGENTS.override.md", ...CLAUDE_MD_CANDIDATES].flatMap((p) => {
    const path = join(root, p);
    const target = symlinkCheckedOutAsText(path);
    return target === null ? [] : [{ path, target }];
  });
}

/** `home` is the user's home directory, whose .claude/CLAUDE.md is user memory and does not count. */
export function claudeMdState(root: string, home: string = homedir()): ClaudeMdState {
  const agents = join(root, "AGENTS.md");
  const memory = join(resolve(home), ".claude", "CLAUDE.md");
  const suppressing: ClaudeMdFile[] = [];
  for (let dir = resolve(root); ; dir = dirname(dir)) {
    for (const c of CLAUDE_MD_CANDIDATES) {
      const path = join(dir, c);
      if (isFile(path) && path !== memory && !same(path, memory)) suppressing.push({ dir, path });
    }
    if (dirname(dir) === dir) break;
  }
  const present = CLAUDE_MD_CANDIDATES.map((p) => join(root, p)).filter((p) => suppressing.some((f) => f.path === resolve(p)));
  const textLinks = present.flatMap((path) => {
    const target = symlinkCheckedOutAsText(path);
    return target === null ? [] : [{ path, target }];
  });
  // A text-linked AGENTS.md holds no block, so neither reading nor importing it counts.
  const agentsLink = symlinkCheckedOutAsText(agents) !== null;
  const isLink = (p: string): boolean => textLinks.some((l) => l.path === p) || (agentsLink && same(p, agents));
  if (suppressing.length === 0) {
    if (!agentsLink) return { present, target: null, reason: "no CLAUDE.md, so Claude Code reads AGENTS.md itself (2.1.277 or later)", suppressing, textLinks };
    const target = join(root, "CLAUDE.local.md");
    return { present, target, reason: "AGENTS.md is a symlink checked out as plain text, which ah does not write into; the block goes in a new CLAUDE.local.md, which Claude Code reads in its place", suppressing, textLinks };
  }
  if (present.length === 0) {
    const target = join(root, "CLAUDE.md");
    return { present, target, reason: `${suppressing[0].path} is above the project, so Claude Code does not read AGENTS.md; the block goes in a new CLAUDE.md`, suppressing, textLinks };
  }
  if (!agentsLink) {
    for (const p of present.filter((p) => !isLink(p))) {
      if (same(p, agents)) return { present, target: null, reason: `${rel(root, p)} is AGENTS.md`, suppressing, textLinks };
      if (importsAgentsMd(readText(p).text ?? "", p, agents, home)) return { present, target: null, reason: `${rel(root, p)} imports AGENTS.md`, suppressing, textLinks };
    }
  }
  const links = present.filter(isLink);
  if (links.length > 0) {
    // Git takes any edit to a text link for a new link target, so the block
    // goes beside it, in CLAUDE.local.md if it can: Claude Code reads that
    // alongside CLAUDE.md, and it is meant to stay out of git, like the broken
    // checkout it makes up for. A block in a committed file would also reach
    // checkouts whose link works, where Claude Code reads AGENTS.md already.
    const safe = [join(root, "CLAUDE.local.md"), join(root, ".claude", "CLAUDE.md"), join(root, "CLAUDE.md")].find((p) => !isLink(p)) ?? null;
    const why = `${links.map((p) => rel(root, p)).join(" and ")} ${links.length === 1 ? "is a symlink" : "are symlinks"} checked out as plain text, which ah does not write into`;
    return { present, target: safe, reason: safe === null ? why : `${why}; the block goes in ${rel(root, safe)}, which Claude Code reads too`, suppressing, textLinks };
  }
  return { present, target: present[0], reason: `${rel(root, present[0])} exists, so Claude Code does not read AGENTS.md; the block goes there too`, suppressing, textLinks };
}

function rel(root: string, p: string): string {
  const r = relative(root, p);
  return r === "" || r === ".." || r.startsWith(`..${sep}`) || isAbsolute(r) ? p : r;
}

/** Codex reads at most this many bytes of a project's AGENTS.md files, root first (project_doc_max_bytes). */
export const CODEX_DOC_BUDGET = 32768;

/** Upsert the block; for Codex, move it to the top when the end of the file is past Codex's read budget. */
function placeBlock(original: string | null, file: string, codex: boolean): { edit: BlockEdit; note?: string } {
  const atEnd = upsertBlock(original, AGENTS_BLOCK_BODY, file);
  if (!codex || atEnd.text === null) return { edit: atEnd };
  const end = blockEndByte(atEnd.text, file);
  if (end === null || end <= CODEX_DOC_BUDGET) return { edit: atEnd };
  return { edit: upsertBlock(original, AGENTS_BLOCK_BODY, file, "start"), note: `at the top of the file: Codex reads only the first ${CODEX_DOC_BUDGET / 1024} KiB` };
}

const UNLINKED = "a symlink checked out as plain text: ah's block comes out, so it holds just the link's target again";

/**
 * Take a block an older ah wrote out of a text link. When the rest is the
 * link's target but for line breaks (ah once put one after it), the file gets
 * the target's exact bytes back, so git sees the link it has.
 */
function unblockLink(l: TextLink, original: string | null): BlockEdit {
  const edit = removeBlock(original, l.path);
  const rest = edit.text?.trimEnd() ?? "";
  return edit.action === "removed" && (rest === "" || rest === l.target.trimEnd()) ? { text: l.target, action: "removed" } : edit;
}

/** The file holds nothing but ah's block, or is not there yet: ah made it. */
function ahsOwn(text: string | null, file: string): boolean {
  return text === null || removeBlock(text, file).text === null;
}

/**
 * The block edits for `ah init` (or `--remove`) with `agents`. On remove,
 * `keep` names the agents that stay wired, and a block one of them reads stays.
 */
export function planInstructions(root: string, agents: readonly string[], remove: boolean, keep: readonly string[] = []): InstructionEdit[] {
  if (remove) return planRemoval(root, agents, keep);
  const out: InstructionEdit[] = [];
  const codex = agents.includes("codex");
  const agentsPath = join(root, "AGENTS.md");
  const overridePath = join(root, "AGENTS.override.md");
  const links = rootTextLinks(root);
  const agentsLink = links.find((l) => l.path === agentsPath);
  const overrideLink = links.find((l) => l.path === overridePath);
  if (agentsLink === undefined) {
    const a = readText(agentsPath).text;
    const placed = placeBlock(a, agentsPath, codex);
    out.push({ path: agentsPath, original: a, edit: placed.edit, why: ["read by Codex, and by Claude Code when there is no CLAUDE.md", placed.note].filter(Boolean).join("; ") });
  } else {
    const a = readText(agentsPath).text;
    const edit = unblockLink(agentsLink, a);
    if (edit.action === "removed") out.push({ path: agentsPath, original: a, edit, why: UNLINKED });
  }
  if (codex && overrideLink !== undefined) {
    // Codex reads the override in place of AGENTS.md, so no file ah may write reaches it.
    const o = readText(overridePath).text;
    const edit = unblockLink(overrideLink, o);
    const removed = edit.action === "removed";
    const why = "AGENTS.override.md is a symlink checked out as plain text, which ah does not write into, and Codex reads it in place of AGENTS.md, so Codex gets no block here; check it out as a real symlink (git config core.symlinks true, which Windows allows in Developer Mode, then git checkout -- AGENTS.override.md) and re-run `ah init`";
    out.push({ path: overridePath, original: o, edit: removed ? edit : { text: o, action: "unchanged" }, why: removed ? `${UNLINKED}; ${why}` : why });
  } else if (codex && !same(overridePath, agentsPath)) {
    const o = readText(overridePath).text;
    if (o !== null || agentsLink !== undefined) {
      const placed = placeBlock(o, overridePath, true);
      const why =
        o === null
          ? "AGENTS.md is a symlink checked out as plain text, which ah does not write into, and Codex reads AGENTS.override.md in its place; this one is for this checkout alone, so it stays out of git"
          : "Codex reads AGENTS.override.md instead of AGENTS.md in this directory";
      const local = agentsLink !== undefined && ahsOwn(o, overridePath);
      out.push({ path: overridePath, original: o, edit: placed.edit, why: [why, placed.note].filter(Boolean).join("; "), ...(local ? { local } : {}) });
    }
  }
  if (agents.includes("claude")) {
    const s = claudeMdState(root);
    if (s.target !== null) {
      const t = readText(s.target).text;
      // A CLAUDE.local.md that stands in for a text link; one of the user's own is theirs to keep or commit.
      const local = links.length > 0 && s.target === join(root, "CLAUDE.local.md") && ahsOwn(t, s.target);
      out.push({ path: s.target, original: t, edit: upsertBlock(t, AGENTS_BLOCK_BODY, s.target), why: s.reason, ...(local ? { local } : {}) });
    }
    for (const l of s.textLinks) {
      const t = readText(l.path).text;
      const edit = unblockLink(l, t);
      if (edit.action === "removed") out.push({ path: l.path, original: t, edit, why: UNLINKED });
    }
  }
  return out;
}

/**
 * AGENTS.md is every agent's file; AGENTS.override.md is Codex's and the
 * CLAUDE.md-style files are Claude Code's, so removing one agent leaves the
 * other's files alone.
 */
function planRemoval(root: string, agents: readonly string[], keep: readonly string[]): InstructionEdit[] {
  const out: InstructionEdit[] = [];
  const agentsPath = join(root, "AGENTS.md");
  const overridePath = join(root, "AGENTS.override.md");
  const links = rootTextLinks(root);
  const take = (path: string, why: string): void => {
    const l = links.find((x) => x.path === path);
    const t = readText(path).text;
    const edit = l !== undefined ? unblockLink(l, t) : removeBlock(t, path);
    if (edit.action === "absent") return;
    const local = edit.text === null && (path === overridePath || path === join(root, "CLAUDE.local.md"));
    out.push({ path, original: t, edit, why: l !== undefined ? UNLINKED : why, ...(local ? { local } : {}) });
  };
  const drops = (agent: string): boolean => agents.includes(agent) && !keep.includes(agent);
  // Nobody reads a block in a text link, so it comes out whoever stays.
  const stillRead = keep.includes("codex") || (keep.includes("claude") && claudeMdState(root).target === null);
  if (!stillRead || links.some((l) => l.path === agentsPath)) take(agentsPath, "ah's block");
  if (drops("codex") && !same(overridePath, agentsPath)) take(overridePath, "ah's block");
  if (drops("claude")) for (const c of CLAUDE_MD_CANDIDATES.map((p) => join(root, p))) if (!same(c, agentsPath)) take(c, "ah's block for Claude Code");
  return out;
}

/** The block in `text` matches the current body. */
export function blockIsCurrent(text: string | null, file: string): "current" | "stale" | "missing" {
  if (text === null) return "missing";
  const b = readBlock(text, file);
  if (b === null) return "missing";
  const want = agentsBlockLines().slice(1, -1);
  return b.length === want.length && b.every((l, i) => l === want[i]) ? "current" : "stale";
}
