/**
 * Where the guard's instructions go so each agent reads them.
 *
 * AGENTS.md at the project root always gets the managed block. Claude Code
 * reads AGENTS.md only when there is no CLAUDE.md, .claude/CLAUDE.md or
 * CLAUDE.local.md at the project root or in any directory above it
 * (~/.claude/CLAUDE.md aside). When one of those exists, the same block goes
 * into the root's file, or into a new CLAUDE.md at the root when the only ones
 * are further up, unless the root's file is AGENTS.md itself or imports it
 * (`@AGENTS.md`). Importing AGENTS.md wholesale would change what Claude Code
 * reads beyond ah's few lines, so ah never adds the import itself.
 */
import { realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { agentsBlockLines, AGENTS_BLOCK_BODY } from "./agents-md.ts";
import { readText } from "./files.ts";
import { blockEndByte, lineKinds, readBlock, removeBlock, upsertBlock, type BlockEdit } from "./text-block.ts";

export interface InstructionEdit {
  path: string;
  original: string | null;
  edit: BlockEdit;
  why: string;
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
 * A line that imports AGENTS.md (`@AGENTS.md`, `@./AGENTS.md`), read as
 * markdown: no byte-order mark, a lone CR ends a line, and an import in code,
 * an HTML comment or a block quote does not count. Claude Code skips code; a
 * missed import only puts the block in CLAUDE.md as well, so the doubtful
 * places do not count either.
 */
export function importsAgentsMd(text: string): boolean {
  const lines = text.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/);
  const kinds = lineKinds(lines);
  return lines.some((l, i) => kinds[i] === "text" && !/^[ \t]*(?:(?:[-+*]|\d{1,9}[.)])[ \t]+)*>/.test(l) && /(^|\s)@(\.\/)?AGENTS\.md(\s|$)/.test(l));
}

export interface ClaudeMdFile {
  dir: string;
  path: string;
}

export interface ClaudeMdState {
  /** CLAUDE.md-style files that exist at the root. */
  present: string[];
  /** The file the block must go in, or null when Claude Code already reads AGENTS.md. */
  target: string | null;
  reason: string;
  /**
   * Every CLAUDE.md-style file at the root and above it, nearest first. Any
   * one of them stops Claude Code reading AGENTS.md by itself.
   */
  suppressing: ClaudeMdFile[];
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
  if (suppressing.length === 0) return { present, target: null, reason: "no CLAUDE.md, so Claude Code reads AGENTS.md itself (2.1.277 or later)", suppressing };
  if (present.length === 0) {
    const target = join(root, "CLAUDE.md");
    return { present, target, reason: `${suppressing[0].path} is above the project, so Claude Code does not read AGENTS.md; the block goes in a new CLAUDE.md`, suppressing };
  }
  for (const p of present) {
    if (same(p, agents)) return { present, target: null, reason: `${rel(root, p)} is AGENTS.md`, suppressing };
    if (importsAgentsMd(readText(p).text ?? "")) return { present, target: null, reason: `${rel(root, p)} imports @AGENTS.md`, suppressing };
  }
  return { present, target: present[0], reason: `${rel(root, present[0])} exists, so Claude Code does not read AGENTS.md; the block goes there too`, suppressing };
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
  if (atEnd.action === "prepended") return { edit: atEnd, note: "at the top of the file: it ends inside a code block that is never closed" };
  if (!codex || atEnd.text === null) return { edit: atEnd };
  const end = blockEndByte(atEnd.text, file);
  if (end === null || end <= CODEX_DOC_BUDGET) return { edit: atEnd };
  return { edit: upsertBlock(original, AGENTS_BLOCK_BODY, file, "start"), note: `at the top of the file: Codex reads only the first ${CODEX_DOC_BUDGET / 1024} KiB` };
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
  const a = readText(agentsPath).text;
  const placed = placeBlock(a, agentsPath, codex);
  out.push({ path: agentsPath, original: a, edit: placed.edit, why: ["read by Codex, and by Claude Code when there is no CLAUDE.md", placed.note].filter(Boolean).join("; ") });
  const o = readText(overridePath).text;
  if (codex && o !== null && !same(overridePath, agentsPath)) {
    const placed = placeBlock(o, overridePath, true);
    out.push({ path: overridePath, original: o, edit: placed.edit, why: ["Codex reads AGENTS.override.md instead of AGENTS.md in this directory", placed.note].filter(Boolean).join("; ") });
  }
  if (agents.includes("claude")) {
    const s = claudeMdState(root);
    if (s.target !== null) {
      const t = readText(s.target).text;
      const placed = placeBlock(t, s.target, false);
      out.push({ path: s.target, original: t, edit: placed.edit, why: [s.reason, placed.note].filter(Boolean).join("; ") });
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
  const take = (path: string, why: string): void => {
    const t = readText(path).text;
    const edit = removeBlock(t, path);
    if (edit.action !== "absent") out.push({ path, original: t, edit, why });
  };
  const drops = (agent: string): boolean => agents.includes(agent) && !keep.includes(agent);
  const stillRead = keep.includes("codex") || (keep.includes("claude") && claudeMdState(root).target === null);
  if (!stillRead) take(agentsPath, "ah's block");
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
