/**
 * Where the guard's instructions go so each agent reads them.
 *
 * AGENTS.md at the project root always gets the managed block. Claude Code
 * reads AGENTS.md only when the project has no CLAUDE.md, .claude/CLAUDE.md
 * or CLAUDE.local.md, so when one of those exists and neither is AGENTS.md
 * itself nor imports it (`@AGENTS.md`), the same block goes into that file too.
 * Importing AGENTS.md wholesale would change what Claude Code reads beyond
 * ah's few lines, so ah never adds the import itself.
 */
import { realpathSync } from "node:fs";
import { join } from "node:path";
import { agentsBlockLines, AGENTS_BLOCK_BODY } from "./agents-md.ts";
import { readText } from "./files.ts";
import { blockEndByte, readBlock, removeBlock, upsertBlock, type BlockEdit } from "./text-block.ts";

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

/** A line that imports AGENTS.md (`@AGENTS.md`, `@./AGENTS.md`), outside fenced code. */
export function importsAgentsMd(text: string): boolean {
  let fenced = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*(```|~~~)/.test(line)) {
      fenced = !fenced;
      continue;
    }
    if (!fenced && /(^|\s)@(\.\/)?AGENTS\.md(\s|$)/.test(line)) return true;
  }
  return false;
}

export interface ClaudeMdState {
  /** CLAUDE.md-style files that exist at the root. */
  present: string[];
  /** The file the block must go in, or null when Claude Code already reads AGENTS.md. */
  target: string | null;
  reason: string;
}

export function claudeMdState(root: string): ClaudeMdState {
  const agents = join(root, "AGENTS.md");
  const present = CLAUDE_MD_CANDIDATES.map((p) => join(root, p)).filter((p) => readText(p).text !== null);
  if (present.length === 0) return { present, target: null, reason: "no CLAUDE.md, so Claude Code reads AGENTS.md itself (2.1.277 or later)" };
  for (const p of present) {
    if (same(p, agents)) return { present, target: null, reason: `${rel(root, p)} is AGENTS.md` };
    const t = readText(p).text ?? "";
    if (importsAgentsMd(t)) return { present, target: null, reason: `${rel(root, p)} imports @AGENTS.md` };
  }
  return { present, target: present[0], reason: `${rel(root, present[0])} exists, so Claude Code does not read AGENTS.md; the block goes there too` };
}

function rel(root: string, p: string): string {
  return p.startsWith(root) ? p.slice(root.length + 1) : p;
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

export function planInstructions(root: string, agents: readonly string[], remove: boolean): InstructionEdit[] {
  const out: InstructionEdit[] = [];
  const codex = agents.includes("codex");
  const agentsPath = join(root, "AGENTS.md");
  const overridePath = join(root, "AGENTS.override.md");
  const a = readText(agentsPath).text;
  if (remove) out.push({ path: agentsPath, original: a, edit: removeBlock(a, agentsPath), why: "ah's block" });
  else {
    const placed = placeBlock(a, agentsPath, codex);
    out.push({ path: agentsPath, original: a, edit: placed.edit, why: ["read by Codex, and by Claude Code when there is no CLAUDE.md", placed.note].filter(Boolean).join("; ") });
  }
  const o = readText(overridePath).text;
  if (o !== null && !same(overridePath, agentsPath)) {
    if (remove) {
      const e = removeBlock(o, overridePath);
      if (e.action !== "absent") out.push({ path: overridePath, original: o, edit: e, why: "ah's block" });
    } else if (codex) {
      const placed = placeBlock(o, overridePath, true);
      out.push({ path: overridePath, original: o, edit: placed.edit, why: ["Codex reads AGENTS.override.md instead of AGENTS.md in this directory", placed.note].filter(Boolean).join("; ") });
    }
  }
  if (remove) {
    for (const c of CLAUDE_MD_CANDIDATES.map((p) => join(root, p))) {
      if (same(c, agentsPath)) continue;
      const t = readText(c).text;
      if (t === null) continue;
      const e = removeBlock(t, c);
      if (e.action !== "absent") out.push({ path: c, original: t, edit: e, why: "ah's block for Claude Code" });
    }
    return out;
  }
  if (agents.includes("claude")) {
    const s = claudeMdState(root);
    if (s.target !== null) {
      const t = readText(s.target).text;
      out.push({ path: s.target, original: t, edit: upsertBlock(t, AGENTS_BLOCK_BODY, s.target), why: s.reason });
    }
  }
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
