/**
 * Facts about the project `ah init` wires and the machine it runs on: where
 * the git repository starts, whether git would commit a file, and keeping a
 * machine-local file out of commits. The hook entries `ah init` writes hold
 * absolute paths for this machine (BUG-2026-014), so a committed copy is
 * wrong on every other machine and leaks a home directory (BUG-2026-006).
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { readText, writeAtomic } from "./files.ts";

export type Os = "linux" | "darwin" | "win32";

export interface Machine {
  /** The project root `ah init` was pointed at. */
  root: string;
  home: string;
  os: Os;
  env: NodeJS.ProcessEnv;
  /** Absolute path of the node binary the hook entry will name. */
  nodePath: string;
  /** Absolute path of dist/guard.mjs the hook entry will name. */
  guardPath: string;
}

export function currentOs(): Os {
  return process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux";
}

export function defaultMachine(root: string, guardPath: string, env: NodeJS.ProcessEnv = process.env): Machine {
  const os = currentOs();
  const home = (os === "win32" ? env.USERPROFILE : env.HOME) || homedir();
  return { root: resolve(root), home, os, env, nodePath: process.execPath, guardPath };
}

function git(cwd: string, args: string[]): { ok: boolean; out: string } {
  const r = spawnSync("git", args, { cwd, encoding: "utf8", windowsHide: true });
  return { ok: r.status === 0, out: (r.stdout ?? "").trim() };
}

/** The repository's top level, or null outside a repository (or without git). */
export function gitTopLevel(dir: string): string | null {
  const r = git(dir, ["rev-parse", "--show-toplevel"]);
  return r.ok && r.out !== "" ? resolve(r.out) : null;
}

/**
 * The main checkout's root when `dir` is inside a linked worktree, else the
 * top level. Claude Code keeps settings.local.json in the main checkout.
 */
export function mainCheckoutRoot(dir: string): string | null {
  const top = gitTopLevel(dir);
  if (top === null) return null;
  const common = git(dir, ["rev-parse", "--path-format=absolute", "--git-common-dir"]);
  if (!common.ok || common.out === "") return top;
  const commonDir = resolve(common.out);
  return commonDir.endsWith(`${sep}.git`) || commonDir.endsWith("/.git") ? dirname(commonDir) : top;
}

export type GitStatus = "tracked" | "ignored" | "untracked" | "no-repo";

export function gitStatusOf(file: string): GitStatus {
  const dir = existingDir(dirname(file));
  if (dir === null || gitTopLevel(dir) === null) return "no-repo";
  // Relative to git's cwd, so git never compares our spelling of the root with its own.
  const rel = relative(dir, file);
  if (git(dir, ["ls-files", "--error-unmatch", "--", rel]).ok) return "tracked";
  return git(dir, ["check-ignore", "-q", "--no-index", "--", rel]).ok ? "ignored" : "untracked";
}

function existingDir(d: string): string | null {
  let cur = d;
  for (let i = 0; i < 64; i++) {
    if (existsSync(cur)) return cur;
    const up = dirname(cur);
    if (up === cur) return null;
    cur = up;
  }
  return null;
}

const EXCLUDE_NOTE = "# machine-local hook wiring written by ah init";

interface InRepo {
  /** The nearest existing directory above the file; git runs there. */
  dir: string;
  /** The file relative to `dir`, in this process's spelling of both. */
  fromDir: string;
  /** The file relative to the repository root, as git spells it (`/` separators). */
  fromTop: string;
  excludePath: string;
}

/**
 * Locate `file` in its repository. Paths are made relative before git sees
 * them, and the root-relative form comes from git, because git's spelling of
 * the root can differ from ours (a Windows 8.3 short name, a symlinked /tmp).
 */
function inRepo(file: string): InRepo | null {
  const dir = existingDir(dirname(file));
  if (dir === null) return null;
  const top = gitTopLevel(dir);
  const prefix = git(dir, ["rev-parse", "--show-prefix"]);
  if (top === null || !prefix.ok) return null;
  const fromDir = relative(dir, file);
  const info = git(dir, ["rev-parse", "--path-format=absolute", "--git-path", "info/exclude"]);
  const excludePath = info.ok && info.out !== "" ? resolve(info.out) : join(top, ".git", "info", "exclude");
  return { dir, fromDir, fromTop: prefix.out + fromDir.split(sep).join("/"), excludePath };
}

/** The exclude line for a root-relative path: anchored, with glob characters escaped. */
function excludeLine(fromTop: string): string {
  return `/${fromTop.replace(/[\\*?[\]!#]/g, "\\$&")}`;
}

/**
 * Add `file` to the repository's `.git/info/exclude` (local to this clone,
 * never committed) unless git already ignores or tracks it. Returns what it did.
 */
export function excludeLocally(file: string, dryRun: boolean): "excluded" | "already-ignored" | "tracked" | "no-repo" {
  const status = gitStatusOf(file);
  if (status === "tracked") return "tracked";
  if (status === "ignored") return "already-ignored";
  const r = inRepo(file);
  if (status === "no-repo" || r === null) return "no-repo";
  if (dryRun) return "excluded";
  const current = readText(r.excludePath).text ?? "";
  const line = excludeLine(r.fromTop);
  if (current.split(/\r?\n/).includes(line)) return "already-ignored";
  const sepNl = current === "" || current.endsWith("\n") ? "" : "\n";
  writeAtomic(r.excludePath, `${current}${sepNl}${EXCLUDE_NOTE}\n${line}\n`);
  return "excluded";
}

/** Take out the lines excludeLocally added for `file`. Returns true when there were some. */
export function unexcludeLocally(file: string, dryRun: boolean): boolean {
  const r = inRepo(file);
  if (r === null) return false;
  const current = readText(r.excludePath).text;
  if (current === null) return false;
  const line = excludeLine(r.fromTop);
  const lines = current.split("\n");
  const out: string[] = [];
  let found = false;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].replace(/\r$/, "") === EXCLUDE_NOTE && lines[i + 1]?.replace(/\r$/, "") === line) {
      found = true;
      i++;
      continue;
    }
    out.push(lines[i]);
  }
  if (found && !dryRun) writeAtomic(r.excludePath, out.join("\n"));
  return found;
}

/** Read a small JSON file, or undefined when it is missing or unreadable. Never throws. */
export function readJsonQuiet(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8").replace(/^﻿/, ""));
  } catch {
    return undefined;
  }
}

/** True when `p` is absolute for the machine's OS (a drive or UNC path on Windows). */
export function isAbsoluteFor(os: Os, p: string): boolean {
  return os === "win32" ? /^(?:[A-Za-z]:[\\/]|\\\\)/.test(p) : isAbsolute(p) && p.startsWith("/");
}
