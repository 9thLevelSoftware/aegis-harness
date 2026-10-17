/**
 * Facts about the project `ah init` wires and the machine it runs on: where
 * the git repository starts, whether git would commit a file or has it as a
 * symlink, and keeping a machine-local file out of commits. The hook entries
 * `ah init` writes hold absolute paths for this machine (BUG-2026-014), so a
 * committed copy is wrong on every other machine and leaks a home directory
 * (BUG-2026-006).
 */
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, posix, relative, resolve, sep, win32 } from "node:path";
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

function git(cwd: string, args: string[]): { ok: boolean; out: string; raw: string } {
  const r = spawnSync("git", args, { cwd, encoding: "utf8", windowsHide: true });
  return { ok: r.status === 0, out: (r.stdout ?? "").trim(), raw: r.stdout ?? "" };
}

/**
 * An absolute path git printed, spelled for `os`, or null when only the git
 * that printed it knows where it is. Git for Windows prints C:/..., but an
 * MSYS2 or Cygwin git first on PATH prints /c/... or /cygdrive/c/..., which
 * path.resolve on Windows takes for C:\c\..., and MSYS2's own git prints a
 * repository under its home as /home/dev/..., somewhere inside its install.
 */
export function fromGitPath(os: Os, p: string): string | null {
  if (os !== "win32") return posix.resolve(p);
  const drive = /^\/(?:cygdrive\/)?([A-Za-z])(\/.*)?$/.exec(p);
  if (drive) return win32.resolve(`${drive[1].toUpperCase()}:${drive[2] ?? "/"}`);
  return /^[\\/](?![\\/])/.test(p) ? null : win32.resolve(p);
}

/**
 * A path git printed when run in `dir`. A relative one is taken from the
 * directory git ran in as git sees it, symlinks resolved, so it holds
 * whichever git printed it. An absolute one goes through fromGitPath, then,
 * on Windows, through cygpath, which belongs to the git that printed it.
 */
function gitPath(dir: string, p: string): string | null {
  const os = currentOs();
  if (!(os === "win32" ? win32.isAbsolute(p) : p.startsWith("/"))) {
    try {
      return resolve(realpathSync(dir), p);
    } catch {
      return resolve(dir, p);
    }
  }
  const mapped = fromGitPath(os, p);
  if (mapped !== null || os !== "win32") return mapped;
  const r = spawnSync("cygpath", ["-w", p], { encoding: "utf8", windowsHide: true });
  const out = r.status === 0 ? (r.stdout ?? "").trim() : "";
  return /^(?:[A-Za-z]:\\|\\\\)/.test(out) ? out : null;
}

/** The repository's top level, or null outside a work tree (or without git). */
export function gitTopLevel(dir: string): string | null {
  // --show-cdup is relative, so no git's spelling of an absolute path comes into it.
  const r = git(dir, ["rev-parse", "--is-inside-work-tree", "--show-cdup"]);
  const [inside, cdup = ""] = r.raw.split(/\r?\n/);
  return r.ok && inside === "true" ? gitPath(dir, cdup === "" ? "." : cdup) : null;
}

/**
 * The main checkout's root when `dir` is inside a linked worktree, else the
 * top level. Claude Code keeps settings.local.json in the main checkout.
 */
export function mainCheckoutRoot(dir: string): string | null {
  const top = gitTopLevel(dir);
  if (top === null) return null;
  const common = git(dir, ["rev-parse", "--git-common-dir"]);
  const commonDir = common.ok && common.out !== "" ? gitPath(dir, common.out) : null;
  if (commonDir === null) return top;
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

/**
 * What `file` links to when git has it as a symlink but the checkout wrote a
 * plain file holding the link's target instead (core.symlinks=false, Git for
 * Windows' default), else null: the target's exact bytes, which are all the
 * checkout wrote. Git takes an edit to that file for a new link target.
 */
export function symlinkCheckedOutAsText(file: string): string | null {
  try {
    if (!lstatSync(file).isFile()) return null;
  } catch {
    return null;
  }
  const staged = git(dirname(file), ["ls-files", "-s", "--", basename(file)]);
  const link = /^120000 ([0-9a-f]+) /.exec(staged.out);
  if (!staged.ok || link === null) return null;
  const target = git(dirname(file), ["cat-file", "blob", link[1]]);
  return target.ok ? target.raw : null;
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

const EXCLUDE_NOTE = "# machine-local file written by ah init";
/** What the note said before ah kept instruction files out of git too. */
const OLD_EXCLUDE_NOTE = "# machine-local hook wiring written by ah init";

interface InRepo {
  /** The nearest existing directory above the file; git runs there. */
  dir: string;
  /** The file relative to `dir`, in this process's spelling of both. */
  fromDir: string;
  /** The file relative to the repository root, as git spells it (`/` separators). */
  fromTop: string;
  /** Null when git named it by a path that cannot be placed on this machine. */
  excludePath: string | null;
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
  const info = git(dir, ["rev-parse", "--git-path", "info/exclude"]);
  const excludePath = info.ok && info.out !== "" ? gitPath(dir, info.out) : join(top, ".git", "info", "exclude");
  return { dir, fromDir, fromTop: prefix.out + fromDir.split(sep).join("/"), excludePath };
}

/** The exclude line for a root-relative path: anchored, with glob characters escaped. */
function excludeLine(fromTop: string): string {
  return `/${fromTop.replace(/[\\*?[\]!#]/g, "\\$&")}`;
}

/**
 * Add `file` to the repository's `.git/info/exclude` (local to this clone,
 * never committed) unless git already ignores or tracks it. Returns what it
 * did; "unmapped" when git named the exclude file by a path that cannot be
 * placed (MSYS2's git, with no cygpath beside it), so nothing was written.
 * A file without a final newline gets one before ah's lines and none after
 * them, so unexcludeLocally takes out exactly what went in.
 */
export function excludeLocally(file: string, dryRun: boolean): "excluded" | "already-ignored" | "tracked" | "no-repo" | "unmapped" {
  const status = gitStatusOf(file);
  if (status === "tracked") return "tracked";
  if (status === "ignored") return "already-ignored";
  const r = inRepo(file);
  if (status === "no-repo" || r === null) return "no-repo";
  if (r.excludePath === null) return "unmapped";
  if (dryRun) return "excluded";
  const current = readText(r.excludePath).text ?? "";
  const line = excludeLine(r.fromTop);
  if (current.split(/\r?\n/).includes(line)) return "already-ignored";
  const open = current !== "" && !current.endsWith("\n");
  writeAtomic(r.excludePath, open ? `${current}\n${EXCLUDE_NOTE}\n${line}` : `${current}${EXCLUDE_NOTE}\n${line}\n`);
  return "excluded";
}

/** True when `file` is kept out of git by a line excludeLocally wrote, so ah put it there. */
export function excludedByAh(file: string): boolean {
  const r = inRepo(file);
  const current = r === null || r.excludePath === null ? null : readText(r.excludePath).text;
  if (r === null || current === null) return false;
  const line = excludeLine(r.fromTop);
  const lines = current.split("\n").map((l) => l.replace(/\r$/, ""));
  return lines.some((l, i) => (l === EXCLUDE_NOTE || l === OLD_EXCLUDE_NOTE) && lines[i + 1] === line);
}

/**
 * True when another worktree of the repository has a file at `fromTop`. Every
 * worktree reads the same .git/info/exclude, so a line one of them still
 * needs stays.
 */
function otherWorktreeHas(r: InRepo, fromTop: string): boolean {
  const top = gitTopLevel(r.dir);
  const list = git(r.dir, ["worktree", "list", "--porcelain"]);
  if (top === null || !list.ok) return false;
  const here = canonical(top);
  return list.raw
    .split(/\r?\n/)
    .filter((l) => l.startsWith("worktree "))
    .map((l) => gitPath(r.dir, l.slice("worktree ".length)))
    .some((wt) => wt !== null && canonical(wt) !== here && existsSync(join(wt, ...fromTop.split("/"))));
}

function canonical(p: string): string {
  try {
    return realpathSync.native(p);
  } catch {
    return resolve(p);
  }
}

/**
 * Take out the lines excludeLocally added for `file`, with the line break
 * after each, or, last in the file and without one, the break before them.
 * Returns "removed" when there were some, "shared" when another worktree has
 * the same file and so still needs them, else "none".
 */
export function unexcludeLocally(file: string, dryRun: boolean): "removed" | "shared" | "none" {
  const r = inRepo(file);
  if (r === null || r.excludePath === null) return "none";
  const current = readText(r.excludePath).text;
  if (current === null) return "none";
  const line = excludeLine(r.fromTop);
  const lines = current.split("\n");
  const out: string[] = [];
  let found = false;
  for (let i = 0; i < lines.length; i++) {
    const note = lines[i].replace(/\r$/, "");
    if ((note === EXCLUDE_NOTE || note === OLD_EXCLUDE_NOTE) && lines[i + 1]?.replace(/\r$/, "") === line) {
      found = true;
      i++;
      continue;
    }
    out.push(lines[i]);
  }
  if (!found) return "none";
  if (otherWorktreeHas(r, r.fromTop)) return "shared";
  if (!dryRun) writeAtomic(r.excludePath, out.join("\n"));
  return "removed";
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

/**
 * When a checkout is shared between WSL and Windows, the side whose agents
 * also read its files but cannot run the paths ah writes: "windows" for a WSL
 * checkout on a Windows drive (/mnt/c/...), "wsl" for Windows opening a WSL
 * checkout (\\wsl$\..., \\wsl.localhost\...). Null otherwise.
 */
export function sharedAcrossWsl(m: Machine, isWsl = Boolean(m.env.WSL_DISTRO_NAME || m.env.WSL_INTEROP) || existsSync("/proc/sys/fs/binfmt_misc/WSLInterop")): "windows" | "wsl" | null {
  if (m.os === "win32") return /^\\\\wsl(\$|\.localhost)\\/i.test(m.root) ? "wsl" : null;
  return m.os === "linux" && isWsl && /^\/mnt\/[a-z](\/|$)/i.test(m.root) ? "windows" : null;
}
