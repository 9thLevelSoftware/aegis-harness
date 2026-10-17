/**
 * The one filesystem fact the guard reads: whether the project sits in a
 * linked git worktree. Codex 0.163 loads project hooks from the main
 * checkout's layers (a session in <worktree>/sub reads <main>/.codex/hooks.json
 * and <main>/sub/.codex/hooks.json, never the worktree's), and Claude Code
 * keeps settings.local.json in the main checkout, so those files wire the
 * session's hooks too. buildContext asks once per project root and process and
 * puts the answer in Context.mainCheckout; the decision core stays pure.
 */
import { readFileSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

/** A linked worktree's gitdir: `<main>/.git/worktrees/<name>`. */
const WORKTREE_GITDIR = /^(.*)[\\/]\.git[\\/]worktrees[\\/][^\\/]+[\\/]*$/;

const cache = new Map<string, string | undefined>();

/**
 * The main checkout's directory that corresponds to `projectRoot` (`<main>/sub`
 * for `<worktree>/sub`) when the project is inside a linked worktree, else
 * undefined. Walks up to the first `.git`: a directory ends the search, a file
 * is read. One stat per level and at most one read.
 */
export function mainCheckoutOf(projectRoot: string): string | undefined {
  if (!cache.has(projectRoot)) cache.set(projectRoot, find(projectRoot));
  return cache.get(projectRoot);
}

function find(projectRoot: string): string | undefined {
  if (!isAbsolute(projectRoot)) return undefined;
  try {
    const root = resolve(projectRoot);
    for (let dir = root; ; dir = dirname(dir)) {
      const dotGit = join(dir, ".git");
      const st = statSync(dotGit, { throwIfNoEntry: false });
      if (st !== undefined) {
        if (!st.isFile()) return undefined;
        const line = /^gitdir:\s*(.+?)\s*$/m.exec(readFileSync(dotGit, "utf8"));
        // git may write the gitdir relative to the worktree (worktree.useRelativePaths).
        const m = line === null ? null : WORKTREE_GITDIR.exec(resolve(dir, line[1]));
        return m === null ? undefined : join(m[1], relative(dir, root));
      }
      if (dirname(dir) === dir) return undefined;
    }
  } catch {
    // An unreadable .git leaves the guard with the project's own layers; it never fails a decision.
    return undefined;
  }
}
