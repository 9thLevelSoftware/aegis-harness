/**
 * Hook wiring above the session's start directory (BUG-2026-019). `ah init`
 * wires the repository's top level, a session may start in a subdirectory, and
 * in a linked worktree Codex reads the main checkout's .codex/ instead of the
 * worktree's. Each of those files is hook configuration to the guard.
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { classifyPath } from "../src/guard/classify.ts";
import { evaluate } from "../src/guard/main.ts";
import type { Context, Decision } from "../src/guard/model.ts";
import { mainCheckoutOf } from "../src/guard/worktree.ts";
import { ed, POSIX, sh, WINDOWS_CODEX, wr } from "./helpers.ts";

const verdictOf = (d: Decision) => `${d.verdict}${d.rule ? ` ${d.rule}` : ""}`;
const SUB: Context = { ...POSIX, projectRoot: "/home/dev/project/sub" };
/** The scratch worktrees below live on this machine's disk, so their paths follow its platform. */
const HOST: Context = process.platform === "win32" ? WINDOWS_CODEX : POSIX;

test("project-level hook files in any ancestor of the project root are hook configuration", () => {
  const c = (p: string) => classifyPath(p, SUB);
  for (const p of ["../.claude/settings.local.json", "/home/dev/project/.claude/settings.local.json", "../.claude/settings.json", "../.codex/hooks.json", "../.codex/config.toml",
    "../../project/.husky/pre-commit", "/home/dev/project/lefthook.yml", "../.pre-commit-config.yaml", "../.claude/hooks/check.sh"]) {
    assert.equal(c(p).category, "hook-config", p);
  }
  assert.equal(c("../.claude/settings.local.json").matched, ".claude/settings.local.json");
  // Two levels up is an ancestor too.
  assert.equal(classifyPath("/home/dev/project/.codex/hooks.json", { ...POSIX, projectRoot: "/home/dev/project/packages/web" }).category, "hook-config");
  // The home directory's own agent settings stay home configuration.
  assert.equal(c("/home/dev/.claude/settings.json").category, "home-config");
  assert.equal(c("/home/dev/.codex/hooks.json").category, "home-config");
});

test("an ancestor's hook files are matched from that ancestor, not by basename anywhere above", () => {
  const c = (p: string) => classifyPath(p, SUB).category;
  for (const p of ["../README.md", "../src/.claude/settings.json", "../other/.codex/hooks.json", "../docs/lefthook.yml", "/home/dev/other/.claude/settings.local.json", "/home/dev/other/.husky/pre-commit"]) {
    assert.equal(c(p), "outside-project", p);
  }
  assert.equal(c("/tmp/.codex/hooks.json"), "temp");
  assert.equal(c("/etc/lefthook.yml"), "system");
  // Inside the project nothing changes.
  assert.equal(c(".claude/settings.json"), "hook-config");
  assert.equal(c("src/a.ts"), "normal");
});

test("ancestor hook files fold case and take Git Bash drive paths on Windows", () => {
  const ctx: Context = { ...WINDOWS_CODEX, projectRoot: "C:\\Users\\dev\\project\\sub" };
  assert.equal(classifyPath("c:\\users\\DEV\\Project\\.Claude\\Settings.Local.json", ctx).category, "hook-config");
  assert.equal(classifyPath("..\\.codex\\hooks.json", ctx).category, "hook-config");
  assert.equal(classifyPath("/c/Users/dev/project/.codex/hooks.json", { ...ctx, shellDialect: "posix" }).category, "hook-config");
  assert.equal(classifyPath("C:\\Users\\dev\\other\\.codex\\hooks.json", ctx).category, "outside-project");
  assert.equal(classifyPath("/home/dev/project/.Claude/settings.local.json", SUB).category, "outside-project");
});

test("from a subdirectory session, removing or rewriting the top level's hook wiring is denied", () => {
  for (const c of ["rm ../.claude/settings.local.json", "rm -f /home/dev/project/.claude/settings.local.json", "mv ../.claude/settings.local.json /tmp/x", "cp /dev/null ../.claude/settings.local.json",
    "truncate -s0 ../.claude/settings.local.json", ": > ../.claude/settings.local.json", "echo '{}' > ../.claude/settings.local.json", "sed -i '/guard.mjs/d' ../.claude/settings.local.json", "rm ../.codex/hooks.json"]) {
    assert.equal(verdictOf(sh(c, SUB)), "deny shell.hook-tamper", c);
  }
  assert.equal(verdictOf(wr("../.claude/settings.local.json", "{}", SUB)), "deny edit.hook-config");
  assert.equal(verdictOf(ed("/home/dev/project/.codex/hooks.json", "\"hooks\"", "\"x\"", SUB)), "deny edit.hook-config");
  assert.equal(sh("cat ../.claude/settings.local.json", SUB).verdict, "allow");
  assert.equal(sh("rm /home/dev/other/.claude/settings.local.json", SUB).verdict, "allow");
  assert.equal(verdictOf(wr("../README.md", "x", SUB)), "ask edit.outside-project");
});

/** A main checkout with a linked worktree beside it, laid out the way `git worktree add` leaves them. */
function worktreeScratch() {
  const base = mkdtempSync(join(tmpdir(), "ah-worktree-"));
  const main = join(base, "main");
  const wt = join(base, "wt");
  mkdirSync(join(main, ".git", "worktrees", "wt"), { recursive: true });
  mkdirSync(join(main, "sub"), { recursive: true });
  mkdirSync(join(wt, "sub", "deeper"), { recursive: true });
  writeFileSync(join(wt, ".git"), `gitdir: ${join(main, ".git", "worktrees", "wt")}\n`);
  return { base, main, wt, done: () => rmSync(base, { recursive: true, force: true }) };
}

test("a linked worktree's twin in the main checkout is found from its .git file", () => {
  const s = worktreeScratch();
  try {
    assert.equal(mainCheckoutOf(join(s.wt, "sub")), join(s.main, "sub"));
    assert.equal(mainCheckoutOf(join(s.wt, "sub", "deeper")), join(s.main, "sub", "deeper"));
    assert.equal(mainCheckoutOf(s.wt), s.main);
    // The main checkout itself has a .git directory: not a worktree.
    assert.equal(mainCheckoutOf(join(s.main, "sub")), undefined);
    // git 2.48+ can write the gitdir relative to the worktree.
    const rel = join(s.base, "rel");
    mkdirSync(rel);
    writeFileSync(join(rel, ".git"), "gitdir: ../main/.git/worktrees/rel\n");
    assert.equal(mainCheckoutOf(rel), s.main);
    // A submodule's .git file points into .git/modules: no main checkout to protect.
    const mod = join(s.base, "mod");
    mkdirSync(mod);
    writeFileSync(join(mod, ".git"), "gitdir: ../main/.git/modules/mod\n");
    assert.equal(mainCheckoutOf(mod), undefined);
    assert.equal(mainCheckoutOf(join(s.base, "nowhere")), undefined);
    assert.equal(mainCheckoutOf("relative/path"), undefined);
  } finally {
    s.done();
  }
});

test("in a linked worktree, the main checkout's hook layers are hook configuration", () => {
  const s = worktreeScratch();
  try {
    const ctx: Context = { ...HOST, projectRoot: join(s.wt, "sub"), mainCheckout: join(s.main, "sub") };
    const c = (p: string) => classifyPath(p, ctx);
    for (const p of [join(s.main, ".codex", "hooks.json"), join(s.main, "sub", ".codex", "hooks.json"), join(s.main, ".claude", "settings.local.json"), join(s.main, ".codex", "config.toml"), join(s.wt, ".codex", "hooks.json")]) {
      assert.equal(c(p).category, "hook-config", p);
    }
    // Only the layers from the main checkout's top down to the twin; a deeper or sibling directory is not loaded.
    for (const p of [join(s.main, "sub", "deeper", ".codex", "hooks.json"), join(s.main, "other", ".codex", "hooks.json"), join(s.main, "src", "a.ts")]) {
      assert.notEqual(c(p).category, "hook-config", p);
    }
    assert.notEqual(classifyPath(join(s.main, "sub", ".codex", "hooks.json"), { ...ctx, mainCheckout: undefined }).category, "hook-config");
  } finally {
    s.done();
  }
});

test("the guard reads the worktree layout itself: a session in <worktree>/sub cannot unwire the main checkout", () => {
  const s = worktreeScratch();
  try {
    const run = (tool_name: string, tool_input: Record<string, unknown>) =>
      evaluate({ hook_event_name: "PreToolUse", session_id: "t", tool_use_id: "t", cwd: join(s.wt, "sub"), tool_name, tool_input }, { home: "/home/dev", log: false }, {});
    const hooks = join(s.main, "sub", ".codex", "hooks.json");
    assert.equal(run("Bash", { command: "ls" }).ctx.mainCheckout, join(s.main, "sub"));
    assert.equal(verdictOf(run("Write", { file_path: hooks, content: "{}" }).decision), "deny edit.hook-config");
    // Single-quoted, so a Windows path keeps its backslashes under the Bash tool's POSIX dialect.
    assert.equal(verdictOf(run("Bash", { command: `rm '${join(s.main, ".codex", "hooks.json")}'` }).decision), "deny shell.hook-tamper");
    assert.equal(verdictOf(run("Bash", { command: `sed -i /guard.mjs/d '${join(s.main, ".claude", "settings.local.json")}'` }).decision), "deny shell.hook-tamper");
    assert.equal(run("Bash", { command: `cat '${hooks}'` }).decision.verdict, "allow");
  } finally {
    s.done();
  }
});
