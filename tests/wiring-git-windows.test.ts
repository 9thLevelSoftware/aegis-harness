/**
 * What Git on Windows does to the files `ah init` reads: a committed symlink
 * checked out as a plain file holding the link's target (core.symlinks=false,
 * Git for Windows' default) is never written into, and the paths an MSYS2 or
 * Cygwin git prints (/c/..., /cygdrive/c/...) are read as the drive paths
 * they are. The text link is made by hand in the index, so this runs the same
 * on every OS.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { test } from "node:test";
import { upsertBlock } from "../src/wiring/text-block.ts";
import { AGENTS_BLOCK_BODY } from "../src/wiring/agents-md.ts";
import { writeAtomic } from "../src/wiring/files.ts";
import { claudeMdState, planInstructions, type InstructionEdit } from "../src/wiring/instructions.ts";
import { fromGitPath, symlinkCheckedOutAsText } from "../src/wiring/project.ts";

function git(cwd: string, ...args: string[]): string {
  const r = spawnSync("git", args, { cwd, encoding: "utf8" });
  assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout.trim();
}

/** A repository where `links` are symlinks in the index and plain files holding their targets on disk. */
function checkout(files: Record<string, string>, links: Record<string, string>): { root: string; home: string; done: () => void } {
  const base = mkdtempSync(join(tmpdir(), "ah-textlink-"));
  const root = join(base, "proj");
  mkdirSync(root);
  git(root, "init", "-q");
  git(root, "config", "core.symlinks", "false");
  for (const [p, text] of Object.entries({ ...files, ...links })) {
    mkdirSync(join(root, p, ".."), { recursive: true });
    writeFileSync(join(root, p), text);
  }
  if (Object.keys(files).length > 0) git(root, "add", "--", ...Object.keys(files));
  for (const p of Object.keys(links)) git(root, "update-index", "--add", "--cacheinfo", `120000,${git(root, "hash-object", "-w", "--", p)},${p}`);
  return { root, home: join(base, "home"), done: () => rmSync(base, { recursive: true, force: true }) };
}

function apply(plan: InstructionEdit[]): void {
  for (const e of plan) {
    if (e.edit.text === null) rmSync(e.path);
    else writeAtomic(e.path, e.edit.text);
  }
}

test("a CLAUDE.md symlink checked out as text is never written into; the block goes in CLAUDE.local.md and comes out again", () => {
  const c = checkout({ "AGENTS.md": "# Agents\n" }, { "CLAUDE.md": "AGENTS.md" });
  try {
    const claude = join(c.root, "CLAUDE.md");
    const local = join(c.root, "CLAUDE.local.md");
    assert.equal(symlinkCheckedOutAsText(claude), "AGENTS.md");
    assert.equal(symlinkCheckedOutAsText(join(c.root, "AGENTS.md")), null, "a tracked plain file");
    assert.equal(symlinkCheckedOutAsText(join(c.root, "missing.md")), null);
    const s = claudeMdState(c.root, c.home);
    assert.deepEqual(s.textLinks, [{ path: claude, target: "AGENTS.md" }]);
    assert.equal(s.target, local);
    assert.equal(s.reason, "CLAUDE.md is a symlink checked out as plain text, which ah does not write into; the block goes in CLAUDE.local.md, which Claude Code reads too");

    const plan = planInstructions(c.root, ["claude", "codex"], false);
    assert.deepEqual(plan.map((e) => [relative(c.root, e.path), e.edit.action]), [["AGENTS.md", "appended"], ["CLAUDE.local.md", "created"]]);
    apply(plan);
    assert.equal(readFileSync(claude, "utf8"), "AGENTS.md");
    assert.equal(git(c.root, "diff", "--name-only", "--", "CLAUDE.md"), "", "git sees the link it has");
    assert.ok(planInstructions(c.root, ["claude", "codex"], false).every((e) => e.edit.action === "unchanged"), "a second run changes nothing");
    apply(planInstructions(c.root, ["claude", "codex"], true));
    assert.equal(existsSync(local), false, "the CLAUDE.local.md init made goes again");
    assert.equal(readFileSync(join(c.root, "AGENTS.md"), "utf8"), "# Agents\n");
    assert.equal(readFileSync(claude, "utf8"), "AGENTS.md");
  } finally {
    c.done();
  }
});

test("a block an older ah wrote into a text link comes out on init, giving git its link back", () => {
  const c = checkout({}, { "CLAUDE.md": "AGENTS.md" });
  try {
    const claude = join(c.root, "CLAUDE.md");
    writeFileSync(claude, upsertBlock("AGENTS.md", AGENTS_BLOCK_BODY, claude).text!);
    assert.notEqual(git(c.root, "diff", "--name-only", "--", "CLAUDE.md"), "");
    const plan = planInstructions(c.root, ["claude"], false);
    assert.deepEqual(plan.map((e) => [relative(c.root, e.path), e.edit.action]), [["AGENTS.md", "created"], ["CLAUDE.local.md", "created"], ["CLAUDE.md", "removed"]]);
    apply(plan);
    assert.equal(readFileSync(claude, "utf8"), "AGENTS.md");
    assert.equal(git(c.root, "diff", "--name-only", "--", "CLAUDE.md"), "");
    assert.deepEqual(planInstructions(c.root, ["codex"], false).map((e) => relative(c.root, e.path)), ["AGENTS.md"], "only Claude Code's wiring looks at CLAUDE.md");
  } finally {
    c.done();
  }
});

test("with a text link, an import elsewhere still counts, and a CLAUDE.local.md that is a text link too is passed over", () => {
  const imported = checkout({ ".claude/CLAUDE.md": "@../AGENTS.md\n" }, { "CLAUDE.md": "AGENTS.md" });
  try {
    const s = claudeMdState(imported.root, imported.home);
    assert.equal(s.target, null);
    assert.equal(s.textLinks.length, 1);
  } finally {
    imported.done();
  }
  const both = checkout({ ".claude/CLAUDE.md": "# Team\n" }, { "CLAUDE.md": "AGENTS.md", "CLAUDE.local.md": "../dotfiles/CLAUDE.md" });
  try {
    const s = claudeMdState(both.root, both.home);
    assert.deepEqual(s.textLinks.map((l) => [relative(both.root, l.path), l.target]), [["CLAUDE.md", "AGENTS.md"], ["CLAUDE.local.md", "../dotfiles/CLAUDE.md"]]);
    assert.equal(s.target, join(both.root, ".claude", "CLAUDE.md"));
  } finally {
    both.done();
  }
});

test("paths from an MSYS2 or Cygwin git become drive paths on Windows, and stay as they are elsewhere", () => {
  const cases: [string, string][] = [
    ["/c/Users/dev/proj", "C:\\Users\\dev\\proj"],
    ["/C/Users/dev/proj/.git/info/exclude", "C:\\Users\\dev\\proj\\.git\\info\\exclude"],
    ["/cygdrive/c/Users/dev/proj/.git", "C:\\Users\\dev\\proj\\.git"],
    ["/cygdrive/e/src/", "E:\\src"],
    ["/e", "E:\\"],
    ["/cygdrive/e", "E:\\"],
    ["C:/Users/dev/proj", "C:\\Users\\dev\\proj"],
    ["C:\\Users\\dev\\proj", "C:\\Users\\dev\\proj"],
    ["//server/share/proj", "\\\\server\\share\\proj"],
  ];
  for (const [from, want] of cases) assert.equal(fromGitPath("win32", from), want, from);
  for (const os of ["linux", "darwin"] as const) {
    for (const p of ["/c/Users/dev/proj", "/cygdrive/c/Users/dev", "/home/dev/proj", "/Users/dev/proj"]) assert.equal(fromGitPath(os, p), p, `${os} ${p}`);
    assert.equal(fromGitPath(os, "/home/dev/proj/"), "/home/dev/proj");
  }
});
