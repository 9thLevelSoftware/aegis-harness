/**
 * What Git on Windows does to the files `ah init` reads: a committed symlink
 * checked out as a plain file holding the link's target (core.symlinks=false,
 * Git for Windows' default) is never written into, CLAUDE.md, AGENTS.md or
 * AGENTS.override.md alike, and a block an older ah left in one comes out to
 * the target's exact bytes. The paths an MSYS2 or Cygwin git prints
 * (/c/..., /cygdrive/c/...) are read as the drive paths they are, and one
 * only that git can place (/home/dev/...) is not guessed at: ah asks git for
 * paths relative to where it ran. The text link is made by hand in the index,
 * so this runs the same on every OS.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, relative } from "node:path";
import { test } from "node:test";
import { upsertBlock } from "../src/wiring/text-block.ts";
import { agentsBlockLines, AGENTS_BLOCK_BODY } from "../src/wiring/agents-md.ts";
import { writeAtomic } from "../src/wiring/files.ts";
import { claudeMdState, planInstructions, rootTextLinks, type InstructionEdit } from "../src/wiring/instructions.ts";
import { excludeLocally, fromGitPath, gitTopLevel, mainCheckoutRoot, symlinkCheckedOutAsText } from "../src/wiring/project.ts";

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

test("an AGENTS.md symlink checked out as text is never written into: Codex gets the block in an AGENTS.override.md for this checkout alone", () => {
  const c = checkout({ "CLAUDE.md": "# Team\n" }, { "AGENTS.md": "CLAUDE.md" });
  try {
    const agents = join(c.root, "AGENTS.md");
    const override = join(c.root, "AGENTS.override.md");
    assert.deepEqual(rootTextLinks(c.root), [{ path: agents, target: "CLAUDE.md" }]);
    const plan = planInstructions(c.root, ["claude", "codex"], false);
    assert.deepEqual(plan.map((e) => [relative(c.root, e.path), e.edit.action, e.local]), [["AGENTS.override.md", "created", true], ["CLAUDE.md", "appended", undefined]]);
    assert.match(plan[0].why, /^AGENTS\.md is a symlink checked out as plain text, which ah does not write into, and Codex reads AGENTS\.override\.md in its place/);
    apply(plan);
    assert.equal(readFileSync(agents, "utf8"), "CLAUDE.md");
    assert.equal(git(c.root, "diff", "--name-only", "--", "AGENTS.md"), "", "git sees the link it has");
    const again = planInstructions(c.root, ["claude", "codex"], false);
    assert.ok(again.every((e) => e.edit.action === "unchanged"), "a second run changes nothing");
    assert.equal(again.find((e) => e.path === override)?.local, true, "the override is still ah's own");
    const removal = planInstructions(c.root, ["claude", "codex"], true);
    assert.deepEqual(removal.map((e) => [relative(c.root, e.path), e.edit.action, e.local]), [["AGENTS.override.md", "removed", true], ["CLAUDE.md", "removed", undefined]]);
    apply(removal);
    assert.equal(existsSync(override), false);
    assert.equal(readFileSync(join(c.root, "CLAUDE.md"), "utf8"), "# Team\n");
    assert.equal(readFileSync(agents, "utf8"), "CLAUDE.md");
  } finally {
    c.done();
  }
});

test("with AGENTS.md a text link, Claude Code gets the block in a CLAUDE.local.md of ah's own, and an @AGENTS.md import does not count", () => {
  const bare = checkout({}, { "AGENTS.md": "docs/AGENTS.md" });
  try {
    const s = claudeMdState(bare.root, bare.home);
    assert.equal(s.target, join(bare.root, "CLAUDE.local.md"));
    assert.equal(s.reason, "AGENTS.md is a symlink checked out as plain text, which ah does not write into; the block goes in a new CLAUDE.local.md, which Claude Code reads in its place");
    assert.deepEqual(planInstructions(bare.root, ["claude"], false).map((e) => [relative(bare.root, e.path), e.edit.action, e.local]), [["CLAUDE.local.md", "created", true]]);
  } finally {
    bare.done();
  }
  const imported = checkout({ "CLAUDE.md": "@AGENTS.md\n" }, { "AGENTS.md": "docs/AGENTS.md" });
  try {
    assert.equal(claudeMdState(imported.root, imported.home).target, join(imported.root, "CLAUDE.md"), "the import brings in the link's one line, not a block");
  } finally {
    imported.done();
  }
});

test("an AGENTS.override.md symlink checked out as text is left alone, and the plan says Codex gets no block", () => {
  const cases: Record<string, string>[] = [{ "AGENTS.override.md": "AGENTS.md" }, { "AGENTS.override.md": "AGENTS.md", "AGENTS.md": "CLAUDE.md" }];
  for (const links of cases) {
    const c = checkout("AGENTS.md" in links ? {} : { "AGENTS.md": "# Agents\n" }, links);
    try {
      const plan = planInstructions(c.root, ["codex"], false);
      assert.deepEqual(plan.map((e) => [relative(c.root, e.path), e.edit.action]), [...("AGENTS.md" in links ? [] : [["AGENTS.md", "appended"]]), ["AGENTS.override.md", "unchanged"]]);
      assert.match(plan.at(-1)!.why, /^AGENTS\.override\.md is a symlink checked out as plain text, which ah does not write into, and Codex reads it in place of AGENTS\.md, so Codex gets no block here/);
      apply(plan);
      assert.equal(readFileSync(join(c.root, "AGENTS.override.md"), "utf8"), "AGENTS.md");
      assert.equal(git(c.root, "diff", "--name-only", "--", "AGENTS.override.md"), "");
    } finally {
      c.done();
    }
  }
});

test("a block an older ah wrote into a text link, a line break after the target and all, comes out to the target's exact bytes", () => {
  const c = checkout({}, { "AGENTS.md": "CLAUDE.md", "CLAUDE.md": "AGENTS.md" });
  try {
    const agents = join(c.root, "AGENTS.md");
    const claude = join(c.root, "CLAUDE.md");
    // What ah wrote before it kept a file's missing final line break missing.
    const older = (target: string): string => `${target}\n\n${agentsBlockLines().join("\n")}\n`;
    for (const remove of [false, true]) {
      writeFileSync(agents, older("CLAUDE.md"));
      writeFileSync(claude, older("AGENTS.md"));
      const plan = planInstructions(c.root, ["claude"], remove);
      assert.deepEqual(plan.filter((e) => e.path !== join(c.root, "CLAUDE.local.md")).map((e) => [relative(c.root, e.path), e.edit.action, e.edit.text]), [["AGENTS.md", "removed", "CLAUDE.md"], ["CLAUDE.md", "removed", "AGENTS.md"]], `remove: ${remove}`);
      apply(plan);
      assert.equal(git(c.root, "diff", "--name-only"), "", `remove: ${remove}`);
    }
    writeFileSync(agents, upsertBlock(null, AGENTS_BLOCK_BODY, agents).text!);
    apply(planInstructions(c.root, ["codex"], false));
    assert.equal(readFileSync(agents, "utf8"), "CLAUDE.md", "a link that held only the block gets its target back");
  } finally {
    c.done();
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
  for (const from of ["/home/dev/proj/.git/info/exclude", "/mnt/c/Users/dev/proj", "/usr/src/proj", "\\Users\\dev\\proj"]) assert.equal(fromGitPath("win32", from), null, `${from} is somewhere only that git knows`);
  for (const os of ["linux", "darwin"] as const) {
    for (const p of ["/c/Users/dev/proj", "/cygdrive/c/Users/dev", "/home/dev/proj", "/Users/dev/proj"]) assert.equal(fromGitPath(os, p), p, `${os} ${p}`);
    assert.equal(fromGitPath(os, "/home/dev/proj/"), "/home/dev/proj");
  }
});

test("a git whose absolute paths only it can place still finds the repository and its exclude file, from a symlink into a subdirectory too", { skip: process.platform === "win32" ? "a shell script stands in for git" : false }, () => {
  const base = mkdtempSync(join(tmpdir(), "ah-gitpath-"));
  const path = process.env.PATH;
  try {
    const root = join(base, "proj");
    mkdirSync(join(root, "sub", "deep"), { recursive: true });
    git(root, "init", "-q");
    symlinkSync(join(root, "sub", "deep"), join(base, "deep"));
    const real = spawnSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).stdout.trim();
    const bin = join(base, "bin");
    mkdirSync(bin);
    // Like MSYS2's git, which prints /home/dev/... for a repository under its own install.
    writeFileSync(join(bin, "git"), `#!/bin/sh\nout=$("${real}" "$@") || exit $?\nprintf '%s\\n' "$out" | sed 's#^/#/msys64/#'\n`, { mode: 0o755 });
    process.env.PATH = `${bin}${delimiter}${path}`;
    const top = realpathSync(root);
    for (const dir of [root, join(root, "sub", "deep"), join(base, "deep")]) {
      assert.equal(gitTopLevel(dir), top, dir);
      assert.equal(mainCheckoutRoot(dir), top, dir);
    }
    assert.equal(excludeLocally(join(base, "deep", "settings.local.json"), false), "excluded");
    assert.match(readFileSync(join(root, ".git", "info", "exclude"), "utf8"), /^\/sub\/deep\/settings\.local\.json$/m);
  } finally {
    process.env.PATH = path;
    rmSync(base, { recursive: true, force: true });
  }
});
