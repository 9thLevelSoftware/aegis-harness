/**
 * The managed AGENTS.md block and the file helpers `ah init` writes through:
 * user content outside the markers survives byte for byte, line endings and a
 * byte-order mark are kept, a malformed block is refused, JSON that cannot be
 * read back exactly is refused, symlinks are written through and never deleted.
 * Where the block goes (a CLAUDE.md above the project counts), what --remove
 * leaves for an agent that stays wired, and .git/info/exclude coming back as
 * it was.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, rmSync, statSync, symlinkSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { test } from "node:test";
import { BLOCK_BEGIN, BLOCK_END, BlockError, readBlock, removeBlock, upsertBlock } from "../src/wiring/text-block.ts";
import { formatJson, readJson, removeFile, writeAtomic } from "../src/wiring/files.ts";
import { agentsBlockLines, AGENTS_BLOCK_BODY } from "../src/wiring/agents-md.ts";
import { claudeMdState, importsAgentsMd, planInstructions, type InstructionEdit } from "../src/wiring/instructions.ts";
import { excludeLocally, unexcludeLocally } from "../src/wiring/project.ts";

const body = ["## Guard", "", "- one"];

test("a missing file gets a file holding only the block", () => {
  const e = upsertBlock(null, body, "AGENTS.md");
  assert.equal(e.action, "created");
  assert.equal(e.text, [BLOCK_BEGIN, ...body, BLOCK_END].join("\n") + "\n");
});

test("an existing file gets the block appended after one blank line, its content untouched", () => {
  const user = "# Project\n\nUse pnpm.\n\n\n";
  const e = upsertBlock(user, body, "AGENTS.md");
  assert.equal(e.action, "appended");
  assert.equal(e.text, `${user}\n${[BLOCK_BEGIN, ...body, BLOCK_END].join("\n")}\n`);
});

test("a second run is a no-op, a changed body replaces only the block", () => {
  const user = "# Project\n\nUse pnpm.\n";
  const once = upsertBlock(user, body, "AGENTS.md").text!;
  const twice = upsertBlock(once, body, "AGENTS.md");
  assert.equal(twice.action, "unchanged");
  assert.equal(twice.text, once);
  const withTail = once + "\n## After\n\nUser text after the block.\n";
  const changed = upsertBlock(withTail, ["## Guard", "- two"], "AGENTS.md");
  assert.equal(changed.action, "replaced");
  assert.ok(changed.text!.startsWith("# Project\n\nUse pnpm.\n\n"));
  assert.ok(changed.text!.endsWith("\n## After\n\nUser text after the block.\n"));
  assert.deepEqual(readBlock(changed.text!, "AGENTS.md"), ["## Guard", "- two"]);
});

test("CRLF line endings and a byte-order mark survive", () => {
  const user = "﻿# Project\r\n\r\nUse pnpm.\r\n";
  const e = upsertBlock(user, body, "AGENTS.md");
  assert.ok(e.text!.startsWith("﻿# Project\r\n"));
  assert.ok(!/(?<!\r)\n/.test(e.text!), "no bare LF");
  const r = removeBlock(e.text, "AGENTS.md");
  assert.equal(r.text, user);
});

test("marker lines the user re-indented or annotated are still recognised", () => {
  const text = `intro\n  <!-- ah:begin edited by hand -->\nold\n<!--ah:end-->\n`;
  const e = upsertBlock(text, body, "AGENTS.md");
  assert.equal(e.action, "replaced");
  assert.ok(e.text!.startsWith("intro\n  <!-- ah:begin edited by hand -->\n## Guard"));
});

test("a malformed block is refused, not guessed at", () => {
  assert.throws(() => upsertBlock(`${BLOCK_BEGIN}\nx\n`, body, "AGENTS.md"), BlockError);
  assert.throws(() => upsertBlock(`${BLOCK_END}\nx\n${BLOCK_BEGIN}\n`, body, "AGENTS.md"), BlockError);
  assert.throws(() => upsertBlock(`${BLOCK_BEGIN}\n${BLOCK_END}\n${BLOCK_BEGIN}\n${BLOCK_END}\n`, body, "AGENTS.md"), BlockError);
});

test("a marker quoted inside a sentence is not a marker", () => {
  const text = "Write `<!-- ah:begin -->` to start a block.\n";
  const e = upsertBlock(text, body, "AGENTS.md");
  assert.equal(e.action, "appended");
});

test("remove restores the file byte for byte", () => {
  for (const user of ["# P\n", "# P\n\nx\n", "# P", "# P\r\n", "# Project\n\nUse pnpm.\n\n\n", "# P\n  \n", "# P\n  ", "", "\uFEFF"]) {
    for (const where of ["end", "start"] as const) {
      const added = upsertBlock(user, body, "AGENTS.md", where).text!;
      const removed = removeBlock(added, "AGENTS.md");
      assert.equal(removed.action, "removed");
      assert.equal(removed.text, user, `${where} ${JSON.stringify(user)}`);
    }
  }
});

test("remove of a block in the middle takes the blank line before it, as for a block at the end", () => {
  const text = `a\n\n${BLOCK_BEGIN}\nx\n${BLOCK_END}\n\nb\n`;
  assert.equal(removeBlock(text, "AGENTS.md").text, "a\n\nb\n");
});

test("remove of a file that held only the block says to delete it", () => {
  const created = upsertBlock(null, body, "AGENTS.md").text;
  assert.deepEqual(removeBlock(created, "AGENTS.md"), { text: null, action: "removed" });
  assert.equal(removeBlock(null, "AGENTS.md").action, "absent");
  assert.equal(removeBlock("# P\n", "AGENTS.md").action, "absent");
});

test("the AGENTS.md block is at most 100 lines, markers included", () => {
  const lines = agentsBlockLines();
  assert.ok(lines.length <= 100, `${lines.length} lines`);
  assert.equal(lines[0], BLOCK_BEGIN);
  assert.equal(lines.at(-1), BLOCK_END);
  for (const l of AGENTS_BLOCK_BODY) assert.ok(!/ah:(begin|end)/.test(l), "the body never contains a marker");
  for (const l of AGENTS_BLOCK_BODY) assert.ok(l.length <= 110, `line too long: ${l}`);
});

function scratch(): string {
  return mkdtempSync(join(tmpdir(), "ah-wiring-"));
}

test("readJson: missing, empty, valid, and JSON with comments", () => {
  const d = scratch();
  try {
    assert.deepEqual(readJson(join(d, "none.json")), { ok: true, exists: false, style: { indent: 2, eol: "\n", bom: false } });
    writeFileSync(join(d, "empty.json"), "  \n");
    const empty = readJson(join(d, "empty.json"));
    assert.ok(empty.ok && empty.exists && JSON.stringify(empty.value) === "{}");
    writeFileSync(join(d, "tabs.json"), '{\r\n\t"a": 1\r\n}\r\n');
    const tabs = readJson(join(d, "tabs.json"));
    assert.ok(tabs.ok && tabs.exists);
    if (tabs.ok && tabs.exists) {
      assert.deepEqual(tabs.style, { indent: "\t", eol: "\r\n", bom: false });
      assert.equal(formatJson(tabs.value, tabs.style), '{\r\n\t"a": 1\r\n}\r\n');
    }
    writeFileSync(join(d, "c.json"), '{\n  // mine\n  "a": 1,\n}\n');
    const c = readJson(join(d, "c.json"));
    assert.equal(c.ok, false);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("writeAtomic creates parents, keeps the mode, and writes through a symlink", { skip: process.platform === "win32" ? "symlinks need privileges on Windows" : false }, () => {
  const d = scratch();
  try {
    const nested = join(d, "a", "b", "settings.json");
    writeAtomic(nested, "{}\n");
    assert.equal(readFileSync(nested, "utf8"), "{}\n");
    chmodSync(nested, 0o600);
    writeAtomic(nested, '{"x":1}\n');
    assert.equal(statSync(nested).mode & 0o777, 0o600);
    const real = join(d, "dotfiles-settings.json");
    writeFileSync(real, "{}\n");
    const link = join(d, "settings.json");
    symlinkSync(real, link);
    writeAtomic(link, '{"y":2}\n');
    assert.ok(lstatSync(link).isSymbolicLink(), "the link is still a link");
    assert.equal(readlinkSync(link), real);
    assert.equal(readFileSync(real, "utf8"), '{"y":2}\n');
    removeFile(link);
    assert.ok(lstatSync(link).isSymbolicLink(), "remove never deletes a link");
    assert.equal(readFileSync(real, "utf8"), "");
    const dangling = join(d, "dangling.json");
    symlinkSync(join(d, "missing.json"), dangling);
    assert.throws(() => writeAtomic(dangling, "{}"), /symlink to a file that does not exist/);
    removeFile(join(d, "never-existed.json"));
    removeFile(nested);
    assert.equal(existsSync(nested), false);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

function apply(plan: InstructionEdit[]): void {
  for (const e of plan) {
    if (e.edit.text === null) rmSync(e.path);
    else writeAtomic(e.path, e.edit.text);
  }
}

test("a CLAUDE.md above the project puts the block in a new CLAUDE.md at the root; ~/.claude/CLAUDE.md does not count", () => {
  const d = scratch();
  try {
    const mono = join(d, "mono");
    const root = join(mono, "pkg");
    const home = join(d, "home");
    mkdirSync(root, { recursive: true });
    mkdirSync(join(home, ".claude"), { recursive: true });
    assert.deepEqual(claudeMdState(root, home), { present: [], target: null, reason: "no CLAUDE.md, so Claude Code reads AGENTS.md itself (2.1.277 or later)", suppressing: [] });

    writeFileSync(join(mono, "CLAUDE.md"), "# Monorepo\n");
    const above = claudeMdState(root, home);
    assert.deepEqual(above.present, []);
    assert.equal(above.target, join(root, "CLAUDE.md"));
    assert.equal(above.reason, `${join(mono, "CLAUDE.md")} is above the project, so Claude Code does not read AGENTS.md; the block goes in a new CLAUDE.md`);
    assert.deepEqual(above.suppressing, [{ dir: mono, path: join(mono, "CLAUDE.md") }]);

    const plan = planInstructions(root, ["claude", "codex"], false);
    assert.deepEqual(plan.map((e) => [relative(root, e.path), e.edit.action]), [["AGENTS.md", "created"], ["CLAUDE.md", "created"]]);
    apply(plan);
    assert.ok(planInstructions(root, ["claude", "codex"], false).every((e) => e.edit.action === "unchanged"), "a second run changes nothing");
    apply(planInstructions(root, ["claude", "codex"], true));
    assert.equal(existsSync(join(root, "CLAUDE.md")), false, "the CLAUDE.md init made goes again");
    assert.equal(readFileSync(join(mono, "CLAUDE.md"), "utf8"), "# Monorepo\n");

    writeFileSync(join(root, "CLAUDE.local.md"), "# Local\n");
    const both = claudeMdState(root + sep, home);
    assert.equal(both.target, join(root, "CLAUDE.local.md"));
    assert.equal(both.reason, "CLAUDE.local.md exists, so Claude Code does not read AGENTS.md; the block goes there too");
    assert.deepEqual(both.suppressing.map((f) => f.dir), [root, mono]);
    writeFileSync(join(root, "CLAUDE.md"), "@AGENTS.md\n");
    assert.equal(claudeMdState(root, home).target, null, "the root's import wins over the file above");

    const proj = join(home, "proj");
    mkdirSync(proj);
    writeFileSync(join(home, ".claude", "CLAUDE.md"), "# My memory\n");
    assert.equal(claudeMdState(proj, home).target, null);
    assert.equal(claudeMdState(proj, join(d, "elsewhere")).target, join(proj, "CLAUDE.md"));
    writeFileSync(join(home, "CLAUDE.md"), "# Home\n");
    assert.equal(claudeMdState(proj, home).target, join(proj, "CLAUDE.md"));
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("--remove leaves the blocks an agent that stays wired reads, and touches only the removed agent's files", () => {
  const d = scratch();
  try {
    writeFileSync(join(d, "AGENTS.md"), "# P\n");
    writeFileSync(join(d, "AGENTS.override.md"), "# Override\n");
    apply(planInstructions(d, ["claude", "codex"], false));
    const files = (plan: InstructionEdit[]) => plan.map((e) => relative(d, e.path));
    assert.deepEqual(files(planInstructions(d, ["claude"], true, ["codex"])), []);
    assert.deepEqual(files(planInstructions(d, ["codex"], true, ["claude"])), ["AGENTS.override.md"], "Claude Code reads AGENTS.md here");
    assert.deepEqual(files(planInstructions(d, ["claude"], true)), ["AGENTS.md"], "the override is Codex's");
    assert.deepEqual(files(planInstructions(d, ["claude", "codex"], true)), ["AGENTS.md", "AGENTS.override.md"]);

    writeFileSync(join(d, "CLAUDE.md"), "# Claude\n");
    apply(planInstructions(d, ["claude"], false));
    assert.deepEqual(files(planInstructions(d, ["codex"], true, ["claude"])), ["AGENTS.md", "AGENTS.override.md"], "Claude Code reads CLAUDE.md, not AGENTS.md");
    assert.deepEqual(files(planInstructions(d, ["claude"], true, ["codex"])), ["CLAUDE.md"]);
    apply(planInstructions(d, ["claude", "codex"], true));
    for (const [f, text] of [["AGENTS.md", "# P\n"], ["AGENTS.override.md", "# Override\n"], ["CLAUDE.md", "# Claude\n"]]) assert.equal(readFileSync(join(d, f), "utf8"), text, f);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("an @AGENTS.md import counts only outside code, by CommonMark's rules", () => {
  assert.equal(importsAgentsMd("# Notes\n\n@AGENTS.md\n"), true);
  assert.equal(importsAgentsMd("See @./AGENTS.md\r\n"), true);
  assert.equal(importsAgentsMd("```\nx\n```\n@AGENTS.md\n"), true);
  assert.equal(importsAgentsMd("```\n@AGENTS.md\n```\n"), false);
  assert.equal(importsAgentsMd("````\n```\n@AGENTS.md\n````\n"), false, "a shorter fence does not close a longer one");
  assert.equal(importsAgentsMd("```md\n~~~\n@AGENTS.md\n```\n"), false, "a tilde fence does not close a backtick one");
  assert.equal(importsAgentsMd("```sh\n@AGENTS.md\n"), false, "a fence that never closes runs to the end");
  for (const bom of ["﻿```markdown\n@AGENTS.md\n```\n\n# Our rules\n", "﻿~~~\n@AGENTS.md\n~~~\n", "﻿```md\r\n@AGENTS.md\r\n```\r\n"]) assert.equal(importsAgentsMd(bom), false, "a byte-order mark does not hide the fence on line 1");
  assert.equal(importsAgentsMd("﻿@AGENTS.md\n"), true);
  assert.equal(importsAgentsMd("```\r@AGENTS.md\r```\r"), false, "a lone CR ends a line");
  assert.equal(importsAgentsMd("# Notes\r@AGENTS.md\r"), true);
  assert.equal(importsAgentsMd("# Notes\n\n    ```\n@AGENTS.md\n"), true, "four spaces in is indented code, not a fence");
  assert.equal(importsAgentsMd("- ```\n  @AGENTS.md\n  ```\n"), false, "a fence in a list item");
  assert.equal(importsAgentsMd("<!--\n@AGENTS.md\n-->\n"), false, "an HTML comment");
  assert.equal(importsAgentsMd("> ```\n> @AGENTS.md\n> ```\n"), false, "a block quote");
  assert.equal(importsAgentsMd("- > @AGENTS.md\n"), false);
});

test("a CLAUDE.md saved with a byte-order mark and a fenced @AGENTS.md example still gets the block; an AGENTS.md ending in open code gets it on top", () => {
  const d = scratch();
  try {
    writeFileSync(join(d, "AGENTS.md"), "# P\n");
    writeFileSync(join(d, "CLAUDE.md"), "﻿```markdown\n@AGENTS.md\n```\n\n# Our rules\n");
    const s = claudeMdState(d, join(d, "home"));
    assert.equal(s.target, join(d, "CLAUDE.md"));
    assert.deepEqual(planInstructions(d, ["claude"], false).map((e) => [relative(d, e.path), e.edit.action]), [["AGENTS.md", "appended"], ["CLAUDE.md", "appended"]]);
    writeFileSync(join(d, "AGENTS.md"), "# Build\n\n```sh\nmake\n");
    const [agents] = planInstructions(d, ["codex"], false);
    assert.equal(agents.edit.action, "prepended");
    assert.match(agents.why, /at the top of the file: it ends inside a code block that is never closed/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("unexcludeLocally takes out exactly what excludeLocally put in, final newline or not", () => {
  for (const before of ["*.log", "*.log\n", "", "# mine\r\n*.tmp\r\n", "*.log\n\n", "*.log\r\n*.tmp"]) {
    const d = scratch();
    try {
      spawnSync("git", ["init", "-q"], { cwd: d });
      const exclude = join(d, ".git", "info", "exclude");
      writeFileSync(exclude, before);
      const files = [join(d, ".claude", "settings.local.json"), join(d, ".codex", "hooks.json")];
      for (const order of [files, [...files].reverse()]) {
        for (const f of files) assert.equal(excludeLocally(f, false), "excluded", JSON.stringify(before));
        for (const f of [".claude/settings.local.json", ".codex/hooks.json"]) assert.equal(spawnSync("git", ["check-ignore", "-q", "--no-index", f], { cwd: d }).status, 0, `${f} is ignored`);
        for (const f of order) assert.equal(unexcludeLocally(f, false), true);
        assert.equal(readFileSync(exclude, "utf8"), before, JSON.stringify(before));
      }
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
});
