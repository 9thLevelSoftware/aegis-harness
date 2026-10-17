/**
 * The managed AGENTS.md block and the file helpers `ah init` writes through:
 * user content outside the markers survives byte for byte, line endings and a
 * byte-order mark are kept, a malformed block is refused, JSON that cannot be
 * read back exactly is refused, symlinks are written through and never deleted.
 */
import assert from "node:assert/strict";
import { lstatSync, mkdtempSync, readFileSync, readlinkSync, rmSync, statSync, symlinkSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { BLOCK_BEGIN, BLOCK_END, BlockError, readBlock, removeBlock, upsertBlock } from "../src/wiring/text-block.ts";
import { formatJson, readJson, removeFile, writeAtomic } from "../src/wiring/files.ts";
import { agentsBlockLines, AGENTS_BLOCK_BODY } from "../src/wiring/agents-md.ts";

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
  assert.ok(e.text!.startsWith("# Project\n\nUse pnpm.\n\n<!-- ah:begin"));
  assert.ok(e.text!.endsWith(`${BLOCK_END}\n`));
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

test("remove restores the file as it was before the block was appended", () => {
  for (const user of ["# P\n", "# P\n\nx\n", "# P", "# P\r\n"]) {
    const added = upsertBlock(user, body, "AGENTS.md").text!;
    const removed = removeBlock(added, "AGENTS.md");
    assert.equal(removed.action, "removed");
    assert.equal(removed.text?.replace(/\r?\n$/, ""), user.replace(/\r?\n$/, ""), JSON.stringify(user));
  }
});

test("remove of a block in the middle keeps the text on both sides", () => {
  const text = `a\n\n${BLOCK_BEGIN}\nx\n${BLOCK_END}\n\nb\n`;
  assert.equal(removeBlock(text, "AGENTS.md").text, "a\n\n\nb\n");
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
