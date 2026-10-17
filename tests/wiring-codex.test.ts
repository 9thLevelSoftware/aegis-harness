/**
 * Codex wiring helpers, per what Codex 0.163.0 did with test files
 * (BUG-2026-019): how a matcher selects a tool, and the command ah writes.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { CODEX_MATCHER, CODEX_REQUIRED_TOOLS, codexCommand, codexMatcherCovers, posixQuote } from "../src/wiring/codex.ts";
import type { Machine } from "../src/wiring/project.ts";

const apply = CODEX_REQUIRED_TOOLS[1].names;

test("a matcher of plain names is a list of exact names; anything else is a regex search", () => {
  assert.ok(codexMatcherCovers(CODEX_MATCHER, ["Bash"]));
  assert.ok(codexMatcherCovers(CODEX_MATCHER, apply), "Edit and Write select apply_patch");
  assert.equal(codexMatcherCovers("Bas", ["Bash"]), false, "Codex: Bas does not match Bash");
  assert.equal(codexMatcherCovers("Ba|Zzz", ["Bash"]), false);
  assert.equal(codexMatcherCovers("bash", ["Bash"]), false, "case-sensitive");
  assert.ok(codexMatcherCovers("Ba.h", ["Bash"]));
  assert.ok(codexMatcherCovers("^Bash$", ["Bash"]));
  assert.ok(codexMatcherCovers("*", ["Bash"]));
  assert.ok(codexMatcherCovers(undefined, ["Bash"]));
  assert.equal(codexMatcherCovers("Bash", apply), false, "Bash alone skips apply_patch");
});

test("the command quotes what bash and zsh would split, and nothing else", () => {
  assert.equal(posixQuote("/usr/local/bin/node"), "/usr/local/bin/node");
  assert.equal(posixQuote("/Users/dev/My Tools/node"), "'/Users/dev/My Tools/node'");
  assert.equal(posixQuote("/home/dev/it's/node"), `'/home/dev/it'\\''s/node'`);
  const m = { root: "/home/dev/project", home: "/home/dev", os: "linux", env: {}, nodePath: "/home/dev/.nvm/versions/node/v22.18.0/bin/node", guardPath: "/home/dev/My Tools/aegis/dist/guard.mjs" } as unknown as Machine;
  assert.equal(codexCommand(m, ["--agent", "codex"]).command, "/home/dev/.nvm/versions/node/v22.18.0/bin/node '/home/dev/My Tools/aegis/dist/guard.mjs' --agent codex");
});
