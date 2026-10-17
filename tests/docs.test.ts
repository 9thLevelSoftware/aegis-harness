/**
 * BUG-2026-010: documentation outgrew the code in every earlier attempt.
 * The README stays short enough to read in one sitting, and the files the
 * bug records and README point at exist.
 */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { CLAUDE_MATCHER } from "../src/wiring/claude.ts";
import { CODEX_MATCHER } from "../src/wiring/codex.ts";
import { isOwnedEntry } from "../src/wiring/owned.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const readme = readFileSync(resolve(root, "README.md"), "utf8");
const guard = resolve(root, "dist/guard.mjs");

test("README is under 300 lines", () => {
  const lines = readme.split("\n").length;
  assert.ok(lines <= 300, `README.md is ${lines} lines`);
});

test("README has the sections the bug records link to", () => {
  for (const h of ["## Wiring the hook", "## What it blocks", "## Recording a false positive"]) assert.match(readme, new RegExp(`^${h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "m"), h);
});

test("CONTRIBUTING has the sections the bug records link to", () => {
  const c = readFileSync(resolve(root, "CONTRIBUTING.md"), "utf8");
  assert.match(c, /^## Grow by incident/m);
  assert.match(c, /^## Docs/m);
});

test("local links in the README resolve", () => {
  for (const m of readme.matchAll(/\]\((?!https?:)([^)#]+)(#[^)]*)?\)/g)) {
    assert.ok(existsSync(resolve(root, m[1])), `README links to missing ${m[1]}`);
  }
});

test("there is no plans directory, under any name or nesting", () => {
  const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" }).split("\0").filter(Boolean);
  const offenders = tracked.filter((p) => p.split("/").slice(0, -1).some((seg) => /^(plans|planning|\.planning|roadmaps?)$/i.test(seg)));
  assert.deepEqual(offenders, [], `plans directory exists (${offenders.join(", ")}); design reasoning belongs in .harness/memory/bugs/ and commit messages`);
});

test("the README's sample deny is what the built guard prints for rm -rf /", { skip: !existsSync(guard) && "run npm run build first" }, () => {
  const block = /^```\n(\[ah guard\] denied by [\s\S]*?)\n```$/m.exec(readme);
  assert.ok(block, "README opens with a fenced [ah guard] denied by ... block");
  const payload = { hook_event_name: "PreToolUse", session_id: "t", cwd: "/home/dev/project", tool_name: "Bash", tool_input: { command: "rm -rf /" } };
  const r = spawnSync(process.execPath, [guard, "--agent", "claude", "--root", "/home/dev/project", "--home", "/home/dev", "--platform", "posix", "--no-log"], { input: JSON.stringify(payload), encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const printed = JSON.parse(r.stdout).hookSpecificOutput.permissionDecisionReason as string;
  const norm = (s: string) => s.split("\n").map((l) => l.trimEnd()).join("\n").trim();
  assert.equal(norm(block![1]), norm(printed));
});

test("the README's hand-wired entries are what ah init writes, and ah init would adopt them", () => {
  const blocks = [...readme.matchAll(/^```json\n([\s\S]*?)\n```$/gm)].map((m) => JSON.parse(m[1]) as { matcher: string; hooks: Record<string, unknown>[] });
  const claude = blocks.find((b) => Array.isArray(b.hooks[0].args) && b.hooks[0].args.includes("claude"));
  const codex = blocks.find((b) => String(b.hooks[0].command).endsWith("--agent codex"));
  assert.ok(claude && codex, "README shows a Claude Code and a Codex entry");
  assert.equal(claude.matcher, CLAUDE_MATCHER);
  assert.equal(codex.matcher, CODEX_MATCHER);
  for (const b of [claude, codex]) assert.ok(isOwnedEntry(b.hooks[0]), JSON.stringify(b.hooks[0]));
});
