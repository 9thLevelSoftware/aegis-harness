/**
 * Meta-test: prove `ah test-hooks` can go red. BUG-2026-004 records a
 * harness whose own post-mortem found a third of its self-written checks
 * could not fail. A fixture runner that always passes is worse than none.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { runTestHooks } from "../src/cli/test-hooks.ts";

const here = dirname(fileURLToPath(import.meta.url));
const cli = resolve(here, "../dist/ah.mjs");
const fixturesDir = resolve(here, "../fixtures");
const built = existsSync(cli);

function tmpFixtures(spec: Record<string, Array<Record<string, unknown>>>): string {
  const dir = mkdtempSync(join(tmpdir(), "ah-fixtures-"));
  for (const [sub, list] of Object.entries(spec)) {
    mkdirSync(join(dir, sub));
    list.forEach((f, i) => writeFileSync(join(dir, sub, `${i}.json`), JSON.stringify(f)));
  }
  return dir;
}

test("a wrong expectation makes the in-process runner fail and name the fixture", () => {
  const dir = tmpFixtures({ must_block: [{ name: "echo is wrongly expected to be blocked", rule: "shell.fork-bomb", payload: { tool_name: "Bash", tool_input: { command: "echo hello" } } }] });
  let out = "";
  const code = runTestHooks(["--fixtures", dir, "--in-process"], (s) => { out += s; });
  assert.equal(code, 1);
  assert.match(out, /FAIL in-process\s+echo is wrongly expected to be blocked/);
  assert.match(out, /expected deny \(shell\.fork-bomb\), got allow/);
});

test("a correct rule id is required, not just the verdict", () => {
  const dir = tmpFixtures({ must_block: [{ name: "right verdict, wrong rule", rule: "shell.fork-bomb", payload: { tool_name: "Bash", tool_input: { command: "rm -rf /" } } }] });
  let out = "";
  const code = runTestHooks(["--fixtures", dir, "--in-process"], (s) => { out += s; });
  assert.equal(code, 1);
  assert.match(out, /got deny \(shell\.rm-recursive-root\)/);
});

test("a fixture whose expect field contradicts its directory is rejected", () => {
  const dir = tmpFixtures({ must_allow: [{ name: "x", expect: "deny", near: "shell.fork-bomb", payload: { tool_name: "Bash", tool_input: { command: "ls" } } }] });
  assert.throws(() => runTestHooks(["--fixtures", dir, "--in-process"], () => {}), /disagrees with its directory/);
});

test("an always-allow guard binary fails the real corpus end to end", { skip: !built && "run npm run build first" }, () => {
  const stub = join(mkdtempSync(join(tmpdir(), "ah-stub-")), "guard.mjs");
  writeFileSync(stub, "process.stdin.resume(); process.stdin.on('end', () => process.exit(0));\n");
  const r = spawnSync(process.execPath, [cli, "test-hooks", "--fixtures", fixturesDir, "--guard", stub, "--filter", "rm -rf / is denied"], { encoding: "utf8" });
  assert.equal(r.status, 1, r.stdout);
  assert.match(r.stdout, /FAIL subprocess/);
});

test("the real corpus passes end to end", { skip: !built && "run npm run build first" }, () => {
  const r = spawnSync(process.execPath, [cli, "test-hooks", "--fixtures", fixturesDir, "--json"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout);
  const j = JSON.parse(r.stdout);
  assert.equal(j.summary.failures, 0);
  assert.ok(j.summary.fixtures >= 60);
});
