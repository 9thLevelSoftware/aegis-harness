import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const here = dirname(fileURLToPath(import.meta.url));
const script = resolve(here, "../scripts/check-hygiene.mjs");

test("no maintainer paths or user names in tracked files (BUG-2026-006)", () => {
  const r = spawnSync(process.execPath, [script], { cwd: resolve(here, ".."), encoding: "utf8" });
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
});

test("the hygiene check itself can fail", () => {
  const dir = mkdtempSync(resolve(tmpdir(), "ah-hygiene-"));
  spawnSync("git", ["init", "-q"], { cwd: dir });
  // Assembled from pieces so this test file itself passes the scan.
  writeFileSync(resolve(dir, "notes.md"), ["logs live in C:/Us", "ers/", "das", "bl", "/.codex/tmp\n"].join(""));
  const r = spawnSync(process.execPath, [script], { cwd: dir, encoding: "utf8" });
  assert.equal(r.status, 1, r.stdout);
  assert.match(r.stdout, /maintainer user name/);
});

test("the hygiene check catches capitalised home directories", () => {
  const dir = mkdtempSync(resolve(tmpdir(), "ah-hygiene-"));
  spawnSync("git", ["init", "-q"], { cwd: dir });
  // Assembled from pieces so this test file itself passes the scan.
  writeFileSync(resolve(dir, "notes.md"), [["/Users/Jo", "hn/code/x"].join(""), ["/home/De", "vil/code/x"].join(""), ""].join("\n"));
  const r = spawnSync(process.execPath, [script], { cwd: dir, encoding: "utf8" });
  assert.equal(r.status, 1, r.stdout);
  assert.match(r.stdout, /notes\.md:1: a real macOS home directory/);
  assert.match(r.stdout, /notes\.md:2: a real Linux home directory/);
});

test("the neutral home directories pass in any case", () => {
  const dir = mkdtempSync(resolve(tmpdir(), "ah-hygiene-"));
  spawnSync("git", ["init", "-q"], { cwd: dir });
  writeFileSync(resolve(dir, "notes.md"), ["/Users/Dev/x", "/home/DEV/x", "/home/User/x", "/home/RUNNER/work", "/Users/dev/x", "/home/dev/x", ""].join("\n"));
  const r = spawnSync(process.execPath, [script], { cwd: dir, encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout);
});
