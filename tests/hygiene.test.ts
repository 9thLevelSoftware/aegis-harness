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
