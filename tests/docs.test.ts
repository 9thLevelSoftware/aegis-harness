/**
 * BUG-2026-010: documentation outgrew the code in every earlier attempt.
 * The README stays short enough to read in one sitting, and the files the
 * bug records and README point at exist.
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const readme = readFileSync(resolve(root, "README.md"), "utf8");

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

test("there is no plans directory", () => {
  for (const d of ["plans", ".planning", "docs/plans"]) assert.ok(!existsSync(resolve(root, d)), `${d}/ exists; design reasoning belongs in .harness/memory/bugs/ and commit messages`);
});
