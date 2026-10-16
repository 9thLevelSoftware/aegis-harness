import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { loadFixtures, runInProcess } from "../src/cli/test-hooks.ts";
import { RULES } from "../src/guard/rules/registry.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = loadFixtures(resolve(here, "../fixtures"));
const ids = new Set(RULES.map((r) => r.id));

test("the corpus is large enough to mean something", () => {
  const deny = fixtures.filter((f) => f.expect === "deny").length;
  const allow = fixtures.filter((f) => f.expect === "allow").length;
  assert.ok(deny >= 30, `${deny} must_block fixtures, need at least 30`);
  assert.ok(allow >= 30, `${allow} must_allow fixtures, need at least 30`);
});

test("every fixture names a registered rule", () => {
  for (const f of fixtures) {
    if (f.expect === "allow") assert.ok(f.near && ids.has(f.near), `${f.file}: "near" must name a registered rule (got ${f.near})`);
    else assert.ok(f.rule && ids.has(f.rule), `${f.file}: "rule" must name a registered rule (got ${f.rule})`);
  }
});

test("every rule has a fixture on each side", () => {
  const firing = new Set(fixtures.filter((f) => f.expect !== "allow").map((f) => f.rule));
  const near = new Set(fixtures.filter((f) => f.expect === "allow").map((f) => f.near));
  const missingFire = RULES.filter((r) => !firing.has(r.id)).map((r) => r.id);
  const missingNear = RULES.filter((r) => !near.has(r.id)).map((r) => r.id);
  assert.deepEqual(missingFire, [], `rules with no must_block/must_ask fixture: ${missingFire.join(", ")}`);
  assert.deepEqual(missingNear, [], `rules with no must_allow neighbour: ${missingNear.join(", ")}`);
});

test("a must_block or must_ask fixture's rule has that verdict in the registry", () => {
  for (const f of fixtures) {
    if (f.expect === "allow" || !f.rule) continue;
    const info = RULES.find((r) => r.id === f.rule);
    assert.ok(info, f.file);
    assert.equal(info?.verdict, f.expect, `${f.file}: rule ${f.rule} is registered as ${info?.verdict} but the fixture expects ${f.expect}`);
  }
});

for (const f of fixtures) {
  test(`${f.expect.padEnd(5)} ${f.name}`, () => {
    const r = runInProcess(f);
    assert.ok(r.ok, `expected ${f.expect}${f.rule ? ` (${f.rule})` : ""}, got ${r.verdict}${r.rule ? ` (${r.rule})` : ""}${r.reason ? `: ${r.reason}` : ""}`);
  });
}
