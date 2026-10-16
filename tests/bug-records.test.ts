/**
 * Every bug record under .harness/memory/bugs/ parses, carries the required
 * keys, and points at fixtures and rules that exist. A rule's provenance may
 * cite a record; a cited record must exist.
 */
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { parse } from "yaml";
import { RULES } from "../src/guard/rules/registry.ts";
import { nextIncidentId, renderBugRecord } from "../src/cli/bug.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const dir = join(root, ".harness", "memory", "bugs");
const files = readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort();
const REQUIRED = ["incident_id", "date_recorded", "status", "title", "observed_on", "source", "root_cause", "impact", "countermeasure", "expiry_policy"];
const ids = new Set(RULES.map((r) => r.id));

test("there are seed records", () => {
  assert.ok(files.length >= 10, `${files.length} records`);
});

for (const f of files) {
  test(`record ${f} is complete`, () => {
    const doc = parse(readFileSync(join(dir, f), "utf8")) as Record<string, unknown>;
    for (const k of REQUIRED) assert.ok(doc[k] !== undefined && doc[k] !== "", `${f}: missing ${k}`);
    assert.equal(`${doc.incident_id}.yaml`, f, `${f}: file name must match incident_id`);
    const cm = doc.countermeasure as { kind: string; ref: string | string[] };
    assert.ok(["rule", "process", "test"].includes(cm.kind), `${f}: countermeasure.kind`);
    const refs = Array.isArray(cm.ref) ? cm.ref : [cm.ref];
    for (const ref of refs) {
      if (cm.kind === "rule") assert.ok(ids.has(ref), `${f}: countermeasure.ref ${ref} is not a registered rule`);
      else assert.ok(existsSync(join(root, ref.split("#")[0])), `${f}: countermeasure.ref ${ref} does not exist in the repo`);
    }
    for (const k of ["must_block_fixture", "must_allow_fixture"]) {
      const v = doc[k];
      if (typeof v === "string" && v !== "") assert.ok(existsSync(join(root, v)), `${f}: ${k} ${v} does not exist`);
    }
  });
}

test("every record cited by a rule's provenance exists", () => {
  const have = new Set(files.map((f) => f.replace(/\.ya?ml$/, "")));
  for (const r of RULES) {
    const m = /BUG-\d{4}-\d{3,}/.exec(r.provenance);
    if (m) assert.ok(have.has(m[0]), `${r.id} cites ${m[0]}, which has no record`);
  }
});

test("ah bug add numbers records after the existing ones and renders the schema", () => {
  const id = nextIncidentId(dir, 2026);
  assert.match(id, /^BUG-2026-\d{3}$/);
  const n = Number(id.slice(-3));
  assert.ok(n > files.length - 1);
  const doc = parse(renderBugRecord(id, "2026-10-16", { rule: "edit.lint-config", title: "t" })) as Record<string, unknown>;
  for (const k of REQUIRED) assert.ok(doc[k] !== undefined, k);
});
