/**
 * planHooks: ah's PreToolUse group goes in, gets updated, and comes out again
 * without moving or changing anybody else's hooks or settings.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { HookShapeError, planHooks } from "../src/wiring/hooks-json.ts";

const GUARD = "/home/dev/.npm-global/lib/node_modules/@9thlevel/aegis/dist/guard.mjs";
const entry = (extra: Record<string, unknown> = {}) => ({ type: "command", command: "/usr/bin/node", args: [GUARD, "--agent", "claude"], timeout: 5, ...extra });
const group = (extra: Record<string, unknown> = {}) => ({ matcher: "Bash|Edit", hooks: [entry(extra)] });
const build = () => group();
const theirs = { matcher: "Write", hooks: [{ type: "command", command: "npx prettier --write" }] };

test("adds a group to a settings file with no hooks, keeping every other key in order", () => {
  const s = { model: "x", permissions: { allow: ["Bash(ls)"] } };
  const p = planHooks(s, "settings.json", build);
  assert.equal(p.action, "added");
  assert.deepEqual(Object.keys(p.value), ["model", "permissions", "hooks"]);
  assert.deepEqual(p.value.hooks, { PreToolUse: [group()] });
});

test("appends after the user's own groups and leaves other events alone", () => {
  const s = { hooks: { PostToolUse: [theirs], PreToolUse: [theirs] } };
  const p = planHooks(s, "settings.json", build);
  assert.equal(p.action, "added");
  assert.deepEqual(p.value.hooks, { PostToolUse: [theirs], PreToolUse: [theirs, group()] });
});

test("a second run changes nothing and returns the same object", () => {
  const s = { hooks: { PreToolUse: [theirs, group()] } };
  const p = planHooks(s, "settings.json", build);
  assert.equal(p.action, "unchanged");
  assert.equal(p.value, s);
});

test("a stale ah group is replaced in place", () => {
  const old = { matcher: "Bash", hooks: [{ type: "command", command: "/old/node /old/dist/guard.mjs --agent claude" }] };
  const s = { hooks: { PreToolUse: [old, theirs] } };
  const p = planHooks(s, "settings.json", build);
  assert.equal(p.action, "updated");
  assert.deepEqual(p.value.hooks, { PreToolUse: [group(), theirs] });
  assert.equal(p.found.length, 1);
});

test("an ah entry inside the user's group is lifted out; their hooks and matcher stay", () => {
  const mixed = { matcher: "Bash|Write", hooks: [theirs.hooks[0], entry()] };
  const p = planHooks({ hooks: { PreToolUse: [mixed] } }, "settings.json", build);
  assert.equal(p.action, "updated");
  assert.deepEqual(p.value.hooks, { PreToolUse: [group(), { matcher: "Bash|Write", hooks: [theirs.hooks[0]] }] });
  assert.ok(p.notes.some((n) => /moved the ah entry/.test(n)));
});

test("duplicates collapse to one", () => {
  const p = planHooks({ hooks: { PreToolUse: [group(), theirs, group()] } }, "settings.json", build);
  assert.deepEqual(p.value.hooks, { PreToolUse: [group(), theirs] });
  assert.ok(p.notes.some((n) => /found 2 ah entries/.test(n)));
});

test("remove takes out only ah's entries and drops keys it emptied", () => {
  assert.deepEqual(planHooks({ a: 1, hooks: { PreToolUse: [group()] } }, "s", () => null), { value: { a: 1 }, action: "removed", found: [entry()], notes: [] });
  const p = planHooks({ hooks: { PreToolUse: [theirs, group()], Stop: [] } }, "s", () => null);
  assert.deepEqual(p.value, { hooks: { PreToolUse: [theirs], Stop: [] } });
  assert.equal(planHooks({ hooks: {} }, "s", () => null).action, "absent");
  assert.equal(planHooks({}, "s", () => null).action, "absent");
});

test("malformed groups the user wrote are kept, not repaired", () => {
  const weird = ["a string", { matcher: "Bash" }, { hooks: "nope" }];
  const p = planHooks({ hooks: { PreToolUse: weird } }, "s", build);
  assert.deepEqual(p.value.hooks, { PreToolUse: [...weird, group()] });
});

test("a value ah cannot read safely is refused", () => {
  assert.throws(() => planHooks([], "s", build), HookShapeError);
  assert.throws(() => planHooks({ hooks: [] }, "s", build), HookShapeError);
  assert.throws(() => planHooks({ hooks: { PreToolUse: {} } }, "s", build), HookShapeError);
});

test("build sees the entries it replaces", () => {
  let seen: unknown[] = [];
  planHooks({ hooks: { PreToolUse: [group({ timeout: 30 })] } }, "s", (found) => {
    seen = found;
    return group();
  });
  assert.deepEqual(seen, [entry({ timeout: 30 })]);
});
