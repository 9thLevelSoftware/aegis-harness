/**
 * End-to-end: the bundled guard over stdin, the way an agent runs it.
 * Needs `npm run build` first; CI runs build before test.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { percentile } from "../src/cli/test-hooks.ts";

const here = dirname(fileURLToPath(import.meta.url));
const guard = resolve(here, "../dist/guard.mjs");
const built = existsSync(guard);

function run(payload: unknown, args: string[] = []) {
  return spawnSync(process.execPath, [guard, "--no-log", "--root", "/home/dev/project", "--home", "/home/dev", "--platform", "posix", ...args], { input: JSON.stringify(payload), encoding: "utf8" });
}

test("deny over stdin", { skip: !built && "run npm run build first" }, () => {
  const r = run({ hook_event_name: "PreToolUse", session_id: "t", cwd: "/home/dev/project", tool_name: "Bash", tool_input: { command: "rm -rf /" } });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision, "deny");
});

test("allow is silent", { skip: !built && "run npm run build first" }, () => {
  const r = run({ hook_event_name: "PreToolUse", session_id: "t", cwd: "/home/dev/project", tool_name: "Bash", tool_input: { command: "npm test" } });
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "");
});

test("malformed input is a non-blocking error (exit 1), never a crash", { skip: !built && "run npm run build first" }, () => {
  const r = spawnSync(process.execPath, [guard, "--no-log"], { input: "not json", encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /not JSON/);
  const empty = spawnSync(process.execPath, [guard, "--no-log"], { input: "", encoding: "utf8" });
  assert.equal(empty.status, 1);
});

test("per-call latency budget", { skip: !built && "run npm run build first" }, () => {
  // BUG-2026-003: clodex declined tool hooks because "each hook starts a
  // process, which would slow every tool call". This is the measurement that
  // answers it. Budget is p95 over 25 calls on a representative payload.
  const budget = Number(process.env.AH_LATENCY_BUDGET_MS ?? (process.platform === "win32" ? 400 : 150));
  const payload = JSON.stringify({ hook_event_name: "PreToolUse", session_id: "t", cwd: "/home/dev/project", tool_name: "Bash", tool_input: { command: "git fetch origin && git rebase origin/main && npm test -- --reporter dot" } });
  const samples: number[] = [];
  run(JSON.parse(payload)); // warm the OS file cache once; the agent's second call sees this state too
  for (let i = 0; i < 25; i++) {
    const t0 = process.hrtime.bigint();
    const r = spawnSync(process.execPath, [guard, "--no-log"], { input: payload, encoding: "utf8" });
    samples.push(Number(process.hrtime.bigint() - t0) / 1e6);
    assert.equal(r.status, 0, r.stderr);
  }
  const p50 = percentile(samples, 50);
  const p95 = percentile(samples, 95);
  console.log(`guard latency: p50 ${p50.toFixed(1)} ms, p95 ${p95.toFixed(1)} ms, max ${Math.max(...samples).toFixed(1)} ms (budget p95 <= ${budget} ms)`);
  assert.ok(p95 <= budget, `p95 ${p95.toFixed(1)} ms exceeds the ${budget} ms budget`);
});
