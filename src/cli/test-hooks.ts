/**
 * `ah test-hooks`: replay the fixture corpus through the guard.
 *
 * Each fixture is one hook payload plus the verdict it must produce. Fixtures
 * live in three directories whose names carry the expectation:
 * `must_block/` (deny), `must_allow/` (allow), `must_ask/` (ask). Every fixture
 * runs twice: in-process against the decision core, and end to end through the
 * bundled guard process over stdin, which is what the agent actually runs.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluate } from "../guard/main.ts";
import type { Verdict } from "../guard/model.ts";
import type { Agent } from "../guard/normalize.ts";

export interface Fixture {
  file: string;
  name: string;
  expect: Verdict;
  agent: Agent;
  platform: "posix" | "windows";
  cwd: string;
  /** The project root, when it is not the payload's cwd: Claude Code's CLAUDE_PROJECT_DIR after the agent ran `cd`. */
  root: string;
  home: string;
  payload: Record<string, unknown>;
  rule?: string;
  near?: string;
  source?: string;
}

const DIR_EXPECT: Record<string, Verdict> = { must_block: "deny", must_allow: "allow", must_ask: "ask" };

export function loadFixtures(dir: string): Fixture[] {
  const out: Fixture[] = [];
  for (const [sub, expect] of Object.entries(DIR_EXPECT)) {
    const d = join(dir, sub);
    if (!existsSync(d)) continue;
    for (const f of readdirSync(d).sort()) {
      if (!f.endsWith(".json")) continue;
      const file = join(d, f);
      const raw = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
      if (raw.expect !== undefined && raw.expect !== expect) {
        throw new Error(`${file}: "expect": "${String(raw.expect)}" disagrees with its directory (${sub})`);
      }
      const platform = raw.platform === "windows" ? "windows" : "posix";
      const cwd = typeof raw.cwd === "string" ? raw.cwd : platform === "windows" ? "C:\\Users\\dev\\project" : "/home/dev/project";
      out.push({
        file,
        name: typeof raw.name === "string" ? raw.name : f,
        expect,
        agent: raw.agent === "codex" ? "codex" : "claude",
        platform,
        cwd,
        home: typeof raw.home === "string" ? raw.home : platform === "windows" ? "C:\\Users\\dev" : "/home/dev",
        root: typeof raw.root === "string" ? raw.root : cwd,
        payload: (raw.payload ?? {}) as Record<string, unknown>,
        rule: typeof raw.rule === "string" ? raw.rule : undefined,
        near: typeof raw.near === "string" ? raw.near : undefined,
        source: typeof raw.source === "string" ? raw.source : undefined,
      });
    }
  }
  return out;
}

/** The payload exactly as an agent would send it. */
export function fullPayload(fx: Fixture): Record<string, unknown> {
  const base: Record<string, unknown> = {
    session_id: "fixture",
    transcript_path: fx.agent === "codex" ? "/tmp/.codex/fixture.jsonl" : "/tmp/fixture.jsonl",
    cwd: fx.cwd,
    hook_event_name: "PreToolUse",
    permission_mode: "default",
    ...(fx.agent === "codex" ? { turn_id: "fixture", model: "fixture" } : { tool_use_id: "fixture" }),
  };
  return { ...base, ...fx.payload };
}

export interface FixtureResult {
  fixture: Fixture;
  mode: "in-process" | "subprocess";
  verdict: Verdict;
  rule?: string;
  reason?: string;
  ok: boolean;
  ms?: number;
  error?: string;
}

export function runInProcess(fx: Fixture): FixtureResult {
  const { decision } = evaluate(fullPayload(fx), { agent: fx.agent, root: fx.root, home: fx.home, platform: fx.platform, log: false }, {});
  const ok = decision.verdict === fx.expect && (fx.rule === undefined || fx.expect === "allow" || decision.rule === fx.rule);
  return { fixture: fx, mode: "in-process", verdict: decision.verdict, rule: decision.rule, reason: decision.reason, ok };
}

export function runSubprocess(fx: Fixture, guardPath: string): FixtureResult {
  const args = [guardPath, "--agent", fx.agent, "--output", "claude", "--root", fx.root, "--home", fx.home, "--platform", fx.platform, "--no-log"];
  const started = process.hrtime.bigint();
  const r = spawnSync(process.execPath, args, { input: JSON.stringify(fullPayload(fx)), encoding: "utf8", timeout: 20_000 });
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  if (r.error || r.status !== 0) {
    return { fixture: fx, mode: "subprocess", verdict: "allow", ok: false, ms, error: r.error?.message ?? `exit ${r.status}: ${r.stderr}` };
  }
  let verdict: Verdict = "allow";
  let rule: string | undefined;
  let reason: string | undefined;
  const text = r.stdout.trim();
  if (text !== "") {
    try {
      const parsed = JSON.parse(text) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string; additionalContext?: string } };
      const d = parsed.hookSpecificOutput?.permissionDecision;
      if (d === "deny" || d === "ask") verdict = d;
      reason = parsed.hookSpecificOutput?.permissionDecisionReason;
      // deny: "[ah guard] denied by <rule>: ..." in the reason; ask (Claude Code output):
      // "[ah guard] <rule>: ..." in the reason and the full explanation in additionalContext.
      const explained = [reason, parsed.hookSpecificOutput?.additionalContext].filter(Boolean).join("\n");
      rule = /(?:\bby|\[ah guard\]) ([a-z]+\.[a-z0-9-]+):/.exec(explained)?.[1];
    } catch {
      return { fixture: fx, mode: "subprocess", verdict: "allow", ok: false, ms, error: `guard printed non-JSON: ${text.slice(0, 200)}` };
    }
  }
  const ok = verdict === fx.expect && (fx.rule === undefined || fx.expect === "allow" || rule === fx.rule);
  return { fixture: fx, mode: "subprocess", verdict, rule, reason, ok, ms };
}

export function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

export interface TestHooksOptions {
  fixtures?: string[];
  guard?: string;
  inProcess?: boolean;
  budgetMs?: number;
  filter?: string;
  json?: boolean;
}

export function parseTestHooksArgs(argv: readonly string[]): TestHooksOptions {
  const o: TestHooksOptions = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = () => argv[++i] ?? "";
    if (a === "--fixtures") (o.fixtures ??= []).push(v());
    else if (a === "--guard") o.guard = v();
    else if (a === "--in-process") o.inProcess = true;
    else if (a === "--budget-ms") o.budgetMs = Number(v());
    else if (a === "--filter") o.filter = v();
    else if (a === "--json") o.json = true;
  }
  return o;
}

function defaultFixtureDirs(): string[] {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [resolve(here, "../fixtures"), resolve(here, "../../fixtures")];
  const dirs = candidates.filter((d) => existsSync(d)).slice(0, 1);
  const project = resolve(process.cwd(), ".harness", "hook_tests");
  if (existsSync(project) && statSync(project).isDirectory()) dirs.push(project);
  return dirs;
}

/** The bundled guard next to this file (dist/), or the repository's dist/ when run from source. */
export function defaultGuardPath(): string | undefined {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const c of [resolve(here, "guard.mjs"), resolve(here, "../dist/guard.mjs"), resolve(here, "../../dist/guard.mjs")]) {
    if (existsSync(c)) return c;
  }
  return undefined;
}

export function runTestHooks(argv: readonly string[], write: (s: string) => void = (s) => process.stdout.write(s)): number {
  const o = parseTestHooksArgs(argv);
  const dirs = o.fixtures && o.fixtures.length > 0 ? o.fixtures.map((d) => resolve(d)) : defaultFixtureDirs();
  let fixtures = dirs.flatMap((d) => loadFixtures(d));
  if (o.filter) fixtures = fixtures.filter((f) => f.name.includes(o.filter as string) || f.file.includes(o.filter as string));
  if (fixtures.length === 0) {
    write(`ah test-hooks: no fixtures found in ${dirs.join(", ")}\n`);
    return 1;
  }
  const guardPath = o.inProcess ? undefined : (o.guard ? resolve(o.guard) : defaultGuardPath());
  if (!o.inProcess && !guardPath) {
    write("ah test-hooks: no built guard found (run `npm run build`, or pass --guard FILE, or use --in-process)\n");
    return 1;
  }

  const results: FixtureResult[] = [];
  for (const fx of fixtures) {
    results.push(runInProcess(fx));
    if (guardPath) results.push(runSubprocess(fx, guardPath));
  }
  const failures = results.filter((r) => !r.ok);
  const latencies = results.filter((r) => r.mode === "subprocess" && r.ms !== undefined).map((r) => r.ms as number);
  const p50 = percentile(latencies, 50);
  const p95 = percentile(latencies, 95);
  const max = latencies.length ? Math.max(...latencies) : 0;
  const budgetBroken = o.budgetMs !== undefined && latencies.length > 0 && p95 > o.budgetMs;

  const summary = {
    fixtures: fixtures.length,
    byExpectation: { deny: fixtures.filter((f) => f.expect === "deny").length, allow: fixtures.filter((f) => f.expect === "allow").length, ask: fixtures.filter((f) => f.expect === "ask").length },
    runs: results.length,
    failures: failures.length,
    latencyMs: latencies.length ? { p50: round(p50), p95: round(p95), max: round(max), samples: latencies.length } : undefined,
    budgetMs: o.budgetMs,
    budgetBroken,
    ok: failures.length === 0 && !budgetBroken,
  };

  if (o.json) {
    write(`${JSON.stringify({ summary, failures: failures.map(describeFailure) }, null, 2)}\n`);
  } else {
    for (const f of failures) write(`FAIL ${f.mode.padEnd(10)} ${f.fixture.name}\n     expected ${f.fixture.expect}${f.fixture.rule ? ` (${f.fixture.rule})` : ""}, got ${f.verdict}${f.rule ? ` (${f.rule})` : ""}${f.error ? `, error: ${f.error}` : ""}\n     ${f.fixture.file}\n`);
    write(`\n${fixtures.length} fixtures (${summary.byExpectation.deny} must_block, ${summary.byExpectation.allow} must_allow, ${summary.byExpectation.ask} must_ask), ${results.length} runs, ${failures.length} failed.\n`);
    if (summary.latencyMs) write(`guard latency: p50 ${summary.latencyMs.p50} ms, p95 ${summary.latencyMs.p95} ms, max ${summary.latencyMs.max} ms over ${summary.latencyMs.samples} runs${o.budgetMs !== undefined ? ` (budget p95 <= ${o.budgetMs} ms: ${budgetBroken ? "BROKEN" : "ok"})` : ""}\n`);
    write(summary.ok ? "ok\n" : "FAILED\n");
  }
  return summary.ok ? 0 : 1;
}

function describeFailure(f: FixtureResult): Record<string, unknown> {
  return { file: f.fixture.file, name: f.fixture.name, mode: f.mode, expected: f.fixture.expect, expectedRule: f.fixture.rule, got: f.verdict, gotRule: f.rule, reason: f.reason, error: f.error };
}

function round(n: number): number {
  return Math.round(n * 10) / 10;
}
