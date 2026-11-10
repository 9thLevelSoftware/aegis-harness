/**
 * `ah stats`: what the guard has fired on in this project, read from `.harness/metrics.jsonl`.
 * BUG-2026-009 and CONTRIBUTING.md make that log the input to every rule change (a rule nobody has
 * seen fire for a quarter is a candidate for removal); this is how it is read (BUG-2026-022).
 */
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { RULES } from "../guard/rules/registry.ts";

export const STATS_HELP = `ah stats [--root DIR] [--days N] [--json]
    Count denies, asks and overridden ("off") decisions per rule from .harness/metrics.jsonl.
    --days N keeps the last N days.
`;

export interface RuleCount {
  rule: string;
  deny: number;
  ask: number;
  off: number;
  last: string;
}

export interface Stats {
  file: string;
  total: number;
  first: string | null;
  last: string | null;
  rules: RuleCount[];
  /** Registered rules with no line in the window. */
  silent: string[];
  /** Lines that were not a guard decision (not JSON, or another event). */
  skipped: number;
}

/** Tally metrics.jsonl text. `since` (an ISO time) drops older lines. */
export function tally(text: string, file: string, since?: string): Stats {
  const by = new Map<string, RuleCount>();
  let total = 0;
  let skipped = 0;
  let first: string | null = null;
  let last: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    let e: { event?: unknown; ts?: unknown; verdict?: unknown; rule?: unknown };
    try {
      e = JSON.parse(line);
    } catch {
      skipped++;
      continue;
    }
    if (e === null || typeof e !== "object" || e.event !== "ah.guard.decision" || typeof e.ts !== "string" || typeof e.rule !== "string" || (e.verdict !== "deny" && e.verdict !== "ask" && e.verdict !== "off")) {
      skipped++;
      continue;
    }
    if (since !== undefined && e.ts < since) continue;
    total++;
    if (first === null || e.ts < first) first = e.ts;
    if (last === null || e.ts > last) last = e.ts;
    const c = by.get(e.rule) ?? { rule: e.rule, deny: 0, ask: 0, off: 0, last: e.ts };
    c[e.verdict]++;
    if (e.ts > c.last) c.last = e.ts;
    by.set(e.rule, c);
  }
  const rules = [...by.values()].sort((a, b) => b.deny + b.ask + b.off - (a.deny + a.ask + a.off) || a.rule.localeCompare(b.rule));
  const silent = RULES.map((r) => r.id).filter((id) => !by.has(id));
  return { file, total, first, last, rules, silent, skipped };
}

export function renderStats(s: Stats): string {
  if (s.total === 0) return `ah stats: no guard decisions in ${s.file}${s.skipped > 0 ? ` (${s.skipped} other lines)` : ""}.\n`;
  const day = (t: string | null) => (t ?? "").slice(0, 10);
  const width = Math.max(4, ...s.rules.map((r) => r.rule.length));
  const lines = [
    `ah stats: ${s.total} decision${s.total === 1 ? "" : "s"} from ${day(s.first)} to ${day(s.last)} in ${s.file}`,
    `${"rule".padEnd(width)}  deny   ask   off  last`,
    ...s.rules.map((r) => `${r.rule.padEnd(width)}  ${String(r.deny).padStart(4)}  ${String(r.ask).padStart(4)}  ${String(r.off).padStart(4)}  ${day(r.last)}`),
    `${s.rules.length} of ${s.rules.length + s.silent.length} rules fired; ${s.silent.length} never did in this window.`,
  ];
  return `${lines.join("\n")}\n`;
}

export function runStats(argv: readonly string[], io: { stdout: (s: string) => void; stderr: (s: string) => void } = { stdout: (s) => process.stdout.write(s), stderr: (s) => process.stderr.write(s) }, now: Date = new Date()): number {
  if (argv.includes("--help") || argv.includes("-h")) {
    io.stdout(STATS_HELP);
    return 0;
  }
  let root = process.cwd();
  let days: number | undefined;
  let json = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--root" && argv[i + 1] !== undefined) root = argv[++i];
    else if (a === "--days" && argv[i + 1] !== undefined) {
      days = Number(argv[++i]);
      if (!Number.isFinite(days) || days <= 0) {
        io.stderr(`ah stats: --days takes a positive number\n`);
        return 1;
      }
    } else if (a === "--json") json = true;
    else {
      io.stderr(`ah stats: unknown option ${a}\n\n${STATS_HELP}`);
      return 1;
    }
  }
  const file = join(resolve(root), ".harness", "metrics.jsonl");
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    io.stderr(`ah stats: no ${file}; the guard logs there once \`ah init\` has created .harness/ and a call is denied or asked.\n`);
    return 1;
  }
  const since = days === undefined ? undefined : new Date(now.getTime() - days * 86_400_000).toISOString();
  const s = tally(text, file, since);
  io.stdout(json ? `${JSON.stringify(s, null, 2)}\n` : renderStats(s));
  return 0;
}
