/**
 * Which hook entries are ah's. An entry is ah's when every command form it
 * carries runs the guard and nothing else: `node .../dist/guard.mjs --agent
 * claude|codex` or `ah guard`, followed only by the guard's own options. That
 * covers what `ah init` writes and what the README told people to write by
 * hand before it existed, so `ah init` adopts a hand-wired entry instead of
 * adding a second one. A command that wraps or chains the guard, sets
 * variables, or runs another vendor's guard.mjs is the user's and is never
 * touched; looksLikeGuard() lets the report say so.
 */
import { readFileSync } from "node:fs";

/** Split a command line into words. Quotes group; backslashes stay literal (Windows paths). */
export function splitWords(command: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: '"' | "'" | null = null;
  let has = false;
  for (const ch of command) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      has = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (has || cur !== "") out.push(cur);
      cur = "";
      has = false;
      continue;
    }
    cur += ch;
    has = true;
  }
  if (has || cur !== "") out.push(cur);
  return out;
}

export const GUARD_FILE = /(^|[\\/])dist[\\/]guard\.mjs$/i;
const AH_BIN = /(^|[\\/])(ah|aegis)(\.cmd|\.ps1|\.exe)?$/i;
const NODE_BIN = /(^|[\\/])node(\.exe)?$/i;

/** The guard's options (src/guard/main.ts parseGuardArgs): these take a value... */
const VALUED = new Set(["--agent", "--output", "--root", "--ask-fallback", "--platform", "--home"]);
/** ...and this one does not. */
const BARE = new Set(["--no-log"]);

/** Words that may come before `ah` when it is the command being run: `npx ah`, `pnpm exec ah`, `& 'ah.cmd'`. */
const RUNNER_WORDS = new Set(["&", "call", "npx", "pnpx", "bunx", "npm", "pnpm", "yarn", "bun", "exec", "dlx", "x", "--no-install", "--no", "-y", "--yes", "-q", "--quiet"]);

/** Guard options as [flag, value] pairs, or null when a word is anything else. */
export function parseGuardOptions(words: readonly string[]): [string, string | undefined][] | null {
  const out: [string, string | undefined][] = [];
  for (let i = 0; i < words.length; i++) {
    const a = words[i];
    const eq = a.startsWith("--") ? a.indexOf("=") : -1;
    const flag = eq > 0 ? a.slice(0, eq) : a;
    if (BARE.has(a)) out.push([a, undefined]);
    else if (VALUED.has(flag) && eq > 0) out.push([flag, a.slice(eq + 1)]);
    else if (VALUED.has(flag) && i + 1 < words.length) out.push([flag, words[++i]]);
    else return null;
  }
  return out;
}

/** The guard's own arguments in a command form that runs only the guard, or null. */
export function guardArgs(words: readonly string[]): string[] | null {
  let i = 0;
  while (words[i] === "&" || words[i]?.toLowerCase() === "call") i++;
  const first = words[i]?.replace(/^&\s*/, "");
  if (first !== undefined && NODE_BIN.test(first) && GUARD_FILE.test(words[i + 1] ?? "")) {
    const rest = words.slice(i + 2);
    const opts = parseGuardOptions(rest);
    const agent = opts?.find(([f]) => f === "--agent")?.[1];
    return opts && (agent === "claude" || agent === "codex") && guardPackageIsOurs(words[i + 1]) ? rest : null;
  }
  let j = 0;
  while (j < words.length && RUNNER_WORDS.has(words[j].toLowerCase())) j++;
  const bin = words[j]?.replace(/^&\s*/, "");
  if (bin !== undefined && AH_BIN.test(bin) && words[j + 1] === "guard") {
    const rest = words.slice(j + 2);
    return parseGuardOptions(rest) ? rest : null;
  }
  return null;
}

/**
 * False only when the guard file belongs to some other package: dist/guard.mjs
 * is a common name. A guard that is gone (an old install) still counts, so
 * `ah init` can replace the stale entry and `ah doctor` can say it is stale.
 */
function guardPackageIsOurs(guard: string): boolean {
  const pkg = guard.replace(GUARD_FILE, (m, sep: string) => `${sep}package.json`);
  try {
    return (JSON.parse(readFileSync(pkg, "utf8")) as { name?: unknown }).name === "@9thlevel/aegis";
  } catch {
    return true;
  }
}

/** The words of every command form an entry carries (`command`, `args`, `commandWindows`). */
export function entryWords(entry: Record<string, unknown>): string[][] {
  const forms: string[][] = [];
  const args = Array.isArray(entry.args) ? entry.args.filter((a): a is string => typeof a === "string") : null;
  if (typeof entry.command === "string") forms.push(args ? [entry.command, ...args] : splitWords(entry.command));
  if (typeof entry.commandWindows === "string") forms.push(splitWords(entry.commandWindows));
  return forms;
}

export function isOwnedEntry(entry: unknown): boolean {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return false;
  const e = entry as Record<string, unknown>;
  if (e.type !== undefined && e.type !== "command") return false;
  const forms = entryWords(e);
  return forms.length > 0 && forms.every((w) => guardArgs(w) !== null);
}

/** An entry that mentions the guard but is not ah's by the rule above: someone wrapped or changed it. */
export function looksLikeGuard(entry: unknown): boolean {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry) || isOwnedEntry(entry)) return false;
  return entryWords(entry as Record<string, unknown>).some((w) => w.some((x, i) => GUARD_FILE.test(x.replace(/^&\s*/, "")) || (AH_BIN.test(x) && w[i + 1] === "guard")));
}

/** Options a person may have added to the guard command that `ah init` carries over. */
export interface CarriedOptions {
  askFallback?: "deny" | "warn";
  noLog?: boolean;
  /** --root, --home, --platform and --output, as `--flag value` words in the order found. */
  extra?: string[];
}

export function carriedOptions(entry: Record<string, unknown>): CarriedOptions {
  const o: CarriedOptions = {};
  for (const w of entryWords(entry)) {
    const args = guardArgs(w);
    const opts = args && parseGuardOptions(args);
    if (!opts) continue;
    const extra: string[] = [];
    for (const [flag, v] of opts) {
      if (flag === "--ask-fallback" && (v === "warn" || v === "deny")) o.askFallback = v;
      else if (flag === "--no-log") o.noLog = true;
      else if (flag !== "--agent" && flag !== "--ask-fallback" && v !== undefined) extra.push(flag, v);
    }
    if (extra.length > 0 && o.extra === undefined) o.extra = extra;
  }
  return o;
}
