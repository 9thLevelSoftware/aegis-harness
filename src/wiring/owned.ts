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

/** The characters PowerShell reads as quotes: ' and U+2018 to U+201B as single, " and U+201C to U+201E as double. */
const PS_QUOTE: Record<"'" | '"', RegExp> = { "'": /^['\u2018-\u201B]$/, '"': /^["\u201C-\u201E]$/ };

/**
 * Split a command line into words, the way the shell it is written for reads
 * every form ah writes. Quotes group; backslashes stay literal (Windows
 * paths), except that `posix` reads `\'` outside quotes as the apostrophe
 * posixQuote writes it as. `powershell` (the default for a line that starts
 * with the call operator `&`, which no other shell takes) reads PS_QUOTE as
 * quotes, and two of a kind inside quotes of that kind as the second one.
 */
export function splitWords(command: string, shell: "posix" | "powershell" = /^\s*&/.test(command) ? "powershell" : "posix"): string[] {
  const ps = shell === "powershell";
  const is = (kind: "'" | '"', c: string | undefined) => c !== undefined && (ps ? PS_QUOTE[kind].test(c) : c === kind);
  const chars = [...command];
  const out: string[] = [];
  let cur = "";
  let quote: '"' | "'" | null = null;
  let has = false;
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    if (quote) {
      if (!is(quote, ch)) cur += ch;
      else if (ps && is(quote, chars[i + 1])) cur += chars[++i];
      else quote = null;
      continue;
    }
    if (is("'", ch) || is('"', ch)) {
      quote = is("'", ch) ? "'" : '"';
      has = true;
      continue;
    }
    if (!ps && ch === "\\" && chars[i + 1] === "'") {
      cur += chars[++i];
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

/**
 * The words of a commandWindows as ah wrote it before it read typographic
 * quotes the way PowerShell does: the `& '...'` form, with node and guard
 * single-quoted, options bare or single-quoted and only ASCII ' doubled, so
 * U+2018 to U+201B stayed single; or the cmd.exe form, a bare node, then the
 * guard and options bare or in double quotes that could hold U+201C to U+201E.
 * PowerShell ends a string at such a quote. Reading these lines the way they
 * were written lets `ah init` replace them and --remove take them out. Null
 * unless quoting these words that way gives back exactly this line.
 */
function legacyWindowsWords(command: string): string[] | null {
  const ps = command.startsWith("& ");
  const words = [...command.matchAll(ps ? /'((?:[^']|'')*)'|\S+/g : /"([^"]*)"|\S+/g)].map((t) => (t[1] === undefined ? t[0] : ps ? t[1].replace(/''/g, "'") : t[1]));
  const q = (w: string) => (ps ? `'${w.replace(/'/g, "''")}'` : `"${w}"`);
  const again = words.map((w, i) => (i === 0 ? w : (ps && i < 3) || !/^[A-Za-z0-9_\\/.:@~+=,-]+$/.test(w) ? q(w) : w));
  return again.join(" ") === command ? words : null;
}

/** The words of every command form an entry carries (`command`, `args`, `commandWindows`). */
export function entryWords(entry: Record<string, unknown>): string[][] {
  const forms: string[][] = [];
  const args = Array.isArray(entry.args) ? entry.args.filter((a): a is string => typeof a === "string") : null;
  if (typeof entry.command === "string") forms.push(args ? [entry.command, ...args] : splitWords(entry.command));
  if (typeof entry.commandWindows === "string") {
    // cmd.exe does not quote with ', so a single quote in a Windows command is PowerShell's.
    const words = splitWords(entry.commandWindows, "powershell");
    const legacy = guardArgs(words) === null ? legacyWindowsWords(entry.commandWindows) : null;
    forms.push(legacy !== null && guardArgs(legacy) !== null ? legacy : words);
  }
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
