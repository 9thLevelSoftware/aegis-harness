/**
 * Which hook entries are ah's. An entry is ah's when it runs the guard: a
 * `.../dist/guard.mjs` token with `--agent`, or `ah guard`. That covers what
 * `ah init` writes and what the README told people to write by hand before it
 * existed, so `ah init` adopts a hand-wired entry instead of adding a second
 * one. Everything else in a settings file is the user's and is never touched.
 */

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

const GUARD_FILE = /(^|[\\/])dist[\\/]guard\.mjs$/i;
const AH_BIN = /(^|[\\/])(ah|aegis)(\.cmd|\.ps1|\.exe)?$/i;

/** The words of every command form an entry carries (`command`, `args`, `commandWindows`). */
export function entryWords(entry: Record<string, unknown>): string[][] {
  const forms: string[][] = [];
  const args = Array.isArray(entry.args) ? entry.args.filter((a): a is string => typeof a === "string") : null;
  if (typeof entry.command === "string") forms.push(args ? [entry.command, ...args] : splitWords(entry.command));
  if (typeof entry.commandWindows === "string") forms.push(splitWords(entry.commandWindows));
  return forms;
}

/** The guard's own arguments in a command form that runs it, or null when the form does not run the guard. */
export function guardArgs(words: readonly string[]): string[] | null {
  for (let i = 0; i < words.length; i++) {
    const w = words[i].replace(/^&\s*/, "");
    if (GUARD_FILE.test(w)) {
      const rest = words.slice(i + 1);
      return rest.includes("--agent") ? rest : null;
    }
    if (AH_BIN.test(w) && words[i + 1] === "guard" && words.slice(0, i).every((p) => RUNNER_WORDS.has(p.toLowerCase()))) return words.slice(i + 2);
  }
  return null;
}

/** Words that may come before `ah` when it is the command being run: `npx ah`, `pnpm exec ah`, `& 'ah.cmd'`. */
const RUNNER_WORDS = new Set(["&", "call", "npx", "pnpx", "bunx", "npm", "pnpm", "yarn", "bun", "exec", "dlx", "x", "--no-install", "--no", "-y", "--yes", "-q", "--quiet"]);

export function isOwnedEntry(entry: unknown): boolean {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return false;
  return entryWords(entry as Record<string, unknown>).some((w) => guardArgs(w) !== null);
}

/** Options a person may have added to the guard command that `ah init` carries over. */
export interface CarriedOptions {
  askFallback?: "deny" | "warn";
  noLog?: boolean;
}

export function carriedOptions(entry: Record<string, unknown>): CarriedOptions {
  const o: CarriedOptions = {};
  for (const w of entryWords(entry)) {
    const args = guardArgs(w);
    if (!args) continue;
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      const v = a.startsWith("--ask-fallback=") ? a.split("=")[1] : a === "--ask-fallback" ? args[i + 1] : undefined;
      if (v === "warn" || v === "deny") o.askFallback = v;
      if (a === "--no-log") o.noLog = true;
    }
  }
  return o;
}
