/**
 * Codex wiring, per Codex 0.163's hook documentation and what its
 * app-server reported for test files (BUG-2026-019 records what was checked):
 *
 * - Hooks from every source run (user ~/.codex/hooks.json, each trusted
 *   project layer's .codex/hooks.json, inline [hooks] in config.toml, managed
 *   files). The same entry in two files runs twice.
 * - hooks.json takes only `description` and `hooks` at the top level; any other
 *   key, a wrong value type or an unknown handler `type` rejects the whole file.
 * - `command` runs as `bash -c <command>` on Linux and macOS, so paths are
 *   shell-quoted. Codex does not document the shell behind `commandWindows`;
 *   ah writes a form that cmd.exe and PowerShell both run (short 8.3 paths
 *   without quotes) when it can, and `ah doctor` runs it through both.
 * - Trust is recorded per hook in ~/.codex/config.toml under
 *   `[hooks.state."<file>:pre_tool_use:<group>:<handler>"] trusted_hash`. The
 *   hash covers command, matcher, timeout and statusMessage, and the key covers
 *   the position, so ah keeps its group where it is or appends it at the end.
 * - Project hooks load only for a project trusted in config.toml.
 */
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { carriedOptions, type CarriedOptions } from "./owned.ts";
import type { Machine } from "./project.ts";

export const CODEX_MATCHER = "Bash|Edit|Write|Agent";

export type CodexScope = "user" | "project";

export function codexHome(m: Machine): string {
  return m.env.CODEX_HOME && m.env.CODEX_HOME !== "" ? m.env.CODEX_HOME : join(m.home, ".codex");
}

export function codexHooksFiles(m: Machine): { scope: CodexScope; path: string }[] {
  return [
    { scope: "project", path: join(m.root, ".codex", "hooks.json") },
    { scope: "user", path: join(codexHome(m), "hooks.json") },
  ];
}

/** `local` and `project` both mean the project's .codex/hooks.json: Codex has no machine-local project layer. */
export function codexHooksFile(m: Machine, scope: "local" | "project" | "user"): string {
  return scope === "user" ? join(codexHome(m), "hooks.json") : join(m.root, ".codex", "hooks.json");
}

export function codexConfigFiles(m: Machine): { scope: CodexScope; path: string }[] {
  return [
    { scope: "project", path: join(m.root, ".codex", "config.toml") },
    { scope: "user", path: join(codexHome(m), "config.toml") },
  ];
}

export function codexRequirementsFile(m: Machine): string {
  return m.os === "win32" ? join(m.env.ProgramData ?? "C:\\ProgramData", "OpenAI", "Codex", "requirements.toml") : "/etc/codex/requirements.toml";
}

/** A word bash passes through unchanged; anything else is single-quoted. */
export function posixQuote(word: string): string {
  return /^[A-Za-z0-9_\/.:@%+=,-]+$/.test(word) ? word : `'${word.replace(/'/g, `'\\''`)}'`;
}

/** A Windows path cmd.exe and PowerShell both take as one bare word. */
export function windowsBare(word: string): boolean {
  return /^[A-Za-z0-9_\\/.:@~+=,-]+$/.test(word) && !word.startsWith("@") && !word.startsWith("-");
}

/** The 8.3 short form of a Windows path, or the path itself when the volume has none. */
export function shortPath(path: string): string {
  if (process.platform !== "win32") return path;
  const r = spawnSync("cmd.exe", ["/d", "/s", "/c", `for %I in ("${path}") do @echo %~sI`], { encoding: "utf8", windowsHide: true, windowsVerbatimArguments: true });
  const out = (r.stdout ?? "").trim().split(/\r?\n/).pop() ?? "";
  return r.status === 0 && out !== "" ? out : path;
}

export interface CodexCommand {
  command: string;
  commandWindows?: string;
  /** Why the Windows form is what it is, for the report. */
  windowsNote?: string;
}

export function codexCommand(m: Machine, guardArgs: string[], short: (p: string) => string = shortPath): CodexCommand {
  if (m.os !== "win32") return { command: [m.nodePath, m.guardPath, ...guardArgs].map(posixQuote).join(" ") };
  const posixForm = [m.nodePath.replace(/\\/g, "/"), m.guardPath.replace(/\\/g, "/"), ...guardArgs].map(posixQuote).join(" ");
  let node = m.nodePath;
  let guard = m.guardPath;
  if (!windowsBare(node)) node = short(node);
  if (!windowsBare(guard)) guard = short(guard);
  if (windowsBare(node) && windowsBare(guard)) {
    const changed = node !== m.nodePath || guard !== m.guardPath;
    return { command: posixForm, commandWindows: [node, guard, ...guardArgs].join(" "), windowsNote: changed ? "short 8.3 paths, so the command needs no quoting in cmd.exe or PowerShell" : undefined };
  }
  const q = (p: string) => `'${p.replace(/'/g, "''")}'`;
  return {
    command: posixForm,
    commandWindows: `& ${q(m.nodePath)} ${q(m.guardPath)} ${guardArgs.join(" ")}`,
    windowsNote: "PowerShell quoting: this volume has no 8.3 names and the paths contain spaces; Codex does not document its Windows hook shell, so run `ah doctor`",
  };
}

export interface CodexEntryOptions {
  askFallback?: "deny" | "warn";
  noLog?: boolean;
}

export function codexGroup(m: Machine, o: CodexEntryOptions, found: Record<string, unknown>[], short?: (p: string) => string): Record<string, unknown> {
  const carried: CarriedOptions = {};
  let timeout: number | undefined;
  let statusMessage: string | undefined;
  for (const e of found) {
    Object.assign(carried, carriedOptions(e));
    // Codex reads timeout as an unsigned integer; anything else rejects the whole file.
    if (timeout === undefined && Number.isInteger(e.timeout) && (e.timeout as number) > 0) timeout = e.timeout as number;
    if (statusMessage === undefined && typeof e.statusMessage === "string" && e.statusMessage !== "") statusMessage = e.statusMessage;
  }
  const args = ["--agent", "codex"];
  const fallback = o.askFallback ?? carried.askFallback;
  if (fallback === "warn") args.push("--ask-fallback", "warn");
  if (o.noLog ?? carried.noLog) args.push("--no-log");
  const c = codexCommand(m, args, short);
  const entry: Record<string, unknown> = { type: "command", command: c.command };
  if (c.commandWindows !== undefined) entry.commandWindows = c.commandWindows;
  entry.timeout = timeout ?? 5;
  if (statusMessage !== undefined) entry.statusMessage = statusMessage;
  return { matcher: CODEX_MATCHER, hooks: [entry] };
}

export function codexNextSteps(changed: boolean): string[] {
  if (!changed) return [];
  return [
    "Codex skips a new or changed hook until you trust it: start Codex in this project, open /hooks, and trust the ah entry.",
    "Codex loads a project's .codex/hooks.json only for a trusted project; accept the trust prompt when Codex asks.",
  ];
}

/** Does a Codex matcher (a regex, tried against the tool name and its aliases) select `names`? */
export function codexMatcherCovers(matcher: unknown, names: readonly string[]): boolean {
  if (matcher === undefined || matcher === null || matcher === "" || matcher === "*") return true;
  if (typeof matcher !== "string") return false;
  try {
    const re = new RegExp(matcher);
    return names.some((n) => re.test(n));
  } catch {
    return false;
  }
}

/** Tool names (with aliases) whose calls the guard must see on Codex. */
export const CODEX_REQUIRED_TOOLS: { label: string; names: string[] }[] = [
  { label: "shell commands (Bash)", names: ["Bash"] },
  { label: "apply_patch edits", names: ["apply_patch", "Edit", "Write"] },
];

/** "codex-cli 0.163.0" -> "0.163.0". */
export function parseCodexVersion(stdout: string): string | null {
  const m = /^codex-cli (\S+)$/m.exec(stdout.trim());
  return m ? m[1] : null;
}

/** The `hooks` row of `codex features list`: true, false, or null when absent. */
export function parseFeaturesHooks(stdout: string): boolean | null {
  const m = /^hooks\s+\S+\s+(true|false)\s*$/m.exec(stdout);
  return m ? m[1] === "true" : null;
}
