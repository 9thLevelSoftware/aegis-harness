/**
 * Codex wiring, per Codex 0.163's hook documentation and what its
 * app-server reported for test files (BUG-2026-019 records what was checked):
 *
 * - Hooks from every source run (user ~/.codex/hooks.json, each trusted
 *   project layer's .codex/hooks.json, inline [hooks] in config.toml, managed
 *   files). The same entry in two files runs twice.
 * - hooks.json takes only `description` and `hooks` at the top level; any other
 *   key, a wrong value type or an unknown handler `type` rejects the whole file.
 * - `command` runs as `<login shell> -c <command>` when the login shell is
 *   bash or zsh (so zsh on a default macOS), else `bash -c`; paths are quoted
 *   for both. Codex does not document the shell behind `commandWindows`;
 *   ah writes a form that cmd.exe and PowerShell both run when it can
 *   (codexCommand), and `ah doctor` runs it through both.
 * - Trust is recorded per hook in ~/.codex/config.toml under
 *   `[hooks.state."<file>:pre_tool_use:<group>:<handler>"] trusted_hash`. The
 *   hash covers command, matcher, timeout and statusMessage, and the key covers
 *   the position, so ah keeps its group where it is or appends it at the end.
 * - Project hooks load only for a project trusted in config.toml.
 */
import { spawn, spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { carriedOptions, type CarriedOptions } from "./owned.ts";
import { gitTopLevel, type Machine } from "./project.ts";

export const CODEX_MATCHER = "Bash|Edit|Write|Agent";

export type CodexScope = "user" | "project";

/** Codex canonicalizes a CODEX_HOME it is given, and keys hook trust by that spelling; the default ~/.codex it takes as is. */
export function codexHome(m: Machine): string {
  const set = m.env.CODEX_HOME;
  if (set === undefined || set === "") return join(m.home, ".codex");
  try {
    return realpathSync(set);
  } catch {
    return set;
  }
}

export function canonical(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
}

/**
 * The project layers Codex reads for a session started in m.root: every
 * directory from the repository's top level down to m.root (just m.root
 * outside a repository), top first.
 */
export function codexLayers(m: Machine): string[] {
  const top = gitTopLevel(m.root);
  if (top === null) return [m.root];
  const want = canonical(top);
  const out: string[] = [];
  for (let d = m.root; ; d = dirname(d)) {
    out.unshift(d);
    if (canonical(d) === want || dirname(d) === d) break;
  }
  return canonical(out[0]) === want ? out : [m.root];
}

export function codexHooksFiles(m: Machine): { scope: CodexScope; path: string; layer?: string }[] {
  return [
    ...codexLayers(m)
      .reverse()
      .map((d) => ({ scope: "project" as const, path: join(d, ".codex", "hooks.json"), layer: d })),
    { scope: "user", path: join(codexHome(m), "hooks.json") },
  ];
}

/** `local` and `project` both mean the project's .codex/hooks.json: Codex has no machine-local project layer. */
export function codexHooksFile(m: Machine, scope: "local" | "project" | "user"): string {
  return scope === "user" ? join(codexHome(m), "hooks.json") : join(m.root, ".codex", "hooks.json");
}

export function codexConfigFiles(m: Machine): { scope: CodexScope; path: string }[] {
  return [
    ...codexLayers(m)
      .reverse()
      .map((d) => ({ scope: "project" as const, path: join(d, ".codex", "config.toml") })),
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

/** The first `node` on PATH, per `where node`, or null. */
export function nodeOnPath(): string | null {
  if (process.platform !== "win32") return null;
  const r = spawnSync("where.exe", ["node"], { encoding: "utf8", windowsHide: true });
  const first = (r.stdout ?? "").split(/\r?\n/).find((l) => l.trim() !== "");
  return r.status === 0 && first ? first.trim() : null;
}

export interface WindowsLookups {
  short?: (p: string) => string;
  onPath?: () => string | null;
}

/**
 * The hook command. On Windows, `commandWindows` must run in cmd.exe and in
 * PowerShell alike, since Codex does not document which one it uses. Both run
 * a line whose first word is a bare path, and both take later arguments in
 * double quotes. So the node path goes first as is, as its 8.3 short form, or
 * as plain `node` when that is the same node on PATH; the guard path goes
 * bare, short, or double-quoted. Only when none of that works does ah fall
 * back to PowerShell's `& '...'`, which cmd.exe cannot run.
 */
export function codexCommand(m: Machine, guardArgs: string[], look: WindowsLookups = {}): CodexCommand {
  if (m.os !== "win32") return { command: [m.nodePath, m.guardPath, ...guardArgs].map(posixQuote).join(" ") };
  const short = look.short ?? shortPath;
  const posixForm = [m.nodePath.replace(/\\/g, "/"), m.guardPath.replace(/\\/g, "/"), ...guardArgs].map(posixQuote).join(" ");
  const notes: string[] = [];
  let node: string | null = m.nodePath;
  if (!windowsBare(node)) {
    node = short(m.nodePath);
    if (windowsBare(node)) notes.push("the node path as its 8.3 short name");
    else {
      const found = (look.onPath ?? nodeOnPath)();
      node = found !== null && found.toLowerCase() === m.nodePath.toLowerCase() ? "node" : null;
      if (node) notes.push("`node` from PATH (the same node.exe), because its path has spaces and no 8.3 name");
    }
  }
  let guard: string | null = m.guardPath;
  if (!windowsBare(guard)) {
    guard = short(m.guardPath);
    if (windowsBare(guard)) notes.push("the guard path as its 8.3 short name");
    else {
      guard = /["%$`]/.test(m.guardPath) ? null : `"${m.guardPath}"`;
      if (guard) notes.push("the guard path in double quotes");
    }
  }
  const bareArg = (a: string) => /^[A-Za-z0-9_\\/.:@~+=,-]+$/.test(a);
  const args = guardArgs.map((a) => (bareArg(a) ? a : /["%$`]/.test(a) ? null : `"${a}"`));
  if (node !== null && guard !== null && args.every((a) => a !== null)) {
    return { command: posixForm, commandWindows: [node, guard, ...args].join(" "), windowsNote: notes.length > 0 ? `${notes.join(" and ")}, so cmd.exe and PowerShell both run it` : undefined };
  }
  const q = (p: string) => `'${p.replace(/'/g, "''")}'`;
  return {
    command: posixForm,
    commandWindows: `& ${q(m.nodePath)} ${q(m.guardPath)} ${guardArgs.map((a) => (bareArg(a) ? a : q(a))).join(" ")}`,
    windowsNote: "PowerShell quoting, which cmd.exe cannot run: the paths have spaces and no 8.3 names. Codex does not document its Windows hook shell, so run `ah doctor`",
  };
}

export interface CodexEntryOptions {
  askFallback?: "deny" | "warn";
  noLog?: boolean;
}

export function codexGroup(m: Machine, o: CodexEntryOptions, found: Record<string, unknown>[], look?: WindowsLookups, notes?: string[]): Record<string, unknown> {
  const carried: CarriedOptions = {};
  let timeout: number | undefined;
  let statusMessage: string | undefined;
  for (const e of found) {
    Object.assign(carried, carriedOptions(e));
    // Codex reads timeout as an unsigned integer; anything else rejects the whole file.
    if (timeout === undefined && Number.isInteger(e.timeout) && (e.timeout as number) > 0) timeout = e.timeout as number;
    if (statusMessage === undefined && typeof e.statusMessage === "string" && e.statusMessage !== "") statusMessage = e.statusMessage;
  }
  const args = ["--agent", "codex", ...(carried.extra ?? [])];
  const fallback = o.askFallback ?? carried.askFallback;
  if (fallback === "warn") args.push("--ask-fallback", "warn");
  if (o.noLog ?? carried.noLog) args.push("--no-log");
  const c = codexCommand(m, args, look);
  if (c.windowsNote && notes) notes.push(`commandWindows uses ${c.windowsNote}`);
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

/**
 * Does a Codex matcher select a tool known by any of `names`? Codex compares a
 * matcher made only of names and `|` as a list of exact, case-sensitive names
 * ("Bas" does not match Bash); anything else is an unanchored regex search.
 */
export function codexMatcherCovers(matcher: unknown, names: readonly string[]): boolean {
  if (matcher === undefined || matcher === null || matcher === "" || matcher === "*") return true;
  if (typeof matcher !== "string") return false;
  if (/^[A-Za-z0-9_|]+$/.test(matcher)) return matcher.split("|").some((n) => names.includes(n));
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

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Events Codex 0.163 parses; it ignores any other key under `hooks`, whatever it holds. */
export const CODEX_EVENTS = new Set(["PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact", "PostCompact", "SessionStart", "SessionEnd", "UserPromptSubmit", "SubagentStart", "SubagentStop", "Stop", "Interrupt"]);
const CODEX_HOOK_TYPES = new Set(["command", "mcp_tool", "prompt", "agent"]);

/**
 * What makes Codex 0.163 reject a whole hooks.json, or null. Checked against
 * the binary's parser (hooks/list): serde types, where null is accepted for
 * optional strings and numbers but not for `async`, `input` or `hooks`.
 */
export function codexFileProblem(value: unknown, text?: string): string | null {
  if (text !== undefined) {
    if (text.startsWith("﻿")) return "a byte-order mark at the start (Codex cannot parse it; save the file as UTF-8 without BOM)";
    if (text.trim() === "") return "no content (Codex cannot parse an empty file; it needs at least {})";
    const dup = duplicateKey(text);
    if (dup !== null) return `the key ${JSON.stringify(dup)} twice in one object`;
  }
  if (!isObj(value)) return "a value that is not a JSON object";
  const extra = Object.keys(value).filter((k) => k !== "description" && k !== "hooks");
  if (extra.length > 0) return `top-level key ${extra.map((k) => JSON.stringify(k)).join(", ")} (only "description" and "hooks" are allowed)`;
  const optStr = (v: unknown) => v === undefined || v === null || typeof v === "string";
  const optUint = (v: unknown) => v === undefined || v === null || (Number.isInteger(v) && (v as number) >= 0);
  if (!optStr(value.description)) return '"description" that is not a string';
  if (value.hooks === undefined) return null;
  if (!isObj(value.hooks)) return '"hooks" that is not an object';
  for (const [event, groups] of Object.entries(value.hooks)) {
    if (!CODEX_EVENTS.has(event)) continue;
    if (!Array.isArray(groups)) return `hooks.${event} that is not a list`;
    for (const g of groups) {
      if (!isObj(g)) return `a ${event} group that is not an object`;
      if (!optStr(g.matcher)) return `a ${event} matcher that is not a string`;
      if (g.hooks === undefined) continue;
      if (!Array.isArray(g.hooks)) return `a ${event} group whose hooks is not a list`;
      for (const e of g.hooks) {
        if (!isObj(e) || typeof e.type !== "string" || !CODEX_HOOK_TYPES.has(e.type)) return `a ${event} hook with type ${JSON.stringify(isObj(e) ? e.type : e)}`;
        if (!optUint(e.timeout)) return `a ${event} timeout of ${JSON.stringify(e.timeout)} (it must be a whole number of seconds)`;
        if (!optStr(e.statusMessage)) return `a ${event} statusMessage that is not a string`;
        if (e.type === "command") {
          if (typeof e.command !== "string") return `a ${event} command hook without a command string`;
          if (!optStr(e.commandWindows)) return `a ${event} commandWindows that is not a string`;
          if (e.async !== undefined && typeof e.async !== "boolean") return `a ${event} async that is not true or false`;
          if (!optUint(e.additionalContextLimit)) return `a ${event} additionalContextLimit of ${JSON.stringify(e.additionalContextLimit)} (it must be a whole number)`;
        }
        if (e.type === "mcp_tool") {
          if (typeof e.server !== "string" || typeof e.tool !== "string") return `a ${event} mcp_tool hook without server and tool strings`;
          if (e.input !== undefined && !isObj(e.input)) return `a ${event} mcp_tool input that is not an object`;
        }
      }
    }
  }
  return null;
}

/** The first key that appears twice in one JSON object (serde rejects it; JSON.parse keeps the last), or null. */
export function duplicateKey(text: string): string | null {
  const stack: (Set<string> | null)[] = [];
  let expectKey = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const keys = stack[stack.length - 1];
      if (expectKey && keys) {
        let key: string;
        try {
          key = JSON.parse(text.slice(i, j + 1)) as string;
        } catch {
          return null;
        }
        if (keys.has(key)) return key;
        keys.add(key);
        expectKey = false;
      }
      i = j;
    } else if (c === "{") {
      stack.push(new Set());
      expectKey = true;
    } else if (c === "}") stack.pop();
    else if (c === "[") stack.push(null);
    else if (c === "]") stack.pop();
    else if (c === ",") expectKey = (stack[stack.length - 1] ?? null) !== null;
  }
  return null;
}

/** One hook as Codex's own loader reports it (app-server `hooks/list`, 0.163). */
export interface CodexListedHook {
  key: string;
  eventName: string;
  handlerType: string;
  command?: string;
  matcher: string | null;
  timeoutSec: number;
  sourcePath: string;
  source: string;
  enabled: boolean;
  isManaged: boolean;
  trustStatus: "managed" | "untrusted" | "trusted" | "modified";
}

export interface CodexListing {
  hooks: CodexListedHook[];
  warnings: string[];
  errors: { path: string; message: string }[];
}

/**
 * Ask Codex which hooks a session started in `cwd` would load and whether it
 * trusts each one: `codex app-server` answers `hooks/list` offline in a
 * fraction of a second, from the same loader a session uses, so a file it
 * cannot parse, a hook it skips and a hook that changed since it was trusted
 * all show. Resolves null when Codex cannot be asked.
 */
export function codexHooksList(cwd: string, env: NodeJS.ProcessEnv, timeoutMs = 15_000): Promise<CodexListing | null> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v: CodexListing | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        p.stdin?.end();
      } catch {
        // already closed
      }
      setTimeout(() => p.kill(), 2000).unref();
      resolve(v);
    };
    const p = spawn("codex", ["app-server", "--listen", "stdio://"], { cwd, env, stdio: ["pipe", "pipe", "ignore"], windowsHide: true, shell: process.platform === "win32" });
    const timer = setTimeout(() => done(null), timeoutMs);
    p.on("error", () => done(null));
    p.on("exit", () => done(null));
    p.stdin?.on("error", () => done(null));
    const send = (msg: unknown) => p.stdin?.write(`${JSON.stringify(msg)}\n`);
    let buf = "";
    p.stdout?.setEncoding("utf8");
    p.stdout?.on("data", (chunk: string) => {
      buf += chunk;
      for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        let msg: { id?: number; result?: { data?: unknown[] }; error?: unknown };
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        if (msg.id === 1) {
          send({ method: "initialized" });
          send({ method: "hooks/list", id: 2, params: { cwds: [cwd] } });
        } else if (msg.id === 2) {
          const d = msg.result?.data?.[0] as Partial<CodexListing> | undefined;
          done(d && Array.isArray(d.hooks) ? { hooks: d.hooks, warnings: d.warnings ?? [], errors: d.errors ?? [] } : null);
        }
      }
    });
    send({ method: "initialize", id: 1, params: { clientInfo: { name: "ah-doctor", title: null, version: "0" }, capabilities: { experimentalApi: true } } });
  });
}
