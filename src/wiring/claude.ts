/**
 * Claude Code wiring, per Claude Code 2.1.302's hook reference and settings
 * code (BUG-2026-019 records what was checked):
 *
 * - Hooks from every settings file run (managed, user, project, local).
 *   Copies with the same command, args, shell and `if` run once, with one
 *   copy's timeout and onFailure; Claude Code does not say which.
 * - .claude/settings.json is read only from the directory a session starts
 *   in; .claude/settings.local.json from the repository root, so a session
 *   started in a subdirectory still loads it.
 * - The entry is exec form (`command` + `args`, since 2.1.139): no shell, so a
 *   path with spaces needs no quoting, and on Windows `command` must be a real
 *   .exe (node.exe, never an npm .cmd shim).
 * - Unknown keys on a hook entry are dropped silently, so ah recognises its
 *   entry by the guard path, not by a marker key. One invalid PreToolUse entry
 *   stops Claude Code loading the whole file, so ah writes only schema-valid values.
 * - `onFailure: "block"` (2.1.295+) makes a hook that cannot start block the call.
 * - AGENTS.md is read natively (2.1.277+) only when no CLAUDE.md exists.
 */
import { statSync } from "node:fs";
import { join } from "node:path";
import type { CarriedOptions } from "./owned.ts";
import { carriedOptions } from "./owned.ts";
import { mainCheckoutRoot, type Machine } from "./project.ts";

export const CLAUDE_MATCHER = "Bash|PowerShell|Edit|Write|MultiEdit|NotebookEdit|Read|Agent|WebFetch|Workflow";
/** Tools whose calls the guard must see; a matcher that misses one leaves a hole. */
export const CLAUDE_REQUIRED_TOOLS = ["Bash", "PowerShell", "Edit", "Write", "NotebookEdit", "Read"];
export const CLAUDE_OPTIONAL_TOOLS = ["Agent", "WebFetch", "Workflow"];

export const CLAUDE_MIN = { execForm: "2.1.139", agentsMd: "2.1.277", onFailure: "2.1.295" } as const;

export type ClaudeScope = "managed" | "user" | "project" | "local";

export interface SettingsFile {
  scope: ClaudeScope;
  path: string;
  /** ah may write this file. Managed files are read only. */
  writable: boolean;
}

export function claudeConfigDir(m: Machine): string {
  return m.env.CLAUDE_CONFIG_DIR && m.env.CLAUDE_CONFIG_DIR !== "" ? m.env.CLAUDE_CONFIG_DIR : join(m.home, ".claude");
}

export function managedDir(m: Machine): string {
  if (m.os === "darwin") return "/Library/Application Support/ClaudeCode";
  if (m.os === "win32") return "C:\\Program Files\\ClaudeCode";
  return "/etc/claude-code";
}

/**
 * Where Claude Code reads settings.local.json: the repository root (the main
 * checkout's, in a worktree), except on Windows, outside a repository, when
 * that root is the home directory, or when the root, its .git or its .claude
 * belongs to another user; then it sits beside settings.json.
 */
export function localSettingsRoot(m: Machine): string {
  if (m.os === "win32") return m.root;
  const top = mainCheckoutRoot(m.root);
  if (top === null || top === m.home) return m.root;
  if (!ownedByMe(top) || !ownedByMe(join(top, ".git")) || !ownedByMe(join(top, ".claude"))) return m.root;
  return top;
}

/** True unless `p` exists and belongs to another user. */
function ownedByMe(p: string): boolean {
  if (typeof process.getuid !== "function") return true;
  try {
    return statSync(p).uid === process.getuid();
  } catch {
    return true;
  }
}

/** The settings files in precedence order, highest first (managed, local, project, user). */
export function claudeSettingsFiles(m: Machine, managedDropIns: string[] = []): SettingsFile[] {
  return [
    { scope: "managed", path: join(managedDir(m), "managed-settings.json"), writable: false },
    ...managedDropIns.map((p) => ({ scope: "managed" as const, path: p, writable: false })),
    { scope: "local", path: join(localSettingsRoot(m), ".claude", "settings.local.json"), writable: true },
    { scope: "project", path: join(m.root, ".claude", "settings.json"), writable: true },
    { scope: "user", path: join(claudeConfigDir(m), "settings.json"), writable: true },
  ];
}

export function claudeFileFor(m: Machine, scope: Exclude<ClaudeScope, "managed">): string {
  const f = claudeSettingsFiles(m).find((s) => s.scope === scope);
  return (f as SettingsFile).path;
}

export interface ClaudeEntryOptions {
  failClosed?: boolean;
  noLog?: boolean;
}

/** The canonical ah matcher group for Claude Code, carrying over what a person set on the entry it replaces. */
export function claudeGroup(m: Machine, o: ClaudeEntryOptions, found: Record<string, unknown>[]): Record<string, unknown> {
  const carried: CarriedOptions = {};
  let timeout: number | undefined;
  let onFailure: "block" | "continue" | undefined;
  let statusMessage: string | undefined;
  for (const e of found) {
    Object.assign(carried, carriedOptions(e));
    if (timeout === undefined && typeof e.timeout === "number" && e.timeout > 0) timeout = e.timeout;
    if (onFailure === undefined && (e.onFailure === "block" || e.onFailure === "continue")) onFailure = e.onFailure;
    if (statusMessage === undefined && typeof e.statusMessage === "string" && e.statusMessage !== "") statusMessage = e.statusMessage;
  }
  const args = [m.guardPath, "--agent", "claude", ...(carried.extra ?? [])];
  if (o.noLog ?? carried.noLog) args.push("--no-log");
  const entry: Record<string, unknown> = { type: "command", command: m.nodePath, args, timeout: timeout ?? 5 };
  const fail = o.failClosed ? "block" : onFailure;
  if (fail === "block") entry.onFailure = "block";
  if (statusMessage !== undefined) entry.statusMessage = statusMessage;
  return { matcher: CLAUDE_MATCHER, hooks: [entry] };
}

const ALIASES: Record<string, string> = { Task: "Agent" };

/** Does a Claude Code matcher select `tool`? Exact-name lists split on | or ,; anything else is an unanchored regex. */
export function claudeMatcherCovers(matcher: unknown, tool: string): boolean {
  if (matcher === undefined || matcher === null || matcher === "" || matcher === "*") return true;
  if (typeof matcher !== "string") return false;
  if (/^[a-zA-Z0-9_|, -]+$/.test(matcher)) {
    return matcher.split(/[|,]/).map((s) => s.trim()).map((s) => ALIASES[s] ?? s).includes(tool);
  }
  try {
    return new RegExp(matcher).test(tool);
  } catch {
    return false;
  }
}

/** "2.1.302 (Claude Code)" -> [2, 1, 302]. */
export function parseVersion(text: string): number[] | null {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(text);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

export function atLeast(v: number[] | null, min: string): boolean | null {
  if (v === null) return null;
  const w = min.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if (v[i] !== w[i]) return v[i] > w[i];
  }
  return true;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Events whose one invalid entry makes Claude Code apply nothing from the file (2.1.302); others drop just the entry. */
export const CLAUDE_FATAL_EVENTS = ["PreToolUse", "PermissionRequest"] as const;

const optStr = (v: unknown) => v === undefined || typeof v === "string";
const optBool = (v: unknown) => v === undefined || typeof v === "boolean";
const optStrs = (v: unknown) => v === undefined || (Array.isArray(v) && v.every((a) => typeof a === "string"));
const optRecord = (v: unknown, values?: (x: unknown) => boolean) => v === undefined || (isObj(v) && (!values || Object.values(v).every(values)));

/** Why Claude Code 2.1.302's hook schema rejects `e`, or null. Mirrors the zod schema in the binary; null is never accepted for an optional field. */
export function claudeEntryProblem(e: unknown): string | null {
  if (!isObj(e)) return "a hook that is not an object";
  const bad = (field: string, want: string) => `a ${String(e.type)} hook whose ${field} is not ${want}`;
  if (!optStr(e.if)) return bad("if", "a string");
  if (e.timeout !== undefined && !(typeof e.timeout === "number" && e.timeout > 0)) return `a hook with timeout ${JSON.stringify(e.timeout)} (it must be a positive number)`;
  if (!optStr(e.statusMessage)) return bad("statusMessage", "a string");
  if (!optBool(e.once)) return bad("once", "true or false");
  const failure = e.onFailure === undefined || e.onFailure === "continue" || e.onFailure === "block";
  switch (e.type) {
    case "command":
      if (typeof e.command !== "string") return "a command hook without a command string";
      if (!optStrs(e.args)) return bad("args", "a list of strings");
      if (e.shell !== undefined && e.shell !== "bash" && e.shell !== "powershell") return `a command hook with shell ${JSON.stringify(e.shell)}`;
      if (!failure) return `a command hook with onFailure ${JSON.stringify(e.onFailure)}`;
      if (!optBool(e.async)) return bad("async", "true or false");
      if (!optBool(e.asyncRewake)) return bad("asyncRewake", "true or false");
      for (const k of ["rewakeMessage", "rewakeSummary"]) if (e[k] !== undefined && !(typeof e[k] === "string" && e[k] !== "")) return bad(k, "a non-empty string");
      return null;
    case "prompt":
    case "agent":
      if (typeof e.prompt !== "string") return `a ${e.type} hook without a prompt string`;
      if (!optStr(e.model)) return bad("model", "a string");
      if (e.type === "prompt" && !optBool(e.continueOnBlock)) return bad("continueOnBlock", "true or false");
      return null;
    case "mcp_tool":
      if (typeof e.server !== "string" || typeof e.tool !== "string") return "an mcp_tool hook without server and tool strings";
      if (!optRecord(e.input)) return bad("input", "an object");
      return null;
    case "http":
      if (typeof e.url !== "string" || !URL.canParse(e.url)) return `an http hook whose url ${JSON.stringify(e.url)} is not a URL`;
      if (!failure) return `an http hook with onFailure ${JSON.stringify(e.onFailure)}`;
      if (!optRecord(e.headers, (h) => typeof h === "string")) return bad("headers", "an object of strings");
      if (!optStrs(e.allowedEnvVars)) return bad("allowedEnvVars", "a list of strings");
      return null;
    default:
      return `a hook with type ${JSON.stringify(e.type)}`;
  }
}

/** What in a settings value makes Claude Code 2.1.302 apply nothing from the file, or null. */
export function claudeHooksProblem(value: unknown): string | null {
  const hooks = isObj(value) ? value.hooks : undefined;
  if (!isObj(hooks)) return null;
  for (const event of CLAUDE_FATAL_EVENTS) {
    const groups = hooks[event];
    if (groups === undefined) continue;
    if (!Array.isArray(groups)) return `hooks.${event} that is not a list`;
    for (const [i, g] of groups.entries()) {
      if (!isObj(g)) return `a ${event} matcher group that is not an object`;
      if (!optStr(g.matcher)) return `a ${event} matcher that is not a string (${event}[${i}])`;
      if (!Array.isArray(g.hooks)) return `a ${event} matcher group without a hooks list (${event}[${i}])`;
      for (const [j, e] of g.hooks.entries()) {
        const bad = claudeEntryProblem(e);
        if (bad) return `${bad} under ${event} (${event}[${i}].hooks[${j}])`;
      }
    }
  }
  return null;
}
