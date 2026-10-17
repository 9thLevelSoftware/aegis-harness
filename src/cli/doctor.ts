/**
 * `ah doctor`: is the guard actually in the path of each agent's tool calls?
 *
 * For each agent it finds the CLI and its version, reads every file the agent
 * loads hooks from, checks the switches that turn hooks off (Claude Code's
 * disableAllHooks and allowManagedHooksOnly, workspace trust; Codex's
 * features.hooks, project trust, per-hook trust), and pushes canaries through
 * the exact command each ah entry would run: `rm -rf /` and an edit to
 * `.ruff.toml` must be refused, `ls` must pass. Exits 1 when anything would
 * leave a call unguarded. Reads only; the canaries write nothing (AH_NO_LOG).
 */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { userInfo } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { atLeast, CLAUDE_MIN, CLAUDE_OPTIONAL_TOOLS, CLAUDE_REQUIRED_TOOLS, claudeConfigDir, claudeMatcherCovers, claudeSettingsFiles, managedDir, parseVersion, type SettingsFile } from "../wiring/claude.ts";
import { canaries, runCanary, type Launch } from "../wiring/canary.ts";
import { CODEX_REQUIRED_TOOLS, codexConfigFiles, codexHome, codexHooksFiles, codexMatcherCovers, codexRequirementsFile, parseCodexVersion, parseFeaturesHooks } from "../wiring/codex.ts";
import { readJson, readText } from "../wiring/files.ts";
import { blockIsCurrent, claudeMdState, CODEX_DOC_BUDGET } from "../wiring/instructions.ts";
import { entryWords, guardArgs, isOwnedEntry, splitWords } from "../wiring/owned.ts";
import { defaultMachine, gitTopLevel, readJsonQuiet, type Machine } from "../wiring/project.ts";
import { blockEndByte } from "../wiring/text-block.ts";
import { get, parseToml } from "../wiring/toml.ts";

export type Level = "ok" | "info" | "warn" | "fail";

export interface Check {
  agent: "claude" | "codex" | "project";
  level: Level;
  title: string;
  fix?: string;
}

export interface DoctorOptions {
  agents: ("claude" | "codex")[];
  root: string;
  json: boolean;
}

export const DOCTOR_HELP = `ah doctor [--agents claude,codex] [--root DIR] [--json]
    Check that each agent will run the guard: CLI version, every settings file it loads hooks from,
    switches and trust that turn hooks off, and a canary through each ah hook command (rm -rf / and an
    edit to .ruff.toml must be refused, ls must pass). Exits 1 if any call would go unguarded.
`;

export function parseDoctorArgs(argv: readonly string[]): DoctorOptions | string {
  const o: DoctorOptions = { agents: ["claude", "codex"], root: process.cwd(), json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const eq = a.startsWith("--") ? a.indexOf("=") : -1;
    const flag = eq > 0 ? a.slice(0, eq) : a;
    const v = (): string | undefined => (eq > 0 ? a.slice(eq + 1) : argv[++i]);
    if (flag === "--json" && eq < 0) o.json = true;
    else if (flag === "--root") {
      const r = v();
      if (!r) return "--root needs a directory";
      o.root = r;
    } else if (flag === "--agents") {
      const list = (v() ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
      if (list.length === 0 || list.some((s) => s !== "claude" && s !== "codex")) return "--agents takes claude, codex or both";
      o.agents = [...new Set(list)] as ("claude" | "codex")[];
    } else return `unknown option ${a}`;
  }
  return o;
}

// ---------------------------------------------------------------------------
// Shared

interface CliProbe {
  found: boolean;
  stdout: string;
}

/** Run `<name> --version`. On Windows through the shell, so a .cmd shim resolves too. */
export function probeCli(name: string, env: NodeJS.ProcessEnv): CliProbe {
  const r = spawnSync(name, ["--version"], { encoding: "utf8", env, timeout: 15_000, windowsHide: true, shell: process.platform === "win32" });
  if (r.error || r.status !== 0) return { found: false, stdout: "" };
  return { found: true, stdout: r.stdout ?? "" };
}

function rel(m: Machine, p: string): string {
  const r = relative(m.root, p);
  if (!r.startsWith("..") && r !== "") return r;
  const h = relative(m.home, p);
  return h.startsWith("..") ? p : `~/${h.replace(/\\/g, "/")}`;
}

function exists(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

interface OwnedAt {
  file: string;
  scope: string;
  group: Record<string, unknown>;
  entry: Record<string, unknown>;
  groupIndex: number;
  handlerIndex: number;
}

function ownedIn(value: unknown, file: string, scope: string): OwnedAt[] {
  const groups = get(value, "hooks", "PreToolUse");
  if (!Array.isArray(groups)) return [];
  const out: OwnedAt[] = [];
  groups.forEach((g, groupIndex) => {
    if (!isObj(g) || !Array.isArray(g.hooks)) return;
    g.hooks.forEach((e, handlerIndex) => {
      if (isOwnedEntry(e)) out.push({ file, scope, group: g, entry: e as Record<string, unknown>, groupIndex, handlerIndex });
    });
  });
  return out;
}

/** The node and guard paths an entry names, for checking they still exist. */
function namedPaths(words: string[]): { node?: string; guard?: string } {
  const gi = words.findIndex((w) => /(^|[\\/])dist[\\/]guard\.mjs$/i.test(w));
  if (gi < 0) return {};
  const before = words.slice(0, gi).filter((w) => w !== "&");
  return { node: before.length > 0 ? before[before.length - 1] : undefined, guard: words[gi] };
}

function canaryLine(agent: "claude" | "codex", m: Machine, launch: Launch, timeoutSec: number, label: string): Check[] {
  const env: NodeJS.ProcessEnv = { ...m.env, AH_NO_LOG: "1" };
  if (agent === "claude") env.CLAUDE_PROJECT_DIR = m.root;
  const results: string[] = [];
  const failures: string[] = [];
  let slowest = 0;
  for (const c of canaries(agent, m.root, m.os === "win32" ? "\\" : "/")) {
    const r = runCanary(launch, c.payload, { cwd: m.root, env, timeoutMs: Math.min(timeoutSec, 30) * 1000 });
    slowest = Math.max(slowest, r.ms);
    if (r.verdict === c.expect) results.push(`${c.label} ${c.expect === "deny" ? "refused" : "allowed"}`);
    else {
      const why = !r.started ? `the command could not start (${r.error ?? "unknown"})` : r.timedOut ? `timed out after ${timeoutSec} s` : r.verdict === null ? `exit ${r.exitCode}${r.stderr.trim() ? `: ${r.stderr.trim().split(/\r?\n/)[0]}` : ""}` : `it was ${r.verdict === "deny" ? "refused" : r.verdict === "ask" ? "held for a human" : "allowed"}`;
      failures.push(`${c.label} should be ${c.expect === "deny" ? "refused" : "allowed"}, but ${why}`);
    }
  }
  if (failures.length > 0) return [{ agent, level: "fail", title: `canary through ${label}: ${failures.join("; ")}`, fix: "re-run `ah init`, then `ah doctor`" }];
  return [{ agent, level: "ok", title: `canary through ${label}: ${results.join(", ")} (slowest ${Math.round(slowest)} ms)` }];
}

// ---------------------------------------------------------------------------
// Claude Code

const CLAUDE_HOOK_TYPES = new Set(["command", "prompt", "agent", "http", "mcp_tool"]);

/** What makes Claude Code reject a PreToolUse entry, and with it the whole file (2.1.302). */
function claudeFatal(g: unknown): string | null {
  if (!isObj(g)) return "a matcher group that is not an object";
  if (g.matcher !== undefined && typeof g.matcher !== "string") return "a matcher that is not a string";
  if (!Array.isArray(g.hooks)) return "a matcher group without a hooks array";
  for (const e of g.hooks) {
    if (!isObj(e)) return "a hook that is not an object";
    if (typeof e.type !== "string" || !CLAUDE_HOOK_TYPES.has(e.type)) return `a hook with type ${JSON.stringify(e.type)}`;
    if (e.type === "command" && typeof e.command !== "string") return "a command hook without a command string";
    if (e.args !== undefined && !(Array.isArray(e.args) && e.args.every((a) => typeof a === "string"))) return "args that is not a list of strings";
    if (e.timeout !== undefined && !(typeof e.timeout === "number" && e.timeout > 0)) return `timeout ${JSON.stringify(e.timeout)} (it must be a positive number)`;
    if (e.onFailure !== undefined && e.onFailure !== "continue" && e.onFailure !== "block") return `onFailure ${JSON.stringify(e.onFailure)}`;
    if (e.shell !== undefined && e.shell !== "bash" && e.shell !== "powershell") return `shell ${JSON.stringify(e.shell)}`;
  }
  return null;
}

function managedDropIns(m: Machine): string[] {
  const d = join(managedDir(m), "managed-settings.d");
  try {
    return readdirSync(d).filter((f) => f.endsWith(".json")).sort().map((f) => join(d, f));
  } catch {
    return [];
  }
}

export function doctorClaude(m: Machine, probe: CliProbe): Check[] {
  const out: Check[] = [];
  const add = (level: Level, title: string, fix?: string) => out.push({ agent: "claude", level, title, fix });
  const version = probe.found ? parseVersion(probe.stdout) : null;
  if (!probe.found) add("warn", "`claude` is not on PATH here; checking its settings files anyway");
  else add(atLeast(version, CLAUDE_MIN.execForm) === false ? "fail" : "ok", `Claude Code ${version ? version.join(".") : probe.stdout.trim()}${atLeast(version, CLAUDE_MIN.execForm) === false ? `: ah's exec-form hook needs ${CLAUDE_MIN.execForm} or later` : ""}`, atLeast(version, CLAUDE_MIN.execForm) === false ? "update Claude Code" : undefined);

  const files: SettingsFile[] = claudeSettingsFiles(m, managedDropIns(m));
  const values: { f: SettingsFile; value: Record<string, unknown> }[] = [];
  const owned: OwnedAt[] = [];
  for (const f of files) {
    const r = readJson(f.path);
    if (!r.ok) {
      add("fail", `${rel(m, f.path)} is not plain JSON (${r.error}); Claude Code loads nothing from it, hooks included`, "fix the file; settings files are strict JSON");
      continue;
    }
    if (!r.exists) continue;
    if (!isObj(r.value)) {
      add("fail", `${rel(m, f.path)} is not a JSON object; Claude Code loads nothing from it`);
      continue;
    }
    values.push({ f, value: r.value });
    const pre = get(r.value, "hooks", "PreToolUse");
    if (pre !== undefined && !Array.isArray(pre)) add("fail", `${rel(m, f.path)}: hooks.PreToolUse is not a list; Claude Code rejects the whole file`);
    else if (Array.isArray(pre)) {
      for (const g of pre) {
        const bad = claudeFatal(g);
        if (bad) {
          add("fail", `${rel(m, f.path)} has ${bad} under PreToolUse; Claude Code then loads nothing from this file, ah's hook included`, "fix or remove that entry");
          break;
        }
      }
    }
    owned.push(...ownedIn(r.value, f.path, f.scope));
  }

  // Switches that turn hooks off. Precedence: managed, then local, project, user.
  const managedValues = values.filter((v) => v.f.scope === "managed");
  const disable = values.find((v) => typeof v.value.disableAllHooks === "boolean");
  if (disable?.value.disableAllHooks === true) add("fail", `disableAllHooks is true in ${rel(m, disable.f.path)}; no hook runs`, "remove disableAllHooks or set it to false");
  const onlyManaged = managedValues.find((v) => v.value.allowManagedHooksOnly === true);
  if (onlyManaged && !owned.some((o) => o.scope === "managed")) add("fail", `allowManagedHooksOnly is set in ${onlyManaged.f.path}; only hooks your organization deploys run, and ah's is not one`, "ask whoever manages that file to add the ah hook to it");

  if (owned.length === 0) {
    add("fail", "no ah PreToolUse hook in any Claude Code settings file", "run `ah init --agents claude`");
  } else {
    const scopes = [...new Set(owned.map((o) => rel(m, o.file)))];
    if (owned.length > 1) {
      // Claude Code runs copies with the same command, args, shell and `if` once, taking one copy's other fields.
      const byRun = new Map<string, Set<string>>();
      for (const o of owned) {
        const k = JSON.stringify([o.entry.command, o.entry.args, o.entry.shell, o.entry.if]);
        byRun.set(k, (byRun.get(k) ?? new Set()).add(JSON.stringify([o.entry.onFailure ?? "continue", o.entry.timeout])));
      }
      const mixed = [...byRun.values()].some((v) => v.size > 1);
      add(mixed ? "warn" : "info", `ah is wired ${owned.length} times (${scopes.join(", ")}); Claude Code runs copies of the same command once${mixed ? ", and these copies differ in onFailure or timeout, so which setting applies is not documented" : ""}`, mixed ? "keep one: `ah init --remove`, then `ah init`" : undefined);
    }
    const seen = new Set<string>();
    for (const o of owned) {
      const where = rel(m, o.file);
      const e = o.entry;
      const words = entryWords(e)[0] ?? [];
      const exec = Array.isArray(e.args);
      const { node, guard } = namedPaths(words);
      const args = guardArgs(words) ?? [];
      const agentAt = args.indexOf("--agent");
      if (agentAt >= 0 && args[agentAt + 1] !== "claude") add("fail", `${where}: the ah entry runs the guard with --agent ${args[agentAt + 1]}; Claude Code payloads need --agent claude`, "re-run `ah init --agents claude`");
      if (e.async === true || e.asyncRewake === true) add("fail", `${where}: the ah entry is async, so it cannot block anything`, "re-run `ah init`");
      if (typeof e.if === "string") add("warn", `${where}: the ah entry only runs when ${JSON.stringify(e.if)} matches`, "re-run `ah init` to drop the filter");
      const missing = CLAUDE_REQUIRED_TOOLS.filter((t) => !claudeMatcherCovers(o.group.matcher, t));
      const optional = CLAUDE_OPTIONAL_TOOLS.filter((t) => !claudeMatcherCovers(o.group.matcher, t));
      if (missing.length > 0) add("fail", `${where}: the matcher ${JSON.stringify(o.group.matcher)} skips ${missing.join(", ")}; those calls are never checked`, "re-run `ah init`");
      else add("ok", `${where}: ah hook bound${exec ? " (exec form)" : " (shell form)"} for ${CLAUDE_REQUIRED_TOOLS.join(", ")}${optional.length > 0 ? `; not for ${optional.join(", ")}` : ""}`);
      if (o.scope === "project") add("info", `${where} is read only by sessions started in ${m.root}; one started in a subdirectory runs without this hook`, "`ah init --scope local` covers the whole repository");
      if (node && !exists(node) && exec) add("fail", `${where}: ${node} does not exist, so the hook cannot start${e.onFailure === "block" ? " and every matched call is blocked" : " and every call goes through unchecked"}`, "re-run `ah init` with the node you use now");
      if (guard && !exists(guard)) add("fail", `${where}: ${guard} does not exist`, "reinstall @9thlevel/aegis, then re-run `ah init`");
      if (e.onFailure === "block") {
        if (atLeast(version, CLAUDE_MIN.onFailure) === false) add("warn", `${where}: onFailure needs Claude Code ${CLAUDE_MIN.onFailure} or later; this version ignores it and fails open`);
      } else add("info", `${where}: fails open: if the hook cannot start or times out, the call goes ahead`, "`ah init --fail-closed` blocks the call instead");
      const key = JSON.stringify([e.command, e.args]);
      if (seen.has(key)) continue;
      seen.add(key);
      const timeout = typeof e.timeout === "number" && e.timeout > 0 ? e.timeout : 600;
      const sub = (s: string) => s.replace(/\$\{CLAUDE_PROJECT_DIR\}/g, m.root);
      if (exec) out.push(...canaryLine("claude", m, { kind: "exec", file: sub(e.command as string), args: (e.args as string[]).map(sub) }, timeout, where));
      else if (m.os !== "win32") out.push(...canaryLine("claude", m, { kind: "shell", command: e.command as string, shell: "/bin/sh", shellArgs: ["-c"] }, timeout, where));
      else add("warn", `${where}: shell-form entry not tested on Windows (Claude Code picks Git Bash or PowerShell)`, "re-run `ah init` to switch to exec form");
    }
  }

  // Workspace trust: interactive sessions hold back settings-file hooks until it is accepted.
  const claudeJson = readJsonQuiet(m.env.CLAUDE_CONFIG_DIR ? join(m.env.CLAUDE_CONFIG_DIR, ".claude.json") : join(m.home, ".claude.json"));
  if (claudeJson !== undefined) {
    const projects = get(claudeJson, "projects");
    let trusted = false;
    for (let d = m.root; ; d = dirname(d)) {
      if (isObj(projects) && get(projects, d, "hasTrustDialogAccepted") === true) trusted = true;
      if (dirname(d) === d || trusted) break;
    }
    if (!trusted) add("warn", "this folder's workspace trust is not accepted yet; interactive Claude Code sessions run no settings-file hook until it is", "start `claude` here once and accept the trust prompt");
  }

  // Instructions.
  const s = claudeMdState(m.root);
  const target = s.target ?? (s.present.length === 0 ? join(m.root, "AGENTS.md") : null);
  if (target !== null) {
    let state: string;
    try {
      state = blockIsCurrent(readText(target).text, target);
    } catch (err) {
      state = `unreadable (${(err as Error).message})`;
    }
    if (state === "current") add("ok", `${rel(m, target)} carries the guard's instructions for Claude Code`);
    else add("warn", `${rel(m, target)}: the guard's instructions are ${state}`, "re-run `ah init`");
    if (s.target === null && atLeast(version, CLAUDE_MIN.agentsMd) === false) add("warn", `Claude Code reads AGENTS.md from ${CLAUDE_MIN.agentsMd}; this version does not`, "update Claude Code");
  }
  for (let d = dirname(m.root); dirname(d) !== d; d = dirname(d)) {
    if (exists(join(d, "CLAUDE.md")) && s.target === null && s.present.length === 0) {
      add("warn", `${join(d, "CLAUDE.md")} exists above the project, so Claude Code does not read AGENTS.md here`, "re-run `ah init`, or add the guard's block to that file");
      break;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Codex

const CODEX_HOOK_TYPES = new Set(["command", "mcp_tool", "prompt", "agent"]);

/** What makes Codex 0.163 reject a hooks.json file. */
function codexFileProblem(value: unknown): string | null {
  if (!isObj(value)) return "it is not a JSON object";
  const extra = Object.keys(value).filter((k) => k !== "description" && k !== "hooks");
  if (extra.length > 0) return `top-level key ${extra.map((k) => JSON.stringify(k)).join(", ")} (only "description" and "hooks" are allowed)`;
  if (value.hooks === undefined) return null;
  if (!isObj(value.hooks)) return '"hooks" is not an object';
  for (const [event, groups] of Object.entries(value.hooks)) {
    if (!Array.isArray(groups)) return `hooks.${event} is not a list`;
    for (const g of groups) {
      if (!isObj(g) || !Array.isArray(g.hooks)) return `a ${event} group without a hooks list`;
      if (g.matcher !== undefined && typeof g.matcher !== "string") return `a ${event} matcher that is not a string`;
      for (const e of g.hooks) {
        if (!isObj(e) || typeof e.type !== "string" || !CODEX_HOOK_TYPES.has(e.type)) return `a ${event} hook with type ${JSON.stringify(isObj(e) ? e.type : e)}`;
        if (e.type === "command" && typeof e.command !== "string") return `a ${event} command hook without a command string`;
        if (e.commandWindows !== undefined && e.commandWindows !== null && typeof e.commandWindows !== "string") return `a ${event} commandWindows that is not a string`;
        if (e.timeout !== undefined && !(Number.isInteger(e.timeout) && (e.timeout as number) >= 0)) return `a ${event} timeout of ${JSON.stringify(e.timeout)} (it must be a whole number of seconds)`;
        if (e.async !== undefined && typeof e.async !== "boolean") return `a ${event} async that is not true or false`;
        if (e.statusMessage !== undefined && typeof e.statusMessage !== "string") return `a ${event} statusMessage that is not a string`;
      }
    }
  }
  return null;
}

function readToml(path: string): { doc?: Record<string, unknown>; error?: string; exists: boolean } {
  const t = readText(path).text;
  if (t === null) return { exists: false };
  try {
    return { doc: parseToml(t), exists: true };
  } catch (err) {
    return { error: (err as Error).message, exists: true };
  }
}

export function doctorCodex(m: Machine, probe: CliProbe, featuresList: string | null): Check[] {
  const out: Check[] = [];
  const add = (level: Level, title: string, fix?: string) => out.push({ agent: "codex", level, title, fix });
  if (!probe.found) add("warn", "`codex` is not on PATH here; checking its files anyway");
  else add("ok", `Codex ${parseCodexVersion(probe.stdout) ?? probe.stdout.trim()}`);

  const userConfigPath = codexConfigFiles(m).find((f) => f.scope === "user")?.path as string;
  const projectConfigPath = codexConfigFiles(m).find((f) => f.scope === "project")?.path as string;
  const userConfig = readToml(userConfigPath);
  if (userConfig.error) add("warn", `${rel(m, userConfigPath)} could not be read (${userConfig.error}); trust and feature checks below are incomplete`);
  // An entry for the repository root also trusts the layers below it.
  const top = gitTopLevel(m.root);
  const projectTrust = get(userConfig.doc, "projects", m.root, "trust_level") ?? (top !== null ? get(userConfig.doc, "projects", top, "trust_level") : undefined);
  const projectTrusted = projectTrust === "trusted";

  // features.hooks: `codex features list` knows the effective value; config.toml says where it was set.
  const fromList = featuresList === null ? null : parseFeaturesHooks(featuresList);
  const projectConfig = projectTrusted ? readToml(projectConfigPath) : { exists: false };
  const setOff = [
    { path: userConfigPath, doc: userConfig.doc },
    { path: projectConfigPath, doc: (projectConfig as { doc?: Record<string, unknown> }).doc },
  ].filter((c) => get(c.doc, "features", "hooks") === false || get(c.doc, "features", "codex_hooks") === false);
  if (fromList === false || (fromList === null && setOff.length > 0)) add("fail", `Codex hooks are off (features.hooks = false${setOff.length > 0 ? ` in ${setOff.map((c) => rel(m, c.path)).join(", ")}` : ""}); no hook runs`, "remove `hooks = false` from [features], or run `codex features enable hooks`");
  else if (fromList === true) add("ok", "features.hooks is on");

  const req = readToml(codexRequirementsFile(m));
  const managedOnly = get(req.doc, "allow_managed_hooks_only") === true;

  const owned: OwnedAt[] = [];
  for (const f of codexHooksFiles(m)) {
    const r = readJson(f.path);
    if (!r.ok) {
      add("fail", `${rel(m, f.path)} is not plain JSON (${r.error}); Codex loads no hook from it`);
      continue;
    }
    if (!r.exists) continue;
    const bad = codexFileProblem(r.value);
    if (bad) add("fail", `${rel(m, f.path)} has ${bad}; Codex rejects the whole file`, "fix the file, then re-run `ah init`");
    owned.push(...ownedIn(r.value, f.path, f.scope));
  }
  for (const c of [{ path: userConfigPath, doc: userConfig.doc }, { path: projectConfigPath, doc: (projectConfig as { doc?: Record<string, unknown> }).doc }]) {
    if (ownedIn(c.doc, c.path, "toml").length > 0) add("info", `${rel(m, c.path)} has an inline ah hook in [hooks]; ah init does not manage TOML, so check it by hand`);
  }

  if (managedOnly) add("fail", `allow_managed_hooks_only is set in ${codexRequirementsFile(m)}; Codex skips user and project hooks, ah's included`, "ask whoever manages that file to add the ah hook as a managed hook");
  if (owned.length === 0) {
    add("fail", "no ah PreToolUse hook in ~/.codex/hooks.json or .codex/hooks.json", "run `ah init --agents codex`");
    return [...out, ...codexInstructions(m, projectTrust)];
  }
  if (owned.length > 1) add("warn", `ah is wired ${owned.length} times (${[...new Set(owned.map((o) => rel(m, o.file)))].join(", ")}); Codex runs every copy on every matched call`, "keep one: `ah init --remove` then `ah init`, or delete the extra entry");

  for (const o of owned) {
    const where = rel(m, o.file);
    const e = o.entry;
    const cmd = m.os === "win32" && typeof e.commandWindows === "string" ? e.commandWindows : (e.command as string);
    const words = splitWords(cmd);
    const args = guardArgs(words) ?? [];
    const agentAt = args.indexOf("--agent");
    if (agentAt >= 0 && args[agentAt + 1] !== "codex") add("fail", `${where}: the ah entry runs the guard with --agent ${args[agentAt + 1]}; Codex payloads need --agent codex`, "re-run `ah init --agents codex`");
    if (e.async === true) add("fail", `${where}: the ah entry is async, so it cannot block anything`, "re-run `ah init`");
    const missing = CODEX_REQUIRED_TOOLS.filter((t) => !codexMatcherCovers(o.group.matcher, t.names));
    if (missing.length > 0) add("fail", `${where}: the matcher ${JSON.stringify(o.group.matcher)} skips ${missing.map((t) => t.label).join(" and ")}`, "re-run `ah init`");
    else add("ok", `${where}: ah hook bound for shell commands and apply_patch`);
    const { node, guard } = namedPaths(words);
    if (node && /[\\/]/.test(node) && !exists(node)) add("fail", `${where}: ${node} does not exist, so the hook cannot start and Codex lets every call through`, "re-run `ah init` with the node you use now");
    if (guard && !exists(guard)) add("fail", `${where}: ${guard} does not exist`, "reinstall @9thlevel/aegis, then re-run `ah init`");
    if (o.scope === "project") {
      if (projectTrust === "untrusted") add("fail", `this project is marked untrusted in ${rel(m, userConfigPath)}; Codex skips .codex/hooks.json`, "trust the project when Codex asks, or set trust_level = \"trusted\" for it");
      else if (!projectTrusted) add("fail", `this project is not trusted in ${rel(m, userConfigPath)} yet; Codex loads .codex/hooks.json only for trusted projects`, "start Codex here and accept the trust prompt");
    }
    const key = `${o.file}:pre_tool_use:${o.groupIndex}:${o.handlerIndex}`;
    const state = get(userConfig.doc, "hooks", "state", key);
    if (get(state, "enabled") === false) add("fail", `${where}: the ah hook is disabled in Codex's /hooks`, "open /hooks in Codex and enable it");
    else if (typeof get(state, "trusted_hash") === "string") add("ok", `${where}: Codex has a trust record for the ah hook (if the entry changed since, Codex asks again in /hooks)`);
    else add("fail", `${where}: Codex has not trusted the ah hook yet, so it skips it`, "start Codex in this project, open /hooks, and trust the ah entry");

    const timeout = Number.isInteger(e.timeout) && (e.timeout as number) > 0 ? (e.timeout as number) : 600;
    if (m.os !== "win32") {
      const shell = codexShell();
      out.push(...canaryLine("codex", m, { kind: "shell", command: e.command as string, shell, shellArgs: ["-c"] }, timeout, `${where} (${basename(shell)} -c)`));
    }
    else {
      const ps = canaryLine("codex", m, { kind: "shell", command: cmd, shell: "powershell.exe", shellArgs: ["-NoProfile", "-NonInteractive", "-Command"] }, timeout, `${where} (PowerShell)`);
      const cmdExe = canaryLine("codex", m, { kind: "shell", command: `"${cmd}"`, shell: "cmd.exe", shellArgs: ["/d", "/s", "/c"] }, timeout, `${where} (cmd.exe)`);
      const okBoth = ps[0].level === "ok" && cmdExe[0].level === "ok";
      if (okBoth) out.push(...ps, ...cmdExe);
      else if (ps[0].level === "ok" || cmdExe[0].level === "ok") {
        out.push(...ps, ...cmdExe.map((c) => ({ ...c, level: "warn" as Level })));
        add("warn", "the Windows command works in one shell only; Codex does not document which shell runs commandWindows", "tell the ah maintainers which one Codex used (ah bug add)");
      } else out.push(...ps, ...cmdExe);
    }
  }
  return [...out, ...codexInstructions(m, projectTrust)];
}

/** The shell Codex runs a hook `command` with: the login shell when it is bash or zsh, else bash from PATH. */
function codexShell(): string {
  let login = "";
  try {
    login = userInfo().shell ?? "";
  } catch {
    // no passwd entry
  }
  if (/(^|\/)(bash|zsh)$/.test(login) && existsSync(login)) return login;
  for (const d of (process.env.PATH ?? "").split(":")) if (d !== "" && existsSync(join(d, "bash"))) return join(d, "bash");
  return "/bin/sh";
}

function codexInstructions(m: Machine, projectTrust: unknown): Check[] {
  const out: Check[] = [];
  const override = join(m.root, "AGENTS.override.md");
  const file = readText(override).text !== null ? override : join(m.root, "AGENTS.md");
  const text = readText(file).text;
  let state: string;
  try {
    state = blockIsCurrent(text, file);
  } catch (err) {
    state = `unreadable (${(err as Error).message})`;
  }
  const where = rel(m, file);
  if (state !== "current") out.push({ agent: "codex", level: "warn", title: `${where}: the guard's instructions are ${state}`, fix: "re-run `ah init`" });
  else {
    const end = text === null ? null : blockEndByte(text, file);
    if (end !== null && end > CODEX_DOC_BUDGET) out.push({ agent: "codex", level: "warn", title: `${where}: the guard's block ends past the first ${CODEX_DOC_BUDGET / 1024} KiB, which is all Codex reads`, fix: "re-run `ah init`; it moves the block to the top" });
    else out.push({ agent: "codex", level: "ok", title: `${where} carries the guard's instructions for Codex` });
  }
  if (projectTrust === "untrusted") out.push({ agent: "codex", level: "warn", title: "Codex does not read a project's AGENTS.md while the project is marked untrusted" });
  return out;
}

// ---------------------------------------------------------------------------

export interface DoctorResult {
  ok: boolean;
  root: string;
  checks: Check[];
}

export interface DoctorDeps {
  probe: (name: string) => CliProbe;
  featuresList: (root: string) => string | null;
}

export const realDeps = (env: NodeJS.ProcessEnv): DoctorDeps => ({
  probe: (name) => probeCli(name, env),
  featuresList: (root) => {
    const r = spawnSync("codex", ["features", "list"], { cwd: root, encoding: "utf8", env, timeout: 15_000, windowsHide: true, shell: process.platform === "win32" });
    return r.status === 0 ? (r.stdout ?? "") : null;
  },
});

export function doctor(o: DoctorOptions, env: NodeJS.ProcessEnv = process.env, deps: DoctorDeps = realDeps(env)): DoctorResult {
  const m = defaultMachine(resolve(o.root), "", env);
  const checks: Check[] = [];
  if (!existsSync(m.root)) return { ok: false, root: m.root, checks: [{ agent: "project", level: "fail", title: `${m.root} does not exist` }] };
  if (o.agents.includes("claude")) checks.push(...doctorClaude(m, deps.probe("claude")));
  if (o.agents.includes("codex")) {
    const p = deps.probe("codex");
    checks.push(...doctorCodex(m, p, p.found ? deps.featuresList(m.root) : null));
  }
  if (!existsSync(join(m.root, ".harness"))) checks.push({ agent: "project", level: "info", title: "no .harness/ directory, so denies and asks are not logged to .harness/metrics.jsonl", fix: "`ah init` creates it" });
  return { ok: !checks.some((c) => c.level === "fail"), root: m.root, checks };
}

export function renderDoctor(r: DoctorResult): string {
  const names = { claude: "Claude Code", codex: "Codex", project: "Project" } as const;
  const lines = [`ah doctor: ${r.root}`];
  for (const agent of ["claude", "codex", "project"] as const) {
    const cs = r.checks.filter((c) => c.agent === agent);
    if (cs.length === 0) continue;
    lines.push(names[agent]);
    for (const c of cs) {
      lines.push(`  ${c.level.padEnd(4)}  ${c.title}`);
      if (c.fix && c.level !== "ok") lines.push(`        fix: ${c.fix}`);
    }
  }
  const fails = r.checks.filter((c) => c.level === "fail").length;
  const warns = r.checks.filter((c) => c.level === "warn").length;
  lines.push(fails === 0 ? `No failures${warns > 0 ? `, ${warns} warning${warns === 1 ? "" : "s"}` : ""}.` : `${fails} failure${fails === 1 ? "" : "s"}${warns > 0 ? `, ${warns} warning${warns === 1 ? "" : "s"}` : ""}: some tool calls would not reach the guard.`);
  return `${lines.join("\n")}\n`;
}

export function runDoctor(argv: readonly string[], io: { stdout: (s: string) => void; stderr: (s: string) => void } = { stdout: (s) => process.stdout.write(s), stderr: (s) => process.stderr.write(s) }, env: NodeJS.ProcessEnv = process.env, deps?: DoctorDeps): number {
  if (argv.includes("--help") || argv.includes("-h")) {
    io.stdout(DOCTOR_HELP);
    return 0;
  }
  const o = parseDoctorArgs(argv);
  if (typeof o === "string") {
    io.stderr(`ah doctor: ${o}\n\n${DOCTOR_HELP}`);
    return 2;
  }
  const r = doctor(o, env, deps ?? realDeps(env));
  io.stdout(o.json ? `${JSON.stringify(r, null, 2)}\n` : renderDoctor(r));
  return r.ok ? 0 : 1;
}

export { claudeConfigDir, codexHome };
