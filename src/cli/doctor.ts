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
import { existsSync, readdirSync, realpathSync, statSync } from "node:fs";
import { userInfo } from "node:os";
import { basename, delimiter, dirname, join, relative, resolve } from "node:path";
import { atLeast, CLAUDE_MIN, CLAUDE_OPTIONAL_TOOLS, CLAUDE_REQUIRED_TOOLS, claudeConfigDir, claudeHooksProblem, claudeMatcherCovers, claudeSettingsFiles, managedDir, parseVersion, type SettingsFile } from "../wiring/claude.ts";
import { canaries, runCanary, type Launch } from "../wiring/canary.ts";
import { canonical, CODEX_REQUIRED_TOOLS, codexConfigFiles, codexFileProblem, codexHome, codexHooksFiles, codexHooksList, codexLayers, codexMatcherCovers, codexRequirementsFile, parseCodexVersion, parseFeaturesHooks, type CodexListedHook, type CodexListing } from "../wiring/codex.ts";
import { readJson, readText } from "../wiring/files.ts";
import { blockIsCurrent, claudeMdState, CODEX_DOC_BUDGET, committedStandIns, rootTextLinks, staleStandIns } from "../wiring/instructions.ts";
import { entryWords, GUARD_FILE, guardArgs, isOwnedEntry, looksLikeGuard, splitWords } from "../wiring/owned.ts";
import { defaultMachine, gitTopLevel, mainCheckoutRoot, readJsonQuiet, sharedAcrossWsl, type Machine } from "../wiring/project.ts";
import { defaultGuardPath } from "./test-hooks.ts";
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
    edit to .ruff.toml must be refused, ls must pass). With codex on PATH it also asks Codex itself
    (codex app-server, offline) which hooks it loads here and whether it trusts them.
    Exits 1 if any call would go unguarded.
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

/** A command an agent starts by name: a path is checked as is, a bare name on PATH (with .exe/.cmd on Windows). */
function findCommand(m: Machine, cmd: string): boolean {
  if (/[\\/]/.test(cmd)) return exists(cmd);
  const exts = m.os === "win32" ? ["", ".exe", ".cmd", ".bat"] : [""];
  return (m.env.PATH ?? m.env.Path ?? "").split(m.os === "win32" ? ";" : delimiter).some((d) => d !== "" && exts.some((x) => exists(join(d, cmd + x))));
}

/** `<node> <guard> --version`, or null when the guard does not answer with one (builds before it learned to). */
function guardVersion(node: string, guard: string, env: NodeJS.ProcessEnv): string | null {
  const r = spawnSync(node, [guard, "--version"], { encoding: "utf8", env, input: "", timeout: 10_000, windowsHide: true });
  const v = (r.stdout ?? "").trim();
  return r.status === 0 && /^\d+\.\d+\.\d+\S*$/.test(v) ? v : null;
}

/** Warn when a hook runs a different guard build than the one `ah init` wires now: rules added since are missing from it. */
function versionCheck(agent: "claude" | "codex", m: Machine, where: string, node: string | undefined, guard: string | undefined): Check[] {
  const ours = defaultGuardPath();
  if (!guard || !ours || !exists(guard) || canonical(guard) === canonical(ours)) return [];
  const theirs = guardVersion(node && findCommand(m, node) ? node : process.execPath, guard, m.env);
  const mine = guardVersion(process.execPath, ours, m.env);
  if (theirs !== null && theirs === mine) return [];
  const what = theirs === null ? "an older build that does not report its version" : `version ${theirs}`;
  return [{ agent, level: "warn", title: `${where}: the hook runs the guard at ${guard}, ${what}; this ah wires ${ours}${mine ? ` (${mine})` : ""}, so rules added since may be missing from the hook`, fix: "re-run `ah init` to point the hook at this ah's guard" }];
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

function ownedIn(value: unknown, file: string, scope: string, test: (e: unknown) => boolean = isOwnedEntry): OwnedAt[] {
  const groups = get(value, "hooks", "PreToolUse");
  if (!Array.isArray(groups)) return [];
  const out: OwnedAt[] = [];
  groups.forEach((g, groupIndex) => {
    if (!isObj(g) || !Array.isArray(g.hooks)) return;
    g.hooks.forEach((e, handlerIndex) => {
      if (test(e)) out.push({ file, scope, group: g, entry: e as Record<string, unknown>, groupIndex, handlerIndex });
    });
  });
  return out;
}

/** The spellings Claude Code may have keyed a directory's trust under in ~/.claude.json. */
function trustKeys(m: Machine, dir: string): string[] {
  if (m.os !== "win32") return [...new Set([dir, canonical(dir)])];
  let real = dir;
  try {
    real = realpathSync.native(dir);
  } catch {
    // keep the spelling we have
  }
  return [...new Set([real, dir].map((d) => d.replace(/\\/g, "/")))];
}

/** The node and guard paths an entry names, for checking they still exist. */
function namedPaths(words: string[]): { node?: string; guard?: string } {
  const gi = words.findIndex((w) => GUARD_FILE.test(w));
  if (gi < 0) return {};
  const before = words.slice(0, gi).filter((w) => w !== "&");
  return { node: before.length > 0 ? before[before.length - 1] : undefined, guard: words[gi] };
}

/** A project file shared across WSL and Windows holds paths only one side can run. */
function wslCheck(agent: "claude" | "codex", m: Machine, owned: OwnedAt[]): Check[] {
  const across = sharedAcrossWsl(m);
  const files = [...new Set(owned.filter((o) => o.scope === "local" || o.scope === "project").map((o) => rel(m, o.file)))];
  if (across === null || files.length === 0) return [];
  const title = across === "windows" ? `${files.join(", ")} sits on a Windows drive, so ${agent === "claude" ? "Claude Code" : "Codex"} running on Windows reads it too and cannot start this WSL node; its calls go through unchecked` : `${files.join(", ")} lives inside WSL, so ${agent === "claude" ? "Claude Code" : "Codex"} running in WSL reads it too and cannot start this Windows node; its calls go through unchecked`;
  return [{ agent, level: "warn", title, fix: "wire each side with `ah init --scope user` instead" }];
}

function canaryLine(agent: "claude" | "codex", m: Machine, launch: Launch, timeoutSec: number, label: string): Check[] {
  const env: NodeJS.ProcessEnv = { ...m.env, AH_NO_LOG: "1" };
  if (agent === "claude") env.CLAUDE_PROJECT_DIR = m.root;
  const results: string[] = [];
  const failures: string[] = [];
  let slowest = 0;
  for (const c of canaries(agent, m.root, m.os === "win32" ? "\\" : "/")) {
    const r = runCanary(launch, c.payload, { cwd: m.root, env, timeoutMs: Math.min(timeoutSec, 30) * 1000, agent });
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

function managedDropIns(m: Machine): string[] {
  const d = join(managedDir(m), "managed-settings.d");
  try {
    return readdirSync(d).filter((f) => f.endsWith(".json")).sort().map((f) => join(d, f));
  } catch {
    return [];
  }
}

/** A managed policy source. Lower tiers win whole: HKLM (0), then the managed files merged (1), then HKCU (2). */
export interface PolicySource {
  scope: string;
  path: string;
  value: Record<string, unknown>;
  tier?: number;
}

/**
 * The switches that turn Claude Code's hooks off, per 2.1.302's hook source:
 * the first managed tier that exists is the policy (managed-settings.json and
 * its drop-ins merge, later files winning), except that allowManagedHooksOnly
 * holds when any managed source sets it; elsewhere the first of local,
 * project, user that sets one wins. `files` is in precedence order, managed first.
 */
export function claudeSwitches(files: PolicySource[], managedAh: boolean, env: NodeJS.ProcessEnv): Check[] {
  const out: Check[] = [];
  const add = (level: Level, title: string, fix?: string) => out.push({ agent: "claude", level, title, fix });
  const sources = files.filter((f) => f.scope === "managed");
  const tier = Math.min(...sources.map((f) => f.tier ?? 1));
  const managed = sources.filter((f) => (f.tier ?? 1) === tier);
  const policy: Record<string, unknown> = Object.assign({}, ...managed.map((f) => f.value));
  const setIn = (key: string) => [...managed].reverse().find((f) => f.value[key] !== undefined)?.path ?? "";
  const first = files.filter((f) => f.scope !== "managed").find((f) => typeof f.value.disableAllHooks === "boolean");
  const disabledIn = typeof policy.disableAllHooks === "boolean" ? (policy.disableAllHooks ? setIn("disableAllHooks") : null) : first?.value.disableAllHooks === true ? first.path : null;
  if (disabledIn !== null) add("fail", `disableAllHooks is true in ${disabledIn}; no hook runs`, "remove disableAllHooks or set it to false");
  const strict = policy.strictPluginOnlyCustomization;
  const lockedIn = sources.find((f) => f.value.allowManagedHooksOnly === true)?.path;
  if (lockedIn !== undefined && !managedAh) add("fail", `allowManagedHooksOnly is set in ${lockedIn}; only hooks your organization deploys run, and ah's is not one`, "ask whoever manages that policy to add the ah hook to it");
  else if ((strict === true || (Array.isArray(strict) && strict.includes("hooks"))) && !managedAh) add("fail", `strictPluginOnlyCustomization covers hooks in ${setIn("strictPluginOnlyCustomization")}; only managed and plugin hooks run, and ah's is neither`, "ask whoever manages that file to add the ah hook to it");
  if (/^(1|true|yes|on)$/i.test(env.CLAUDE_CODE_SAFE_MODE ?? "") && !managedAh) add("warn", "CLAUDE_CODE_SAFE_MODE is set in this shell; a Claude Code session started from it runs only managed hooks", "unset CLAUDE_CODE_SAFE_MODE");
  return out;
}

/** The REG_SZ `Settings` value in `reg.exe query` output, or null. */
export function parseRegSettings(stdout: string): string | null {
  return /^\s*Settings\s+REG_(?:EXPAND_)?SZ\s+(.*?)\s*$/m.exec(stdout)?.[1] ?? null;
}

/**
 * Claude Code's policy from the Windows registry, plus, in WSL, the Windows
 * policy a session inherits when wslInheritsWindowsSettings is set. Null when
 * reg.exe could not be asked.
 */
function registryPolicy(m: Machine): PolicySource[] | null {
  const wsl = m.os === "linux" && Boolean(m.env.WSL_DISTRO_NAME || m.env.WSL_INTEROP) && existsSync("/mnt/c/Windows/System32/reg.exe");
  if (m.os !== "win32" && !wsl) return [];
  const reg = m.os === "win32" ? "reg.exe" : "/mnt/c/Windows/System32/reg.exe";
  const out: PolicySource[] = [];
  for (const [key, tier] of [["HKLM\\SOFTWARE\\Policies\\ClaudeCode", 0], ["HKCU\\SOFTWARE\\Policies\\ClaudeCode", 2]] as const) {
    const r = spawnSync(reg, ["query", key, "/v", "Settings"], { encoding: "utf8", windowsHide: true, timeout: 10_000 });
    if (r.error) return null;
    const text = r.status === 0 ? parseRegSettings(r.stdout ?? "") : null;
    if (text === null) continue;
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      value = undefined;
    }
    out.push({ scope: "managed", path: `${key}\\Settings`, value: isObj(value) ? value : {}, tier });
  }
  if (wsl) {
    const file = readJsonQuiet("/mnt/c/Program Files/ClaudeCode/managed-settings.json");
    if (isObj(file)) out.push({ scope: "managed", path: "/mnt/c/Program Files/ClaudeCode/managed-settings.json", value: file, tier: 1 });
    // Windows policy reaches a WSL session only when it opts in.
    if (!out.some((s) => s.value.wslInheritsWindowsSettings === true)) return [];
  }
  return out;
}

export function doctorClaude(m: Machine, probe: CliProbe, registry: PolicySource[] | null = registryPolicy(m)): Check[] {
  const out: Check[] = [];
  const add = (level: Level, title: string, fix?: string) => out.push({ agent: "claude", level, title, fix });
  const version = probe.found ? parseVersion(probe.stdout) : null;
  if (!probe.found) add("warn", "`claude` is not on PATH here; checking its settings files anyway");
  else add(atLeast(version, CLAUDE_MIN.execForm) === false ? "fail" : "ok", `Claude Code ${version ? version.join(".") : probe.stdout.trim()}${atLeast(version, CLAUDE_MIN.execForm) === false ? `: ah's exec-form hook needs ${CLAUDE_MIN.execForm} or later` : ""}`, atLeast(version, CLAUDE_MIN.execForm) === false ? "update Claude Code" : undefined);

  const files: SettingsFile[] = claudeSettingsFiles(m, managedDropIns(m));
  const values: { f: SettingsFile; value: Record<string, unknown> }[] = [];
  const owned: OwnedAt[] = [];
  const wrapped: string[] = [];
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
    const bad = claudeHooksProblem(r.value);
    if (bad) {
      add("fail", `${rel(m, f.path)} has ${bad}; Claude Code then applies nothing from this file, ah's hook included`, "fix or remove that entry");
      continue;
    }
    owned.push(...ownedIn(r.value, f.path, f.scope));
    wrapped.push(...ownedIn(r.value, f.path, f.scope, looksLikeGuard).map((o) => rel(m, o.file)));
  }
  for (const w of new Set(wrapped)) add("info", `${w} has an entry that runs the guard with other words around it; ah does not count or test it`);

  if (registry === null) add("warn", "could not ask reg.exe for Claude Code's registry policy (HKLM and HKCU \\SOFTWARE\\Policies\\ClaudeCode); a policy there can turn ah's hook off", "check that key by hand");
  out.push(...claudeSwitches([...(registry ?? []), ...values.map((v) => ({ scope: v.f.scope, path: rel(m, v.f.path), value: v.value }))], owned.some((o) => o.scope === "managed"), m.env));

  if (owned.length === 0) {
    add("fail", "no ah PreToolUse hook in any Claude Code settings file", "run `ah init --agents claude`");
  } else {
    const scopes = [...new Set(owned.map((o) => rel(m, o.file)))];
    out.push(...wslCheck("claude", m, owned));
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
      if (typeof e.if === "string") add("fail", `${where}: the ah entry only runs when ${JSON.stringify(e.if)} matches, so every other call skips the guard`, "re-run `ah init` to drop the filter");
      const missing = CLAUDE_REQUIRED_TOOLS.filter((t) => !claudeMatcherCovers(o.group.matcher, t));
      const optional = CLAUDE_OPTIONAL_TOOLS.filter((t) => !claudeMatcherCovers(o.group.matcher, t)).map((t) => (t.startsWith("mcp__") ? "MCP tools" : t));
      if (missing.length > 0) add("fail", `${where}: the matcher ${JSON.stringify(o.group.matcher)} skips ${missing.join(", ")}; those calls are never checked`, "re-run `ah init`");
      else add("ok", `${where}: ah hook bound${exec ? " (exec form)" : " (shell form)"} for ${CLAUDE_REQUIRED_TOOLS.join(", ")}${optional.length > 0 ? `; not for ${optional.join(", ")}` : ""}`);
      const sub = (s: string) => s.replace(/\$\{CLAUDE_PROJECT_DIR\}/g, m.root);
      if (o.scope === "project" || (o.scope === "local" && m.os === "win32")) add("info", `${where} is read only by sessions started in ${dirname(dirname(o.file))}; one started in a subfolder runs without this hook`, m.os === "win32" ? "`ah init --scope user` covers every folder" : "`ah init --scope local` covers the whole repository");
      if (node && !findCommand(m, sub(node)) && exec) add("fail", `${where}: ${node} ${/[\\/]/.test(node) ? "does not exist" : "is not on PATH"}, so the hook cannot start${e.onFailure === "block" ? " and every matched call is blocked" : " and every call goes through unchecked"}`, "re-run `ah init` with the node you use now");
      if (guard && !exists(sub(guard))) add("fail", `${where}: ${guard} does not exist`, "reinstall @9thlevel/aegis, then re-run `ah init`");
      out.push(...versionCheck("claude", m, where, node, guard));
      if (e.onFailure === "block") {
        if (atLeast(version, CLAUDE_MIN.onFailure) === false) add("warn", `${where}: onFailure needs Claude Code ${CLAUDE_MIN.onFailure} or later; this version ignores it and fails open`);
      } else add("info", `${where}: fails open: if the hook cannot start or times out, the call goes ahead`, "`ah init --fail-closed` blocks the call instead");
      const key = JSON.stringify([e.command, e.args]);
      if (seen.has(key)) continue;
      seen.add(key);
      const timeout = typeof e.timeout === "number" && e.timeout > 0 ? e.timeout : 600;
      if (exec) out.push(...canaryLine("claude", m, { kind: "exec", file: sub(e.command as string), args: (e.args as string[]).map(sub) }, timeout, where));
      else if (m.os !== "win32") out.push(...canaryLine("claude", m, { kind: "shell", command: e.command as string, shell: "/bin/sh", shellArgs: ["-c"] }, timeout, where));
      else add("warn", `${where}: shell-form entry not tested on Windows (Claude Code picks Git Bash or PowerShell)`, "re-run `ah init` to switch to exec form");
    }
  }

  // Workspace trust: interactive sessions hold back settings-file hooks until it is accepted.
  const claudeJson = readJsonQuiet(m.env.CLAUDE_CONFIG_DIR ? join(m.env.CLAUDE_CONFIG_DIR, ".claude.json") : join(m.home, ".claude.json"));
  if (claudeJson !== undefined) {
    const projects = get(claudeJson, "projects");
    // Claude Code keys trust by the main checkout's root, then walks up from the session directory
    // as far as the repository's top level; on Windows its keys use forward slashes.
    const accepted = (d: string) => isObj(projects) && trustKeys(m, d).some((k) => get(projects, k, "hasTrustDialogAccepted") === true);
    const top = gitTopLevel(m.root);
    const main = mainCheckoutRoot(m.root);
    let trusted = main !== null && accepted(main);
    for (let d = m.root; !trusted; d = dirname(d)) {
      trusted = accepted(d);
      if ((top !== null && canonical(d) === canonical(top)) || dirname(d) === d) break;
    }
    if (!trusted) add("warn", "this folder's workspace trust is not accepted yet; interactive Claude Code sessions run no settings-file hook until it is", "start `claude` here once and accept the trust prompt");
  }

  // Instructions: the file Claude Code reads the block from (AGENTS.md when nothing suppresses it, or a CLAUDE.md imports it).
  const s = claudeMdState(m.root, m.home);
  const target = s.target ?? join(m.root, "AGENTS.md");
  let state: string;
  try {
    state = blockIsCurrent(readText(target).text, target);
  } catch (err) {
    state = `unreadable (${(err as Error).message})`;
  }
  if (state === "current") add("ok", `${rel(m, target)} carries the guard's instructions for Claude Code`);
  else if (s.target === null && (rootTextLinks(m.root).some((l) => l.path === target) || (s.present.length > 0 && s.present.every((p) => s.textLinks.some((l) => l.path === p))))) add("warn", `Claude Code gets none of the guard's instructions: ${s.reason}`, symlinkFix(m, s.textLinks[0]?.path ?? target));
  else add("warn", `${rel(m, target)}: the guard's instructions are ${state}${s.target !== null && s.present.length === 0 ? ` (${s.reason})` : ""}`, "re-run `ah init`");
  if (s.suppressing.length === 0 && atLeast(version, CLAUDE_MIN.agentsMd) === false) add("warn", `Claude Code reads AGENTS.md from ${CLAUDE_MIN.agentsMd}; this version does not`, "update Claude Code");
  return out;
}

// ---------------------------------------------------------------------------
// Codex

function readToml(path: string): { doc?: Record<string, unknown>; error?: string; exists: boolean } {
  const t = readText(path).text;
  if (t === null) return { exists: false };
  try {
    return { doc: parseToml(t), exists: true };
  } catch (err) {
    return { error: (err as Error).message, exists: true };
  }
}

/** The listed hook Codex built from an entry at this file and position, if it loads one. */
function listedAt(listing: CodexListing, file: string, groupIndex: number, handlerIndex: number): CodexListedHook | undefined {
  const at = `:pre_tool_use:${groupIndex}:${handlerIndex}`;
  return listing.hooks.find((h) => h.eventName === "preToolUse" && h.key.endsWith(at) && canonical(h.sourcePath) === canonical(file));
}

function isAhListed(h: CodexListedHook): boolean {
  return h.eventName === "preToolUse" && h.handlerType === "command" && typeof h.command === "string" && isOwnedEntry({ type: "command", command: h.command });
}

export function doctorCodex(m: Machine, probe: CliProbe, featuresList: string | null, listing: CodexListing | null = null): Check[] {
  const out: Check[] = [];
  const add = (level: Level, title: string, fix?: string) => out.push({ agent: "codex", level, title, fix });
  if (!probe.found) add("warn", "`codex` is not on PATH here; checking its files anyway, without asking Codex what it loads");
  else {
    add("ok", `Codex ${parseCodexVersion(probe.stdout) ?? probe.stdout.trim()}`);
    if (listing === null) add("warn", "Codex did not answer hooks/list (`codex app-server`), so the checks below come from reading its files and may miss what Codex rejects");
  }

  const configs = codexConfigFiles(m);
  const userConfigPath = configs.find((f) => f.scope === "user")?.path as string;
  const userConfig = readToml(userConfigPath);
  if (userConfig.error) add("warn", `${rel(m, userConfigPath)} could not be read (${userConfig.error}); trust and feature checks below are incomplete`);
  // A project entry for the session directory or the repository root trusts every layer in between.
  // In a linked worktree an entry for the main checkout counts too.
  const top = gitTopLevel(m.root);
  const trustOf = (dir: string | null) => (dir === null ? undefined : (get(userConfig.doc, "projects", dir, "trust_level") ?? get(userConfig.doc, "projects", canonical(dir), "trust_level")));
  const projectTrust = trustOf(m.root) ?? trustOf(top) ?? trustOf(mainCheckoutRoot(m.root));
  const projectTrusted = projectTrust === "trusted";

  // features.hooks: `codex features list` knows the effective value; config.toml says where it was set.
  const fromList = featuresList === null ? null : parseFeaturesHooks(featuresList);
  const configDocs = [{ path: userConfigPath, doc: userConfig.doc }, ...(projectTrusted ? configs.filter((f) => f.scope === "project").map((f) => ({ path: f.path, doc: readToml(f.path).doc })) : [])];
  const setOff = configDocs.filter((c) => get(c.doc, "features", "hooks") === false || get(c.doc, "features", "codex_hooks") === false);
  if (fromList === false || (fromList === null && setOff.length > 0)) add("fail", `Codex hooks are off (features.hooks = false${setOff.length > 0 ? ` in ${setOff.map((c) => rel(m, c.path)).join(", ")}` : ""}); no hook runs`, "remove `hooks = false` from [features], or run `codex features enable hooks`");
  else if (fromList === true) add("ok", "features.hooks is on");

  const req = readToml(codexRequirementsFile(m));
  const managedOnly = get(req.doc, "allow_managed_hooks_only") === true;

  const owned: OwnedAt[] = [];
  const rejected = new Set<string>();
  for (const f of codexHooksFiles(m)) {
    const r = readJson(f.path);
    if (!r.ok) {
      add("fail", `${rel(m, f.path)} is not plain JSON (${r.error}); Codex loads no hook from it`);
      rejected.add(canonical(f.path));
      continue;
    }
    if (!r.exists) continue;
    const bad = codexFileProblem(r.value, r.text);
    if (bad) {
      add("fail", `${rel(m, f.path)} has ${bad}; Codex rejects the whole file, ah's hook included`, "fix the file, then re-run `ah init`");
      rejected.add(canonical(f.path));
      continue;
    }
    owned.push(...ownedIn(r.value, f.path, f.scope));
    if (ownedIn(r.value, f.path, f.scope, looksLikeGuard).length > 0) add("info", `${rel(m, f.path)} has an entry that runs the guard with other words around it; ah does not count or test it`);
  }
  const own = join(m.root, ".codex", "hooks.json");
  if (!codexHooksFiles(m).some((f) => canonical(f.path) === canonical(own))) {
    const r = readJson(own);
    if (r.ok && r.exists && ownedIn(r.value, own, "project").length > 0) add("info", `${rel(m, own)} has an ah entry, but in a linked worktree Codex reads .codex/hooks.json from the main checkout, never this one`, "`ah init --scope local` wires the main checkout's copy");
  }
  for (const c of configDocs) {
    if (ownedIn(c.doc, c.path, "toml").length > 0) add("info", `${rel(m, c.path)} has an inline ah hook in [hooks]; ah init does not manage TOML, so check it by hand`);
  }

  if (listing) {
    for (const w of listing.warnings) {
      const file = /hooks config (.+?\.json):/.exec(w)?.[1];
      if (file !== undefined && rejected.has(canonical(file))) continue;
      if (/^failed to parse/.test(w)) add("fail", `Codex cannot load ${file ? rel(m, file) : "a hooks file"}: ${w.replace(/^failed to parse hooks config .+?\.json: /, "")}`, "fix the file, then re-run `ah init`");
      else add("info", `Codex: ${w.split("\n")[0]}`);
    }
    for (const e of listing.errors) add("fail", `Codex: ${rel(m, e.path)}: ${e.message}`);
    // Hooks Codex loads that ah did not find in a file it reads: managed or plugin sources.
    for (const h of listing.hooks.filter(isAhListed)) {
      const [g, i] = h.key.split(":").slice(-2).map(Number);
      if (owned.some((o) => o.groupIndex === g && o.handlerIndex === i && canonical(o.file) === canonical(h.sourcePath))) continue;
      owned.push({ file: h.sourcePath, scope: h.source, group: { matcher: h.matcher }, entry: { type: "command", command: h.command, timeout: h.timeoutSec }, groupIndex: g, handlerIndex: i });
    }
  }

  if (managedOnly && !owned.some((o) => listing && listedAt(listing, o.file, o.groupIndex, o.handlerIndex)?.isManaged)) add("fail", `allow_managed_hooks_only is set in ${codexRequirementsFile(m)}; Codex skips user and project hooks, ah's included`, "ask whoever manages that file to add the ah hook as a managed hook");
  if (owned.length === 0) {
    if (rejected.size === 0) add("fail", "no ah PreToolUse hook in ~/.codex/hooks.json or .codex/hooks.json", "run `ah init --agents codex`");
    return [...out, ...codexInstructions(m, projectTrust)];
  }
  if (owned.length > 1) add("warn", `ah is wired ${owned.length} times (${[...new Set(owned.map((o) => rel(m, o.file)))].join(", ")}); Codex runs every copy on every matched call`, "keep one: `ah init --remove` then `ah init`, or delete the extra entry");
  out.push(...wslCheck("codex", m, owned));

  for (const o of owned) {
    const where = rel(m, o.file);
    const e = o.entry;
    const cmd = m.os === "win32" && typeof e.commandWindows === "string" ? e.commandWindows : (e.command as string);
    // Read commandWindows the way ah wrote it (PowerShell quoting), as isOwnedEntry does.
    const forms = entryWords(e);
    const words = (cmd === e.commandWindows ? forms.at(-1) : forms[0]) ?? splitWords(cmd);
    const args = guardArgs(words) ?? [];
    const agentAt = args.indexOf("--agent");
    if (agentAt >= 0 && args[agentAt + 1] !== "codex") add("fail", `${where}: the ah entry runs the guard with --agent ${args[agentAt + 1]}; Codex payloads need --agent codex`, "re-run `ah init --agents codex`");
    if (e.async === true) add("fail", `${where}: the ah entry is async, so it cannot block anything`, "re-run `ah init`");
    const missing = CODEX_REQUIRED_TOOLS.filter((t) => !codexMatcherCovers(o.group.matcher, t.names));
    if (missing.length > 0) add("fail", `${where}: the matcher ${JSON.stringify(o.group.matcher)} skips ${missing.map((t) => t.label).join(" and ")}`, "re-run `ah init`");
    else add("ok", `${where}: ah hook bound for shell commands and apply_patch`);
    const { node, guard } = namedPaths(words);
    if (node && !findCommand(m, node)) add("fail", `${where}: ${node} ${/[\\/]/.test(node) ? "does not exist" : "is not on PATH"}, so the hook cannot start and Codex lets every call through`, "re-run `ah init` with the node you use now");
    if (guard && !exists(guard)) add("fail", `${where}: ${guard} does not exist`, "reinstall @9thlevel/aegis, then re-run `ah init`");
    out.push(...versionCheck("codex", m, where, node, guard));
    const untrustedProject = o.scope === "project" && !projectTrusted;
    if (untrustedProject) {
      if (projectTrust === "untrusted") add("fail", `this project is marked untrusted in ${rel(m, userConfigPath)}; Codex skips .codex/hooks.json`, "trust the project when Codex asks, or set trust_level = \"trusted\" for it");
      else add("fail", `this project is not trusted in ${rel(m, userConfigPath)} yet; Codex loads .codex/hooks.json only for trusted projects`, "start Codex here and accept the trust prompt");
    }
    const untrustedFix = "start Codex in this project, open /hooks, and trust the ah entry";
    if (listing) {
      const h = listedAt(listing, o.file, o.groupIndex, o.handlerIndex);
      if (h === undefined) {
        if (!untrustedProject) add("fail", `${where}: Codex does not load this ah entry for a session started in ${m.root}`, "run `ah doctor` from the directory you start Codex in");
      } else if (!h.enabled) add("fail", `${where}: the ah hook is disabled in Codex's /hooks`, "open /hooks in Codex and enable it");
      else if (h.trustStatus === "trusted" || h.trustStatus === "managed") add("ok", `${where}: Codex ${h.trustStatus === "managed" ? "runs the ah hook as a managed hook" : "trusts the ah hook"}`);
      else if (h.trustStatus === "modified") add("fail", `${where}: the ah hook changed since you trusted it, so Codex skips it until you review it`, "open /hooks in Codex and trust the ah entry again");
      else add("fail", `${where}: Codex has not trusted the ah hook yet, so it skips it`, untrustedFix);
    } else {
      const keys = [canonical(o.file), o.file].map((f) => `${f}:pre_tool_use:${o.groupIndex}:${o.handlerIndex}`);
      const state = keys.map((k) => get(userConfig.doc, "hooks", "state", k)).find((v) => v !== undefined);
      if (get(state, "enabled") === false) add("fail", `${where}: the ah hook is disabled in Codex's /hooks`, "open /hooks in Codex and enable it");
      else if (typeof get(state, "trusted_hash") === "string") add("warn", `${where}: Codex has a trust record for the ah hook, but without asking Codex ah cannot tell whether the entry changed since; Codex skips a changed entry until you trust it again`, "put codex on PATH and re-run `ah doctor`, or check /hooks in Codex");
      else add("fail", `${where}: Codex has not trusted the ah hook yet, so it skips it`, untrustedFix);
    }

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

/**
 * Codex reads one instructions file per project layer, from the repository's
 * top down to the session directory (AGENTS.override.md in place of
 * AGENTS.md), within one combined 32 KiB budget. The block counts when one of
 * those files carries it and it ends inside the budget.
 */
function codexInstructions(m: Machine, projectTrust: unknown): Check[] {
  const out: Check[] = [];
  let before = 0;
  let stale: string | null = null;
  for (const dir of codexLayers(m)) {
    const override = join(dir, "AGENTS.override.md");
    const file = readText(override).text !== null ? override : join(dir, "AGENTS.md");
    const text = readText(file).text;
    if (text === null) continue;
    let state: string;
    try {
      state = blockIsCurrent(text, file);
    } catch (err) {
      state = `unreadable (${(err as Error).message})`;
    }
    const where = rel(m, file);
    if (state === "current") {
      const end = before + (blockEndByte(text, file) ?? 0);
      if (end > CODEX_DOC_BUDGET) out.push({ agent: "codex", level: "warn", title: `${where}: the guard's block ends past the first ${CODEX_DOC_BUDGET / 1024} KiB of this project's instructions, which is all Codex reads`, fix: "re-run `ah init`; it moves the block to the top" });
      else out.push({ agent: "codex", level: "ok", title: `${where} carries the guard's instructions for Codex` });
      stale = null;
      break;
    }
    if (state !== "missing" && stale === null) stale = `${where}: the guard's instructions are ${state}`;
    before += Buffer.byteLength(text, "utf8");
  }
  if (out.length === 0) {
    const file = readText(join(m.root, "AGENTS.override.md")).text !== null ? join(m.root, "AGENTS.override.md") : join(m.root, "AGENTS.md");
    // ah writes nothing into a text link, so re-running it cannot fix one Codex reads.
    if (file.endsWith("AGENTS.override.md") && rootTextLinks(m.root).some((l) => l.path === file)) out.push({ agent: "codex", level: "warn", title: `${rel(m, file)} is a symlink checked out as plain text, and Codex reads its one line in place of AGENTS.md, so Codex gets none of the guard's instructions`, fix: symlinkFix(m, file) });
    else out.push({ agent: "codex", level: "warn", title: stale ?? `${rel(m, file)}: the guard's instructions are missing`, fix: "re-run `ah init`" });
  }
  if (projectTrust === "untrusted") out.push({ agent: "codex", level: "warn", title: "Codex does not read a project's AGENTS.md while the project is marked untrusted" });
  return out;
}

/** How to turn a symlink that git checked out as a plain file back into a link. */
function symlinkFix(m: Machine, file: string): string {
  return `check it out as a real symlink: \`git config core.symlinks true\` (Windows allows symlinks in Developer Mode), then \`git checkout -- ${rel(m, file)}\`, and re-run \`ah init\``;
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
  /** What Codex's own loader reports for a session started in root (hooks/list), or null. */
  codexListing?: (root: string) => CodexListing | null;
}

export const realDeps = (env: NodeJS.ProcessEnv, listing: CodexListing | null = null): DoctorDeps => ({
  probe: (name) => probeCli(name, env),
  featuresList: (root) => {
    const r = spawnSync("codex", ["features", "list"], { cwd: root, encoding: "utf8", env, timeout: 15_000, windowsHide: true, shell: process.platform === "win32" });
    return r.status === 0 ? (r.stdout ?? "") : null;
  },
  codexListing: () => listing,
});

export function doctor(o: DoctorOptions, env: NodeJS.ProcessEnv = process.env, deps: DoctorDeps = realDeps(env)): DoctorResult {
  const m = defaultMachine(resolve(o.root), "", env);
  const checks: Check[] = [];
  if (!existsSync(m.root)) return { ok: false, root: m.root, checks: [{ agent: "project", level: "fail", title: `${m.root} does not exist` }] };
  if (o.agents.includes("claude")) checks.push(...doctorClaude(m, deps.probe("claude")));
  if (o.agents.includes("codex")) {
    const p = deps.probe("codex");
    checks.push(...doctorCodex(m, p, p.found ? deps.featuresList(m.root) : null, p.found ? (deps.codexListing?.(m.root) ?? null) : null));
  }
  if (!existsSync(join(m.root, ".harness"))) checks.push({ agent: "project", level: "info", title: "no .harness/ directory, so denies and asks are not logged to .harness/metrics.jsonl", fix: "`ah init` creates it" });
  const links = rootTextLinks(m.root);
  /** What a stale stand-in does now, and where ah's block goes once it is removed. */
  const hidden = (p: string): string => {
    if (p.endsWith("AGENTS.override.md")) return "it hides AGENTS.md from Codex";
    const without = claudeMdState(m.root, m.home, [p]);
    if (without.suppressing.length === 0) return "it hides AGENTS.md from Claude Code";
    if (without.target === null) return `it only repeats ah's block, which Claude Code reads anyway (${without.reason})`;
    return `without it, ah's block goes in ${rel(m, without.target)}${existsSync(without.target) ? "" : ", a new file"}`;
  };
  for (const p of staleStandIns(m.root, links, o.agents)) {
    checks.push({ agent: "project", level: "warn", title: `${rel(m, p)} is the stand-in ah made while a symlink was checked out as plain text; none is now, and ${hidden(p)}`, fix: "re-run `ah init`, which removes it" });
  }
  for (const p of committedStandIns(m.root, links, o.agents)) {
    checks.push({ agent: "project", level: "warn", title: `${rel(m, p)} is the stand-in ah made while a symlink was checked out as plain text, and it is committed; no symlink needs it now, and ${hidden(p)}`, fix: `\`git rm --cached ${rel(m, p)}\`, commit, then re-run \`ah init\`, which removes it` });
  }
  for (const l of links) {
    const target = l.target.trim();
    checks.push({ agent: "project", level: "warn", title: `${rel(m, l.path)} is a symlink${target === "" || target.length > 120 ? "" : ` to ${JSON.stringify(target)}`} checked out as a plain file holding its target, so agents read that one line instead of the file it names, and ah writes nothing into it`, fix: symlinkFix(m, l.path) });
  }
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

export async function runDoctor(argv: readonly string[], io: { stdout: (s: string) => void; stderr: (s: string) => void } = { stdout: (s) => process.stdout.write(s), stderr: (s) => process.stderr.write(s) }, env: NodeJS.ProcessEnv = process.env, deps?: DoctorDeps): Promise<number> {
  if (argv.includes("--help") || argv.includes("-h")) {
    io.stdout(DOCTOR_HELP);
    return 0;
  }
  const o = parseDoctorArgs(argv);
  if (typeof o === "string") {
    io.stderr(`ah doctor: ${o}\n\n${DOCTOR_HELP}`);
    return 2;
  }
  let d = deps;
  if (d === undefined) {
    const root = resolve(o.root);
    const askCodex = o.agents.includes("codex") && existsSync(root) && probeCli("codex", env).found;
    d = realDeps(env, askCodex ? await codexHooksList(root, env) : null);
  }
  const r = doctor(o, env, d);
  io.stdout(o.json ? `${JSON.stringify(r, null, 2)}\n` : renderDoctor(r));
  return r.ok ? 0 : 1;
}

export { claudeConfigDir, codexHome };
