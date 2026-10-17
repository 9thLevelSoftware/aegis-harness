/**
 * `ah init`: wire the guard into Claude Code and Codex for one project.
 *
 * Writes one PreToolUse entry per agent and a short managed block in
 * AGENTS.md (and CLAUDE.md when Claude Code would not read AGENTS.md).
 * Touches nothing in those files except ah's own entry and block, refuses a
 * file it cannot read back exactly, and checks the guard answers before it
 * wires it. `--remove` takes all of it out again. See BUG-2026-019.
 */
import { existsSync, mkdirSync, readdirSync, realpathSync, rmdirSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { claudeFileFor, claudeGroup, claudeHooksProblem, claudeSettingsFiles } from "../wiring/claude.ts";
import { codexFileProblem, codexGroup, codexHooksFile, codexHooksFiles, codexNextSteps, duplicateKey } from "../wiring/codex.ts";
import { canaries, runCanary } from "../wiring/canary.ts";
import { isSymlink, readJson, removeFile, writeAtomic, writeProblem, type JsonStyle } from "../wiring/files.ts";
import { editJson } from "../wiring/json-edit.ts";
import { HookShapeError, planHooks, type HookAction } from "../wiring/hooks-json.ts";
import { planInstructions } from "../wiring/instructions.ts";
import { isOwnedEntry, looksLikeGuard } from "../wiring/owned.ts";
import { defaultMachine, excludeLocally, gitStatusOf, sharedAcrossWsl, unexcludeLocally, type Machine } from "../wiring/project.ts";
import { BlockError } from "../wiring/text-block.ts";
import { defaultGuardPath } from "./test-hooks.ts";

export type AgentName = "claude" | "codex";
export type Scope = "local" | "project" | "user";

export interface InitOptions {
  agents: AgentName[];
  root: string;
  scope: Scope;
  remove: boolean;
  dryRun: boolean;
  failClosed: boolean;
  askFallback?: "deny" | "warn";
  noLog: boolean;
  instructions: boolean;
  json: boolean;
  guard?: string;
  node?: string;
}

export const INIT_HELP = `ah init [--agents claude,codex] [--scope local|project|user] [--root DIR] [--fail-closed]
        [--ask-fallback deny|warn] [--no-log] [--no-instructions] [--remove] [--dry-run] [--json]
    Wire the guard as a PreToolUse hook for each agent and add ah's block to AGENTS.md.
    --scope local (default): .claude/settings.local.json and .codex/hooks.json, kept out of git
    commits because they hold this machine's paths. project: .claude/settings.json and
    .codex/hooks.json. user: ~/.claude/settings.json and ~/.codex/hooks.json (every project).
    --fail-closed: Claude Code blocks the call when the hook cannot run (Claude Code 2.1.295+).
    --ask-fallback warn: on Codex, let calls that need a human through with a warning.
    --remove: take ah's entries and blocks out of every file it can write. --dry-run: print the plan.
`;

export function parseInitArgs(argv: readonly string[]): InitOptions | string {
  const o: InitOptions = { agents: ["claude", "codex"], root: process.cwd(), scope: "local", remove: false, dryRun: false, failClosed: false, noLog: false, instructions: true, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const eq = a.indexOf("=");
    const flag = a.startsWith("--") && eq > 0 ? a.slice(0, eq) : a;
    const inline = a.startsWith("--") && eq > 0 ? a.slice(eq + 1) : undefined;
    const v = (): string | undefined => inline ?? argv[++i];
    switch (flag) {
      case "--agents": {
        const list = (v() ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
        const bad = list.filter((s) => s !== "claude" && s !== "codex");
        if (list.length === 0 || bad.length > 0) return `--agents takes claude, codex or both (got ${bad.join(", ") || "nothing"})`;
        o.agents = [...new Set(list)] as AgentName[];
        break;
      }
      case "--scope": {
        const s = v();
        if (s !== "local" && s !== "project" && s !== "user") return `--scope takes local, project or user (got ${s ?? "nothing"})`;
        o.scope = s;
        break;
      }
      case "--root": {
        const r = v();
        if (!r) return "--root needs a directory";
        o.root = r;
        break;
      }
      case "--ask-fallback": {
        const f = v();
        if (f !== "deny" && f !== "warn") return `--ask-fallback takes deny or warn (got ${f ?? "nothing"})`;
        o.askFallback = f;
        break;
      }
      case "--guard":
        o.guard = v();
        break;
      case "--node":
        o.node = v();
        break;
      case "--fail-closed":
        o.failClosed = true;
        break;
      case "--no-log":
        o.noLog = true;
        break;
      case "--no-instructions":
        o.instructions = false;
        break;
      case "--remove":
      case "--uninstall":
        o.remove = true;
        break;
      case "--dry-run":
        o.dryRun = true;
        break;
      case "--json":
        o.json = true;
        break;
      default:
        return `unknown option ${a}`;
    }
  }
  return o;
}

export interface Change {
  agent: AgentName | "instructions" | "git";
  file: string;
  action: HookAction | "created" | "appended" | "prepended" | "replaced" | "excluded" | "skipped" | "error";
  detail: string;
}

export interface InitResult {
  ok: boolean;
  dryRun: boolean;
  changes: Change[];
  next: string[];
  error?: string;
}

/** The guard answers a canary through the exact command `ah init` will write. */
function selfTest(m: Machine): string | null {
  for (const c of canaries("claude", m.root, m.os === "win32" ? "\\" : "/")) {
    const r = runCanary({ kind: "exec", file: m.nodePath, args: [m.guardPath, "--agent", "claude", "--no-log"] }, c.payload, { cwd: m.root, env: { ...m.env, AH_NO_LOG: "1" }, timeoutMs: 10_000 });
    if (r.verdict !== c.expect) {
      const why = !r.started ? `could not start: ${r.error ?? "unknown error"}` : r.timedOut ? "timed out" : `answered ${r.verdict ?? `exit ${r.exitCode}`}${r.stderr ? `: ${r.stderr.trim().split("\n")[0]}` : ""}`;
      return `the guard at ${m.guardPath} did not refuse/allow "${c.label}" as expected (${why}); nothing was written`;
    }
  }
  return null;
}

export function init(o: InitOptions, env: NodeJS.ProcessEnv = process.env): InitResult {
  const root = resolve(o.root);
  if (!existsSync(root)) return { ok: false, dryRun: o.dryRun, changes: [], next: [], error: `${root} does not exist` };
  const guardPath = o.guard ? resolve(o.guard) : defaultGuardPath();
  if (!guardPath || !existsSync(guardPath)) return { ok: false, dryRun: o.dryRun, changes: [], next: [], error: "cannot find dist/guard.mjs next to ah; run `npm run build` in a checkout, or reinstall @9thlevel/aegis" };
  const m = defaultMachine(root, realpathSync(guardPath), env);
  if (o.node) m.nodePath = resolve(o.node);
  if (!o.remove) {
    const bad = selfTest(m);
    if (bad) return { ok: false, dryRun: o.dryRun, changes: [], next: [], error: bad };
  }

  const changes: Change[] = [];
  const next: string[] = [];
  const writes: Write[] = [];
  const localFiles: string[] = [];
  let failed = false;
  const fail = (agent: Change["agent"], file: string, detail: string) => {
    changes.push({ agent, file, action: "error", detail });
    failed = true;
  };

  const hookTargets: { agent: AgentName; path: string; local: boolean }[] = [];
  for (const agent of o.agents) {
    if (o.remove) {
      for (const path of new Set(hookFiles(m, agent))) hookTargets.push({ agent, path, local: false });
    } else {
      const path = agent === "claude" ? claudeFileFor(m, o.scope) : codexHooksFile(m, o.scope);
      hookTargets.push({ agent, path, local: o.scope === "local" });
    }
  }

  for (const t of hookTargets) {
    const read = readJson(t.path);
    if (!read.ok) {
      fail(t.agent, t.path, `not plain JSON (${read.error}); ah will not rewrite it. Fix the file or wire the hook by hand.`);
      continue;
    }
    if (o.remove && !read.exists) continue;
    const dup = read.exists ? duplicateKey(read.text) : null;
    if (dup !== null) {
      fail(t.agent, t.path, `has the key ${JSON.stringify(dup)} twice in one object; ah will not guess which one you meant. Merge them, then re-run.`);
      continue;
    }
    const value = read.exists ? read.value : {};
    // Codex cannot parse a hooks.json that starts with a byte-order mark; Claude Code can.
    const style: JsonStyle = t.agent === "codex" ? { ...read.style, bom: false } : read.style;
    const original = read.exists ? read.text : undefined;
    const source = t.agent === "codex" ? original?.replace(/^\uFEFF/, "") : original;
    try {
      const built: string[] = [];
      const plan = planHooks(value, t.path, (found) => {
        if (o.remove) return null;
        return t.agent === "claude" ? claudeGroup(m, { failClosed: o.failClosed, noLog: o.noLog || undefined }, found) : codexGroup(m, { askFallback: o.askFallback, noLog: o.noLog || undefined }, found, undefined, built);
      }, { placement: t.agent === "codex" ? "keep-indexes" : "first-owned" });
      plan.notes.push(...built);
      if (o.remove && plan.action === "absent") continue;
      if (!o.remove) {
        const bad = t.agent === "claude" ? claudeHooksProblem(plan.value) : codexFileProblem(plan.value);
        if (bad) {
          fail(t.agent, t.path, `${t.agent === "claude" ? "Claude Code" : "Codex"} would load nothing from this file, ah's entry included: it has ${bad}. Fix that entry, then re-run.`);
          continue;
        }
        const wrapped = (Array.isArray(get(plan.value, "hooks", "PreToolUse")) ? (get(plan.value, "hooks", "PreToolUse") as unknown[]) : []).flatMap((g) => (isObj(g) && Array.isArray(g.hooks) ? g.hooks : [])).filter(looksLikeGuard).length;
        if (wrapped > 0) plan.notes.push(`left alone ${wrapped === 1 ? "an entry that runs" : `${wrapped} entries that run`} the guard with other words around it; ah adopts only its own form`);
        if (o.scope === "project") plan.notes.push("this file is meant to be committed, and it now holds this machine's node and guard paths: on another machine the hook cannot start, and the call goes through unchecked (Claude Code blocks it instead with --fail-closed). `--scope local` keeps the paths out of git");
        if (t.agent === "codex" && read.exists && read.style.bom) plan.notes.push("dropped the byte-order mark: Codex cannot parse a hooks.json that starts with one");
        if (t.agent === "claude" && o.scope === "local" && m.os === "win32") plan.notes.push(`on Windows Claude Code reads this file only for sessions started in ${m.root}; one started in a subfolder runs without the hook (\`--scope user\` covers every folder)`);
        if (t.agent === "codex" && o.scope === "project" && t.path !== codexHooksFile(m, "local")) plan.notes.push(`in a linked worktree Codex reads ${codexHooksFile(m, "local")} in the main checkout, not this file, so this entry takes effect once the main checkout has it (\`--scope local\` writes it there)`);
        const across = o.scope === "user" ? null : sharedAcrossWsl(m);
        if (across !== null) plan.notes.push(across === "windows" ? "this checkout is on a Windows drive, so Claude Code and Codex running on Windows read this file too and cannot start this WSL node; their calls go through unchecked. Wire each side with `--scope user` instead" : "this checkout lives inside WSL, so agents running in WSL read this file too and cannot start this Windows node; their calls go through unchecked. Wire each side with `--scope user` instead");
      }
      changes.push({ agent: t.agent, file: t.path, action: plan.action, detail: [describeHook(t.agent, plan.action, o), ...plan.notes].join("; ") });
      if (plan.action !== "unchanged" && plan.action !== "absent") {
        // A file that --remove leaves as {} means the same as no file to both agents, so it goes,
        // unless git tracks it or it is a link into somebody's dotfiles.
        const empty = o.remove && Object.keys(plan.value).length === 0;
        const keep = empty && (isSymlink(t.path) || gitStatusOf(t.path) === "tracked");
        const text = empty && !keep ? null : editJson(source, plan.value, style);
        writes.push({ path: t.path, text, original: read.exists ? read.text : null });
      }
      if (!o.remove && t.local) localFiles.push(t.path);
    } catch (err) {
      if (!(err instanceof HookShapeError)) throw err;
      fail(t.agent, t.path, err.message);
    }
  }

  if (o.instructions) {
    try {
      // On --remove, an agent that stays wired keeps the instructions it reads.
      const keep = o.remove ? (["claude", "codex"] as AgentName[]).filter((a) => !o.agents.includes(a) && wired(m, a)) : [];
      for (const e of planInstructions(root, o.agents, o.remove, keep)) {
        if (o.remove && e.edit.action === "absent") continue;
        changes.push({ agent: "instructions", file: e.path, action: e.edit.action === "absent" ? "unchanged" : e.edit.action, detail: e.why });
        if (e.edit.action === "unchanged" || e.edit.action === "absent") continue;
        const keep = e.edit.text === null && (isSymlink(e.path) || gitStatusOf(e.path) === "tracked");
        writes.push({ path: e.path, text: keep ? "" : e.edit.text, original: e.original });
      }
    } catch (err) {
      if (!(err instanceof BlockError)) throw err;
      fail("instructions", "", err.message);
    }
  }

  // Every file must be writable before the first one is touched.
  for (const w of writes) {
    const bad = writeProblem(w.path, w.text === null);
    if (bad) fail(changes.find((c) => c.file === w.path)?.agent ?? "instructions", w.path, bad);
  }
  if (failed) return { ok: false, dryRun: o.dryRun, changes, next: [], error: "nothing was written; fix the files named above and re-run" };

  const done: Write[] = [];
  try {
    if (!o.dryRun) {
      for (const w of writes) {
        if (w.text === null) removeFile(w.path);
        else writeAtomic(w.path, w.text);
        done.push(w);
      }
    }
    for (const f of localFiles) {
      const r = excludeLocally(f, o.dryRun);
      if (r === "excluded") changes.push({ agent: "git", file: f, action: "excluded", detail: "added to .git/info/exclude: it holds this machine's paths" });
      if (r === "tracked") changes.push({ agent: "git", file: f, action: "skipped", detail: "tracked by git, so the next commit carries this machine's node and guard paths; use --scope user or untrack it" });
    }
    if (o.remove) {
      // The exclude lines go once the file they cover is gone; a file that keeps your own settings stays excluded.
      const local = [...(o.agents.includes("claude") ? [claudeFileFor(m, "local")] : []), ...(o.agents.includes("codex") ? [codexHooksFile(m, "local")] : [])];
      for (const f of local) {
        const gone = writes.some((w) => w.path === f && w.text === null) || (!existsSync(f) && !writes.some((w) => w.path === f));
        if (gone && unexcludeLocally(f, o.dryRun)) changes.push({ agent: "git", file: f, action: "removed", detail: "took its line out of .git/info/exclude" });
      }
      if (!o.dryRun) removeEmptyDirs([...writes.filter((w) => w.text === null).map((w) => dirname(w.path)), join(root, ".harness")]);
    } else if (!o.dryRun) mkdirSync(join(root, ".harness"), { recursive: true });
  } catch (err) {
    const left = undo(done);
    const what = done.length === 0 ? "nothing was written" : left.length === 0 ? "the files already written were put back as they were" : `could not put back ${left.join(", ")}`;
    return { ok: false, dryRun: o.dryRun, changes, next: [], error: `${(err as Error).message}; ${what}` };
  }

  if (!o.remove) {
    if (o.agents.includes("codex")) next.push(...codexNextSteps(changes.some((c) => c.agent === "codex" && (c.action === "added" || c.action === "updated"))));
    next.push("Run `ah doctor` to push a canary through each hook.");
  }
  return { ok: true, dryRun: o.dryRun, changes, next };
}

interface Write {
  path: string;
  /** The new content, or null to delete the file. */
  text: string | null;
  /** The content before, or null when the file did not exist. */
  original: string | null;
}

/** Put back files a failed run already wrote. Returns the ones it could not. */
function undo(done: Write[]): string[] {
  const left: string[] = [];
  for (const w of [...done].reverse()) {
    try {
      if (w.original === null) removeFile(w.path);
      else writeAtomic(w.path, w.original);
    } catch {
      left.push(w.path);
    }
  }
  return left;
}

/** Remove the .claude, .codex and .harness directories --remove left empty. */
function removeEmptyDirs(dirs: string[]): void {
  for (const d of new Set(dirs)) {
    if (![".claude", ".codex", ".harness"].includes(basename(d))) continue;
    try {
      if (readdirSync(d).length === 0) rmdirSync(d);
    } catch {
      // missing or not ours to judge
    }
  }
}

/** Every writable file the agent loads hooks from, for --remove; for Codex also a worktree's own copy, which it does not read. */
function hookFiles(m: Machine, agent: AgentName): string[] {
  return agent === "claude" ? claudeSettingsFiles(m).filter((f) => f.writable).map((f) => f.path) : [...codexHooksFiles(m).map((f) => f.path), codexHooksFile(m, "project")];
}

/** Does a file the agent loads hooks from hold ah's entry? */
function wired(m: Machine, agent: AgentName): boolean {
  return hookFiles(m, agent).some((f) => {
    const r = readJson(f);
    const groups = r.ok && r.exists ? get(r.value, "hooks", "PreToolUse") : undefined;
    return Array.isArray(groups) && groups.some((g) => isObj(g) && Array.isArray(g.hooks) && g.hooks.some(isOwnedEntry));
  });
}

function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function get(v: unknown, ...keys: string[]): unknown {
  let cur = v;
  for (const k of keys) cur = isObj(cur) ? cur[k] : undefined;
  return cur;
}

function describeHook(agent: AgentName, action: HookAction, o: InitOptions): string {
  if (action === "removed") return "removed ah's PreToolUse entry";
  if (action === "unchanged") return "ah's PreToolUse entry is already current";
  const verb = action === "added" ? "added" : "updated";
  if (agent === "claude") return `${verb} ah's PreToolUse entry (exec form, ${o.failClosed ? "fails closed" : "fails open if the hook cannot run"})`;
  return `${verb} ah's PreToolUse entry`;
}

export function renderInit(r: InitResult, root: string): string {
  const lines: string[] = [];
  lines.push(r.dryRun ? "ah init (dry run, nothing written)" : "ah init");
  for (const c of r.changes) {
    const file = c.file === "" ? "" : rel(root, c.file);
    lines.push(`  ${c.agent.padEnd(12)} ${c.action.padEnd(9)} ${file}${c.detail ? `: ${c.detail}` : ""}`);
  }
  if (r.changes.length === 0) lines.push("  nothing to do");
  if (r.error) lines.push(`error: ${r.error}`);
  for (const n of r.next) lines.push(`next: ${n}`);
  return `${lines.join("\n")}\n`;
}

function rel(root: string, p: string): string {
  const r = relative(root, p);
  return r.startsWith("..") ? p : r;
}

export function runInit(argv: readonly string[], io: { stdout: (s: string) => void; stderr: (s: string) => void } = { stdout: (s) => process.stdout.write(s), stderr: (s) => process.stderr.write(s) }, env: NodeJS.ProcessEnv = process.env): number {
  if (argv.includes("--help") || argv.includes("-h")) {
    io.stdout(INIT_HELP);
    return 0;
  }
  const o = parseInitArgs(argv);
  if (typeof o === "string") {
    io.stderr(`ah init: ${o}\n\n${INIT_HELP}`);
    return 2;
  }
  const r = init(o, env);
  if (o.json) io.stdout(`${JSON.stringify(r, null, 2)}\n`);
  else (r.ok ? io.stdout : io.stderr)(renderInit(r, resolve(o.root)));
  return r.ok ? 0 : 1;
}
