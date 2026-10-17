/**
 * `ah guard`: the PreToolUse hook process. Reads one payload from stdin,
 * decides, prints the agent's response, exits 0. Malformed input exits 1 with
 * a message on stderr; Claude Code treats that as a non-blocking hook error
 * unless the hook sets `onFailure: "block"` (v2.1.295 or later), which fails closed.
 */
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { decideAll } from "./decide.ts";
import type { Context, Decision, Platform } from "./model.ts";
import { normalizeHookPayload, type Agent, type HookEvent } from "./normalize.ts";
import { DEFAULT_POLICY } from "./policy.ts";
import { render, type AskFallback } from "./respond.ts";
import { VERSION } from "../version.ts";

export interface GuardOptions {
  agent?: Agent;
  output?: Agent;
  root?: string;
  askFallback?: AskFallback;
  platform?: Platform;
  home?: string;
  log?: boolean;
}

export function parseGuardArgs(argv: readonly string[]): GuardOptions {
  const o: GuardOptions = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const v = () => argv[++i];
    if (a === "--agent") o.agent = v() as Agent;
    else if (a === "--output") o.output = v() as Agent;
    else if (a === "--root") o.root = v();
    else if (a === "--ask-fallback") o.askFallback = v() as AskFallback;
    else if (a === "--platform") o.platform = v() as Platform;
    else if (a === "--home") o.home = v();
    else if (a === "--no-log") o.log = false;
  }
  return o;
}

export function buildContext(event: HookEvent, o: GuardOptions, env: NodeJS.ProcessEnv = process.env): Context {
  const platform: Platform = o.platform ?? (env.AH_PLATFORM as Platform | undefined) ?? (process.platform === "win32" ? "windows" : "posix");
  const projectRoot = o.root ?? env.AH_PROJECT_ROOT ?? env.CLAUDE_PROJECT_DIR ?? event.cwd ?? process.cwd();
  const homeDir = o.home ?? env.AH_HOME ?? (platform === "windows" ? (env.USERPROFILE ?? homedir()) : (env.HOME ?? homedir()));
  const agent = o.agent ?? event.agent;
  // The dialect follows the tool: Claude Code's PowerShell tool is PowerShell on any
  // platform; Codex on Windows runs commands through PowerShell; everything else
  // (Bash, Claude Code on Windows under Git Bash) is POSIX sh.
  const shellDialect = event.toolName === "PowerShell" || (platform === "windows" && agent === "codex") ? "powershell" : "posix";
  return { projectRoot, homeDir, platform, shellDialect, policy: DEFAULT_POLICY };
}

export function evaluate(raw: unknown, o: GuardOptions, env: NodeJS.ProcessEnv = process.env): { event: HookEvent; decision: Decision; ctx: Context } {
  const event = normalizeHookPayload(raw, o.agent);
  const ctx = buildContext(event, o, env);
  const decision = decideAll(event.calls, ctx);
  return { event, decision, ctx };
}

function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function logDecision(ctx: Context, event: HookEvent, decision: Decision): void {
  if (decision.verdict === "allow") return;
  try {
    const dir = join(ctx.projectRoot, ".harness");
    if (!existsSync(dir)) return;
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      event: "ah.guard.decision",
      agent: event.agent,
      tool: event.toolName,
      verdict: decision.verdict,
      rule: decision.rule,
      reason: decision.reason,
      session: event.sessionId,
    });
    appendFileSync(join(dir, "metrics.jsonl"), `${line}\n`);
  } catch {
    // Logging is best-effort; a logging failure never changes a decision.
  }
}

export function runGuard(argv: readonly string[], io: { stdin?: string; stdout: (s: string) => void; stderr: (s: string) => void } = { stdout: (s) => process.stdout.write(s), stderr: (s) => process.stderr.write(s) }, env: NodeJS.ProcessEnv = process.env): number {
  // `ah doctor` asks a hooked guard its version, to tell an old build from the one ah wires now.
  if (argv.includes("--version")) {
    io.stdout(`${VERSION}\n`);
    return 0;
  }
  const o = parseGuardArgs(argv);
  const text = io.stdin ?? readStdin();
  if (text.trim() === "") {
    io.stderr("ah guard: no hook payload on stdin\n");
    return 1;
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    io.stderr("ah guard: hook payload is not JSON\n");
    return 1;
  }
  const { event, decision, ctx } = evaluate(raw, o, env);
  // AH_NO_LOG=1 lets `ah doctor` push canaries through the exact configured command
  // without adding lines to metrics.jsonl. It changes logging only, never a decision.
  if (o.log !== false && env.AH_NO_LOG !== "1") logDecision(ctx, event, decision);
  const out = render(decision, o.output ?? event.agent, o.askFallback ?? "deny");
  if (out.stdout) io.stdout(`${out.stdout}\n`);
  return out.exitCode;
}

export function guardEntry(): void {
  process.exitCode = runGuard(process.argv.slice(2));
}
