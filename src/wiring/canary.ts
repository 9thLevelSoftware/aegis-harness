/**
 * Push a payload through a hook command the way the agent would launch it and
 * read back what the guard said. `ah doctor` uses it to prove the configured
 * command (the exact node path, guard path and flags in the settings file)
 * starts, answers inside its timeout, and refuses what it must refuse.
 */
import { spawnSync } from "node:child_process";

export type Launch =
  /** Exec form: no shell. Claude Code's `command` + `args`. */
  | { kind: "exec"; file: string; args: string[] }
  /** Shell form: the agent hands the string to a shell. */
  | { kind: "shell"; command: string; shell: string; shellArgs: string[] };

export interface CanaryResult {
  started: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  ms: number;
  timedOut: boolean;
  /** What the agent does with the hook's answer (verdictOf), or null when the answer is unreadable. */
  verdict: "deny" | "ask" | "allow" | null;
  error?: string;
}

export function runCanary(launch: Launch, payload: unknown, opts: { cwd: string; env: NodeJS.ProcessEnv; timeoutMs: number; agent?: "claude" | "codex" }): CanaryResult {
  const input = JSON.stringify(payload);
  const t0 = process.hrtime.bigint();
  const r =
    launch.kind === "exec"
      ? spawnSync(launch.file, launch.args, { input, cwd: opts.cwd, env: opts.env, timeout: opts.timeoutMs, encoding: "utf8", windowsHide: true })
      : spawnSync(launch.shell, [...launch.shellArgs, launch.command], { input, cwd: opts.cwd, env: opts.env, timeout: opts.timeoutMs, encoding: "utf8", windowsHide: true, windowsVerbatimArguments: /cmd(\.exe)?$/i.test(launch.shell) });
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const err = r.error as NodeJS.ErrnoException | undefined;
  const timedOut = err?.code === "ETIMEDOUT";
  const started = !(err && !timedOut);
  const stdout = r.stdout ?? "";
  const stderr = r.stderr ?? "";
  return { started, exitCode: r.status, stdout, stderr, ms, timedOut, verdict: started && !timedOut ? verdictOf(r.status, stdout, stderr, opts.agent) : null, error: err ? err.message : undefined };
}

/**
 * What the agent does with a hook's answer. Claude Code blocks on exit 2 or a
 * deny and pauses on an ask. Codex 0.163 blocks only on exit 2 with a reason on
 * stderr, a deny with a non-empty reason, or a legacy `decision: "block"`; it
 * runs the call on an ask, a bare allow, a deny without a reason, or output it
 * cannot read. A decision neither agent defines is unreadable (null).
 */
export function verdictOf(exitCode: number | null, stdout: string, stderr = "", agent: "claude" | "codex" = "claude"): CanaryResult["verdict"] {
  const codex = agent === "codex";
  if (exitCode === 2) return codex && stderr.trim() === "" ? "allow" : "deny";
  if (exitCode !== 0) return null;
  const text = stdout.trim();
  if (text === "") return "allow";
  let out: { hookSpecificOutput?: { permissionDecision?: unknown; permissionDecisionReason?: unknown }; decision?: unknown };
  try {
    out = JSON.parse(text);
  } catch {
    return codex ? "allow" : null;
  }
  const d = out.hookSpecificOutput?.permissionDecision;
  const reason = out.hookSpecificOutput?.permissionDecisionReason;
  if (d === undefined) return out.decision === "block" ? "deny" : "allow";
  if (d === "deny") return codex && !(typeof reason === "string" && reason.trim() !== "") ? "allow" : "deny";
  if (d === "ask") return codex ? "allow" : "ask";
  if (d === "allow") return "allow";
  return null;
}

export interface Canary {
  label: string;
  expect: "deny" | "allow";
  payload: Record<string, unknown>;
}

/**
 * The calls `ah doctor` pushes through each hook: the two refusals the plan
 * names (a recursive delete of the filesystem root, an edit to `.ruff.toml`)
 * and one call that must pass, so a hook that denies everything is caught too.
 */
export function canaries(agent: "claude" | "codex", root: string, sep: "/" | "\\"): Canary[] {
  const base = { hook_event_name: "PreToolUse", cwd: root, session_id: "ah-doctor", transcript_path: "" };
  const ruff = `${root}${sep}.ruff.toml`;
  const edit =
    agent === "claude"
      ? { tool_name: "Edit", tool_input: { file_path: ruff, old_string: 'select = ["E"]', new_string: 'select = ["E"]\nignore = ["F401"]' } }
      : { tool_name: "apply_patch", tool_input: { command: '*** Begin Patch\n*** Update File: .ruff.toml\n@@\n select = ["E"]\n+ignore = ["F401"]\n*** End Patch' } };
  return [
    { label: "rm -rf /", expect: "deny", payload: { ...base, tool_name: "Bash", tool_input: { command: "rm -rf /" } } },
    { label: "an edit to .ruff.toml", expect: "deny", payload: { ...base, ...edit } },
    { label: "ls", expect: "allow", payload: { ...base, tool_name: "Bash", tool_input: { command: "ls" } } },
  ];
}
