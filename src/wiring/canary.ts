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
  /** The permissionDecision the guard printed, "allow" for an empty stdout with exit 0, or null when unreadable. */
  verdict: "deny" | "ask" | "allow" | null;
  error?: string;
}

export function runCanary(launch: Launch, payload: unknown, opts: { cwd: string; env: NodeJS.ProcessEnv; timeoutMs: number }): CanaryResult {
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
  return { started, exitCode: r.status, stdout, stderr, ms, timedOut, verdict: started && !timedOut ? verdictOf(r.status, stdout) : null, error: err ? err.message : undefined };
}

export function verdictOf(exitCode: number | null, stdout: string): CanaryResult["verdict"] {
  if (exitCode === 2) return "deny";
  if (exitCode !== 0) return null;
  const text = stdout.trim();
  if (text === "") return "allow";
  try {
    const out = JSON.parse(text) as { hookSpecificOutput?: { permissionDecision?: string }; decision?: string };
    const d = out.hookSpecificOutput?.permissionDecision ?? (out.decision === "block" ? "deny" : undefined);
    if (d === "deny" || d === "ask" || d === "allow") return d;
    return "allow";
  } catch {
    return null;
  }
}
