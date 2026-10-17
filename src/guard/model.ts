/**
 * Agent-neutral model of a tool call and of the guard's decision.
 *
 * Everything in this module is plain data. The decision core never touches
 * the filesystem, the network, or the clock, so every decision is a pure
 * function of (call, context) and can be replayed from a fixture.
 */

export type Verdict = "allow" | "deny" | "ask";

/** A shell command the agent wants to run. */
export interface ShellCall {
  kind: "shell";
  command: string;
}

/** A whole-file write (create or overwrite). */
export interface WriteCall {
  kind: "write";
  path: string;
  content: string;
}

/** An in-place edit: `oldText` is replaced by `newText` inside `path`. */
export interface EditCall {
  kind: "edit";
  path: string;
  oldText: string;
  newText: string;
}

/** Any tool the guard does not model. It is allowed unless a rule says otherwise. */
export interface OtherCall {
  kind: "other";
  toolName: string;
  input: unknown;
}

export type ToolCall = ShellCall | WriteCall | EditCall | OtherCall;

export type Platform = "posix" | "windows";

/**
 * Tunable policy. Defaults live in `policy.ts`. Every list is a set of globs
 * matched against the project-relative path (patterns containing `/`) or the
 * basename (patterns without `/`).
 */
export interface Policy {
  /** Branch names (globs) that must never receive a force push or deletion. */
  protectedBranches: string[];
  /** Paths the agent must never write through any tool. Owned by `ah`. */
  harnessPaths: string[];
  /** Hook wiring for the agents themselves and for git. */
  hookConfigPaths: string[];
  /** Linter and formatter-as-linter configuration files. */
  lintConfigPaths: string[];
  /** Test runner configuration files. */
  testConfigPaths: string[];
  /** Dependency lockfiles that must be produced by a package manager, not edited. */
  lockfilePaths: string[];
  /** Manifests that mix dependencies with lint/test sections; edits are inspected. */
  manifestPaths: string[];
  /** Files whose edits always need a human: CI definitions, compiler config, env files. */
  askPaths: string[];
  /** Env-like files that are documentation, not secrets, and therefore free to edit. */
  envExamplePaths: string[];
  /** Files under the user's home directory that are never written by an agent. */
  homeSensitivePaths: string[];
  /** Test file patterns. Some content rules apply only here, some are relaxed here. */
  testFilePaths: string[];
  /** Baselines and snapshots: refreshing them by hand hides regressions. */
  baselinePaths: string[];
}

export interface Context {
  /** Absolute project root. Relative tool paths resolve against it. */
  projectRoot: string;
  /** Absolute home directory, used to expand `~` and `$HOME` in paths and commands. */
  homeDir?: string;
  platform: Platform;
  /** Shell that will run `ShellCall.command`. Defaults to POSIX sh (Git Bash on Windows under Claude Code). */
  shellDialect?: "posix" | "powershell" | "cmd";
  /**
   * In a linked git worktree, the main checkout's directory that corresponds to
   * projectRoot. Codex loads project hooks there, so hook files in it and above
   * it are protected like the project's own. buildContext finds it on disk.
   */
  mainCheckout?: string;
  policy: Policy;
}

export interface Decision {
  verdict: Verdict;
  /** Stable rule id such as `shell.rm-recursive-root`. Absent when nothing matched. */
  rule?: string;
  /** One line saying what matched. Shown to the agent on deny; on ask it is the user's prompt text and also reaches the agent via additionalContext. */
  reason?: string;
  /** What to do instead. Reaches the agent in the deny reason, and on ask (Claude Code) through `additionalContext`. */
  remediation?: string;
}

export const ALLOW: Decision = Object.freeze({ verdict: "allow" });

export function deny(rule: string, reason: string, remediation: string): Decision {
  return { verdict: "deny", rule, reason, remediation };
}

export function ask(rule: string, reason: string, remediation: string): Decision {
  return { verdict: "ask", rule, reason, remediation };
}

const RANK: Record<Verdict, number> = { allow: 0, ask: 1, deny: 2 };

/** The strictest decision wins; among equals the first one stays. */
export function strictest(decisions: Decision[]): Decision {
  let best = ALLOW;
  for (const d of decisions) {
    if (RANK[d.verdict] > RANK[best.verdict]) best = d;
  }
  return best;
}
