/**
 * Render a decision in the dialect an agent understands.
 *
 * Claude Code: `permissionDecision` allow/deny/ask. An allow is rendered as no
 * output at all, so the agent's own permission rules still apply; the guard
 * vetoes, it never approves.
 *
 * Codex: `permissionDecision` deny is honoured; `ask` is not (Codex marks the
 * hook failed and continues), so `ask` falls back to deny with an explanation,
 * or to a warning when the caller chooses `warn`.
 */
import type { Decision } from "./model.ts";
import type { Agent } from "./normalize.ts";

export type AskFallback = "deny" | "warn";

export interface Rendered {
  stdout: string;
  exitCode: number;
}

export function explain(d: Decision, verb: string): string {
  const head = `[ah guard] ${verb} by ${d.rule ?? "policy"}: ${d.reason ?? ""}`.trim();
  const tail = d.remediation ? `\nDo instead: ${d.remediation}` : "";
  const record = d.rule ? `\n(If this is a false positive, tell the user and record it: ah bug add --rule ${d.rule})` : "";
  return `${head}${tail}${record}`;
}

export function render(d: Decision, agent: Agent, askFallback: AskFallback = "deny"): Rendered {
  if (d.verdict === "allow") return { stdout: "", exitCode: 0 };
  const hookEventName = "PreToolUse";
  if (d.verdict === "deny") {
    return { stdout: JSON.stringify({ hookSpecificOutput: { hookEventName, permissionDecision: "deny", permissionDecisionReason: explain(d, "denied") } }), exitCode: 0 };
  }
  if (agent === "codex") {
    if (askFallback === "warn") {
      const text = explain(d, "flagged for a human");
      return { stdout: JSON.stringify({ systemMessage: text, hookSpecificOutput: { hookEventName, additionalContext: text } }), exitCode: 0 };
    }
    return { stdout: JSON.stringify({ hookSpecificOutput: { hookEventName, permissionDecision: "deny", permissionDecisionReason: `${explain(d, "held for a human")}\nCodex cannot pause for approval here. Ask the user to run this step themselves.` } }), exitCode: 0 };
  }
  return { stdout: JSON.stringify({ hookSpecificOutput: { hookEventName, permissionDecision: "ask", permissionDecisionReason: explain(d, "held for a human") } }), exitCode: 0 };
}
