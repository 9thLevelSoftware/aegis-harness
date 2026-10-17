import { ask, strictest, type Context, type Decision, type ToolCall } from "./model.ts";
import { editRules } from "./rules/edit.ts";
import { otherRules } from "./rules/other.ts";
import { shellRules } from "./rules/shell.ts";

/** The pure decision core: one tool call in, one decision out. No IO. */
export function decide(call: ToolCall, ctx: Context): Decision {
  switch (call.kind) {
    case "shell":
      return shellRules(call, ctx);
    case "write":
    case "edit":
      return editRules(call, ctx);
    case "other":
      return otherRules(call, ctx);
  }
}

/**
 * A hook event can carry several calls (a multi-file patch); the strictest decision wins.
 * A call the guard fails on is put to the user rather than let through: an error a command
 * can provoke would otherwise switch every check off for the whole command.
 */
export function decideAll(calls: readonly ToolCall[], ctx: Context): Decision {
  return strictest(calls.map((c) => {
    try {
      return decide(c, ctx);
    } catch (e) {
      const why = e instanceof Error ? e.message : String(e);
      return ask("guard.internal-error", `the guard failed while checking this call (${why.slice(0, 200)})`, "This is a bug in ah. Ask the user to run the command, and report it with the command that triggered it.");
    }
  }));
}
