import { strictest, type Context, type Decision, type ToolCall } from "./model.ts";
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

/** A hook event can carry several calls (a multi-file patch); the strictest decision wins. */
export function decideAll(calls: readonly ToolCall[], ctx: Context): Decision {
  return strictest(calls.map((c) => decide(c, ctx)));
}
