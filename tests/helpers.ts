import { DEFAULT_POLICY } from "../src/guard/policy.ts";
import type { Context, Decision, ToolCall } from "../src/guard/model.ts";
import { decide } from "../src/guard/decide.ts";

export const POSIX: Context = { projectRoot: "/home/dev/project", homeDir: "/home/dev", platform: "posix", shellDialect: "posix", policy: DEFAULT_POLICY };
export const WINDOWS_CODEX: Context = { projectRoot: "C:\\Users\\dev\\project", homeDir: "C:\\Users\\dev", platform: "windows", shellDialect: "powershell", policy: DEFAULT_POLICY };

export function sh(command: string, ctx: Context = POSIX): Decision {
  return decide({ kind: "shell", command }, ctx);
}

export function ed(path: string, oldText: string, newText: string, ctx: Context = POSIX): Decision {
  return decide({ kind: "edit", path, oldText, newText }, ctx);
}

export function wr(path: string, content: string, ctx: Context = POSIX): Decision {
  return decide({ kind: "write", path, content }, ctx);
}

export function call(c: ToolCall, ctx: Context = POSIX): Decision {
  return decide(c, ctx);
}
