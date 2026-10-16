/**
 * Turn an agent's hook payload into agent-neutral tool calls.
 *
 * Claude Code and Codex both send `{ hook_event_name, tool_name, tool_input, cwd, ... }`
 * on stdin. They differ in tool names and in how edits arrive: Claude Code has
 * Write/Edit/MultiEdit with explicit fields; Codex sends `apply_patch` with a
 * patch text in `tool_input.command`.
 */
import type { ToolCall } from "./model.ts";

export type Agent = "claude" | "codex" | "unknown";

export interface HookEvent {
  agent: Agent;
  eventName: string;
  toolName: string;
  calls: ToolCall[];
  cwd?: string;
  sessionId?: string;
  permissionMode?: string;
}

type Dict = Record<string, unknown>;

function dict(v: unknown): Dict {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Dict) : {};
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

export function detectAgent(payload: Dict, hint?: Agent): Agent {
  if (hint && hint !== "unknown") return hint;
  if (typeof payload.turn_id === "string" || typeof payload.model === "string") return "codex";
  if (str(payload.transcript_path)?.includes(".codex")) return "codex";
  if (payload.tool_name === "apply_patch") return "codex";
  if (typeof payload.tool_use_id === "string" || typeof payload.session_id === "string") return "claude";
  return "unknown";
}

export function normalizeHookPayload(raw: unknown, hint?: Agent): HookEvent {
  const payload = dict(raw);
  const agent = detectAgent(payload, hint);
  const toolName = str(payload.tool_name) ?? "";
  const input = payload.tool_input;
  const event: HookEvent = {
    agent,
    eventName: str(payload.hook_event_name) ?? "",
    toolName,
    calls: [],
    cwd: str(payload.cwd),
    sessionId: str(payload.session_id),
    permissionMode: str(payload.permission_mode),
  };
  event.calls = agent === "codex" ? codexCalls(toolName, input) : claudeCalls(toolName, input);
  return event;
}

// ---------------------------------------------------------------------------
// Claude Code

function claudeCalls(toolName: string, input: unknown): ToolCall[] {
  const i = dict(input);
  switch (toolName) {
    case "Bash":
      return [{ kind: "shell", command: str(i.command) ?? "" }];
    case "Write":
      return [{ kind: "write", path: str(i.file_path) ?? "", content: str(i.content) ?? "" }];
    case "Edit":
      return [{ kind: "edit", path: str(i.file_path) ?? "", oldText: str(i.old_string) ?? "", newText: str(i.new_string) ?? "" }];
    case "MultiEdit": {
      const path = str(i.file_path) ?? "";
      const edits = Array.isArray(i.edits) ? i.edits : [];
      const calls: ToolCall[] = edits.map((e) => {
        const d = dict(e);
        return { kind: "edit" as const, path, oldText: str(d.old_string) ?? "", newText: str(d.new_string) ?? "" };
      });
      return calls.length > 0 ? calls : [{ kind: "edit", path, oldText: "", newText: "" }];
    }
    case "NotebookEdit":
      return [{ kind: "edit", path: str(i.notebook_path) ?? "", oldText: "", newText: str(i.new_source) ?? "" }];
    default:
      return [{ kind: "other", toolName, input }];
  }
}

// ---------------------------------------------------------------------------
// Codex

function codexCalls(toolName: string, input: unknown): ToolCall[] {
  const i = dict(input);
  const lower = toolName.toLowerCase();
  if (lower === "bash" || lower === "shell" || lower === "exec_command" || lower === "local_shell" || lower === "container.exec") {
    return [{ kind: "shell", command: commandText(i.command ?? i.cmd ?? i.argv) }];
  }
  if (lower === "apply_patch" || lower === "edit" || lower === "write") {
    const patch = str(i.command) ?? str(i.patch) ?? str(i.input) ?? "";
    if (patch.includes("*** Begin Patch") || patch.includes("*** Update File:") || patch.includes("*** Add File:")) {
      return parseApplyPatch(patch);
    }
    if (typeof i.file_path === "string") return claudeCalls(lower === "write" ? "Write" : "Edit", i);
    return [{ kind: "other", toolName, input }];
  }
  if (lower === "write_stdin") return [];
  return [{ kind: "other", toolName, input }];
}

/** Codex may send the command as a string or as an argv array (often `["bash","-lc","..."]`). */
export function commandText(command: unknown): string {
  if (typeof command === "string") return command;
  if (Array.isArray(command)) {
    const parts = command.map((p) => (typeof p === "string" ? p : JSON.stringify(p)));
    if (parts.length === 3 && /^(bash|sh|zsh|dash)$/.test(parts[0].replace(/^.*[\\/]/, "")) && /^-[a-z]*c[a-z]*$/.test(parts[1])) return parts[2];
    if (parts.length >= 3 && /^(pwsh|powershell)(\.exe)?$/i.test(parts[0].replace(/^.*[\\/]/, "")) && /^-(c|command)$/i.test(parts[1])) return parts.slice(2).join(" ");
    return parts.map(shellQuote).join(" ");
  }
  return "";
}

function shellQuote(s: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, "'\\''")}'`;
}

/**
 * Parse Codex's apply_patch envelope into edit/write calls. Each `*** Update
 * File` becomes an edit whose old text is the removed and context lines and
 * whose new text is the added and context lines; `*** Add File` becomes a
 * write; `*** Delete File` becomes an edit to empty.
 */
export function parseApplyPatch(patch: string): ToolCall[] {
  const calls: ToolCall[] = [];
  const lines = patch.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    let m: RegExpExecArray | null;
    if ((m = /^\*\*\* Add File: (.+)$/.exec(line))) {
      const path = m[1].trim();
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("*** ")) {
        body.push(lines[i].startsWith("+") ? lines[i].slice(1) : lines[i]);
        i++;
      }
      calls.push({ kind: "write", path, content: body.join("\n") });
      continue;
    }
    if ((m = /^\*\*\* Delete File: (.+)$/.exec(line))) {
      calls.push({ kind: "edit", path: m[1].trim(), oldText: "<deleted>", newText: "" });
      i++;
      continue;
    }
    if ((m = /^\*\*\* Update File: (.+)$/.exec(line))) {
      const path = m[1].trim();
      let movedTo: string | undefined;
      const oldLines: string[] = [];
      const newLines: string[] = [];
      i++;
      while (i < lines.length && !/^\*\*\* (Add|Delete|Update) File:|^\*\*\* End Patch/.test(lines[i])) {
        const l = lines[i];
        if ((m = /^\*\*\* Move to: (.+)$/.exec(l))) movedTo = m[1].trim();
        else if (l.startsWith("@@")) { /* hunk header */ }
        else if (l.startsWith("+")) newLines.push(l.slice(1));
        else if (l.startsWith("-")) oldLines.push(l.slice(1));
        else if (l.startsWith(" ")) { oldLines.push(l.slice(1)); newLines.push(l.slice(1)); }
        else if (l === "") { /* blank context */ }
        else { oldLines.push(l); newLines.push(l); }
        i++;
      }
      calls.push({ kind: "edit", path, oldText: oldLines.join("\n"), newText: newLines.join("\n") });
      if (movedTo) calls.push({ kind: "write", path: movedTo, content: newLines.join("\n") });
      continue;
    }
    i++;
  }
  return calls;
}
