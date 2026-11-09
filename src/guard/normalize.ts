/**
 * Turn an agent's hook payload into agent-neutral tool calls.
 *
 * Claude Code and Codex both send `{ hook_event_name, tool_name, tool_input, cwd, ... }`
 * on stdin. They differ in tool names and in how edits arrive: Claude Code has
 * Write/Edit/NotebookEdit with explicit fields (and the legacy MultiEdit);
 * Codex sends `apply_patch` with a patch text in `tool_input.command`, or runs
 * `apply_patch` through its shell tool with the patch as an argument or heredoc.
 */
import type { ToolCall } from "./model.ts";
import { isAbsolute, toPosix } from "./paths.ts";

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
  event.calls = toolName.startsWith("mcp__") ? mcpCalls(toolName, input) : agent === "codex" ? codexCalls(toolName, input) : claudeCalls(toolName, input);
  return event;
}

// ---------------------------------------------------------------------------
// MCP (both agents name them mcp__<server>__<tool>)

/** What an MCP tool's name says it does, from the part after the server: `start_process`, `write_file`, `edit_block`. */
const MCP_SHELL = /(^|_)(exec|execute|run|shell|bash|powershell|pwsh|terminal|command|process|spawn|interact)(_|$)/;
const MCP_WRITE = /(^|_)(write|save|put|append|edit|replace|patch|update|create_file|new_file)(_|$)/;
const MCP_REMOVE = /(^|_)(delete|remove|unlink|rmdir|move|rename|trash)(_|$)/;
const MCP_READ = /(^|_)(read|view|cat|open|get_file|download)(_|$)/;
const MCP_PATHS = ["path", "file_path", "filePath", "filename", "file", "target", "notebook_path"];
const MCP_MOVE_PATHS = ["source", "destination", "src", "dest", "from", "to", "old_path", "new_path", "oldPath", "newPath"];

/**
 * An MCP tool that runs commands or writes files is judged like the built-in tool it stands in
 * for (BUG-2026-023): a shell server's command by the shell rules, a filesystem server's write or
 * edit by the edit rules, a delete or move as a write to each path it names. Tools are recognised
 * by name and argument shape, never by server, so an unknown server is read the same way. The
 * call is also kept whole for the secret-literal and private-key checks.
 */
function mcpCalls(toolName: string, input: unknown): ToolCall[] {
  const i = dict(input);
  const name = toolName.replace(/^mcp__.*__/, "").toLowerCase();
  const whole: ToolCall = { kind: "other", toolName, input };
  const calls: ToolCall[] = [];
  const paths = (fields: readonly string[]) => fields.map((f) => str(i[f])).filter((p): p is string => p !== undefined && p !== "");

  if (MCP_SHELL.test(name)) {
    // `input` is what an interactive-process tool sends to a running shell.
    const raw = i.command ?? i.cmd ?? i.script ?? i.code ?? (/(interact|stdin|send)/.test(name) ? i.input : undefined);
    const args = Array.isArray(i.args) ? i.args : Array.isArray(i.arguments) ? i.arguments : undefined;
    const command = typeof raw === "string" && args !== undefined && !/\s/.test(raw.trim()) ? commandText([raw, ...args]) : commandText(raw);
    if (command.trim() !== "") {
      const cwd = str(i.cwd) ?? str(i.workdir) ?? str(i.working_directory) ?? str(i.workingDirectory) ?? str(i.directory);
      calls.push({ kind: "shell", command, ...(cwd === undefined ? {} : { cwd }) });
    }
  }
  // A path beside `owner` and `repo` names a file in a remote repository (GitHub's create_or_update_file), not on this disk.
  const remote = typeof i.owner === "string" && typeof i.repo === "string";
  if (MCP_WRITE.test(name) && !remote) {
    for (const path of paths(MCP_PATHS)) {
      const oldText = str(i.old_string) ?? str(i.oldText) ?? str(i.old_str) ?? str(i.old_text);
      const newText = str(i.new_string) ?? str(i.newText) ?? str(i.new_str) ?? str(i.new_text);
      const edits = Array.isArray(i.edits) ? i.edits.map(dict) : [];
      if (oldText !== undefined || newText !== undefined) calls.push({ kind: "edit", path, oldText: oldText ?? "", newText: newText ?? "" });
      else if (edits.length > 0) {
        for (const e of edits) calls.push({ kind: "edit", path, oldText: str(e.oldText) ?? str(e.old_string) ?? str(e.old_text) ?? "", newText: str(e.newText) ?? str(e.new_string) ?? str(e.new_text) ?? "" });
      } else calls.push({ kind: "write", path, content: str(i.content) ?? str(i.text) ?? str(i.data) ?? str(i.body) ?? "" });
    }
  }
  if (MCP_REMOVE.test(name) && !remote) {
    for (const path of paths([...MCP_PATHS, ...MCP_MOVE_PATHS])) calls.push({ kind: "write", path, content: "" });
  }
  if (MCP_READ.test(name) && !remote && Array.isArray(i.paths)) {
    // read_multiple_files: each path meets the Read tool's private-key rule.
    for (const p of i.paths) if (typeof p === "string") calls.push({ kind: "other", toolName: "Read", input: { file_path: p } });
  }
  return [...calls, whole];
}

// ---------------------------------------------------------------------------
// Claude Code

function claudeCalls(toolName: string, input: unknown): ToolCall[] {
  const i = dict(input);
  switch (toolName) {
    case "Bash":
    case "PowerShell": // same fields as Bash; main.ts picks the PowerShell dialect from the tool name
      return [{ kind: "shell", command: str(i.command) ?? "" }];
    case "Monitor": // runs `command` in the background under Bash's permission rules (Git Bash on Windows)
      return typeof i.command === "string" ? [{ kind: "shell", command: i.command }] : [{ kind: "other", toolName, input }];
    case "Write":
      return [{ kind: "write", path: str(i.file_path) ?? "", content: str(i.content) ?? "" }];
    case "Edit":
      return [{ kind: "edit", path: str(i.file_path) ?? "", oldText: str(i.old_string) ?? "", newText: str(i.new_string) ?? "" }];
    case "MultiEdit": { // legacy: no longer a Claude Code tool, kept for older installs
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
    const command = i.command ?? i.cmd ?? i.argv;
    // The command runs in `workdir` when Codex names one, so its relative paths resolve there.
    const workdir = str(i.workdir);
    const at = workdir === undefined ? {} : { cwd: workdir };
    const found = applyPatchViaShell(command);
    if (found !== undefined) {
      // The edit rules judge the patch; the shell rules still see the rest of the command line
      // (`cd x && apply_patch <<'EOF' ... EOF && rm -rf /`) with the patch body cut out.
      const calls = parseApplyPatch(found.patch, workdir);
      return found.rest === undefined ? calls : [...calls, { kind: "shell", command: found.rest, ...at }];
    }
    return [{ kind: "shell", command: commandText(command), ...at }];
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
    const script = shellScriptArg(parts);
    if (script !== undefined) return script;
    if (parts.length >= 3 && /^(pwsh|powershell)(\.exe)?$/i.test(parts[0].replace(/^.*[\\/]/, "")) && /^-(c|command)$/i.test(parts[1])) return parts.slice(2).join(" ");
    return parts.map(shellQuote).join(" ");
  }
  return "";
}

const SHELL_C_WRAPPER = /^\s*(?:\S*[\\/])?(?:bash|sh|zsh|dash)\s+-[a-z]*c[a-z]*\s+(?:--\s+)?(["'])([\s\S]*)\1\s*$/;
/** `apply_patch` in command position anywhere before the patch: first word, after `cd x &&`, after `FOO=1`, or a shim path. */
const APPLY_PATCH_CMD = /(?:^|[\s;&|(])(?:\S*[\\/])?apply_patch(?=\s|$)/;
const BEGIN = "*** Begin Patch";
const END = "*** End Patch";

export interface ShellPatch {
  /** The patch envelope, `*** Begin Patch` to `*** End Patch`. */
  patch: string;
  /** The command line with the patch body removed, when the patch came through a shell; absent for the bare argv form. */
  rest?: string;
}

/**
 * Codex models often run `apply_patch` through the shell tool instead of the
 * dedicated tool: as argv `["apply_patch", "<patch>"]` (arg0 may be a shim such
 * as `.../codex-arg0-xxxx/apply_patch`), as `apply_patch <<'EOF' ... EOF`, or
 * either of those wrapped in `bash -lc "..."`. Returns the patch text for those
 * shapes so the edit rules see the edit instead of an opaque shell command, and
 * the remainder of the command line so the shell rules still see everything else.
 */
export function applyPatchViaShell(command: unknown): ShellPatch | undefined {
  let text: string;
  if (Array.isArray(command)) {
    const parts = command.map((p) => (typeof p === "string" ? p : JSON.stringify(p)));
    const script = shellScriptArg(parts);
    if (script !== undefined) {
      text = script;
    } else {
      // `env FOO=1 apply_patch <patch>`: env execs apply_patch with the same argv tail.
      let k = 0;
      if (/^(?:\S*[\\/])?env$/.test(parts[0] ?? "")) {
        k = 1;
        while (k < parts.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(parts[k]) || parts[k] === "-i" || parts[k] === "-")) k++;
      }
      if (parts.length < k + 2 || !/^(?:\S*[\\/])?apply_patch$/.test(parts[k])) return undefined;
      const body = parts.slice(k + 1).join("\n");
      return body.includes(BEGIN) ? { patch: body } : undefined;
    }
  } else if (typeof command === "string") {
    text = command;
  } else {
    return undefined;
  }
  const wrapped = SHELL_C_WRAPPER.exec(text);
  if (wrapped) text = wrapped[2];
  const start = text.indexOf(BEGIN);
  if (start < 0 || !APPLY_PATCH_CMD.test(text.slice(0, start))) return undefined;
  const endAt = text.indexOf(END, start);
  const end = endAt < 0 ? text.length : endAt + END.length;
  return { patch: text.slice(start, end), rest: text.slice(0, start) + text.slice(end) };
}

/** The script carried by argv `["bash", "-lc", script]` or `["bash", "-c", "--", script]`; undefined for any other shape. */
function shellScriptArg(parts: readonly string[]): string | undefined {
  if (!/^(bash|sh|zsh|dash)$/.test((parts[0] ?? "").replace(/^.*[\\/]/, "")) || !/^-[a-z]*c[a-z]*$/.test(parts[1] ?? "")) return undefined;
  const dd = parts[2] === "--" ? 1 : 0;
  return parts.length === 3 + dd ? parts[2 + dd] : undefined;
}

function shellQuote(s: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, "'\\''")}'`;
}

/**
 * Parse Codex's apply_patch envelope into edit/write calls. Each `*** Update
 * File` becomes an edit whose old text is the removed and context lines and
 * whose new text is the added and context lines; `*** Add File` becomes a
 * write; `*** Delete File` becomes an edit to empty. Relative paths are relative to `workdir`
 * when the shell call that carried the patch named one.
 */
export function parseApplyPatch(patch: string, workdir?: string): ToolCall[] {
  const calls: ToolCall[] = [];
  const lines = patch.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    let m: RegExpExecArray | null;
    if ((m = /^\*\*\* Add File: (.+)$/.exec(line))) {
      const path = under(workdir, m[1].trim());
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
      calls.push({ kind: "edit", path: under(workdir, m[1].trim()), oldText: "<deleted>", newText: "" });
      i++;
      continue;
    }
    if ((m = /^\*\*\* Update File: (.+)$/.exec(line))) {
      const path = under(workdir, m[1].trim());
      let movedTo: string | undefined;
      const oldLines: string[] = [];
      const newLines: string[] = [];
      i++;
      while (i < lines.length && !/^\*\*\* (Add|Delete|Update) File:|^\*\*\* End Patch/.test(lines[i])) {
        const l = lines[i];
        if ((m = /^\*\*\* Move to: (.+)$/.exec(l))) movedTo = under(workdir, m[1].trim());
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

/** `path` as seen from the agent's working directory when it is relative to `workdir`. */
function under(workdir: string | undefined, path: string): string {
  if (workdir === undefined || workdir === "" || isAbsolute(toPosix(path)) || path.startsWith("~")) return path;
  return `${workdir.replace(/[\\/]+$/, "")}/${path}`;
}
