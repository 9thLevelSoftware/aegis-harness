import { classifyPath } from "../classify.ts";
import { inCredentialStore, isPrivateFile, isPrivateHomeFile, isPublicInStore } from "../credentials.ts";
import { ALLOW, deny, strictest, type Context, type Decision, type OtherCall } from "../model.ts";
import { findSecrets, redact } from "../secrets.ts";

const PATH_FIELDS = ["file_path", "path", "notebook_path", "filePath", "filename", "file"];
/** Files under ~/.ssh that hold private material: everything except public keys, config, known_hosts, authorized_keys, environment and rc. */
const SSH_PRIVATE = /^\.ssh\/(?!.*\.pub$)(?!(?:config|known_hosts(?:\.old)?|authorized_keys2?|environment|rc)$)/i;
const READ_KEY_FIX = "Private keys and credential stores stay out of the transcript. Use the path by name, or ask the user to run the command that needs it.";
const READ_TOOLS = new Set(["read", "view", "read_file", "view_file", "cat", "open_file", "notebookread"]);

/** Tools the guard does not model in detail: reads, searches, MCP calls, sub-agents. */
export function otherRules(call: OtherCall, ctx: Context): Decision {
  const out: Decision[] = [];
  const input = (call.input ?? {}) as Record<string, unknown>;
  const toolName = call.toolName.toLowerCase();
  const simpleName = toolName.replace(/^mcp__[^_]+(?:_[^_]+)*__/, "");

  if (READ_TOOLS.has(simpleName) || /(^|__)read/.test(toolName)) {
    for (const field of PATH_FIELDS) {
      const value = input[field];
      if (typeof value !== "string") continue;
      const info = classifyPath(value, ctx);
      const rel = info.rel ?? info.homeRel ?? info.abs;
      const home = info.homeRel?.replace(/\\/g, "/") ?? null;
      const isPrivate = isPrivateFile(rel) || (home !== null && (SSH_PRIVATE.test(home) || isPrivateHomeFile(home)));
      if (isPrivate && !info.isTestFile) {
        out.push(deny("tool.read-private-key", `${rel} is a private key or credential store`, READ_KEY_FIX));
      }
    }
  }

  // Grep prints matching lines only in content mode; its other modes list files or counts.
  if (simpleName === "grep" && input.output_mode === "content" && typeof input.path === "string") {
    const info = classifyPath(input.path, ctx);
    const rel = info.rel ?? info.homeRel ?? info.abs;
    const home = info.homeRel?.replace(/\\/g, "/") ?? null;
    if (!info.isTestFile && (isPrivateFile(rel) || (home !== null && (isPrivateHomeFile(home) || (inCredentialStore(home) && !isPublicInStore(home)))))) {
      out.push(deny("tool.read-private-key", `Grep prints lines from ${rel}, which holds private keys or credentials`, READ_KEY_FIX));
    }
  }

  let serialized = "";
  try {
    serialized = JSON.stringify(call.input ?? "");
  } catch {
    serialized = "";
  }
  for (const hit of findSecrets(serialized)) {
    if (hit.severity !== "deny") continue;
    out.push(deny("tool.secret-literal", `${call.toolName} argument contains a ${hit.name} (${redact(hit.match)})`, "Never pass credentials in tool arguments. Reference an environment variable instead."));
    break;
  }
  return out.length === 0 ? ALLOW : strictest(out);
}
