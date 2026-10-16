import { classifyPath } from "../classify.ts";
import { ALLOW, deny, strictest, type Context, type Decision, type OtherCall } from "../model.ts";
import { findSecrets, redact } from "../secrets.ts";

const PATH_FIELDS = ["file_path", "path", "notebook_path", "filePath", "filename", "file"];
const PRIVATE_FILE = /(^|\/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)$|\.(pem|key|p12|pfx)$|(^|\/)\.(netrc|git-credentials|pypirc)$|(^|\/)\.aws\/credentials$|(^|\/)\.docker\/config\.json$|(^|\/)\.kube\/config$/i;
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
      const isPrivate = PRIVATE_FILE.test(rel.replace(/\\/g, "/")) || (info.homeRel !== null && /^\.ssh\/(?!.*\.pub$)/.test(info.homeRel));
      if (isPrivate && !info.isTestFile) {
        out.push(deny("tool.read-private-key", `${rel} is a private key or credential store`, "Private keys and credential stores stay out of the transcript. Use the path by name, or ask the user to run the command that needs it."));
      }
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
