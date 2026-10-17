import type { Verdict } from "../model.ts";

/**
 * Every rule the guard can cite, with where it came from. A rule without a
 * provenance entry cannot exist: tests fail when a fixture cites an unknown id
 * and when a rule has no fixture on each side (block or ask, and allow).
 *
 * Provenance vocabulary:
 *  - `blueprint §x.y`: named in the AegisHarness blueprint PDF.
 *  - `BUG-2026-nnn`: a record under .harness/memory/bugs/.
 */
export interface RuleInfo {
  id: string;
  title: string;
  verdict: Verdict;
  provenance: string;
}

export const RULES: readonly RuleInfo[] = [
  // Shell: destruction
  { id: "shell.rm-recursive-root", title: "Recursive delete of the filesystem root", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (rm -rf / variants)" },
  { id: "shell.rm-recursive-home", title: "Recursive delete of the home directory", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (rm -rf / variants)" },
  { id: "shell.rm-recursive-cwd", title: "Recursive delete that wipes the working tree", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (rm -rf / variants)" },
  { id: "shell.rm-outside-project", title: "Recursive delete outside the project", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard; BUG-2026-013" },
  { id: "shell.rm-git-dir", title: "Delete of the .git directory", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard" },
  { id: "shell.rm-unresolved-variable", title: "Recursive delete whose target is an unexpanded variable", verdict: "ask", provenance: "blueprint §3.2 pre_tool_guard (rm -rf / variants)" },
  { id: "shell.disk-destroy", title: "Raw disk or partition destruction", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.system-power", title: "Shutdown or reboot of the machine", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.fork-bomb", title: "Fork bomb", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.kill-all", title: "Kill every process", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.permissions-sweep", title: "Recursive permission change on root, home or system paths", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.permissions-world-writable", title: "Recursive world-writable permissions", verdict: "ask", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.privilege-escalation", title: "Command run through sudo or doas", verdict: "ask", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.pipe-to-shell", title: "Remote or decoded content piped into an interpreter", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.encoded-command", title: "Encoded PowerShell command", verdict: "ask", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.brace-expansion-limit", title: "Brace expansion too large to check word by word", verdict: "ask", provenance: "BUG-2026-019" },
  { id: "shell.interpreter-destructive", title: "Inline interpreter code that deletes trees", verdict: "ask", provenance: "blueprint §3.2 pre_tool_guard (rm -rf / variants)" },
  { id: "shell.docker-destroy", title: "Docker prune or volume removal", verdict: "ask", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.database-destroy", title: "Drop, truncate or reset of a database", verdict: "ask", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.deploy-or-publish", title: "Deploy, publish or release to a shared destination", verdict: "ask", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.remote-destroy", title: "Destruction of shared infrastructure or a remote repository", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },

  // Shell: git
  { id: "shell.git-force-push", title: "Force push", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.git-force-push-review", title: "Force push that needs a human (unprotected or unknown branch)", verdict: "ask", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.git-branch-delete", title: "Remote branch deletion", verdict: "ask", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.git-discard-changes", title: "Discarding uncommitted work", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.git-discard-file", title: "Discarding uncommitted changes to named files", verdict: "ask", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.git-clean", title: "git clean removing untracked files", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.git-stash-drop", title: "Dropping stashes", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.git-branch-force-delete", title: "Force-deleting a local branch", verdict: "ask", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.git-rewrite-history", title: "History rewrite or reflog destruction", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "shell.git-global-config", title: "Changing the user's global git configuration", verdict: "ask", provenance: "blueprint §3.2 (ECC destructive-command guard)" },

  // Shell: hooks and harness integrity
  { id: "shell.hook-bypass", title: "Skipping git hooks", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (--no-verify)" },
  { id: "shell.hook-tamper", title: "Writing or removing hook configuration from the shell", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (--no-verify)" },
  { id: "shell.write-harness", title: "Writing to .harness/ from the shell", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (.harness/)" },
  { id: "shell.write-git-internals", title: "Writing inside .git/ from the shell", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (.harness/)" },
  { id: "shell.write-lint-config", title: "Writing a linter configuration from the shell", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (linter config)" },
  { id: "shell.write-test-config", title: "Writing a test configuration from the shell", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (linter config)" },
  { id: "shell.write-lockfile", title: "Writing a lockfile by hand from the shell", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (linter config)" },
  { id: "shell.write-baseline", title: "Refreshing a baseline or snapshot from the shell", verdict: "ask", provenance: "BUG-2026-005" },
  { id: "shell.write-ask-path", title: "Writing CI, compiler or env configuration from the shell", verdict: "ask", provenance: "blueprint §3.2 pre_tool_guard (linter config)" },
  { id: "shell.write-home-config", title: "Writing credential or agent configuration under the home directory", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard; BUG-2026-013" },
  { id: "shell.write-system-path", title: "Writing to a system directory", verdict: "ask", provenance: "blueprint §3.2 (ECC destructive-command guard)" },

  // Shell: credentials
  { id: "shell.secret-literal", title: "Credential literal in a shell command", verdict: "deny", provenance: "blueprint §3.2 secret_mcp_guard" },
  { id: "shell.credential-read", title: "Printing private keys or credential stores", verdict: "deny", provenance: "BUG-2026-011" },
  { id: "shell.credential-exfil", title: "Sending credentials or the environment to the network", verdict: "deny", provenance: "BUG-2026-011" },

  // Edits
  { id: "edit.harness-dir", title: "Edit under .harness/", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (.harness/)" },
  { id: "edit.git-internals", title: "Edit inside .git/", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (.harness/)" },
  { id: "edit.hook-config", title: "Edit of hook configuration", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (--no-verify)" },
  { id: "edit.home-config", title: "Edit of credential or agent configuration under the home directory", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard; BUG-2026-013" },
  { id: "edit.system-path", title: "Edit of a system file", verdict: "deny", provenance: "blueprint §3.2 (ECC destructive-command guard)" },
  { id: "edit.lint-config", title: "Edit of a linter configuration", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (linter config)" },
  { id: "edit.test-config", title: "Edit of a test runner configuration", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (linter config)" },
  { id: "edit.lockfile", title: "Hand edit of a lockfile", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (linter config)" },
  { id: "edit.baseline-refresh", title: "Hand edit of a baseline or snapshot", verdict: "ask", provenance: "BUG-2026-005" },
  { id: "edit.manifest-lint-section", title: "Edit of a lint or test section inside a manifest", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (linter config)" },
  { id: "edit.manifest-gate-script", title: "Edit of a test, lint or typecheck script in a manifest", verdict: "ask", provenance: "BUG-2026-004" },
  { id: "edit.manifest-gate-disabled", title: "A gate script turned into a no-op", verdict: "deny", provenance: "BUG-2026-004" },
  { id: "edit.ci-config", title: "Edit of a CI definition", verdict: "ask", provenance: "blueprint §3.2 pre_tool_guard (linter config)" },
  { id: "edit.ci-gate-weakened", title: "CI step allowed to fail or never run", verdict: "deny", provenance: "BUG-2026-004" },
  { id: "edit.compiler-config", title: "Edit of compiler configuration", verdict: "ask", provenance: "blueprint §3.2 pre_tool_guard (tsconfig.json)" },
  { id: "edit.compiler-strictness", title: "Compiler strictness turned off", verdict: "deny", provenance: "blueprint §3.2 pre_tool_guard (tsconfig.json)" },
  { id: "edit.env-file", title: "Edit of an env file", verdict: "ask", provenance: "blueprint §3.2 secret_mcp_guard" },
  { id: "edit.key-material", title: "Write of key material", verdict: "ask", provenance: "blueprint §3.2 secret_mcp_guard" },
  { id: "edit.outside-project", title: "Edit outside the project", verdict: "ask", provenance: "BUG-2026-013" },
  { id: "edit.secret-literal", title: "Credential literal written to a file", verdict: "deny", provenance: "blueprint §3.2 secret_mcp_guard" },
  { id: "edit.secret-literal-suspect", title: "Possible credential written to a file", verdict: "ask", provenance: "blueprint §3.2 secret_mcp_guard" },
  { id: "edit.lint-suppression-blanket", title: "File-wide or all-rules lint suppression added", verdict: "deny", provenance: "BUG-2026-004" },
  { id: "edit.lint-suppression-untargeted", title: "Untargeted lint suppression added", verdict: "ask", provenance: "BUG-2026-004" },
  { id: "edit.test-skip", title: "Test skipped", verdict: "deny", provenance: "BUG-2026-004" },
  { id: "edit.test-only", title: "Test focus (.only) added", verdict: "deny", provenance: "BUG-2026-004" },
  { id: "edit.coverage-exclusion", title: "Coverage exclusion added", verdict: "ask", provenance: "BUG-2026-004" },

  // Other tools
  { id: "tool.secret-literal", title: "Credential literal in a tool argument", verdict: "deny", provenance: "blueprint §3.2 secret_mcp_guard" },
  { id: "tool.read-private-key", title: "Reading a private key or credential store", verdict: "deny", provenance: "BUG-2026-011" },
];

const BY_ID = new Map(RULES.map((r) => [r.id, r] as const));

export function ruleInfo(id: string): RuleInfo | undefined {
  return BY_ID.get(id);
}
