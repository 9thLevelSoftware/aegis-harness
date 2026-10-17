import { classifyPath, type PathInfo } from "../classify.ts";
import { ALLOW, ask, deny, strictest, type Context, type Decision, type EditCall, type WriteCall } from "../model.ts";
import { findSecrets, redact } from "../secrets.ts";
import {
  BLANKET_SUPPRESSIONS,
  CI_WEAKENERS,
  COMPILER_LOOSENERS,
  COVERAGE_EXCLUSIONS,
  MANIFEST_LINT_SECTIONS,
  NOOP_SCRIPT,
  TEST_FOCUS,
  TEST_SKIPS,
  UNTARGETED_SUPPRESSIONS,
  added,
  gateScripts,
  occurrences,
  sectionBodies,
  stripComments,
} from "./content.ts";

const HARNESS_REMEDIATION = "`.harness/` is owned by ah. Record incidents with `ah bug add --rule <rule> --title \"...\"`; rules change in a reviewed commit, not from a session.";
const LINT_REMEDIATION = "Fix the violation in the source file instead. If the rule itself is wrong, say so to the user and record it with `ah bug add`; the config changes in a reviewed commit, not mid-task.";
const TEST_CONFIG_REMEDIATION = "Fix the failing test or the code under test instead. If the runner configuration is really wrong, explain why to the user and change it in a reviewed commit.";
const HOOK_REMEDIATION = "Hook wiring is how this project enforces its rules. Leave it as it is and tell the user if a hook is blocking legitimate work.";

export function editRules(call: WriteCall | EditCall, ctx: Context): Decision {
  const info = classifyPath(call.path, ctx);
  const before = call.kind === "write" ? "" : call.oldText;
  const after = call.kind === "write" ? call.content : call.newText;
  const decisions: Decision[] = [pathDecision(call, info, before, after), ...contentDecisions(info, before, after)];
  return strictest(decisions);
}

function pathDecision(call: WriteCall | EditCall, info: PathInfo, before: string, after: string): Decision {
  const shown = info.rel ?? info.abs;
  switch (info.category) {
    case "harness":
      return deny("edit.harness-dir", `${shown} is under .harness/`, HARNESS_REMEDIATION);
    case "git-internals":
      return deny("edit.git-internals", `${shown} is inside .git/`, "Use git commands to change repository state; never edit .git/ contents directly.");
    case "hook-config":
      return deny("edit.hook-config", `${shown} configures hooks (${info.matched})`, HOOK_REMEDIATION);
    case "home-config":
      return deny("edit.home-config", `${shown} is a credential or agent configuration file in the home directory`, "Agent sessions do not change user-level credentials or agent settings. Ask the user to make this change.");
    case "system":
      return deny("edit.system-path", `${shown} is a system path`, "Keep changes inside the project. If a system change is required, tell the user exactly what to run.");
    case "filesystem-root":
    case "home-root":
      return deny("edit.system-path", `${shown} is a root directory`, "Write files inside the project.");
    case "lockfile":
      return deny("edit.lockfile", `${shown} is a lockfile`, "Run the package manager (npm install, pnpm install, cargo update, uv lock, ...) so the lockfile is generated, not hand-edited.");
    case "lint-config":
      return deny("edit.lint-config", `${shown} is a linter configuration (${info.matched})`, LINT_REMEDIATION);
    case "test-config":
      return deny("edit.test-config", `${shown} is a test runner configuration (${info.matched})`, TEST_CONFIG_REMEDIATION);
    case "baseline":
      return ask("edit.baseline-refresh", `${shown} is a baseline or snapshot`, "A baseline refreshed to make a red gate green is a deleted regression test. Fix the regression, or ask the user to approve the refresh with the diff in front of them.");
    case "manifest":
      return manifestDecision(call, info, before, after);
    case "ci-config":
      if (added(CI_WEAKENERS, before, after).length > 0) {
        const what = added(CI_WEAKENERS, before, after).map((p) => p.id).join(", ");
        return deny("edit.ci-gate-weakened", `${shown}: adds ${what}`, "A CI step that is allowed to fail, or that never runs, is not a gate. Fix what fails, or ask the user before relaxing CI.");
      }
      return ask("edit.ci-config", `${shown} is a CI definition`, "CI changes need a human to confirm they do not weaken a gate.");
    case "compiler-config":
      if (added(COMPILER_LOOSENERS, before, after).length > 0) {
        const what = added(COMPILER_LOOSENERS, before, after).map((p) => p.id).join(", ");
        return deny("edit.compiler-strictness", `${shown}: sets ${what}`, "Fix the type errors instead of loosening the compiler. If strictness is wrong for this project, the user decides that in a reviewed commit.");
      }
      return ask("edit.compiler-config", `${shown} is compiler configuration`, "Compiler configuration changes need a human to confirm.");
    case "env-file":
      return ask("edit.env-file", `${shown} holds environment secrets`, "Describe the variable the user needs to set and let them edit the env file. Edit `.env.example` for documentation.");
    case "key-material":
      return ask("edit.key-material", `${shown} looks like key material`, "Generating or replacing keys needs a human. Prefer a documented command the user runs.");
    case "outside-project":
      return ask("edit.outside-project", `${shown} is outside the project root`, "Keep changes inside the project unless the user asked for this path.");
    case "temp":
    case "env-example":
    case "project-root":
    case "normal":
      return ALLOW;
  }
}

function manifestDecision(call: WriteCall | EditCall, info: PathInfo, before: string, after: string): Decision {
  const shown = info.rel ?? info.abs;
  // Comments cannot configure a linter, so a comment that names a section does not count. An edit
  // touches a section when the section's text differs between the old and new text: a header that
  // only stands as unchanged context (a dependency added above `[tool.ruff]`) is not touched.
  const sections = call.kind === "write"
    ? MANIFEST_LINT_SECTIONS.filter((p) => occurrences(p, stripComments(after)) > 0)
    : MANIFEST_LINT_SECTIONS.filter((p) => {
      const was = sectionBodies(p, stripComments(before));
      const now = sectionBodies(p, stripComments(after));
      return was.length !== now.length || was.some((b, i) => b !== now[i]);
    });
  if (sections.length > 0) {
    return deny("edit.manifest-lint-section", `${shown}: edit touches ${sections.map((s) => s.id).join(", ")}`, LINT_REMEDIATION);
  }
  const afterGates = gateScripts(after);
  const disabled = afterGates.filter((g) => NOOP_SCRIPT.test(g.value));
  if (disabled.length > 0) {
    return deny("edit.manifest-gate-disabled", `${shown}: "${disabled[0].name}" becomes a no-op (${disabled[0].value})`, "A gate script that cannot fail hides every regression behind it. Fix what the gate reports instead.");
  }
  if (call.kind === "edit") {
    const beforeGates = gateScripts(before);
    const changed = beforeGates.filter((b) => {
      const a = afterGates.find((x) => x.name === b.name);
      return a === undefined || a.value !== b.value;
    });
    if (changed.length > 0) {
      return ask("edit.manifest-gate-script", `${shown}: changes the "${changed[0].name}" script`, "Changing what a gate runs needs a human to confirm it still covers the same ground.");
    }
  }
  return ALLOW;
}

/** Prose files. MDX is left out: eslint-plugin-mdx applies the suppressions written in it. */
const PROSE = /\.(md|markdown|txt|rst|adoc|asciidoc)$/i;

function contentDecisions(info: PathInfo, before: string, after: string): Decision[] {
  const out: Decision[] = [];
  const shown = info.rel ?? info.abs;

  const beforeSecrets = new Set(findSecrets(before).map((h) => h.match));
  for (const hit of findSecrets(after)) {
    if (beforeSecrets.has(hit.match)) continue;
    if (hit.severity === "deny") {
      if (info.isTestFile) {
        out.push(ask("edit.secret-literal-suspect", `${shown}: ${hit.name} ${redact(hit.match)} in a test or fixture file`, "Confirm this is synthetic. Real credentials never go into files; reference an environment variable."));
      } else {
        out.push(deny("edit.secret-literal", `${shown}: ${hit.name} ${redact(hit.match)}`, "Never write credentials into files. Reference an environment variable (process.env.X, os.environ[\"X\"]) and tell the user which variable to set."));
      }
    } else if (!info.isTestFile) {
      out.push(ask("edit.secret-literal-suspect", `${shown}: looks like a ${hit.name}`, "If this is a real credential, move it to an environment variable."));
    }
  }

  // A suppression or skip in prose (CLAUDE.md, a contributing guide) is described, not applied.
  if (PROSE.test(shown)) return out;

  const blanket = added(BLANKET_SUPPRESSIONS, before, after);
  if (blanket.length > 0) {
    out.push(deny("edit.lint-suppression-blanket", `${shown}: adds ${blanket.map((p) => p.id).join(", ")}`, "Fix the reported problems. A suppression must name one rule and one line, with a reason."));
  }
  const untargeted = added(UNTARGETED_SUPPRESSIONS, before, after);
  if (untargeted.length > 0) {
    out.push(ask("edit.lint-suppression-untargeted", `${shown}: adds ${untargeted.map((p) => p.id).join(", ")}`, "Name the rule being suppressed (for example `// eslint-disable-next-line no-console`, `# noqa: E501`, `@ts-expect-error <reason>`), or fix the problem."));
  }

  if (info.isTestFile) {
    // A skip or focus named in a comment changes nothing; a skip under a visible condition is a platform guard, not a deleted test.
    const beforeCode = stripComments(before);
    const afterCode = stripComments(after);
    const skips = added(TEST_SKIPS, beforeCode, afterCode);
    if (skips.length > 0) {
      out.push(deny("edit.test-skip", `${shown}: adds ${skips.map((p) => p.id).join(", ")}`, "An unconditional skip is a deleted test. Fix it or delete it in a reviewed commit, and record why with `ah bug add`. A skip that depends on the platform or environment belongs under a visible condition (`if testing.Short()`, `test.skip(condition, reason)`, `@pytest.mark.skipif`)."));
    }
    const focus = added(TEST_FOCUS, beforeCode, afterCode);
    if (focus.length > 0) {
      out.push(deny("edit.test-only", `${shown}: adds ${focus.map((p) => p.id).join(", ")}`, "`.only` silently disables every other test in the file. Run a single test from the command line instead (for example `vitest run -t <name>`)."));
    }
  }

  const cov = added(COVERAGE_EXCLUSIONS, before, after);
  if (cov.length > 0) {
    out.push(ask("edit.coverage-exclusion", `${shown}: adds ${cov.map((p) => p.id).join(", ")}`, "Coverage exclusions need a reason the user agrees with."));
  }
  return out;
}
