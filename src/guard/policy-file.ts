/**
 * `.harness/policy.json`: the user's per-rule overrides (BUG-2026-022).
 *
 *   { "rules": { "edit.lint-config": "ask", "shell.git-discard-changes": "off" } }
 *
 * `ask` puts a rule's deny to a human, `off` lets its calls through, `deny` hardens an ask. The
 * file lives under `.harness/`, which no agent tool may write, so an agent cannot loosen its own
 * policy; the user edits it by hand and commits it like any other project setting. A file that is
 * not valid is ignored as a whole, so a typo leaves every rule at its default, never off.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { isLimitRule, POLICY_FILE, type RuleOverride } from "./model.ts";
import { RULES } from "./rules/registry.ts";

export interface PolicyFile {
  /** The overrides in force: empty when there is no file or it is not valid. */
  overrides: Record<string, RuleOverride>;
  /** What is wrong with the file, for `ah doctor`. A non-empty list with no overrides means the file was ignored. */
  problems: string[];
  /** True when the file exists. */
  present: boolean;
}

const VALUES: readonly RuleOverride[] = ["deny", "ask", "off"];

/** Parse the text of a policy file. Unknown rules are reported and skipped; anything else wrong voids the file. */
export function parsePolicyFile(text: string, known: ReadonlySet<string> = new Set(RULES.map((r) => r.id))): PolicyFile {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    return { overrides: {}, problems: [`${POLICY_FILE} is not JSON (${(e as Error).message}), so it is ignored`], present: true };
  }
  const rules = (raw as { rules?: unknown } | null)?.rules;
  if (raw === null || typeof raw !== "object" || Array.isArray(raw) || rules === null || typeof rules !== "object" || Array.isArray(rules)) {
    return { overrides: {}, problems: [`${POLICY_FILE} needs a "rules" object, such as {"rules": {"edit.lint-config": "ask"}}, so it is ignored`], present: true };
  }
  const overrides: Record<string, RuleOverride> = Object.create(null);
  const problems: string[] = [];
  for (const [id, value] of Object.entries(rules as Record<string, unknown>)) {
    if (!VALUES.includes(value as RuleOverride)) {
      return { overrides: {}, problems: [`${POLICY_FILE}: "${id}" is set to ${JSON.stringify(value)}; use "deny", "ask" or "off". The file is ignored`], present: true };
    }
    if (isLimitRule(id)) problems.push(`${POLICY_FILE}: ${id} is one of the guard's own limits, which ask when a call could not be checked, and cannot be overridden; the entry is skipped`);
    else if (!known.has(id)) problems.push(`${POLICY_FILE}: no rule is called ${id} (\`ah rules\` lists them); the entry is skipped`);
    else overrides[id] = value as RuleOverride;
  }
  return { overrides, problems, present: true };
}

/** Read `<root>/.harness/policy.json`. No file means no overrides. */
export function readPolicyFile(root: string): PolicyFile {
  let text: string;
  try {
    text = readFileSync(join(root, ...POLICY_FILE.split("/")), "utf8");
  } catch {
    return { overrides: {}, problems: [], present: false };
  }
  return parsePolicyFile(text.replace(/^﻿/, ""));
}
