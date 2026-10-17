/**
 * The managed block `ah init` keeps in AGENTS.md: what an agent should do when
 * the guard refuses a call. Short on purpose. It is read on every session, by
 * every agent, and a long block buries the project's own instructions;
 * tests/init.test.ts caps the block at 100 lines.
 */
import { BLOCK_BEGIN, BLOCK_END } from "./text-block.ts";

export const AGENTS_BLOCK_BODY: readonly string[] = [
  "## Guard (`ah`)",
  "",
  "This project runs `ah`, a PreToolUse guard, before your shell commands, file edits and reads.",
  "",
  "- A call refused with `[ah guard] denied by <rule>` did not run. Follow its \"Do instead\" line.",
  "- Do not rephrase, split, encode, or move a refused command into a script or another tool to get",
  "  it past the guard. That is the same action, and it is a worse one.",
  "- If a refusal looks wrong, stop and tell the user what you were doing and which rule fired. A",
  "  false positive is recorded with `ah bug add --rule <rule> --title \"<what you were doing>\"`.",
  "- Hook wiring is the user's: never edit or remove `.claude/settings*.json`, `.codex/`, `.harness/`",
  "  or git hooks, and never run `ah init --remove`. Ask the user instead.",
  "- Fix the code, not the gate. Do not loosen lint, type or test configuration, skip or delete",
  "  tests, or add ignore comments to make a check pass.",
  "- On Codex a call that needs a human arrives as a refusal that says so. Ask the user; do not retry.",
];

/** The whole block as it appears in the file, markers included. */
export function agentsBlockLines(): string[] {
  return [BLOCK_BEGIN, ...AGENTS_BLOCK_BODY, BLOCK_END];
}
