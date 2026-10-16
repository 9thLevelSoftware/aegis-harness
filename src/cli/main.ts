import { runGuard } from "../guard/main.ts";
import { VERSION } from "../version.ts";
import { runBug } from "./bug.ts";
import { runTestHooks } from "./test-hooks.ts";

const HELP = `ah ${VERSION}: a PreToolUse guard for Codex and Claude Code.

Usage:
  ah guard [--agent claude|codex] [--output claude|codex] [--root DIR] [--ask-fallback deny|warn]
      Read one hook payload on stdin, print the agent's decision. Wire this as a PreToolUse hook.
  ah test-hooks [--fixtures DIR] [--guard FILE] [--in-process] [--budget-ms N] [--filter TEXT] [--json]
      Run every must_block / must_allow / must_ask fixture through the guard. Exits 1 on any miss.
  ah bug add --rule RULE --title TEXT [--command TEXT] [--agent NAME] [--observed-on TEXT]
      Record an incident or false positive under .harness/memory/bugs/.
  ah bug list
  ah rules
      List every rule with its default verdict and provenance.
  ah version | ah help
`;

export async function main(argv: readonly string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  switch (cmd) {
    case "guard":
      return runGuard(rest);
    case "test-hooks":
      return runTestHooks(rest);
    case "bug":
      return runBug(rest);
    case "rules": {
      const { RULES } = await import("../guard/rules/registry.ts");
      for (const r of RULES) process.stdout.write(`${r.verdict.padEnd(5)} ${r.id.padEnd(36)} ${r.title}  [${r.provenance}]\n`);
      return 0;
    }
    case "version":
    case "--version":
    case "-v":
      process.stdout.write(`${VERSION}\n`);
      return 0;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      process.stdout.write(HELP);
      return cmd === undefined ? 1 : 0;
    default:
      process.stderr.write(`ah: unknown command "${cmd}"\n\n${HELP}`);
      return 1;
  }
}

export function cliEntry(): void {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err: unknown) => {
      process.stderr.write(`ah: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    },
  );
}
