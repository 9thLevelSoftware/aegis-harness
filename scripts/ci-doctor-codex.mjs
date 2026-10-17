// CI: read `ah doctor --agents codex --json` for a fresh scratch project. Codex is not
// installed on the runner and nobody has trusted the project or the hook, so those are
// the only failures allowed; every canary must pass. Warnings become annotations.
import { readFileSync } from "node:fs";

// --both-shells: on Windows, a commandWindows that runs in only one of cmd.exe and PowerShell fails too.
const bothShells = process.argv.includes("--both-shells");
const text = readFileSync(process.argv[2], "utf8").replace(/^\uFEFF/, "");
const r = JSON.parse(text);
const trust = /not trusted .* yet|has not trusted the ah hook/;
const bad = r.checks.filter((c) => (c.level === "fail" && !trust.test(c.title)) || (bothShells && c.level === "warn" && /canary|one shell/.test(c.title)));
const canaries = r.checks.filter((c) => /canary/.test(c.title));
for (const c of r.checks) console.log(`${c.level.padEnd(4)}  ${c.title}`);
for (const c of r.checks.filter((c) => c.level === "warn")) console.log(`::warning title=ah doctor (codex)::${c.title}`);
if (bad.length > 0) {
  for (const c of bad) console.log(`::error title=ah doctor (codex)::${c.title}`);
  process.exit(1);
}
if (canaries.length === 0 || canaries.some((c) => c.level === "fail")) {
  console.log("::error title=ah doctor (codex)::the canary did not pass through the Codex hook command");
  process.exit(1);
}
