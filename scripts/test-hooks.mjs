// `npm run test:hooks`: the fixture corpus end to end through dist/guard.mjs,
// with the per-call latency budget CI applies. The budget is AH_LATENCY_BUDGET_MS
// when set, else 400 ms on Windows (node.exe starts slower on the runner), else
// 150 ms. When GITHUB_STEP_SUMMARY is set the `guard latency:` line is appended
// to the Actions job summary, so the Windows p95 is visible without opening logs.
import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const cli = resolve(here, "../dist/ah.mjs");
const budget = process.env.AH_LATENCY_BUDGET_MS ?? (process.platform === "win32" ? "400" : "150");

const r = spawnSync(process.execPath, [cli, "test-hooks", "--budget-ms", budget, ...process.argv.slice(2)], {
  stdio: ["inherit", "pipe", "inherit"],
  encoding: "utf8",
});
if (r.error) {
  process.stderr.write(`test-hooks: ${r.error.message}\n`);
  process.exit(1);
}
process.stdout.write(r.stdout ?? "");

const latency = (r.stdout ?? "").split("\n").find((l) => l.startsWith("guard latency:"));
if (latency && process.env.GITHUB_STEP_SUMMARY) {
  try {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### ${process.env.RUNNER_OS ?? process.platform} guard latency\n\n${latency}\n\n`);
  } catch {
    // The summary is a convenience; a failure to write it never changes the result.
  }
}
process.exit(r.status ?? 1);
