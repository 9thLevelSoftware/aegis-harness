/**
 * Where an agent reads ah's files from differs by platform and checkout:
 * linked worktrees, Windows, WSL drives, registry policy, the tools a matcher
 * must cover. Each test pins one of those facts to what ah writes and reports.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { claudeSwitches, doctor, doctorClaude, parseRegSettings, type DoctorDeps } from "../src/cli/doctor.ts";
import { init, type InitOptions } from "../src/cli/init.ts";
import { CLAUDE_MATCHER, claudeMatcherCovers } from "../src/wiring/claude.ts";
import { CODEX_MATCHER, codexConfigLayers, codexHooksFile, codexLayers, codexMatcherCovers } from "../src/wiring/codex.ts";
import { defaultMachine, sharedAcrossWsl, type Machine } from "../src/wiring/project.ts";

const here = dirname(fileURLToPath(import.meta.url));
const guard = resolve(here, "../dist/guard.mjs");
const skip = !existsSync(guard) && "run npm run build first";

interface Sandbox {
  base: string;
  root: string;
  home: string;
  env: NodeJS.ProcessEnv;
  done: () => void;
}

function sandbox(): Sandbox {
  // Native, so the paths match git's spelling on Windows (no 8.3 names such as RUNNER~1).
  const base = realpathSync.native(mkdtempSync(join(tmpdir(), "ah-platforms-")));
  const root = join(base, "proj");
  const home = join(base, "home");
  mkdirSync(root, { recursive: true });
  mkdirSync(home, { recursive: true });
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home, CODEX_HOME: join(home, ".codex"), GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.com", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.com" };
  for (const k of ["CLAUDE_CONFIG_DIR", "CLAUDE_PROJECT_DIR", "AH_PROJECT_ROOT", "CLAUDE_CODE_SAFE_MODE", "WSL_DISTRO_NAME", "WSL_INTEROP"]) delete env[k];
  return { base, root, home, env, done: () => rmSync(base, { recursive: true, force: true }) };
}

const git = (cwd: string, env: NodeJS.ProcessEnv, ...args: string[]) => {
  const r = spawnSync("git", args, { cwd, env, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
};

/** A repository at s.root with one commit, and a linked worktree beside it. */
function withWorktree(s: Sandbox): string {
  git(s.root, s.env, "init", "-q");
  git(s.root, s.env, "commit", "-q", "--allow-empty", "-m", "init");
  const wt = join(s.base, "wt");
  git(s.root, s.env, "worktree", "add", "-q", wt);
  return wt;
}

const opts = (root: string, more: Partial<InitOptions> = {}): InitOptions => ({ agents: ["codex"], root, scope: "local", remove: false, dryRun: false, failClosed: false, noLog: false, instructions: true, json: false, guard, ...more });
const deps: DoctorDeps = {
  probe: (name) => ({ found: true, stdout: name === "claude" ? "2.1.302 (Claude Code)\n" : "codex-cli 0.163.0\n" }),
  featuresList: () => "hooks                                    stable             true\n",
  codexListing: () => null,
};
const titles = (checks: { level: string; title: string }[], level: string) => checks.filter((c) => c.level === level).map((c) => c.title).join("\n");
const machine = (s: Sandbox, root: string, more: Partial<Machine> = {}): Machine => ({ ...defaultMachine(root, guard, s.env), ...more });

test("matchers: Monitor and MCP tools reach the guard, and the anchors keep look-alike names out", () => {
  for (const t of ["Bash", "PowerShell", "Monitor", "Edit", "Write", "Read", "mcp__aws__put_parameter", "mcp__filesystem__read_file"]) assert.ok(claudeMatcherCovers(CLAUDE_MATCHER, t), t);
  for (const t of ["BashOutput", "XBash", "Monitors", "my_mcp__tool"]) assert.ok(!claudeMatcherCovers(CLAUDE_MATCHER, t), t);
  for (const t of [["Bash"], ["apply_patch", "Edit", "Write"], ["mcp__fs__read_file"]]) assert.ok(codexMatcherCovers(CODEX_MATCHER, t), t.join());
  assert.ok(!codexMatcherCovers(CODEX_MATCHER, ["BashOutput"]));
});

test("codex: in a linked worktree, local scope wires the main checkout's file, the one Codex reads", { skip }, () => {
  const s = sandbox();
  try {
    const wt = withWorktree(s);
    mkdirSync(join(wt, "sub"));
    const m = machine(s, join(wt, "sub"));
    assert.deepEqual(codexLayers(m), [wt, join(wt, "sub")]);
    assert.deepEqual(codexConfigLayers(m), [s.root, join(s.root, "sub")]);
    assert.equal(codexHooksFile(m, "local"), join(s.root, "sub", ".codex", "hooks.json"));
    assert.equal(codexHooksFile(m, "project"), join(wt, "sub", ".codex", "hooks.json"));

    const r = init(opts(wt), s.env);
    assert.ok(r.ok, r.error);
    assert.ok(existsSync(join(s.root, ".codex", "hooks.json")), "written where Codex reads it");
    assert.ok(!existsSync(join(wt, ".codex", "hooks.json")), "nothing in the worktree, which Codex ignores");
    assert.match(readFileSync(join(s.root, ".git", "info", "exclude"), "utf8"), /^\/\.codex\/hooks\.json$/m);
    // The instructions still go in the worktree: Codex reads AGENTS.md from there.
    assert.ok(existsSync(join(wt, "AGENTS.md")));

    // Trusting the main checkout trusts the worktree's sessions.
    mkdirSync(join(s.home, ".codex"), { recursive: true });
    writeFileSync(join(s.home, ".codex", "config.toml"), `[projects.${JSON.stringify(s.root)}]\ntrust_level = "trusted"\n`);
    const d = doctor({ agents: ["codex"], root: wt, json: false }, s.env, deps);
    assert.doesNotMatch(titles(d.checks, "fail"), /not trusted in/);
    assert.match(titles(d.checks, "ok"), /\.codex\/hooks\.json: ah hook bound/);
  } finally {
    s.done();
  }
});

test("codex: in a linked worktree, --scope project says Codex does not read that file, and doctor flags a stale worktree copy", { skip }, () => {
  const s = sandbox();
  try {
    const wt = withWorktree(s);
    const r = init(opts(wt, { scope: "project" }), s.env);
    assert.ok(r.ok, r.error);
    const c = r.changes.find((x) => x.agent === "codex");
    assert.equal(c?.file, join(wt, ".codex", "hooks.json"));
    assert.match(c?.detail ?? "", /in a linked worktree Codex reads .* in the main checkout, not this file/);
    const d = doctor({ agents: ["codex"], root: wt, json: false }, s.env, deps);
    assert.match(titles(d.checks, "info"), /\.codex\/hooks\.json has an ah entry, but in a linked worktree Codex reads \.codex\/hooks\.json from the main checkout/);
    assert.match(titles(d.checks, "fail"), /no ah PreToolUse hook/);
    // --remove cleans the worktree copy too.
    const rm = init(opts(wt, { remove: true }), s.env);
    assert.ok(rm.ok, rm.error);
    assert.ok(!existsSync(join(wt, ".codex", "hooks.json")));
  } finally {
    s.done();
  }
});

test("wsl: a checkout under /mnt/<drive> or \\\\wsl$ is shared with agents that cannot run its paths", () => {
  const m = (os: Machine["os"], root: string): Machine => ({ root, home: "/home/dev", os, env: {}, nodePath: "/usr/bin/node", guardPath: "/g/dist/guard.mjs" });
  assert.equal(sharedAcrossWsl(m("linux", "/mnt/c/dev/proj"), true), "windows");
  assert.equal(sharedAcrossWsl(m("linux", "/mnt/d"), true), "windows");
  assert.equal(sharedAcrossWsl(m("linux", "/mnt/cd/proj"), true), null);
  assert.equal(sharedAcrossWsl(m("linux", "/home/dev/proj"), true), null);
  assert.equal(sharedAcrossWsl(m("linux", "/mnt/c/dev/proj"), false), null, "plain Linux with a /mnt/c mount");
  assert.equal(sharedAcrossWsl(m("win32", "\\\\wsl$\\Ubuntu\\home\\dev\\proj")), "wsl");
  assert.equal(sharedAcrossWsl(m("win32", "\\\\wsl.localhost\\Ubuntu\\home\\dev\\proj")), "wsl");
  assert.equal(sharedAcrossWsl(m("win32", "C:\\Users\\dev\\proj")), null);
});

test("claude: registry policy wins over the managed files whole, and allowManagedHooksOnly from any source holds", () => {
  const env = {};
  const hklm = { scope: "managed", path: "HKLM\\SOFTWARE\\Policies\\ClaudeCode\\Settings", tier: 0 };
  const file = { scope: "managed", path: "C:\\Program Files\\ClaudeCode\\managed-settings.json", tier: 1 };
  const hkcu = { scope: "managed", path: "HKCU\\SOFTWARE\\Policies\\ClaudeCode\\Settings", tier: 2 };
  // HKLM exists, so the managed file is not applied.
  assert.equal(titles(claudeSwitches([{ ...hklm, value: { model: "x" } }, { ...file, value: { disableAllHooks: true } }], false, env), "fail"), "");
  assert.match(titles(claudeSwitches([{ ...hklm, value: { disableAllHooks: true } }, { ...file, value: {} }], false, env), "fail"), /disableAllHooks is true in HKLM/);
  // Without HKLM or a file, HKCU is the policy.
  assert.match(titles(claudeSwitches([{ ...hkcu, value: { disableAllHooks: true } }], false, env), "fail"), /in HKCU/);
  // A lock holds wherever it is set.
  assert.match(titles(claudeSwitches([{ ...hklm, value: {} }, { ...hkcu, value: { allowManagedHooksOnly: true } }], false, env), "fail"), /allowManagedHooksOnly is set in HKCU/);
  assert.equal(titles(claudeSwitches([{ ...hklm, value: { allowManagedHooksOnly: true } }], true, env), "fail"), "", "ah deployed as a managed hook");

  const out = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\ClaudeCode\r\n    Settings    REG_SZ    {\"disableAllHooks\": true}\r\n\r\n";
  assert.equal(parseRegSettings(out), '{"disableAllHooks": true}');
  assert.equal(parseRegSettings("ERROR: The system was unable to find the specified registry key or value.\r\n"), null);
});

test("claude: doctor warns when it cannot read the registry policy", { skip }, () => {
  const s = sandbox();
  try {
    const checks = doctorClaude(machine(s, s.root), { found: false, stdout: "" }, null);
    assert.match(titles(checks, "warn"), /could not ask reg\.exe for Claude Code's registry policy/);
  } finally {
    s.done();
  }
});

test("claude: workspace trust is looked up the way Claude Code keys it", { skip }, () => {
  const s = sandbox();
  try {
    // Keyed the way Claude Code writes them: forward slashes on Windows.
    const key = (p: string) => (process.platform === "win32" ? p.replace(/\\/g, "/") : p);
    const trust = (keys: string[]) => writeFileSync(join(s.home, ".claude.json"), JSON.stringify({ projects: Object.fromEntries(keys.map((k) => [key(k), { hasTrustDialogAccepted: true }])) }));
    const trustWarn = (m: Machine) => /workspace trust is not accepted/.test(titles(doctorClaude(m, { found: false, stdout: "" }, []), "warn"));

    // Windows keys use forward slashes.
    trust(["C:/Users/dev/proj"]);
    assert.equal(trustWarn({ ...machine(s, s.root), os: "win32", root: "C:\\Users\\dev\\proj" }), false);

    // A worktree is trusted through its main checkout.
    const wt = withWorktree(s);
    trust([s.root]);
    assert.equal(trustWarn(machine(s, wt)), false);

    // Trust on a folder above the repository does not reach into it.
    trust([s.base]);
    assert.equal(trustWarn(machine(s, s.root)), true);
    // Inside the repository it does.
    mkdirSync(join(s.root, "sub"));
    trust([s.root]);
    assert.equal(trustWarn(machine(s, join(s.root, "sub"))), false);
  } finally {
    s.done();
  }
});

test("claude: on Windows, doctor says local scope does not cover sessions started in a subfolder", { skip }, () => {
  const s = sandbox();
  try {
    const m = { ...machine(s, s.root), os: "win32" as const };
    mkdirSync(join(s.root, ".claude"));
    writeFileSync(join(s.root, ".claude", "settings.local.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: CLAUDE_MATCHER, hooks: [{ type: "command", command: process.execPath, args: [guard, "--agent", "claude"], timeout: 5 }] }] } }));
    const checks = doctorClaude(m, { found: false, stdout: "" }, []);
    const info = checks.find((c) => c.level === "info" && /settings\.local\.json is read only by sessions started in/.test(c.title));
    assert.ok(info, titles(checks, "info"));
    assert.match(info.fix ?? "", /--scope user/);
  } finally {
    s.done();
  }
});

test("claude: a ${CLAUDE_PROJECT_DIR} guard path is checked after substitution", { skip }, () => {
  const s = sandbox();
  try {
    mkdirSync(join(s.root, "tools", "dist"), { recursive: true });
    writeFileSync(join(s.root, "tools", "dist", "guard.mjs"), readFileSync(guard));
    mkdirSync(join(s.root, ".claude"));
    writeFileSync(join(s.root, ".claude", "settings.local.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: CLAUDE_MATCHER, hooks: [{ type: "command", command: process.execPath, args: ["${CLAUDE_PROJECT_DIR}/tools/dist/guard.mjs", "--agent", "claude"], timeout: 5 }] }] } }));
    const checks = doctorClaude(machine(s, s.root), { found: false, stdout: "" }, []);
    assert.doesNotMatch(titles(checks, "fail"), /does not exist/);
    assert.match(titles(checks, "ok"), /canary through/);
  } finally {
    s.done();
  }
});

test("init --remove for one agent keeps the AGENTS.md block the other still reads", { skip }, () => {
  const s = sandbox();
  try {
    git(s.root, s.env, "init", "-q");
    assert.ok(init(opts(s.root, { agents: ["claude", "codex"] }), s.env).ok);
    const block = /<!-- ah:begin/;
    assert.match(readFileSync(join(s.root, "AGENTS.md"), "utf8"), block);
    const r = init(opts(s.root, { agents: ["claude"], remove: true }), s.env);
    assert.ok(r.ok, r.error);
    assert.match(readFileSync(join(s.root, "AGENTS.md"), "utf8"), block, "Codex is still wired and reads AGENTS.md");
    assert.ok(init(opts(s.root, { agents: ["codex"], remove: true }), s.env).ok);
    assert.ok(!existsSync(join(s.root, "AGENTS.md")) || !block.test(readFileSync(join(s.root, "AGENTS.md"), "utf8")));
  } finally {
    s.done();
  }
});

test("claude: a CLAUDE.md above the project is named when the project's instructions are missing", { skip }, () => {
  const s = sandbox();
  try {
    writeFileSync(join(s.base, "CLAUDE.md"), "# above\n");
    writeFileSync(join(s.root, "AGENTS.md"), "# agents\n");
    const checks = doctorClaude(machine(s, s.root), { found: false, stdout: "" }, []);
    assert.match(titles(checks, "warn"), /CLAUDE\.md: the guard's instructions are missing \(.*CLAUDE\.md is above the project/);
    assert.doesNotMatch(titles(checks, "ok"), /AGENTS\.md carries/);
  } finally {
    s.done();
  }
});
