/**
 * `ah init` and `ah doctor` end to end in scratch projects with a scratch
 * home: what gets written, what is left alone, what is refused, and what
 * doctor reports. Uses the built guard (npm run build) for the self-test and
 * the canaries; the agent CLIs are faked, so no agent needs to be installed.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { doctor, type DoctorDeps } from "../src/cli/doctor.ts";
import { init, INIT_HELP, parseInitArgs, type InitOptions } from "../src/cli/init.ts";
import { AH_INIT_VALUED_OPTIONS } from "../src/wiring/init-options.ts";
import { AGENTS_BLOCK_BODY } from "../src/wiring/agents-md.ts";
import { BLOCK_BEGIN, BLOCK_END } from "../src/wiring/text-block.ts";

const here = dirname(fileURLToPath(import.meta.url));
const guard = resolve(here, "../dist/guard.mjs");
const built = existsSync(guard);
const skip = !built && "run npm run build first";
const win = process.platform === "win32";

interface Sandbox {
  root: string;
  home: string;
  env: NodeJS.ProcessEnv;
  done: () => void;
}

function sandbox(files: Record<string, string> = {}, gitInit = true): Sandbox {
  const base = mkdtempSync(join(tmpdir(), "ah-init-"));
  const root = join(base, "proj");
  const home = join(base, "home");
  mkdirSync(root, { recursive: true });
  mkdirSync(home, { recursive: true });
  if (gitInit) spawnSync("git", ["init", "-q"], { cwd: root });
  for (const [p, text] of Object.entries(files)) {
    const full = p.startsWith("~/") ? join(home, p.slice(2)) : join(root, p);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home, CODEX_HOME: join(home, ".codex") };
  delete env.CLAUDE_CONFIG_DIR;
  delete env.CLAUDE_PROJECT_DIR;
  delete env.AH_PROJECT_ROOT;
  return { root, home, env, done: () => rmSync(base, { recursive: true, force: true }) };
}

function opts(s: Sandbox, more: Partial<InitOptions> = {}): InitOptions {
  return { agents: ["claude", "codex"], root: s.root, scope: "local", remove: false, dryRun: false, failClosed: false, noLog: false, instructions: true, json: false, guard, ...more };
}

const read = (p: string) => readFileSync(p, "utf8");
const json = (p: string) => JSON.parse(read(p)) as Record<string, any>;

const fakeDeps = (features = "hooks                                    stable             true\n"): DoctorDeps => ({
  probe: (name) => ({ found: true, stdout: name === "claude" ? "2.1.302 (Claude Code)\n" : "codex-cli 0.163.0\n" }),
  featuresList: () => features,
});

test("init wires both agents, adds the AGENTS.md block, and a second run changes nothing", { skip }, () => {
  const s = sandbox({ "AGENTS.md": "# Project\n\nUse pnpm.\n" });
  try {
    const r = init(opts(s), s.env);
    assert.ok(r.ok, r.error);
    const claude = json(join(s.root, ".claude", "settings.local.json"));
    const e = claude.hooks.PreToolUse[0].hooks[0];
    assert.equal(e.command, process.execPath);
    assert.deepEqual(e.args, [guard, "--agent", "claude"]);
    const codex = json(join(s.root, ".codex", "hooks.json"));
    assert.deepEqual(Object.keys(codex), ["hooks"], "Codex rejects any other top-level key");
    assert.match(codex.hooks.PreToolUse[0].hooks[0].command, /guard\.mjs --agent codex$/);
    assert.equal(Number.isInteger(codex.hooks.PreToolUse[0].hooks[0].timeout), true);
    const agents = read(join(s.root, "AGENTS.md"));
    assert.ok(agents.startsWith("# Project\n\nUse pnpm.\n\n" + BLOCK_BEGIN));
    assert.ok(existsSync(join(s.root, ".harness")));
    const exclude = read(join(s.root, ".git", "info", "exclude"));
    assert.match(exclude, /^\/\.claude\/settings\.local\.json$/m);
    assert.match(exclude, /^\/\.codex\/hooks\.json$/m);

    const before = [".claude/settings.local.json", ".codex/hooks.json", "AGENTS.md"].map((p) => statSync(join(s.root, p)).mtimeMs);
    const again = init(opts(s), s.env);
    assert.ok(again.ok);
    assert.ok(again.changes.every((c) => c.action === "unchanged" || c.agent === "git"), JSON.stringify(again.changes));
    const after = [".claude/settings.local.json", ".codex/hooks.json", "AGENTS.md"].map((p) => statSync(join(s.root, p)).mtimeMs);
    assert.deepEqual(after, before, "nothing rewritten");
    assert.equal(read(join(s.root, ".git", "info", "exclude")), exclude, "exclude lines are not repeated");

    assert.ok(init(opts(s, { remove: true }), s.env).ok);
    assert.equal(existsSync(join(s.root, ".claude", "settings.local.json")), false, "a file that held only ah's hook is removed");
    assert.equal(existsSync(join(s.root, ".codex", "hooks.json")), false);
    assert.equal(read(join(s.root, "AGENTS.md")), "# Project\n\nUse pnpm.\n");
    assert.doesNotMatch(read(join(s.root, ".git", "info", "exclude")), /ah init|settings\.local|hooks\.json/);
  } finally {
    s.done();
  }
});

test("init leaves the user's settings, hooks and order alone, and remove restores the files", { skip }, () => {
  const settings = '{\n    "permissions": {\n        "allow": ["Bash(ls)"]\n    },\n    "hooks": {\n        "PostToolUse": [{"matcher": "Write", "hooks": [{"type": "command", "command": "npx prettier --write"}]}]\n    }\n}\n';
  const codex = '{\n  "description": "team hooks",\n  "hooks": {\n    "PreToolUse": [\n      {\n        "matcher": "^Bash$",\n        "hooks": [\n          {\n            "type": "command",\n            "command": "python3 check.py"\n          }\n        ]\n      }\n    ]\n  }\n}\n';
  const agents = "# Project\r\n\r\nWindows line endings.\r\n";
  const s = sandbox({ ".claude/settings.local.json": settings, ".codex/hooks.json": codex, "AGENTS.md": agents });
  try {
    assert.ok(init(opts(s), s.env).ok);
    const c = json(join(s.root, ".claude", "settings.local.json"));
    assert.deepEqual(Object.keys(c), ["permissions", "hooks"]);
    assert.deepEqual(Object.keys(c.hooks), ["PostToolUse", "PreToolUse"]);
    assert.ok(read(join(s.root, ".claude", "settings.local.json")).includes('\n    "permissions"'), "indentation kept");
    const x = json(join(s.root, ".codex", "hooks.json"));
    assert.equal(x.hooks.PreToolUse[0].hooks[0].command, "python3 check.py", "the user's group keeps index 0, so Codex keeps trusting it");
    assert.match(x.hooks.PreToolUse[1].hooks[0].command, /guard\.mjs/);
    assert.ok(!/(?<!\r)\n/.test(read(join(s.root, "AGENTS.md"))), "CRLF kept");

    const r = init(opts(s, { remove: true }), s.env);
    assert.ok(r.ok, r.error);
    assert.equal(read(join(s.root, ".claude", "settings.local.json")), settings);
    assert.equal(read(join(s.root, ".codex", "hooks.json")), codex);
    assert.equal(read(join(s.root, "AGENTS.md")), agents);
  } finally {
    s.done();
  }
});

test("a file ah cannot read back exactly stops init before anything is written", { skip }, () => {
  const commented = '{\n  // mine\n  "model": "x",\n}\n';
  const s = sandbox({ ".claude/settings.local.json": commented, "AGENTS.md": "# P\n" });
  try {
    const r = init(opts(s), s.env);
    assert.equal(r.ok, false);
    assert.ok(r.changes.some((c) => c.action === "error" && /not plain JSON/.test(c.detail)));
    assert.equal(read(join(s.root, ".claude", "settings.local.json")), commented);
    assert.equal(existsSync(join(s.root, ".codex", "hooks.json")), false);
    assert.equal(read(join(s.root, "AGENTS.md")), "# P\n");
  } finally {
    s.done();
  }
});

test("init refuses to wire a guard that does not refuse rm -rf /", { skip }, () => {
  const s = sandbox();
  try {
    const fake = join(s.root, "dist", "guard.mjs");
    mkdirSync(dirname(fake), { recursive: true });
    writeFileSync(fake, "process.stdin.resume(); process.stdin.on('end', () => process.exit(0));\n");
    const r = init(opts(s, { guard: fake }), s.env);
    assert.equal(r.ok, false);
    assert.match(r.error ?? "", /did not refuse\/allow "rm -rf \/"/);
    assert.equal(existsSync(join(s.root, ".claude")), false);
  } finally {
    s.done();
  }
});

test("a hand-wired entry from the README is adopted, with its options", { skip }, () => {
  const hand = { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "/old/node /old/node_modules/@9thlevelsoftware/aegis/dist/guard.mjs --agent codex --ask-fallback warn", timeout: 10 }] }] } };
  const s = sandbox({ ".codex/hooks.json": JSON.stringify(hand, null, 2) });
  try {
    const r = init(opts(s, { agents: ["codex"] }), s.env);
    assert.ok(r.ok);
    const x = json(join(s.root, ".codex", "hooks.json"));
    assert.equal(x.hooks.PreToolUse.length, 1);
    const e = x.hooks.PreToolUse[0].hooks[0];
    assert.match(e.command, /--agent codex --ask-fallback warn$/);
    assert.equal(e.timeout, 10);
    assert.equal(x.hooks.PreToolUse[0].matcher, "^(Bash|Edit|Write|Agent|mcp__.*)$");
  } finally {
    s.done();
  }
});

test("CLAUDE.md gets the block when Claude Code would not read AGENTS.md; an @AGENTS.md import is left alone", { skip }, () => {
  const s = sandbox({ "CLAUDE.md": "# Claude notes\n" });
  try {
    assert.ok(init(opts(s), s.env).ok);
    assert.ok(read(join(s.root, "CLAUDE.md")).includes(BLOCK_BEGIN));
    assert.ok(read(join(s.root, "AGENTS.md")).startsWith(BLOCK_BEGIN), "AGENTS.md is created for Codex");
    assert.ok(init(opts(s, { remove: true }), s.env).ok);
    assert.equal(read(join(s.root, "CLAUDE.md")), "# Claude notes\n");
    assert.equal(existsSync(join(s.root, "AGENTS.md")), false, "a file that held only the block is removed");
  } finally {
    s.done();
  }
  const t = sandbox({ "CLAUDE.md": "# Notes\n\n@AGENTS.md\n" });
  try {
    assert.ok(init(opts(t), t.env).ok);
    assert.equal(read(join(t.root, "CLAUDE.md")), "# Notes\n\n@AGENTS.md\n");
  } finally {
    t.done();
  }
});

test("Codex: AGENTS.override.md gets the block, and a long AGENTS.md gets it at the top", { skip }, () => {
  const long = "# Big\n\n" + "x".repeat(40_000) + "\n";
  const s = sandbox({ "AGENTS.md": long, "AGENTS.override.md": "# Override\n" });
  try {
    const r = init(opts(s, { agents: ["codex"] }), s.env);
    assert.ok(r.ok);
    assert.ok(read(join(s.root, "AGENTS.md")).startsWith(BLOCK_BEGIN), "inside Codex's first 32 KiB");
    assert.ok(read(join(s.root, "AGENTS.md")).endsWith(long));
    assert.ok(read(join(s.root, "AGENTS.override.md")).includes(AGENTS_BLOCK_BODY[0]));
    assert.ok(r.changes.some((c) => /first 32 KiB/.test(c.detail)));
  } finally {
    s.done();
  }
});

test("--scope user writes the home files and leaves git alone; --dry-run writes nothing", { skip }, () => {
  const s = sandbox();
  try {
    const dry = init(opts(s, { scope: "user", dryRun: true }), s.env);
    assert.ok(dry.ok);
    assert.equal(existsSync(join(s.home, ".claude")), false);
    assert.ok(init(opts(s, { scope: "user" }), s.env).ok);
    assert.ok(existsSync(join(s.home, ".claude", "settings.json")));
    assert.ok(existsSync(join(s.home, ".codex", "hooks.json")));
    assert.equal(existsSync(join(s.root, ".claude")), false);
    const exclude = join(s.root, ".git", "info", "exclude");
    assert.ok(!existsSync(exclude) || !read(exclude).includes("ah init"));
  } finally {
    s.done();
  }
});

test("the exclude lines and the tracked check hold when ah and git spell the project path differently", { skip: skip || (win && "symlinks need elevation on Windows; the runner's 8.3 temp path covers it there") }, () => {
  // git reports the resolved path; a symlinked parent stands in for a Windows 8.3 short name.
  const s = sandbox();
  try {
    const alias = join(dirname(s.root), "alias");
    symlinkSync(s.root, alias, "dir");
    const t: Sandbox = { ...s, root: alias };
    assert.ok(init(opts(t), t.env).ok);
    const exclude = read(join(s.root, ".git", "info", "exclude"));
    assert.match(exclude, /^\/\.claude\/settings\.local\.json$/m);
    assert.match(exclude, /^\/\.codex\/hooks\.json$/m);
    assert.ok(init(opts(t, { remove: true }), t.env).ok);
    assert.doesNotMatch(read(join(s.root, ".git", "info", "exclude")), /ah init/);
    writeFileSync(join(s.root, "AGENTS.md"), "# P\n");
    mkdirSync(join(s.root, ".claude"), { recursive: true });
    writeFileSync(join(s.root, ".claude", "settings.local.json"), "{}\n");
    spawnSync("git", ["add", ".claude/settings.local.json"], { cwd: s.root });
    const r = init(opts(t, { agents: ["claude"] }), t.env);
    assert.ok(r.changes.some((c) => c.agent === "git" && c.action === "skipped"), JSON.stringify(r.changes));
  } finally {
    s.done();
  }
});

test("a tracked settings.local.json is flagged, not excluded", { skip }, () => {
  const s = sandbox({ ".claude/settings.local.json": "{}\n" });
  try {
    spawnSync("git", ["add", ".claude/settings.local.json"], { cwd: s.root });
    const r = init(opts(s, { agents: ["claude"] }), s.env);
    assert.ok(r.ok);
    assert.ok(r.changes.some((c) => c.agent === "git" && c.action === "skipped" && /tracked by git/.test(c.detail)));
  } finally {
    s.done();
  }
});

test("doctor: a fresh init passes for Claude Code and names what Codex still needs", { skip }, () => {
  const s = sandbox();
  try {
    assert.ok(init(opts(s), s.env).ok);
    const r = doctor({ agents: ["claude", "codex"], root: s.root, json: false }, s.env, fakeDeps());
    const claude = r.checks.filter((c) => c.agent === "claude");
    assert.ok(!claude.some((c) => c.level === "fail"), JSON.stringify(claude, null, 1));
    assert.ok(claude.some((c) => c.level === "ok" && /canary .*rm -rf \/ refused, an edit to \.ruff\.toml refused, ls allowed/.test(c.title)));
    const codex = r.checks.filter((c) => c.agent === "codex");
    assert.ok(codex.some((c) => c.level === "fail" && /not trusted .* yet/.test(c.title)));
    assert.ok(codex.some((c) => c.level === "fail" && /has not trusted the ah hook/.test(c.title)));
    assert.ok(codex.some((c) => c.level === "ok" && /canary .*rm -rf \/ refused/.test(c.title)), JSON.stringify(codex, null, 1));
    assert.equal(r.ok, false);

    // What Codex writes once the user trusts the project and the hook in /hooks.
    const key = `${join(s.root, ".codex", "hooks.json")}:pre_tool_use:0:0`;
    mkdirSync(join(s.home, ".codex"), { recursive: true });
    writeFileSync(join(s.home, ".codex", "config.toml"), `[projects.${JSON.stringify(s.root)}]\ntrust_level = "trusted"\n\n[hooks.state.${JSON.stringify(key)}]\ntrusted_hash = "sha256:${"0".repeat(64)}"\n`);
    const ok = doctor({ agents: ["claude", "codex"], root: s.root, json: false }, s.env, fakeDeps());
    assert.ok(ok.ok, JSON.stringify(ok.checks.filter((c) => c.level === "fail"), null, 1));
  } finally {
    s.done();
  }
});

test("doctor catches the switches and mistakes that leave calls unguarded", { skip }, () => {
  const s = sandbox();
  try {
    assert.ok(init(opts(s), s.env).ok);
    const titles = (deps = fakeDeps()) => doctor({ agents: ["claude", "codex"], root: s.root, json: false }, s.env, deps).checks.filter((c) => c.level === "fail").map((c) => c.title).join("\n");

    assert.match(titles(fakeDeps("hooks   stable   false\n")), /Codex hooks are off/);

    mkdirSync(join(s.home, ".claude"), { recursive: true });
    writeFileSync(join(s.home, ".claude", "settings.json"), '{"disableAllHooks": true}\n');
    assert.match(titles(), /disableAllHooks is true/);
    writeFileSync(join(s.home, ".claude", "settings.json"), '{"hooks": {"PreToolUse": [{"matcher": ["Bash"], "hooks": []}]}}\n');
    assert.match(titles(), /a PreToolUse matcher that is not a string .*Claude Code then applies nothing from this file/);
    rmSync(join(s.home, ".claude", "settings.json"));

    const local = join(s.root, ".claude", "settings.local.json");
    const v = json(local);
    v.hooks.PreToolUse[0].matcher = "Bash";
    v.hooks.PreToolUse[0].hooks[0].command = win ? "C:\\nowhere\\node.exe" : "/nowhere/node";
    writeFileSync(local, JSON.stringify(v));
    const t = titles();
    assert.match(t, /skips PowerShell, Monitor, Edit, Write, NotebookEdit, Read/);
    assert.match(t, /node(\.exe)? does not exist/);
    assert.match(t, /canary through \.claude/);

    const hooks = join(s.root, ".codex", "hooks.json");
    const h = json(hooks);
    writeFileSync(hooks, JSON.stringify({ ...h, x_ah: true }));
    assert.match(titles(), /top-level key "x_ah" .*Codex rejects the whole file/);
  } finally {
    s.done();
  }
});

test("doctor's canary catches a guard that lets everything through", { skip }, () => {
  const s = sandbox();
  try {
    assert.ok(init(opts(s, { agents: ["claude"] }), s.env).ok);
    const local = join(s.root, ".claude", "settings.local.json");
    const fake = join(s.root, "fake", "dist", "guard.mjs");
    mkdirSync(dirname(fake), { recursive: true });
    writeFileSync(fake, "process.stdin.resume(); process.stdin.on('end', () => process.exit(0));\n");
    const v = json(local);
    v.hooks.PreToolUse[0].hooks[0].args[0] = fake;
    writeFileSync(local, JSON.stringify(v));
    const r = doctor({ agents: ["claude"], root: s.root, json: false }, s.env, fakeDeps());
    assert.ok(r.checks.some((c) => c.level === "fail" && /rm -rf \/ should be refused, but it was allowed/.test(c.title)), JSON.stringify(r.checks, null, 1));
  } finally {
    s.done();
  }
});

test("init options parse, and bad ones are rejected", () => {
  const o = parseInitArgs(["--agents", "codex", "--scope=user", "--fail-closed", "--ask-fallback", "warn"]);
  assert.ok(typeof o !== "string");
  if (typeof o !== "string") {
    assert.deepEqual(o.agents, ["codex"]);
    assert.equal(o.scope, "user");
    assert.equal(o.failClosed, true);
    assert.equal(o.askFallback, "warn");
  }
  assert.equal(typeof parseInitArgs(["--agents", "cursor"]), "string");
  assert.equal(typeof parseInitArgs(["--scope", "global"]), "string");
  assert.equal(typeof parseInitArgs(["--bogus"]), "string");
});

test("the guard's list of ah init options that take a value matches ah init's parser", () => {
  // shell.hook-tamper reads an agent's `ah init` with this list; a drift would let a value hide a flag.
  const options = [...new Set(INIT_HELP.match(/--[a-z][a-z-]*/g) ?? [])];
  assert.ok(options.length >= 10, options.join(" "));
  for (const opt of options) {
    const r = parseInitArgs([opt, "--remove"]);
    const takesValue = typeof r === "string" || !r.remove;
    assert.equal(takesValue, AH_INIT_VALUED_OPTIONS.has(opt), opt);
  }
});
