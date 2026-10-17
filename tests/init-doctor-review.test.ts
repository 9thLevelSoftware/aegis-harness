/**
 * The cases an adversarial review of `ah init` and `ah doctor` found:
 * doctor saying "No failures" while an agent would skip the guard, and init
 * damaging or half-writing files it does not own. Each test is one of them.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { claudeSwitches, doctor, type DoctorDeps } from "../src/cli/doctor.ts";
import { init, type InitOptions } from "../src/cli/init.ts";
import type { CodexListedHook, CodexListing } from "../src/wiring/codex.ts";

const here = dirname(fileURLToPath(import.meta.url));
const guard = resolve(here, "../dist/guard.mjs");
const skip = !existsSync(guard) && "run npm run build first";
const posixOnly = (skip || (process.platform === "win32" && "POSIX file modes and links")) as string | false;

interface Sandbox {
  root: string;
  home: string;
  env: NodeJS.ProcessEnv;
  done: () => void;
}

function sandbox(files: Record<string, string> = {}): Sandbox {
  const base = mkdtempSync(join(tmpdir(), "ah-review-"));
  const root = join(base, "proj");
  const home = join(base, "home");
  mkdirSync(root, { recursive: true });
  mkdirSync(home, { recursive: true });
  spawnSync("git", ["init", "-q"], { cwd: root });
  for (const [p, text] of Object.entries(files)) {
    const full = p.startsWith("~/") ? join(home, p.slice(2)) : join(root, p);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home, CODEX_HOME: join(home, ".codex") };
  for (const k of ["CLAUDE_CONFIG_DIR", "CLAUDE_PROJECT_DIR", "AH_PROJECT_ROOT", "CLAUDE_CODE_SAFE_MODE"]) delete env[k];
  return { root, home, env, done: () => rmSync(base, { recursive: true, force: true }) };
}

const opts = (s: Sandbox, more: Partial<InitOptions> = {}): InitOptions => ({ agents: ["claude", "codex"], root: s.root, scope: "local", remove: false, dryRun: false, failClosed: false, noLog: false, instructions: true, json: false, guard, ...more });
const read = (p: string) => readFileSync(p, "utf8");
const json = (p: string) => JSON.parse(read(p)) as Record<string, any>;

const deps = (listing: CodexListing | null = null): DoctorDeps => ({
  probe: (name) => ({ found: true, stdout: name === "claude" ? "2.1.302 (Claude Code)\n" : "codex-cli 0.163.0\n" }),
  featuresList: () => "hooks                                    stable             true\n",
  codexListing: () => listing,
});
const run = (s: Sandbox, agents: ("claude" | "codex")[], d = deps()) => doctor({ agents, root: s.root, json: false }, s.env, d);
const titles = (r: ReturnType<typeof doctor>, level: string) => r.checks.filter((c) => c.level === level).map((c) => c.title).join("\n");

function trustProject(s: Sandbox): void {
  mkdirSync(join(s.home, ".codex"), { recursive: true });
  writeFileSync(join(s.home, ".codex", "config.toml"), `[projects.${JSON.stringify(s.root)}]\ntrust_level = "trusted"\n`);
}

/** What `codex app-server` hooks/list reports for ah's entry at .codex/hooks.json group 0. */
function listed(s: Sandbox, more: Partial<CodexListedHook> = {}): CodexListedHook {
  const file = join(s.root, ".codex", "hooks.json");
  const entry = json(file).hooks.PreToolUse[0].hooks[0];
  return { key: `${file}:pre_tool_use:0:0`, eventName: "preToolUse", handlerType: "command", command: entry.command, matcher: "Bash|Edit|Write|Agent", timeoutSec: 5, sourcePath: file, source: "project", enabled: true, isManaged: false, trustStatus: "trusted", ...more };
}

// --- Claude Code ------------------------------------------------------------

test("claude: managed drop-ins merge after managed-settings.json, later files winning", () => {
  const base = { scope: "managed", path: "/etc/claude-code/managed-settings.json", value: { disableAllHooks: false } };
  const dropIn = { scope: "managed", path: "/etc/claude-code/managed-settings.d/50-lockdown.json", value: { disableAllHooks: true } };
  assert.match(claudeSwitches([base, dropIn], false, {}).map((c) => c.title).join(), /disableAllHooks is true in .*50-lockdown\.json/);
  assert.equal(claudeSwitches([dropIn, base].reverse(), false, {}).length, 1);
  assert.equal(claudeSwitches([base, { scope: "user", path: "~/.claude/settings.json", value: { disableAllHooks: true } }], false, {}).length, 0, "the policy's false wins over the user's true");
  assert.equal(claudeSwitches([{ scope: "local", path: "l", value: { disableAllHooks: false } }, { scope: "user", path: "u", value: { disableAllHooks: true } }], false, {}).length, 0, "local is read before user");
  const strict = { scope: "managed", path: "/etc/claude-code/managed-settings.json", value: { strictPluginOnlyCustomization: ["hooks"] } };
  assert.match(claudeSwitches([strict], false, {})[0].title, /strictPluginOnlyCustomization covers hooks/);
  assert.equal(claudeSwitches([strict], true, {}).length, 0, "a managed ah hook still runs");
  assert.equal(claudeSwitches([{ ...strict, value: { strictPluginOnlyCustomization: ["skills"] } }], false, {}).length, 0);
  assert.match(claudeSwitches([], false, { CLAUDE_CODE_SAFE_MODE: "1" })[0].title, /CLAUDE_CODE_SAFE_MODE/);
});

test("claude: an invalid PermissionRequest entry, or a typo in the user's own PreToolUse hook, fails doctor and stops init", { skip }, () => {
  const s = sandbox();
  try {
    assert.ok(init(opts(s, { agents: ["claude"] }), s.env).ok);
    const local = join(s.root, ".claude", "settings.local.json");
    const v = json(local);
    v.hooks.PermissionRequest = [{ hooks: [{ type: "command", command: "/usr/local/bin/notify-me", timeout: "30" }] }];
    writeFileSync(local, JSON.stringify(v));
    assert.match(titles(run(s, ["claude"]), "fail"), /PermissionRequest.*applies nothing from this file/);
    delete v.hooks.PermissionRequest;
    v.hooks.PreToolUse.push({ matcher: "Write", hooks: [{ type: "command", command: "audit", async: "true" }] });
    writeFileSync(local, JSON.stringify(v));
    assert.match(titles(run(s, ["claude"]), "fail"), /async is not true or false under PreToolUse/);
    const before = read(local);
    const r = init(opts(s, { agents: ["claude"], noLog: true }), s.env);
    assert.equal(r.ok, false);
    assert.match(r.changes.map((c) => c.detail).join(), /Claude Code would load nothing from this file/);
    assert.equal(read(local), before, "nothing written");
  } finally {
    s.done();
  }
});

test("claude: an `if` on ah's entry is a failure, and a bare `node` is looked up on PATH", { skip }, () => {
  const s = sandbox();
  try {
    assert.ok(init(opts(s, { agents: ["claude"] }), s.env).ok);
    const local = join(s.root, ".claude", "settings.local.json");
    const v = json(local);
    v.hooks.PreToolUse[0].hooks[0].if = "Edit(src/**)";
    writeFileSync(local, JSON.stringify(v));
    assert.match(titles(run(s, ["claude"]), "fail"), /only runs when "Edit\(src\/\*\*\)" matches/);
    delete v.hooks.PreToolUse[0].hooks[0].if;
    v.hooks.PreToolUse[0].hooks[0].command = "node";
    writeFileSync(local, JSON.stringify(v));
    const r = run(s, ["claude"]);
    assert.doesNotMatch(titles(r, "fail"), /node/);
    assert.match(titles(r, "ok"), /canary/);
  } finally {
    s.done();
  }
});

test("doctor: a hook that runs another guard build is flagged, the same build is not", { skip }, () => {
  const s = sandbox();
  try {
    assert.ok(init(opts(s, { agents: ["claude"] }), s.env).ok);
    const local = join(s.root, ".claude", "settings.local.json");
    const copy = join(s.root, "vendor", "dist", "guard.mjs");
    mkdirSync(dirname(copy), { recursive: true });
    writeFileSync(copy, read(guard));
    const v = json(local);
    v.hooks.PreToolUse[0].hooks[0].args[0] = copy;
    writeFileSync(local, JSON.stringify(v));
    assert.doesNotMatch(titles(run(s, ["claude"]), "warn"), /rules added since/, "same version, different path");
    // An old build: no --version, otherwise the real guard.
    writeFileSync(copy, `if (!process.argv.includes("--version")) await import(${JSON.stringify(`file://${guard.replace(/\\/g, "/")}`)});\n`);
    assert.match(titles(run(s, ["claude"]), "warn"), /an older build that does not report its version/);
  } finally {
    s.done();
  }
});

// --- Codex ------------------------------------------------------------------

test("codex: Codex's own verdict decides trust: trusted, changed since, or not loaded here", { skip }, () => {
  const s = sandbox();
  try {
    assert.ok(init(opts(s, { agents: ["codex"] }), s.env).ok);
    trustProject(s);
    const live = (h: CodexListedHook[], warnings: string[] = []) => run(s, ["codex"], deps({ hooks: h, warnings, errors: [] }));
    assert.match(titles(live([listed(s)]), "ok"), /Codex trusts the ah hook/);
    assert.match(titles(live([listed(s, { trustStatus: "modified" })]), "fail"), /changed since you trusted it/);
    assert.match(titles(live([listed(s, { trustStatus: "untrusted" })]), "fail"), /has not trusted the ah hook yet/);
    assert.match(titles(live([listed(s, { enabled: false })]), "fail"), /disabled in Codex's \/hooks/);
    assert.match(titles(live([]), "fail"), /Codex does not load this ah entry/);
    assert.match(titles(live([listed(s)], [`failed to parse hooks config ${join(s.home, ".codex", "hooks.json")}: missing field \`server\` at line 22 column 9`]), "fail"), /Codex cannot load ~\/\.codex\/hooks\.json: missing field `server`/);
    // Without Codex to ask, a stored hash is not proof the entry is unchanged.
    const key = `${join(s.root, ".codex", "hooks.json")}:pre_tool_use:0:0`;
    writeFileSync(join(s.home, ".codex", "config.toml"), `[projects.${JSON.stringify(s.root)}]\ntrust_level = "trusted"\n\n[hooks.state.${JSON.stringify(key)}]\ntrusted_hash = "sha256:${"0".repeat(64)}"\n`);
    const fileOnly = run(s, ["codex"]);
    assert.match(titles(fileOnly, "warn"), /trust record .* cannot tell whether the entry changed/);
    assert.doesNotMatch(titles(fileOnly, "ok"), /trust/);
  } finally {
    s.done();
  }
});

test("codex: an ah hook Codex loads from a managed source counts, though no file ah reads has it", { skip }, () => {
  const s = sandbox();
  try {
    assert.ok(init(opts(s, { agents: ["codex"] }), s.env).ok);
    const cmd = json(join(s.root, ".codex", "hooks.json")).hooks.PreToolUse[0].hooks[0].command;
    rmSync(join(s.root, ".codex"), { recursive: true });
    const managed: CodexListedHook = { key: "/etc/codex/requirements.toml:pre_tool_use:0:0", eventName: "preToolUse", handlerType: "command", command: cmd, matcher: "Bash|Edit|Write|Agent", timeoutSec: 5, sourcePath: "/etc/codex/requirements.toml", source: "legacyManagedConfigFile", enabled: true, isManaged: true, trustStatus: "managed" };
    const r = run(s, ["codex"], deps({ hooks: [managed], warnings: [], errors: [] }));
    assert.doesNotMatch(titles(r, "fail"), /no ah PreToolUse hook/);
    assert.match(titles(r, "ok"), /runs the ah hook as a managed hook/);
    assert.match(titles(r, "ok"), /canary/);
  } finally {
    s.done();
  }
});

test("codex: files Codex rejects whole fail doctor even without Codex to ask", { skip }, () => {
  const s = sandbox();
  try {
    assert.ok(init(opts(s, { agents: ["codex"], noLog: true }), s.env).ok);
    const hooks = join(s.root, ".codex", "hooks.json");
    const good = read(hooks);
    const cases: [string, RegExp][] = [
      [`﻿${good}`, /byte-order mark/],
      [good.replace('{\n  "hooks"', '{\n  "description": "a",\n  "description": "b",\n  "hooks"'), /the key "description" twice/],
      [JSON.stringify({ hooks: { ...json(hooks).hooks, PostToolUse: [{ hooks: [{ type: "mcp_tool", sever: "audit", tool: "log" }] }] } }), /mcp_tool hook without server and tool/],
      [JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Write", hooks: [{ type: "command", command: "true", additionalContextLimit: "x" }] }, ...json(hooks).hooks.PreToolUse] } }), /additionalContextLimit/],
    ];
    for (const [text, want] of cases) {
      writeFileSync(hooks, text);
      assert.match(titles(run(s, ["codex"]), "fail"), want);
    }
    // Shapes Codex accepts: a null matcher, an event it does not know.
    writeFileSync(hooks, JSON.stringify({ hooks: { Notification: {}, PreToolUse: [{ matcher: null, hooks: [{ type: "command", command: "true" }] }, ...JSON.parse(good).hooks.PreToolUse] } }));
    assert.doesNotMatch(titles(run(s, ["codex"]), "fail"), /rejects the whole file/);
  } finally {
    s.done();
  }
});

test("codex: doctor from a subdirectory finds the repository root's hooks and instructions", { skip }, () => {
  const s = sandbox({ "AGENTS.md": "# P\n" });
  try {
    assert.ok(init(opts(s, { agents: ["codex"] }), s.env).ok);
    trustProject(s);
    const sub = join(s.root, "packages", "api");
    mkdirSync(sub, { recursive: true });
    const r = doctor({ agents: ["codex"], root: sub, json: false }, s.env, deps());
    assert.doesNotMatch(titles(r, "fail"), /no ah PreToolUse hook/);
    assert.match(titles(r, "ok"), /hooks\.json: ah hook bound/);
    assert.match(titles(r, "ok"), /AGENTS\.md carries the guard's instructions for Codex/);
  } finally {
    s.done();
  }
});

// --- ah init ----------------------------------------------------------------

test("init: one file it cannot write stops the run before any file changes", { skip: posixOnly }, () => {
  const s = sandbox({ "AGENTS.md": "# P\n" });
  try {
    mkdirSync(join(s.root, ".codex"));
    writeFileSync(join(s.root, ".codex", "hooks.json"), "{}\n");
    chmodSync(join(s.root, ".codex", "hooks.json"), 0o444);
    const r = init(opts(s), s.env);
    assert.equal(r.ok, false);
    assert.match(r.changes.map((c) => c.detail).join(), /hooks\.json is read-only/);
    assert.equal(existsSync(join(s.root, ".claude", "settings.local.json")), false);
    assert.equal(read(join(s.root, "AGENTS.md")), "# P\n");
    assert.equal(existsSync(join(s.root, ".git", "info", "exclude")) && /ah init/.test(read(join(s.root, ".git", "info", "exclude"))), false, "no exclude lines either");

    chmodSync(join(s.root, ".codex", "hooks.json"), 0o644);
    rmSync(join(s.root, "AGENTS.md"));
    symlinkSync(join(s.root, "docs", "AGENTS.md"), join(s.root, "AGENTS.md"));
    const dangling = init(opts(s), s.env);
    assert.equal(dangling.ok, false);
    assert.match(dangling.changes.map((c) => c.detail).join(), /symlink to a file that does not exist/);
    assert.equal(read(join(s.root, ".codex", "hooks.json")), "{}\n");
  } finally {
    s.done();
  }
});

test("init: a file with a duplicate key is refused instead of silently merged", { skip }, () => {
  const s = sandbox({ ".claude/settings.local.json": '{"model": "a", "model": "b"}\n' });
  try {
    const r = init(opts(s, { agents: ["claude"] }), s.env);
    assert.equal(r.ok, false);
    assert.match(r.changes.map((c) => c.detail).join(), /the key "model" twice/);
  } finally {
    s.done();
  }
});

test("init --remove keeps a file git tracks and a dotfile link, writing {} instead of deleting", { skip: posixOnly }, () => {
  const s = sandbox({ ".codex/hooks.json": "{}\n", "~/dotfiles/codex-hooks.json": "{}\n" });
  try {
    spawnSync("git", ["add", ".codex/hooks.json"], { cwd: s.root });
    mkdirSync(join(s.home, ".codex"), { recursive: true });
    symlinkSync(join(s.home, "dotfiles", "codex-hooks.json"), join(s.home, ".codex", "hooks.json"));
    assert.ok(init(opts(s, { agents: ["codex"], scope: "project", instructions: false }), s.env).ok);
    assert.ok(init(opts(s, { agents: ["codex"], scope: "user", instructions: false }), s.env).ok);
    assert.ok(init(opts(s, { agents: ["codex"], remove: true, instructions: false }), s.env).ok);
    assert.equal(read(join(s.root, ".codex", "hooks.json")), "{}\n", "tracked placeholder back as it was");
    assert.equal(read(join(s.home, "dotfiles", "codex-hooks.json")).trim(), "{}", "Codex cannot parse an empty hooks.json");
  } finally {
    s.done();
  }
});

test("init: Codex's file loses a byte-order mark; --scope project and wrapped guard commands are called out", { skip }, () => {
  const wrapped = { matcher: "Bash", hooks: [{ type: "command", command: `/usr/bin/node ${guard} --agent codex && python3 /home/dev/checks/secrets_scan.py` }] };
  const s = sandbox({ ".codex/hooks.json": `﻿${JSON.stringify({ hooks: { PreToolUse: [wrapped] } }, null, 2)}\n` });
  try {
    const r = init(opts(s, { agents: ["codex"], scope: "project", instructions: false }), s.env);
    assert.ok(r.ok, r.error);
    const text = read(join(s.root, ".codex", "hooks.json"));
    assert.ok(!text.startsWith("﻿"));
    const v = JSON.parse(text);
    assert.equal(v.hooks.PreToolUse.length, 2, "the wrapped entry stays; ah's goes after it");
    assert.deepEqual(v.hooks.PreToolUse[0], wrapped);
    const detail = r.changes.find((c) => c.agent === "codex")?.detail ?? "";
    assert.match(detail, /byte-order mark/);
    assert.match(detail, /left alone an entry that runs the guard with other words around it/);
    assert.match(detail, /meant to be committed, and it now holds this machine's node and guard paths/);
  } finally {
    s.done();
  }
});

test("init carries a hand-wired --root and writes through a hard link", { skip: posixOnly }, () => {
  const hand = { matcher: "Bash", hooks: [{ type: "command", command: process.execPath, args: [guard, "--agent", "claude", "--root", "/srv/app"] }] };
  const s = sandbox({ "~/dotfiles/claude-settings.json": JSON.stringify({ hooks: { PreToolUse: [hand] } }) });
  try {
    mkdirSync(join(s.home, ".claude"), { recursive: true });
    linkSync(join(s.home, "dotfiles", "claude-settings.json"), join(s.home, ".claude", "settings.json"));
    assert.ok(init(opts(s, { agents: ["claude"], scope: "user", instructions: false }), s.env).ok);
    const e = json(join(s.home, "dotfiles", "claude-settings.json")).hooks.PreToolUse[0].hooks[0];
    assert.deepEqual(e.args, [guard, "--agent", "claude", "--root", "/srv/app"]);
    assert.equal(statSync(join(s.home, ".claude", "settings.json")).nlink, 2, "still one file");
  } finally {
    s.done();
  }
});
