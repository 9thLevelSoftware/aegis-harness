import { classifyPath, isBlockDevice, type PathInfo } from "../classify.ts";
import { ALLOW, ask, deny, strictest, type Context, type Decision, type ShellCall } from "../model.ts";
import { globToRegExp, hasVariable, isTempPath } from "../paths.ts";
import { findSecrets, redact } from "../secrets.ts";
import { allStages, flagsOf, parseShell, type Pipeline, type Stage } from "../shell.ts";

const FORK_BOMB = /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;

const DOWNLOADERS = new Set(["curl", "wget", "fetch", "iwr", "invoke-webrequest", "irm", "invoke-restmethod", "http", "https", "aria2c"]);
const DECODERS = new Set(["base64", "xxd", "openssl"]);
const INTERPRETERS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "python", "python2", "python3", "py", "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "pwsh", "powershell", "iex", "invoke-expression", "source", "."]);
const NETWORK_SINKS = new Set(["curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "telnet", "openssl", "iwr", "invoke-webrequest", "irm", "invoke-restmethod", "http", "https", "mail", "mailx", "sendmail", "scp", "sftp", "ftp", "rsync"]);
const ENV_DUMPERS = new Set(["env", "printenv", "set", "export", "declare", "gci", "get-childitem", "dir", "ls"]);
const FILE_READERS = new Set(["cat", "less", "more", "head", "tail", "type", "get-content", "gc", "bat", "strings", "xxd", "hexdump", "od", "base64", "tac", "nl", "view"]);
const REMOVERS = new Set(["rm", "rmdir", "rd", "del", "erase", "remove-item", "ri", "unlink", "shred"]);
const POWER = new Set(["shutdown", "reboot", "halt", "poweroff", "telinit", "stop-computer", "restart-computer"]);
const GIT_HOOKED = new Set(["commit", "push", "merge", "rebase", "cherry-pick", "revert", "am", "apply", "checkout", "switch"]);

const CRED_FILE = /(^|[\\/])(\.env(\.(?!example$|sample$|template$|dist$|defaults$)[^\\/]*)?|\.netrc|\.npmrc|\.pypirc|\.git-credentials|credentials|id_rsa|id_ed25519|id_ecdsa|id_dsa|secrets?\.(json|ya?ml|toml|env)|[^\\/]+\.(pem|key|p12|pfx|jks|keystore))$/i;
const PRIVATE_FILE = /(^|[\\/])(id_rsa|id_ed25519|id_ecdsa|id_dsa)$|\.(pem|key|p12|pfx)$|(^|[\\/])\.(netrc|git-credentials|pypirc)$|(^|[\\/])\.aws[\\/]credentials$|(^|[\\/])\.docker[\\/]config\.json$|(^|[\\/])\.kube[\\/]config$/i;
const SSH_PRIVATE = /(^|[\\/])\.ssh[\\/](?!.*\.pub$)[^\\/]+$/i;

const HOOK_ENV = /^(HUSKY|HUSKY_SKIP_HOOKS|LEFTHOOK|SKIP|PRE_COMMIT_ALLOW_NO_CONFIG|SKIP_SIMPLE_GIT_HOOKS|GIT_HOOKS_SKIP)$/;
const HOOK_PATH_HINT = /\.harness[\\/]|\.claude[\\/]settings|\.claude[\\/]hooks|\.git[\\/]hooks|\.husky|\.codex[\\/]|\.pre-commit-config|lefthook/;
const WRITE_HINT = /\bopen\([^)]*['"][wa]\+?['"]|write(File|FileSync|_text|_bytes|Text|Lines)?\s*\(|\bunlink\b|\bremove\b|\brmtree\b|\brm(Sync)?\s*\(|Set-Content|Out-File|Add-Content|\bos\.system\b|subprocess/;
const DESTRUCTIVE_CODE = /shutil\.rmtree\s*\(|\bfs\.(rm|rmdir|rmSync|rmdirSync)\s*\([^)]*recursive|rimraf|\bos\.system\s*\(\s*['"]rm\s+-rf|Remove-Item[^;|]*-Recurse|\bFileUtils\.rm_rf|\bRemove-Item\b[^;|]*-Force/i;

export function shellRules(call: ShellCall, ctx: Context): Decision {
  const raw = call.command;
  const decisions: Decision[] = [];

  if (FORK_BOMB.test(raw)) {
    decisions.push(deny("shell.fork-bomb", "fork bomb", "This command exists only to exhaust the machine. Do not run it."));
  }
  for (const hit of findSecrets(raw)) {
    if (hit.severity === "deny") {
      decisions.push(deny("shell.secret-literal", `command contains a ${hit.name} (${redact(hit.match)})`, "Never put credentials on a command line; they end up in shell history and transcripts. Read them from an environment variable or a file the user owns."));
      break;
    }
  }

  const pipelines = parseShell(raw, { dialect: ctx.shellDialect ?? "posix" });
  for (const p of pipelines) decisions.push(...pipelineRules(p, ctx));
  for (const s of allStages(pipelines)) decisions.push(...stageRules(s, ctx));
  return strictest(decisions);
}

// ---------------------------------------------------------------------------
// Pipelines

function pipelineRules(p: Pipeline, ctx: Context): Decision[] {
  const out: Decision[] = [];
  const stages = p.stages;
  for (let i = 0; i < stages.length; i++) {
    const src = stages[i];
    const isDownloader = DOWNLOADERS.has(src.cmd);
    const isDecoder = DECODERS.has(src.cmd) && src.argv.some((a) => /^(-d|--decode|-D|-r|enc)$/.test(a));
    const readsCredential = credentialSourceOf(src, ctx) !== null;
    const dumpsEnv = ENV_DUMPERS.has(src.cmd) && (src.argv.length === 1 || src.argv.slice(1).every((a) => /^-|^env:?$/i.test(a)));
    for (let j = i + 1; j < stages.length; j++) {
      const sink = stages[j];
      if ((isDownloader || isDecoder) && INTERPRETERS.has(sink.cmd)) {
        out.push(deny("shell.pipe-to-shell", `${src.cmd} output is piped into ${sink.cmd}`, "Download to a file, read it, then run it: `curl -fsSL URL -o install.sh && cat install.sh` first. Piping remote content into an interpreter runs code nobody reviewed."));
      }
      if ((readsCredential || dumpsEnv) && NETWORK_SINKS.has(sink.cmd)) {
        out.push(deny("shell.credential-exfil", `${describe(src)} is piped into ${sink.cmd}`, "Credentials and the environment never leave the machine through an agent session. If a service needs a value, the user configures it."));
      }
    }
  }
  return out;
}

function describe(s: Stage): string {
  return s.argv.slice(0, 2).join(" ");
}

// ---------------------------------------------------------------------------
// Stages

function stageRules(s: Stage, ctx: Context): Decision[] {
  const out: Decision[] = [];

  if (s.wrappers.includes("sudo") || s.wrappers.includes("doas") || s.cmd === "runas") {
    out.push(ask("shell.privilege-escalation", `${describe(s)} runs with elevated privileges`, "Elevated commands change the machine, not the project. Ask the user to run it, or explain why the project needs it."));
  }

  if (REMOVERS.has(s.cmd)) out.push(...removeRules(s, ctx));
  else if (s.cmd === "find") out.push(...findRules(s, ctx));
  else if (s.cmd === "git") out.push(...gitRules(s, ctx));
  else if (s.cmd === "chmod" || s.cmd === "chown" || s.cmd === "chgrp" || s.cmd === "icacls") out.push(...permissionRules(s, ctx));
  else if (s.cmd === "dd" || s.cmd.startsWith("mkfs") || ["mkswap", "wipefs", "fdisk", "sfdisk", "parted", "diskpart", "format"].includes(s.cmd)) out.push(...diskRules(s));
  else if (POWER.has(s.cmd) || s.cmd === "init" || s.cmd === "systemctl") out.push(...powerRules(s));
  else if (s.cmd === "kill" || s.cmd === "killall5") out.push(...killRules(s));
  else if (DOWNLOADERS.has(s.cmd) || ["scp", "rsync", "sftp", "nc", "ncat", "netcat", "socat"].includes(s.cmd)) out.push(...uploadRules(s, ctx));
  else if (FILE_READERS.has(s.cmd)) out.push(...credentialReadRules(s, ctx));
  else if (s.cmd === "docker" || s.cmd === "podman" || s.cmd === "docker-compose") out.push(...dockerRules(s));
  else if (["pwsh", "powershell"].includes(s.cmd) && s.opaque) {
    out.push(ask("shell.encoded-command", "PowerShell is given an encoded command", "Pass the command as plain text so it can be reviewed."));
  }

  out.push(...databaseRules(s));
  out.push(...publishRules(s));
  out.push(...baselineRefreshRules(s));
  out.push(...interpreterRules(s));

  for (const target of writeTargetsOf(s)) out.push(...writeRules(target, s, ctx));
  return out;
}

// ---------------------------------------------------------------------------
// rm and friends

interface RemoveSpec {
  recursive: boolean;
  targets: string[];
  noPreserveRoot: boolean;
}

function removeSpec(s: Stage): RemoveSpec {
  const argv = s.argv.slice(1);
  const pwshStyle = s.cmd === "remove-item" || s.cmd === "ri" || argv.some((a) => /^-(Recurse|Force|Path|LiteralPath|WhatIf|Confirm)$/i.test(a));
  if (pwshStyle) {
    const targets: string[] = [];
    let recursive = false;
    for (let i = 0; i < argv.length; i++) {
      const a = argv[i];
      if (/^-(recurse|rec|r)$/i.test(a)) recursive = true;
      else if (/^-(path|literalpath|lp|p)$/i.test(a)) {
        const v = argv[i + 1];
        if (v !== undefined) targets.push(...v.split(","));
        i++;
      } else if (/^-(path|literalpath):(.+)$/i.test(a)) targets.push(...a.replace(/^-[a-z]+:/i, "").split(","));
      else if (!a.startsWith("-")) targets.push(...a.split(","));
    }
    return { recursive, targets, noPreserveRoot: false };
  }
  if (s.cmd === "rmdir" || s.cmd === "rd" || s.cmd === "del" || s.cmd === "erase") {
    const recursive = argv.some((a) => /^\/s$/i.test(a));
    const targets = argv.filter((a) => !/^\/[a-z](:.*)?$/i.test(a) && !a.startsWith("-"));
    return { recursive, targets, noPreserveRoot: false };
  }
  const f = flagsOf(s.argv, 1);
  const recursive = f.short.has("r") || f.short.has("R") || f.long.has("recursive");
  return { recursive, targets: f.positionals, noPreserveRoot: f.long.has("no-preserve-root") };
}

function removeRules(s: Stage, ctx: Context): Decision[] {
  const spec = removeSpec(s);
  const out: Decision[] = [];
  if (spec.noPreserveRoot) {
    out.push(deny("shell.rm-recursive-root", `${s.cmd} --no-preserve-root`, "Nothing in a project needs the filesystem root deleted."));
  }
  const destructive = spec.recursive || s.cmd === "del" || s.cmd === "erase" || s.cmd === "shred";
  for (const t of spec.targets) out.push(judgeRemoveTarget(t, destructive, spec.recursive, s, ctx));
  return out;
}

const ROOT_LITERAL = /^(\/|\/\*|\\|\\\*|[A-Za-z]:\\?\*?|[A-Za-z]:\/\*?)$/;
const HOME_LITERAL = /^(~|~\/\*?|~\\\*?|\$\{?HOME\}?(\/\*?)?|%USERPROFILE%(\\\*?)?)$/i;
const CWD_WIPE_LITERAL = /^(\.|\.\/|\.\\|\.\/\*|\.\\\*|\*|\*\.\*|\.\*|\*\*|\.\.|\.\.\/|\.\.\\|\.\.\/\*|:\/)$/;

function judgeRemoveTarget(target: string, destructive: boolean, recursive: boolean, s: Stage, ctx: Context): Decision {
  const t = target.replace(/^["']+|["']+$/g, "");
  if (t === "" || t === "--") return ALLOW;
  if (ROOT_LITERAL.test(t)) {
    return deny("shell.rm-recursive-root", `${s.cmd} targets the filesystem root (${t})`, "Nothing in a project needs the filesystem root deleted. Name the specific directory.");
  }
  if (HOME_LITERAL.test(t)) {
    return deny("shell.rm-recursive-home", `${s.cmd} targets the home directory (${t})`, "Deleting the home directory destroys the user's machine state. Name the specific directory inside the project.");
  }
  if (CWD_WIPE_LITERAL.test(t)) {
    if (recursive || /\*/.test(t) || s.cmd === "del" || s.cmd === "erase") {
      return deny("shell.rm-recursive-cwd", `${s.cmd} ${t} wipes the working directory`, "Delete specific paths (for example `rm -rf dist node_modules`). If the whole tree must go, the user does that.");
    }
    return ALLOW;
  }
  if (hasVariable(t)) {
    if (isTempPath(t)) return ALLOW;
    if (recursive) {
      return ask("shell.rm-unresolved-variable", `${s.cmd} -r on ${t}, whose value cannot be verified`, "An empty or wrong variable turns this into `rm -rf /`. Use a literal path, or guard it: `rm -rf \"${VAR:?unset}/sub\"`.");
    }
    return ALLOW;
  }
  const info = classifyPath(t, ctx);
  switch (info.category) {
    case "filesystem-root":
      return deny("shell.rm-recursive-root", `${s.cmd} targets the filesystem root (${t})`, "Nothing in a project needs the filesystem root deleted.");
    case "home-root":
      return deny("shell.rm-recursive-home", `${s.cmd} targets the home directory (${t})`, "Deleting the home directory destroys the user's machine state.");
    case "project-root":
      return destructive ? deny("shell.rm-recursive-cwd", `${s.cmd} ${t} wipes the project`, "Delete specific paths instead.") : ALLOW;
    case "git-internals":
      return deny("shell.rm-git-dir", `${s.cmd} ${t} destroys repository history`, "Use git commands (git stash, git checkout, git reset --keep) to change state; never delete .git.");
    case "harness":
      return deny("shell.write-harness", `${s.cmd} ${t} removes harness state`, "`.harness/` is owned by ah. Record incidents with `ah bug add`; rules change in reviewed commits.");
    case "hook-config":
      return deny("shell.hook-tamper", `${s.cmd} ${t} removes hook configuration (${info.matched})`, "Hook wiring is how this project enforces its rules. Leave it in place and tell the user if it blocks legitimate work.");
    case "lint-config":
      return deny("shell.write-lint-config", `${s.cmd} ${t} removes a linter configuration`, "Fix the violation in source instead. Linter configuration changes in a reviewed commit.");
    case "test-config":
      return deny("shell.write-test-config", `${s.cmd} ${t} removes a test configuration`, "Fix the failing test instead. Runner configuration changes in a reviewed commit.");
    case "baseline":
      return ask("shell.write-baseline", `${s.cmd} ${t} removes a baseline or snapshot`, "Removing a baseline hides regressions. Ask the user with the diff in front of them.");
    case "ci-config":
    case "compiler-config":
    case "env-file":
    case "key-material":
      return ask("shell.write-ask-path", `${s.cmd} ${t} removes ${info.category.replace("-", " ")}`, "This file needs a human to confirm its removal.");
    case "home-config":
      return deny("shell.write-home-config", `${s.cmd} ${t} removes user credentials or agent configuration`, "Agent sessions do not change user-level credentials or agent settings.");
    case "system":
      return recursive
        ? deny("shell.rm-outside-project", `${s.cmd} -r ${t} targets a system path`, "Keep deletions inside the project.")
        : ask("shell.write-system-path", `${s.cmd} ${t} removes a system file`, "System changes need a human.");
    case "temp":
    case "normal":
    case "lockfile":
    case "manifest":
    case "env-example":
      return ALLOW;
    case "outside-project":
      return recursive
        ? deny("shell.rm-outside-project", `${s.cmd} -r ${t} is outside the project (${info.abs})`, "Recursive deletes stay inside the project root. If this path must go, the user deletes it.")
        : ALLOW;
  }
}

const FIND_FILTERS = /^-(i?name|i?path|i?regex|i?wholename|i?lname|newer\w*|[acm](time|min|newer)|size|empty|user|group|perm|samefile|links|type|used|fstype|uid|gid|nouser|nogroup|readable|writable|executable)$/;

function findRules(s: Stage, ctx: Context): Decision[] {
  const argv = s.argv.slice(1);
  const deletes = argv.includes("-delete") || argv.some((a, i) => /^-exec(dir)?$/.test(a) && REMOVERS.has((argv[i + 1] ?? "").replace(/^\\/, "")));
  if (!deletes) return [];
  if (argv.some((a) => FIND_FILTERS.test(a))) return [];
  const starts: string[] = [];
  for (const a of argv) {
    if (a.startsWith("-") || a === "(" || a === "!") break;
    starts.push(a);
  }
  if (starts.length === 0) starts.push(".");
  return starts.map((t) => judgeRemoveTarget(t, true, true, { ...s, cmd: "find -delete" }, ctx));
}

// ---------------------------------------------------------------------------
// git

function branchProtected(name: string, ctx: Context): boolean {
  const short = name.replace(/^refs\/heads\//, "").replace(/^refs\/remotes\/[^/]+\//, "");
  return ctx.policy.protectedBranches.some((g) => globToRegExp(g, ctx.platform).test(short));
}

function hookBypassEnv(env: Record<string, string>): string | null {
  for (const [k, v] of Object.entries(env)) {
    if (!HOOK_ENV.test(k)) continue;
    if (k === "SKIP" && v.trim() === "") continue;
    return `${k}=${v}`;
  }
  return null;
}

function gitRules(s: Stage, ctx: Context): Decision[] {
  const out: Decision[] = [];
  const argv = s.argv;
  let i = 1;
  while (i < argv.length && argv[i].startsWith("-")) {
    const a = argv[i];
    if (a === "-c" && /^(core\.hookspath|hooks?\.)/i.test(argv[i + 1] ?? "")) {
      out.push(deny("shell.hook-bypass", `git -c ${argv[i + 1]} disables hooks for this command`, HOOK_BYPASS_REMEDIATION));
    }
    if (["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"].includes(a)) i += 2;
    else i++;
  }
  const sub = argv[i];
  if (sub === undefined) return out;
  const rest = argv.slice(i + 1);

  if (rest.includes("--no-verify")) {
    out.push(deny("shell.hook-bypass", `git ${sub} --no-verify skips the project's hooks`, HOOK_BYPASS_REMEDIATION));
  }
  const bypass = hookBypassEnv(s.env);
  if (bypass && GIT_HOOKED.has(sub)) {
    out.push(deny("shell.hook-bypass", `${bypass} disables hooks for git ${sub}`, HOOK_BYPASS_REMEDIATION));
  }

  switch (sub) {
    case "commit": {
      const f = flagsOf(rest, 0, ["-m", "-F", "-C", "-c", "-t", "--author", "--date", "--fixup", "--squash", "--template", "--cleanup", "--trailer"]);
      if (f.short.has("n")) out.push(deny("shell.hook-bypass", "git commit -n is --no-verify", HOOK_BYPASS_REMEDIATION));
      break;
    }
    case "push":
      out.push(...pushRules(rest, ctx));
      break;
    case "reset":
      if (rest.includes("--hard")) {
        out.push(deny("shell.git-discard-changes", "git reset --hard discards uncommitted work", "Run `git stash push -u` first if the changes might matter, use `git reset --keep`, or revert specific files after reading `git diff`."));
      }
      break;
    case "clean": {
      const f = flagsOf(rest, 0, ["-e", "--exclude"]);
      const dry = f.short.has("n") || f.long.has("dry-run") || f.short.has("i") || f.long.has("interactive");
      if (!dry && (f.short.has("f") || f.long.has("force"))) {
        out.push(deny("shell.git-clean", "git clean -f removes untracked files", "Run `git clean -n` to list what would go, then delete named paths. Untracked files may be the user's uncommitted work."));
      }
      break;
    }
    case "checkout":
      out.push(...checkoutRules(rest));
      break;
    case "restore":
      out.push(...restoreRules(rest));
      break;
    case "stash":
      if (rest[0] === "drop" || rest[0] === "clear") {
        out.push(deny("shell.git-stash-drop", `git stash ${rest[0]} destroys stashed work`, "Leave stashes alone; the user decides when they go."));
      }
      break;
    case "branch": {
      const f = flagsOf(rest, 0, ["-u", "--set-upstream-to", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--format", "--sort"]);
      const forceDelete = f.short.has("D") || ((f.short.has("d") || f.long.has("delete")) && (f.short.has("f") || f.long.has("force")));
      if (forceDelete) {
        out.push(ask("shell.git-branch-force-delete", `git branch -D ${f.positionals.join(" ")} deletes unmerged work`, "Confirm with the user that the branch is no longer needed, or use `git branch -d`, which refuses unmerged branches."));
      }
      break;
    }
    case "filter-branch":
    case "filter-repo":
    case "replace":
      out.push(deny("shell.git-rewrite-history", `git ${sub} rewrites history`, "History rewrites are a human decision made with a backup in hand."));
      break;
    case "reflog":
      if (rest.includes("expire") && rest.some((a) => /^--expire(-unreachable)?=(now|all)$/.test(a))) {
        out.push(deny("shell.git-rewrite-history", "git reflog expire --expire=now destroys recovery points", "The reflog is the safety net for every other mistake. Leave it."));
      }
      break;
    case "gc":
      if (rest.some((a) => /^--prune=(now|all)$/.test(a))) {
        out.push(deny("shell.git-rewrite-history", "git gc --prune=now destroys unreachable objects immediately", "Plain `git gc` is fine; immediate pruning removes the ability to recover."));
      }
      break;
    case "update-ref":
      if (rest.includes("-d") && rest.some((a) => branchProtected(a, ctx))) {
        out.push(deny("shell.git-rewrite-history", "git update-ref -d on a protected branch", "Protected branches are not deleted from a session."));
      }
      break;
    case "config": {
      const f = flagsOf(rest, 0, ["-f", "--file", "--blob", "--type", "--default", "--get-color"]);
      const key = f.positionals[0] ?? "";
      if (/^(core\.hookspath|hooks?\.)/i.test(key)) {
        out.push(deny("shell.hook-bypass", `git config ${key} redirects or disables hooks`, HOOK_BYPASS_REMEDIATION));
      } else if (f.long.has("global") || f.long.has("system")) {
        out.push(ask("shell.git-global-config", `git config ${f.long.has("system") ? "--system" : "--global"} ${key} changes the user's git setup`, "Project needs go in the repository's own config (`git config --local`). Ask the user before touching their global configuration."));
      }
      break;
    }
    default:
      break;
  }
  return out;
}

const HOOK_BYPASS_REMEDIATION = "Hooks are this project's gates. Let them run. If a hook fails, fix what it reports, or tell the user which hook blocks you and why.";

function pushRules(rest: string[], ctx: Context): Decision[] {
  const out: Decision[] = [];
  const f = flagsOf(rest, 0, ["-o", "--push-option", "--receive-pack", "--exec", "--repo", "--recurse-submodules", "--signed"]);
  const force = f.short.has("f") || f.long.has("force");
  const lease = f.long.has("force-with-lease") || f.long.has("force-if-includes");
  const del = f.short.has("d") || f.long.has("delete");
  const positionals = f.positionals;

  let refspecs: string[] = [];
  if (positionals.length > 1) refspecs = positionals.slice(1);
  else if (positionals.length === 1 && (positionals[0].includes(":") || positionals[0].startsWith("+"))) refspecs = positionals;

  interface Ref { dst: string; forced: boolean; deletion: boolean }
  const refs: Ref[] = refspecs.map((r) => {
    const forced = r.startsWith("+");
    const body = forced ? r.slice(1) : r;
    const idx = body.indexOf(":");
    const src = idx >= 0 ? body.slice(0, idx) : body;
    const dst = idx >= 0 ? body.slice(idx + 1) : body;
    return { dst, forced, deletion: del || (idx >= 0 && src === "") };
  });

  if (f.long.has("mirror")) {
    out.push(deny("shell.git-force-push", "git push --mirror overwrites every ref on the remote", "Mirror pushes are an administrative action, not a session action."));
    return out;
  }
  for (const r of refs) {
    if (r.deletion) {
      if (branchProtected(r.dst, ctx)) out.push(deny("shell.git-force-push", `git push deletes protected branch ${r.dst}`, "Protected branches are never deleted from a session."));
      else out.push(ask("shell.git-branch-delete", `git push deletes remote branch ${r.dst}`, "Confirm with the user that nobody depends on this remote branch."));
    }
  }
  if (del && refs.length === 0) {
    out.push(ask("shell.git-branch-delete", "git push --delete", "Confirm with the user which remote branch goes."));
  }

  const forcedRefs = refs.filter((r) => r.forced || force).filter((r) => !r.deletion);
  const anyForce = force || refs.some((r) => r.forced);
  if (anyForce && !lease) {
    if (f.long.has("all")) {
      out.push(deny("shell.git-force-push", "git push --force --all rewrites every branch", "Force pushes to shared branches destroy other people's work. Rebase onto the remote instead, or ask the user."));
    } else if (forcedRefs.length === 0) {
      out.push(ask("shell.git-force-push-review", "git push --force with no branch named (current branch unknown)", "Name the branch: `git push --force-with-lease origin <feature-branch>`. Never force-push main."));
    } else {
      for (const r of forcedRefs) {
        if (branchProtected(r.dst, ctx)) {
          out.push(deny("shell.git-force-push", `force push to protected branch ${r.dst}`, "Protected branches are never force-pushed from a session. Rebase your branch onto the remote and push normally, or ask the user."));
        } else {
          out.push(ask("shell.git-force-push-review", `force push to ${r.dst} without --force-with-lease`, "Use `git push --force-with-lease origin ${r.dst}` so the push fails if someone else pushed first."));
        }
      }
    }
  } else if (lease) {
    for (const r of refs.filter((x) => !x.deletion)) {
      if (branchProtected(r.dst, ctx)) {
        out.push(ask("shell.git-force-push-review", `force-with-lease push to protected branch ${r.dst}`, "Even a leased force push to a protected branch rewrites shared history. Ask the user."));
      }
    }
    if (refs.length === 0) {
      out.push(ask("shell.git-force-push-review", "git push --force-with-lease with no branch named", "Name the branch so the target can be checked."));
    }
  }
  if (f.long.has("prune")) {
    out.push(ask("shell.git-branch-delete", "git push --prune deletes remote branches that no longer exist locally", "Confirm with the user before pruning remote branches."));
  }
  return out;
}

const WIPE_PATHSPEC = /^(\.|\.\/|\*|:\/|:\/\.|\.\/\*|\.\*)$/;

function checkoutRules(rest: string[]): Decision[] {
  const f = flagsOf(rest, 0, ["-b", "-B", "--orphan", "-t", "--track", "--conflict", "--pathspec-from-file", "--recurse-submodules"]);
  if (f.short.has("b") || f.short.has("B") || f.long.has("orphan") || f.long.has("detach")) return [];
  const dash = rest.indexOf("--");
  const paths = dash >= 0 ? rest.slice(dash + 1) : f.positionals.length >= 2 ? f.positionals.slice(1) : f.positionals.filter((p) => WIPE_PATHSPEC.test(p));
  if (paths.some((p) => WIPE_PATHSPEC.test(p))) {
    return [deny("shell.git-discard-changes", `git checkout ${paths.join(" ")} discards every uncommitted change`, "Read `git diff` first. Revert named files one at a time, or `git stash push -u` so the work can be recovered.")];
  }
  if (paths.length > 0) {
    return [ask("shell.git-discard-file", `git checkout -- ${paths.join(" ")} discards uncommitted changes to those files`, "Confirm the user does not need the current contents, or stash first.")];
  }
  return [];
}

function restoreRules(rest: string[]): Decision[] {
  const f = flagsOf(rest, 0, ["-s", "--source", "--pathspec-from-file"]);
  const staged = f.short.has("S") || f.long.has("staged");
  const worktree = f.short.has("W") || f.long.has("worktree") || !staged;
  if (!worktree) return [];
  const dash = rest.indexOf("--");
  const paths = dash >= 0 ? rest.slice(dash + 1) : f.positionals;
  if (paths.some((p) => WIPE_PATHSPEC.test(p))) {
    return [deny("shell.git-discard-changes", `git restore ${paths.join(" ")} discards every uncommitted change`, "Read `git diff` first and restore named files, or `git stash push -u`.")];
  }
  if (paths.length > 0) {
    return [ask("shell.git-discard-file", `git restore ${paths.join(" ")} discards uncommitted changes to those files`, "Confirm the user does not need the current contents, or stash first.")];
  }
  return [];
}

// ---------------------------------------------------------------------------
// permissions, disks, power, kill

const CHMOD_SYMBOLIC = /^[ugoa]*[-+=][rwxXstugo]*(,[ugoa]*[-+=][rwxXstugo]*)*$/;
const CHMOD_OCTAL = /^[0-7]{3,4}$/;

/** chmod's mode may start with "-" (`chmod -x hook`), so it cannot be parsed as a flag. */
function parsePermissionArgs(s: Stage): { recursive: boolean; mode: string; targets: string[] } {
  if (s.cmd !== "chmod") {
    const f = flagsOf(s.argv, 1, ["--reference"]);
    return { recursive: f.short.has("R") || f.long.has("recursive"), mode: f.positionals[0] ?? "", targets: f.positionals.slice(1) };
  }
  let recursive = false;
  let mode: string | undefined;
  const targets: string[] = [];
  let onlyOperands = false;
  for (const a of s.argv.slice(1)) {
    if (onlyOperands) {
      targets.push(a);
    } else if (a === "--") {
      onlyOperands = true;
    } else if (mode === undefined && (CHMOD_SYMBOLIC.test(a) || CHMOD_OCTAL.test(a))) {
      mode = a;
    } else if (a.startsWith("--")) {
      if (a === "--recursive") recursive = true;
    } else if (a.startsWith("-") && a.length > 1) {
      if (a.includes("R")) recursive = true;
    } else if (mode === undefined) {
      mode = a;
    } else {
      targets.push(a);
    }
  }
  return { recursive, mode: mode ?? "", targets };
}

function permissionRules(s: Stage, ctx: Context): Decision[] {
  const out: Decision[] = [];
  if (s.cmd === "icacls") {
    if (s.argv.some((a) => /^\/t$/i.test(a)) && s.argv.some((a) => /everyone|users:\(?f/i.test(a))) {
      out.push(ask("shell.permissions-world-writable", "icacls grants broad access recursively", "Grant the narrowest permission on the narrowest path."));
    }
    return out;
  }
  const { recursive, mode, targets } = parsePermissionArgs(s);
  for (const t of targets) {
    const info = classifyPath(t, ctx);
    if (info.category === "hook-config" || info.category === "git-internals") {
      if (s.cmd === "chmod" && /(^|,)[ugoa]*-[rwx]*x|^0*[0-6][0-6][0-6]$/.test(mode)) {
        out.push(deny("shell.hook-tamper", `chmod ${mode} ${t} disables a hook`, "Hooks stay executable. Tell the user if a hook blocks legitimate work."));
      }
      continue;
    }
    if (!recursive) continue;
    if (["filesystem-root", "home-root", "system"].includes(info.category)) {
      out.push(deny("shell.permissions-sweep", `${s.cmd} -R on ${t}`, "Recursive permission changes outside the project break the machine. Change the one path that needs it."));
    } else if (s.cmd === "chmod" && /777|a\+rwx|o\+w|\+w$/.test(mode)) {
      out.push(ask("shell.permissions-world-writable", `chmod -R ${mode} ${t}`, "World-writable trees are a security hole. Use the narrowest mode that works (755 for directories, 644 for files)."));
    }
  }
  return out;
}

function diskRules(s: Stage): Decision[] {
  const argv = s.argv.slice(1);
  const hit =
    (s.cmd === "dd" && argv.some((a) => /^of=/i.test(a) && isBlockDevice(a.slice(3)))) ||
    (s.cmd.startsWith("mkfs") || ["mkswap", "wipefs", "diskpart"].includes(s.cmd)) ||
    (["fdisk", "sfdisk", "parted"].includes(s.cmd) && !argv.some((a) => /^(-l|--list|print)$/.test(a))) ||
    (s.cmd === "format" && argv.some((a) => /^[A-Za-z]:$/.test(a) || /^\/fs:/i.test(a)));
  if (!hit) return [];
  return [deny("shell.disk-destroy", `${s.argv.slice(0, 3).join(" ")} writes to a raw disk or partition table`, "Disk operations are never part of a coding task.")];
}

function powerRules(s: Stage): Decision[] {
  const argv = s.argv.slice(1);
  if (POWER.has(s.cmd)) {
    if (s.cmd === "shutdown" && argv.includes("-c")) return [];
    return [deny("shell.system-power", `${s.cmd} stops the machine`, "Power state is the user's. Say what needs restarting and why.")];
  }
  if (s.cmd === "init" && /^[06]$/.test(argv[0] ?? "")) return [deny("shell.system-power", `init ${argv[0]} stops the machine`, "Power state is the user's.")];
  if (s.cmd === "systemctl" && argv.some((a) => /^(poweroff|reboot|halt|kexec|suspend|hibernate|hybrid-sleep)$/.test(a))) {
    return [deny("shell.system-power", `systemctl ${argv.join(" ")} changes machine power state`, "Power state is the user's.")];
  }
  return [];
}

function killRules(s: Stage): Decision[] {
  const argv = s.argv.slice(1);
  if (s.cmd === "killall5" || (argv.length >= 2 && argv[argv.length - 1] === "-1")) {
    return [deny("shell.kill-all", `${s.argv.join(" ")} signals every process`, "Kill the one process by pid or name.")];
  }
  return [];
}

// ---------------------------------------------------------------------------
// credentials on the move

function credentialSourceOf(s: Stage, ctx: Context): string | null {
  const candidates = [...s.argv.slice(1), ...s.reads];
  if (!FILE_READERS.has(s.cmd) && s.reads.length === 0 && !NETWORK_SINKS.has(s.cmd)) return null;
  for (const a of candidates) {
    if (a.startsWith("-")) continue;
    const info = classifyPath(a, ctx);
    if (info.isTestFile) continue;
    if (CRED_FILE.test(a) || info.category === "home-config" || info.category === "env-file") return a;
  }
  return null;
}

function credentialReadRules(s: Stage, ctx: Context): Decision[] {
  const out: Decision[] = [];
  for (const a of s.argv.slice(1)) {
    if (a.startsWith("-")) continue;
    const info = classifyPath(a, ctx);
    if (info.isTestFile) continue;
    const rel = info.homeRel ?? info.rel ?? info.abs;
    const isPrivate = PRIVATE_FILE.test(a) || (info.homeRel !== null && (SSH_PRIVATE.test(`/${info.homeRel}`) || PRIVATE_FILE.test(`/${info.homeRel}`) || /^\.(npmrc|aws\/credentials)$/.test(info.homeRel)));
    if (isPrivate) {
      out.push(deny("shell.credential-read", `${s.cmd} ${a} prints a private key or credential store (${rel})`, "Private keys stay out of the transcript. Refer to the file by path; if a value is needed, the user supplies it through an environment variable."));
    }
  }
  return out;
}

function uploadRules(s: Stage, ctx: Context): Decision[] {
  const out: Decision[] = [];
  const argv = s.argv;
  const isCred = (p: string): boolean => {
    const clean = p.replace(/^@/, "").replace(/^[^=]*=@/, "");
    if (!clean || clean === "-") return false;
    const info = classifyPath(clean, ctx);
    return !info.isTestFile && (CRED_FILE.test(clean) || info.category === "home-config" || info.category === "env-file");
  };
  if (DOWNLOADERS.has(s.cmd)) {
    for (let i = 1; i < argv.length; i++) {
      const a = argv[i];
      const next = argv[i + 1] ?? "";
      if (/^(-d|--data|--data-binary|--data-raw|--data-urlencode|-F|--form|-T|--upload-file|--json)$/.test(a) && (next.startsWith("@") || /=@/.test(next) || a === "-T" || a === "--upload-file") && isCred(next)) {
        out.push(deny("shell.credential-exfil", `${s.cmd} uploads ${next.replace(/^.*@/, "")}`, "Credentials never leave the machine through an agent session."));
      }
      if (/^(--post-file|--body-file)=(.+)$/.test(a) && isCred(a.split("=")[1])) {
        out.push(deny("shell.credential-exfil", `${s.cmd} uploads ${a.split("=")[1]}`, "Credentials never leave the machine through an agent session."));
      }
      if (/^-(InFile|Body)$/i.test(a) && isCred(next)) {
        out.push(deny("shell.credential-exfil", `${s.cmd} uploads ${next}`, "Credentials never leave the machine through an agent session."));
      }
    }
    for (const r of s.reads) if (isCred(r)) out.push(deny("shell.credential-exfil", `${s.cmd} reads ${r} as input`, "Credentials never leave the machine through an agent session."));
  } else {
    const positionals = argv.slice(1).filter((a) => !a.startsWith("-"));
    const remote = positionals.some((p) => /^[^/]+:/.test(p) || /^rsync:\/\//.test(p) || /@/.test(p));
    if (remote && positionals.some((p) => isCred(p))) {
      out.push(deny("shell.credential-exfil", `${s.cmd} copies a credential file to a remote host`, "Credentials never leave the machine through an agent session."));
    }
    for (const r of s.reads) if (isCred(r)) out.push(deny("shell.credential-exfil", `${s.cmd} sends ${r} over the network`, "Credentials never leave the machine through an agent session."));
  }
  return out;
}

// ---------------------------------------------------------------------------
// containers, databases, deploys

function dockerRules(s: Stage): Decision[] {
  const a = s.argv.slice(1).filter((x) => !x.startsWith("-"));
  const joined = s.argv.join(" ");
  const hit =
    (a[0] === "system" && a[1] === "prune") ||
    (a[0] === "volume" && (a[1] === "prune" || a[1] === "rm")) ||
    ((a[0] === "image" || a[0] === "builder" || a[0] === "container" || a[0] === "network") && a[1] === "prune") ||
    (a[0] === "compose" && a[1] === "down" && /\s(-v|--volumes)\b/.test(joined)) ||
    (s.cmd === "docker-compose" && a[0] === "down" && /\s(-v|--volumes)\b/.test(joined)) ||
    (a[0] === "rm" && /\$\(\s*docker ps -aq?\s*\)/.test(joined)) ||
    (a[0] === "rmi" && /\$\(\s*docker images -q\s*\)/.test(joined));
  if (!hit) return [];
  return [ask("shell.docker-destroy", `${s.argv.slice(0, 4).join(" ")} removes containers, images or volumes wholesale`, "Volumes may hold local databases. Remove the named container or volume the task needs.")];
}

const SQL_DESTROY = /\b(DROP\s+(DATABASE|SCHEMA|TABLE)|TRUNCATE(\s+TABLE)?\s+\w|FLUSHALL|FLUSHDB|dropDatabase\(\))/i;

function databaseRules(s: Stage): Decision[] {
  const joined = s.argv.slice(1).join(" ");
  const tail = s.argv.slice(1).filter((x) => !x.startsWith("-"));
  let hit = false;
  if (["psql", "mysql", "mysqladmin", "sqlite3", "mongo", "mongosh", "redis-cli", "clickhouse-client", "cockroach"].includes(s.cmd)) hit = SQL_DESTROY.test(joined) || (s.cmd === "mysqladmin" && tail[0] === "drop");
  else if (s.cmd === "dropdb") hit = true;
  else if (s.cmd === "supabase") hit = (tail[0] === "db" && tail[1] === "reset" && /--(linked|db-url)/.test(joined)) || (tail[0] === "projects" && tail[1] === "delete");
  else if (s.cmd === "prisma" || (s.cmd === "npx" && tail[0] === "prisma")) hit = /\bmigrate\s+reset\b|--force-reset/.test(joined);
  else if (s.cmd === "rails" || s.cmd === "rake" || s.cmd === "bin/rails") hit = /\bdb:(drop|reset|schema:load|purge)\b/.test(joined);
  else if (s.cmd === "alembic") hit = /\bdowngrade\s+base\b/.test(joined);
  else if (s.cmd === "flyway") hit = tail.includes("clean");
  if (!hit) return [];
  return [ask("shell.database-destroy", `${s.argv.slice(0, 4).join(" ")} drops or resets data`, "Confirm with the user which database this hits. Local disposable databases are fine; say so when asking.")];
}

function publishRules(s: Stage): Decision[] {
  const argv = s.argv;
  const tail = argv.slice(1).filter((x) => !x.startsWith("-"));
  const joined = argv.join(" ");
  const askIt = (what: string, why: string): Decision[] => [ask("shell.deploy-or-publish", `${what} reaches a shared destination`, why)];
  const denyIt = (what: string, why: string): Decision[] => [deny("shell.remote-destroy", `${what} destroys shared infrastructure`, why)];
  const human = "Publishing and deploying are not undone by a revert. Tell the user it is ready and let them pull the trigger.";
  const never = "Shared infrastructure is never destroyed from a session.";

  switch (s.cmd) {
    case "npm":
    case "pnpm":
    case "yarn":
    case "bun":
      if (tail[0] === "publish" || (tail[0] === "npm" && tail[1] === "publish")) return askIt(`${s.cmd} publish`, human);
      if (tail[0] === "unpublish" || (tail[0] === "npm" && tail[1] === "unpublish")) return denyIt(`${s.cmd} unpublish`, "Unpublishing breaks every downstream install.");
      if (tail[0] === "run" && /^(deploy|publish|release|ship)(:|$)/.test(tail[1] ?? "")) return askIt(`${s.cmd} run ${tail[1]}`, human);
      return [];
    case "cargo":
      if (tail[0] === "publish") return askIt("cargo publish", human);
      if (tail[0] === "yank") return askIt("cargo yank", "Yanking affects every dependant.");
      return [];
    case "twine":
      return tail[0] === "upload" ? askIt("twine upload", human) : [];
    case "uv":
    case "poetry":
    case "flit":
    case "hatch":
      return tail[0] === "publish" ? askIt(`${s.cmd} publish`, human) : [];
    case "gem":
      return tail[0] === "push" ? askIt("gem push", human) : tail[0] === "yank" ? askIt("gem yank", human) : [];
    case "dotnet":
    case "nuget":
      return /\bnuget\s+push\b|^nuget push/.test(joined) || (s.cmd === "nuget" && tail[0] === "push") ? askIt(`${s.cmd} push`, human) : [];
    case "docker":
    case "podman":
      return tail[0] === "push" ? askIt(`${s.cmd} push`, human) : [];
    case "gh":
      if (tail[0] === "repo" && (tail[1] === "delete" || tail[1] === "archive")) return denyIt(`gh repo ${tail[1]}`, never);
      if (tail[0] === "release" && tail[1] === "delete") return denyIt("gh release delete", never);
      if (tail[0] === "release" && ["create", "upload", "edit"].includes(tail[1] ?? "")) return askIt(`gh release ${tail[1]}`, human);
      if (tail[0] === "pr" && tail[1] === "merge") return askIt("gh pr merge", "Merging is the user's decision.");
      if (tail[0] === "secret" || tail[0] === "variable") return askIt(`gh ${tail[0]} ${tail[1] ?? ""}`, "Repository secrets are set by the user.");
      if (tail[0] === "api" && /\s-X\s+(DELETE|PUT|PATCH)\b/i.test(joined)) return askIt("gh api with a mutating method", human);
      return [];
    case "wrangler":
      if (tail[0] === "delete" || (tail[0] === "pages" && tail[1] === "project" && tail[2] === "delete")) return denyIt(`wrangler ${tail.slice(0, 3).join(" ")}`, never);
      if (["deploy", "publish", "versions", "rollback"].includes(tail[0] ?? "") || (tail[0] === "pages" && tail[1] === "deploy") || (tail[0] === "secret" && tail[1] === "put") || (tail[0] === "d1" && tail[1] === "execute" && /--remote/.test(joined)) || /^kv:key$/.test(tail[0] ?? "") && tail[1] === "delete") return askIt(`wrangler ${tail.slice(0, 2).join(" ")}`, human);
      return [];
    case "vercel":
      if (tail[0] === "rm" || tail[0] === "remove") return denyIt("vercel rm", never);
      if (/--prod\b/.test(joined) || tail[0] === "promote" || tail[0] === "rollback") return askIt("vercel production deploy", human);
      return [];
    case "netlify":
      if (/^sites:delete$/.test(tail[0] ?? "")) return denyIt("netlify sites:delete", never);
      if (tail[0] === "deploy" && /--prod\b/.test(joined)) return askIt("netlify deploy --prod", human);
      return [];
    case "fly":
    case "flyctl":
      if (tail[0] === "apps" && tail[1] === "destroy") return denyIt("fly apps destroy", never);
      if (tail[0] === "deploy" || tail[0] === "scale" || tail[0] === "secrets") return askIt(`fly ${tail[0]}`, human);
      return [];
    case "firebase":
      if (/^projects:delete$/.test(tail[0] ?? "")) return denyIt("firebase projects:delete", never);
      if (tail[0] === "deploy") return askIt("firebase deploy", human);
      return [];
    case "gcloud":
      if (tail.includes("delete")) return denyIt(`gcloud ${tail.slice(0, 3).join(" ")}`, never);
      if (tail.includes("deploy")) return askIt(`gcloud ${tail.slice(0, 3).join(" ")}`, human);
      return [];
    case "aws":
      if (/\b(s3 rb|terminate-instances|delete-db-instance|delete-stack|delete-function|delete-table|delete-bucket|delete-user|delete-role|delete-cluster)\b/.test(joined) || (/\bs3 rm\b/.test(joined) && /--recursive/.test(joined))) return denyIt(`aws ${tail.slice(0, 2).join(" ")}`, never);
      if (/\b(deploy|update-function-code|update-service|put-bucket-policy|s3 sync)\b/.test(joined)) return askIt(`aws ${tail.slice(0, 2).join(" ")}`, human);
      return [];
    case "az":
      if (tail.includes("delete")) return denyIt(`az ${tail.slice(0, 3).join(" ")}`, never);
      if (tail.includes("deploy") || tail.includes("create")) return askIt(`az ${tail.slice(0, 3).join(" ")}`, human);
      return [];
    case "terraform":
    case "tofu":
      if (tail[0] === "destroy" || (tail[0] === "apply" && /-destroy\b/.test(joined))) return denyIt(`${s.cmd} destroy`, never);
      if (tail[0] === "apply" || (tail[0] === "state" && (tail[1] === "rm" || tail[1] === "mv")) || tail[0] === "import") return askIt(`${s.cmd} ${tail.slice(0, 2).join(" ")}`, human);
      return [];
    case "pulumi":
      if (tail[0] === "destroy") return denyIt("pulumi destroy", never);
      if (tail[0] === "up") return askIt("pulumi up", human);
      return [];
    case "kubectl":
      if (tail[0] === "delete" && (tail.includes("namespace") || tail.includes("ns") || /\s(--all|-A|--all-namespaces)\b/.test(joined))) return denyIt("kubectl delete across a namespace", never);
      if (tail[0] === "delete" || tail[0] === "apply" || tail[0] === "drain" || (tail[0] === "rollout" && tail[1] !== "status")) return askIt(`kubectl ${tail.slice(0, 2).join(" ")}`, human);
      return [];
    case "helm":
      if (["install", "upgrade", "uninstall", "delete", "rollback"].includes(tail[0] ?? "")) return askIt(`helm ${tail[0]}`, human);
      return [];
    case "heroku":
      if (/^(apps:destroy|pg:reset)$/.test(tail[0] ?? "")) return denyIt(`heroku ${tail[0]}`, never);
      if (/^(releases:rollback|config:set|container:release)$/.test(tail[0] ?? "")) return askIt(`heroku ${tail[0]}`, human);
      return [];
    case "supabase":
      if ((tail[0] === "db" && tail[1] === "push") || (tail[0] === "functions" && tail[1] === "deploy") || (tail[0] === "secrets" && (tail[1] === "set" || tail[1] === "unset")) || (tail[0] === "migration" && tail[1] === "up" && /--(linked|db-url)/.test(joined))) return askIt(`supabase ${tail.slice(0, 2).join(" ")}`, human);
      return [];
    case "serverless":
    case "sls":
    case "sam":
    case "cdk":
      if (tail[0] === "remove" || tail[0] === "destroy" || (tail[0] === "delete")) return denyIt(`${s.cmd} ${tail[0]}`, never);
      if (tail[0] === "deploy") return askIt(`${s.cmd} deploy`, human);
      return [];
    default:
      return [];
  }
}

/** Snapshot and baseline refresh commands: `vitest -u`, `npm run typecheck:baseline`, `cargo insta accept`. */
function baselineRefreshRules(s: Stage): Decision[] {
  const argv = s.argv;
  const tail = argv.slice(1);
  const runners = new Set(["vitest", "jest", "playwright", "pytest", "ava", "mocha", "bun", "deno", "node"]);
  const updateFlag = tail.some((a) => /^(-u|--update|--updateSnapshot|--update-snapshots|--snapshot-update|--force-update-snapshots)$/.test(a));
  let hit = false;
  if (runners.has(s.cmd) && updateFlag) hit = true;
  else if (s.cmd === "cargo" && tail[0] === "insta" && (tail[1] === "accept" || tail.includes("--accept"))) hit = true;
  else if ((s.cmd === "npm" || s.cmd === "pnpm" || s.cmd === "yarn" || s.cmd === "bun") && (tail[0] === "run" || s.cmd === "yarn") && /baseline|snapshot/i.test(tail[tail[0] === "run" ? 1 : 0] ?? "") && /update|refresh|accept|write|baseline$/i.test(tail[tail[0] === "run" ? 1 : 0] ?? "")) hit = true;
  if (!hit) return [];
  return [ask("shell.write-baseline", `${argv.slice(0, 3).join(" ")} rewrites recorded expectations`, "A baseline or snapshot refreshed to turn a red run green is a deleted regression test. Look at the diff with the user before accepting it.")];
}

// ---------------------------------------------------------------------------
// inline interpreter code and write targets

function interpreterRules(s: Stage): Decision[] {
  if (!s.opaque) return [];
  const code = s.argv.slice(1).join(" ");
  const out: Decision[] = [];
  if (HOOK_PATH_HINT.test(code) && WRITE_HINT.test(code)) {
    const harness = /\.harness[\\/]/.test(code);
    out.push(
      harness
        ? deny("shell.write-harness", `${s.cmd} inline code writes under .harness/`, "`.harness/` is owned by ah. Use `ah bug add`.")
        : deny("shell.hook-tamper", `${s.cmd} inline code touches hook configuration`, "Hook wiring stays as it is. Tell the user if a hook blocks legitimate work."),
    );
  }
  if (DESTRUCTIVE_CODE.test(code)) {
    out.push(ask("shell.interpreter-destructive", `${s.cmd} inline code deletes directory trees`, "Inline code cannot be checked the way a shell command can. Run the deletion as a plain command (`rm -rf <path>`) so the target is visible, or ask the user."));
  }
  return out;
}

function writeTargetsOf(s: Stage): string[] {
  const targets = [...s.writes];
  const positionals = s.argv.slice(1).filter((a) => !a.startsWith("-"));
  switch (s.cmd) {
    case "sed":
      if (s.argv.includes("-i") || s.argv.some((a) => /^-i/.test(a) || a === "--in-place")) {
        const hasScriptFlag = s.argv.some((a) => a === "-e" || a === "-f" || a === "--expression" || a === "--file");
        targets.push(...(hasScriptFlag ? positionals : positionals.slice(1)));
      }
      break;
    case "cp":
    case "mv":
    case "install":
    case "ln":
    case "copy":
    case "move":
    case "copy-item":
    case "move-item":
      if (positionals.length >= 2) targets.push(positionals[positionals.length - 1]);
      break;
    case "truncate":
    case "touch":
    case "mkdir":
    case "new-item":
    case "set-content":
    case "add-content":
    case "out-file":
      targets.push(...positionals.filter((p) => p !== "-s" && !/^\d+$/.test(p)));
      break;
    case "git":
      break;
    default:
      break;
  }
  return targets;
}

function writeRules(target: string, s: Stage, ctx: Context): Decision[] {
  if (isBlockDevice(target)) {
    return [deny("shell.disk-destroy", `${s.cmd} writes to ${target}`, "Raw devices are never written from a coding task.")];
  }
  const info: PathInfo = classifyPath(target, ctx);
  const shown = info.rel ?? info.abs;
  switch (info.category) {
    case "harness":
      return [deny("shell.write-harness", `${s.cmd} writes ${shown} under .harness/`, "`.harness/` is owned by ah. Record incidents with `ah bug add`; rules change in reviewed commits.")];
    case "git-internals":
      return [deny("shell.write-git-internals", `${s.cmd} writes inside .git/ (${shown})`, "Use git commands to change repository state.")];
    case "hook-config":
      return [deny("shell.hook-tamper", `${s.cmd} writes hook configuration ${shown}`, "Hook wiring is how this project enforces its rules. Leave it as it is.")];
    case "lint-config":
      return [deny("shell.write-lint-config", `${s.cmd} writes linter configuration ${shown}`, "Fix the violation in source. Linter configuration changes in a reviewed commit.")];
    case "test-config":
      return [deny("shell.write-test-config", `${s.cmd} writes test configuration ${shown}`, "Fix the failing test. Runner configuration changes in a reviewed commit.")];
    case "lockfile":
      return [deny("shell.write-lockfile", `${s.cmd} writes lockfile ${shown} by hand`, "Run the package manager so the lockfile is generated.")];
    case "baseline":
      return [ask("shell.write-baseline", `${s.cmd} rewrites baseline or snapshot ${shown}`, "A refreshed baseline can hide a regression. Ask the user with the diff in front of them.")];
    case "ci-config":
    case "compiler-config":
    case "env-file":
    case "key-material":
      return [ask("shell.write-ask-path", `${s.cmd} writes ${shown} (${info.category.replace("-", " ")})`, "This file needs a human to confirm the change.")];
    case "home-config":
      return [deny("shell.write-home-config", `${s.cmd} writes ${shown} in the home directory`, "Agent sessions do not change user-level credentials or agent settings. Ask the user.")];
    case "system":
      return [ask("shell.write-system-path", `${s.cmd} writes system path ${shown}`, "System changes need a human. Say exactly what should be written and why.")];
    case "filesystem-root":
    case "home-root":
      return [ask("shell.write-system-path", `${s.cmd} writes to ${shown}`, "Write inside the project.")];
    default:
      return [];
  }
}
