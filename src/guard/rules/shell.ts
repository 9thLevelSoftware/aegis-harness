import { classifyPath, isBlockDevice, protectedInside, wildcardReach, type PathInfo } from "../classify.ts";
import { isPrivateFile, isPublicPem } from "../credentials.ts";
import { ALLOW, ask, deny, onTime, strictest, TimeLimit, type Context, type Decision, type ShellCall } from "../model.ts";
import { globToRegExp, hasVariable, isTempPath, normalize, resolvePath, stripQuotes, trimSeparators } from "../paths.ts";
import { findSecrets, redact } from "../secrets.ts";
import { append, BRACE_LIMIT, flagsOf, MAX_DEPTH, normalizeCmd, parseBudget, parseShell, pwshRun, subcommandIndex, type ParseBudget, type Pipeline, type ShellDialect, type Stage } from "../shell.ts";
import { AH_INIT_VALUED_OPTIONS } from "../../wiring/init-options.ts";

const FORK_BOMB = /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;

const DOWNLOADERS = new Set(["curl", "wget", "fetch", "iwr", "invoke-webrequest", "irm", "invoke-restmethod", "http", "https", "aria2c"]);
const DECODERS = new Set(["base64", "xxd", "openssl"]);
const INTERPRETERS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "python", "python2", "python3", "py", "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "pwsh", "powershell", "iex", "invoke-expression", "source", "."]);
const NETWORK_SINKS = new Set(["curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "telnet", "openssl", "iwr", "invoke-webrequest", "irm", "invoke-restmethod", "http", "https", "mail", "mailx", "sendmail", "scp", "sftp", "ftp", "rsync"]);
const ENV_DUMPERS = new Set(["env", "printenv", "set", "export", "declare"]);
/** Directory listers that dump the environment only when pointed at the `env:` drive (PowerShell). */
const ENV_LISTERS = new Set(["gci", "get-childitem", "dir", "ls"]);
const FILE_READERS = new Set(["cat", "less", "more", "head", "tail", "type", "get-content", "gc", "bat", "strings", "xxd", "hexdump", "od", "base64", "tac", "nl", "view"]);
const REMOVERS = new Set(["rm", "rmdir", "rd", "del", "erase", "remove-item", "ri", "unlink", "shred"]);
const MOVERS = new Set(["mv", "move", "move-item", "mi"]);
/** Rename-Item and cmd's ren take a path and a new name; util-linux and perl `rename` take an expression, then the files. */
const RENAMERS = new Set(["rename-item", "rni", "ren", "rename"]);
const COPIERS = new Set(["cp", "copy", "copy-item", "cpi", "install"]);
const POWER = new Set(["shutdown", "reboot", "halt", "poweroff", "telinit", "stop-computer", "restart-computer"]);
const GIT_HOOKED = new Set(["commit", "push", "merge", "rebase", "cherry-pick", "revert", "am", "apply", "checkout", "switch"]);

const CRED_FILE = /(^|[\\/])(\.env(\.(?!example$|sample$|template$|dist$|defaults$)[^\\/]*)?|\.netrc|\.npmrc|\.pypirc|\.git-credentials|credentials|id_rsa|id_ed25519|id_ecdsa|id_dsa|secrets?\.(json|ya?ml|toml|env)|[^\\/]+\.(pem|key|p12|pfx|jks|keystore))$/i;
/** Files under ~/.ssh that hold private material: everything except public keys, config, known_hosts, authorized_keys, environment and rc. */
/**
 * A file directly inside a `.ssh` directory that is not a public key or one of ssh's own
 * settings files. Worked out from the last two components: a RegExp with `(?!.*\.pub$)` read the
 * rest of the path again at every `.ssh/` in it.
 */
function sshPrivate(p: string): boolean {
  const cut = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  if (cut < 0) return false;
  const dir = p.slice(0, cut);
  const base = p.slice(cut + 1);
  return dir.slice(Math.max(dir.lastIndexOf("/"), dir.lastIndexOf("\\")) + 1).toLowerCase() === ".ssh" && base !== "" && !/\.pub$/i.test(base) && !/^(?:config|known_hosts(?:\.old)?|authorized_keys2?|environment|rc)$/i.test(base);
}

const HOOK_ENV = /^(HUSKY|HUSKY_SKIP_HOOKS|LEFTHOOK|SKIP|PRE_COMMIT_ALLOW_NO_CONFIG|SKIP_SIMPLE_GIT_HOOKS|GIT_HOOKS_SKIP)$/;
/** git config keys that redirect or disable hooks. `hooks.allownonascii` and friends are read by hooks, not bypasses. */
const HOOK_CONFIG_KEY = /^(core\.hookspath|hooks?\.(enabled|disabled|skip)[\w.-]*)(=|$)/i;
const HOOK_PATH_HINT = /\.harness[\\/]|\.claude[\\/]settings|\.claude[\\/]hooks|\.git[\\/]hooks|\.husky|\.codex[\\/]|\.pre-commit-config|lefthook/;
const WRITE_HINT = /\bopen\([^)]*['"][wa]\+?['"]|write(File|FileSync|_text|_bytes|Text|Lines)?\s*\(|\bunlink\b|\bremove\b|\brmtree\b|\brm(Sync)?\s*\(|Set-Content|Out-File|Add-Content|\bos\.system\b|subprocess/;
/** Direct tree-delete calls in inline code: Python, Node (fs already bound), Deno, Perl, Ruby, PowerShell. */
const DESTRUCTIVE_CODE = /shutil\.rmtree\s*\(|\b(?:fs|fsp|promises)\.(?:rm|rmdir|rmSync|rmdirSync)\s*\([^)]*recursive|\brimraf\b|\bDeno\.remove(?:Sync)?\s*\([^)]*recursive|\b(?:rmtree|remove_tree)\b|\bFileUtils\.(?:rm_rf|rm_r|rmtree|remove_dir|remove_entry_secure)\b|Remove-Item[^;|]*-Recurse|\bRemove-Item\b[^;|]*-Force/i;
/** `require("fs")`, `require("node:fs/promises")`, `from "fs"`, `import("fs")`: the module is loaded inline rather than bound to `fs`. */
const NODE_FS_IMPORT = /require\s*\(\s*['"](?:node:)?fs(?:\/promises)?['"]\s*\)|\bfrom\s+['"](?:node:)?fs(?:\/promises)?['"]|\bimport\s*\(\s*['"](?:node:)?fs(?:\/promises)?['"]\s*\)|getBuiltinModule\s*\(\s*['"](?:node:)?fs/i;
const FS_DELETE_CALL = /\.\s*(?:rm|rmdir|rmSync|rmdirSync|unlink|unlinkSync)\s*\(/;
/** Something in the code hands a string to a shell. */
const EXEC_HINT = /\b(?:child_process|execSync|execFileSync|spawnSync|exec|execFile|spawn|system|subprocess|popen|Popen|run|%x|Invoke-Expression|iex|Start-Process)\b|`[^`]*\brm\b/i;
/** A recursive delete spelled as a shell command inside a string or an argv list. */
const DESTRUCTIVE_SHELL = /\brm\s+(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)\b|['"]rm['"]\s*,\s*['"]-[a-zA-Z]*[rR]|\b(?:rd|rmdir)\s+\/s\b|\bdel\s+\/[sq]\b|Remove-Item\b[^;|'"`]*-Recurse/i;
/** Perl deletes a tree when `unlink` is fed by a glob or a directory walk. */
const PERL_WALK = /\bglob\b|<\*|File::Find|\bfind(?:depth)?\s*\(|\breaddir\b|\bopendir\b/;
/** The PowerShell profile variable: `$PROFILE`, `$profile.CurrentUserAllHosts`. A shell rc file, like ~/.bashrc. */
const PWSH_PROFILE = /^\$\{?profile\}?(?:\.[A-Za-z]+)?$/i;

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

  const budget = parseBudget(ctx.deadline ?? Infinity);
  const pipelines = parseShell(raw, { dialect: ctx.shellDialect ?? "posix", budget });
  const at = directories(ctx);
  const where = workingDirs(pipelines, call.cwd === undefined ? ctx : at(ctx, call.cwd), at);
  // Text piped into a shell (`echo 'rm x' | sh`) runs where the pipeline feeding it ran; it is
  // listed after the whole command line, so it is judged from every directory the line visits.
  const everywhere = [...new Set([...where.values()].flat())];
  append(pipelines, pipedCommands(pipelines, budget));
  for (const p of pipelines) {
    for (const c of where.get(p) ?? everywhere) {
      onTime(ctx.deadline);
      append(decisions, pipelineRules(p, c));
    }
  }
  for (const p of pipelines) {
    for (const c of where.get(p) ?? everywhere) {
      for (const s of p.stages) {
        onTime(ctx.deadline);
        append(decisions, stageRules(s, s.chdir === undefined ? c : at(c, s.chdir)));
      }
    }
  }
  return strictest(decisions);
}

// ---------------------------------------------------------------------------
// Working directory

/** Commands that move the rest of the command line to another directory. */
const CHDIR = new Set(["cd", "chdir", "pushd", "set-location", "sl", "push-location"]);
/** Commands that move it back to where a `pushd` left, which the text does not say. */
const CHDIR_BACK = new Set(["popd", "pop-location"]);
/** Past this many directories one command could be in, the guard asks rather than judge it from each. */
const MAX_DIRS = 32;

/**
 * Contexts for the directories a command line visits, each made once: `at(c, dir)` is `c` moved to
 * `dir`, which is absolute or relative to where `c` is.
 */
function directories(root: Context): (c: Context, dir: string) => Context {
  const made = new Map<string, Context>();
  return (c, dir) => {
    const abs = resolvePath(stripQuotes(dir), c.cwd ?? c.projectRoot, c.homeDir, c.platform);
    let moved = made.get(abs);
    if (moved === undefined) made.set(abs, (moved = { ...root, cwd: abs }));
    return moved;
  };
}

/**
 * Where `cd` sends the rest of the command line: the directory, `~` for a bare `cd` (POSIX sh, and
 * PowerShell 7 too), or undefined when the text does not say (`cd "$dir"`, `cd -`).
 */
function chdirTarget(s: Stage): string | undefined {
  const args = s.argv.slice(1);
  const pwsh = s.cmd === "set-location" || s.cmd === "sl" || s.cmd === "push-location";
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") return args[i + 1] ?? "~";
    // `-Path x`, `-LiteralPath x`, `-Path:x` (PowerShell names, any case, any unique prefix).
    const named = /^-(p(?:a(?:t(?:h)?)?)?|l(?:i(?:t(?:e(?:r(?:a(?:l(?:p(?:a(?:t(?:h)?)?)?)?)?)?)?)?)?)?|lp|pspath)(?::(.*))?$/i.exec(a);
    if (named !== null && (pwsh || s.cmd === "cd" || s.cmd === "chdir" || s.cmd === "pushd")) return named[2] ?? args[i + 1];
    if (/^-stackname$/i.test(a)) { i++; continue; }
    if (a === "-") return undefined;
    // sh's `-L`, `-P`, `-e`, `-@`; PowerShell's `-PassThru`; cmd's `/d`.
    if (/^-[LPe@]+$/.test(a) || /^-passthru$/i.test(a) || /^\/d$/i.test(a)) continue;
    return a;
  }
  return "~";
}

/**
 * The directories each pipeline of a command line may run in, following `cd`, `pushd` and
 * `Set-Location` as the shell would: a `cd` moves what follows it in the same list, inside the
 * subshell, group or `sh -c` string it is in. After `&&` the rest runs only where the `cd` led;
 * after `;`, `||` or `&` it may run where the line was, since the `cd` may have failed. A `cd` the
 * text does not resolve leaves every directory the line has been in possible, and a substitution,
 * which the parser lists after the line it sits in, is judged from each of them.
 */
function workingDirs(pipelines: readonly Pipeline[], start: Context, at: (c: Context, dir: string) => Context): Map<Pipeline, Context[]> {
  interface Scope { depth: number; now: Context[]; failed: Context[]; seen: Context[]; last: Context[] }
  const out = new Map<Pipeline, Context[]>();
  const union = (a: readonly Context[], b: readonly Context[]): Context[] => {
    const u = [...new Set([...a, ...b])];
    if (u.length > MAX_DIRS) throw new TimeLimit(`the command moves between more than ${MAX_DIRS} directories, too many to check from each`);
    return u;
  };
  const scopes: Scope[] = [{ depth: pipelines[0]?.depth ?? 0, now: [start], failed: [], seen: [start], last: [start] }];
  for (const p of pipelines) {
    while (scopes.length > 1 && scopes[scopes.length - 1].depth > p.depth) scopes.pop();
    let top = scopes[scopes.length - 1];
    if (p.depth > top.depth) {
      // A group or `sh -c` string follows the command it belongs to; a substitution may sit anywhere in the line.
      const from = p.substitution ? top.seen : top.last;
      scopes.push((top = { depth: p.depth, now: from, failed: [], seen: from, last: from }));
    }
    if (p.after !== "&&") {
      top.now = union(top.now, top.failed);
      top.failed = [];
    }
    out.set(p, top.now);
    top.last = top.now;
    const s = p.stages.length === 1 ? p.stages[0] : undefined;
    if (s === undefined) continue;
    if (CHDIR.has(s.cmd)) {
      const target = chdirTarget(s);
      if (target === undefined || hasVariable(target)) {
        top.now = union(top.now, top.seen);
        continue;
      }
      const next = [...new Set(top.now.map((c) => at(c, target)))];
      top.failed = union(top.failed, top.now);
      top.now = next;
      top.seen = union(top.seen, next);
    } else if (CHDIR_BACK.has(s.cmd)) {
      top.now = union(top.now, top.seen);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Pipelines

function pipelineRules(p: Pipeline, ctx: Context): Decision[] {
  // From the right, so that each stage meets the nearest later sink in one pass, not every later stage.
  const found: Decision[][] = [];
  let interpreter: Stage | undefined;
  let network: Stage | undefined;
  for (let i = p.stages.length - 1; i >= 0; i--) {
    onTime(ctx.deadline);
    const here: Decision[] = [];
    for (const src of members(p.stages[i])) {
      const isDownloader = DOWNLOADERS.has(src.cmd);
      const isDecoder = DECODERS.has(src.cmd) && src.argv.some((a) => /^(-d|--decode|-D|-r|enc)$/.test(a));
      if ((isDownloader || isDecoder) && interpreter !== undefined) {
        here.push(deny("shell.pipe-to-shell", `${src.cmd} output is piped into ${interpreter.cmd}, which runs it as code`, PIPE_TO_SHELL_FIX));
      }
      if (network === undefined) continue;
      const readsCredential = credentialSourceOf(src, ctx) !== null;
      const dumpsEnv = ENV_LISTERS.has(src.cmd)
        ? src.argv.slice(1).some((a) => /^env:/i.test(a))
        : ENV_DUMPERS.has(src.cmd) && (src.argv.length <= 1 || src.argv.slice(1).every((a) => a.startsWith("-")));
      if (readsCredential || dumpsEnv) {
        here.push(deny("shell.credential-exfil", `${describe(src)} is piped into ${network.cmd}`, "Credentials and the environment never leave the machine through an agent session. If a service needs a value, the user configures it."));
      }
    }
    found.push(here);
    for (const sink of members(p.stages[i])) {
      if (INTERPRETERS.has(sink.cmd) && readsStdinAsCode(sink)) interpreter = sink;
      if (NETWORK_SINKS.has(sink.cmd)) network = sink;
    }
  }
  return found.reverse().flat();
}

/**
 * `s`, or every command in a `( )` or `{ }` group: what any of them prints may reach the pipe out of
 * it (`( curl URL | cat ) | sh`), and any of them may read what the pipe into it carries, as in a
 * pipeline without the group.
 */
function members(s: Stage): Stage[] {
  return s.group === undefined ? [s] : s.group.flatMap((p) => p.stages.flatMap(members));
}

/** The commands a pipe into `s` feeds: `s` itself, or for a `( )` or `{ }` group the first command of each pipeline in it. */
function entries(s: Stage): Stage[] {
  return s.group === undefined ? [s] : s.group.flatMap((p) => (p.stages.length > 0 ? entries(p.stages[0]) : []));
}

/** The commands whose output a pipe out of `s` carries: `s`, or for a group the last command of each pipeline in it. */
function exits(s: Stage): Stage[] {
  return s.group === undefined ? [s] : s.group.flatMap((p) => (p.stages.length > 0 ? exits(p.stages[p.stages.length - 1]) : []));
}

/** Shells that run the command lines arriving on stdin, and the dialect they read them in. */
const STDIN_SHELLS: Record<string, ShellDialect> = {
  sh: "posix", bash: "posix", zsh: "posix", dash: "posix", ksh: "posix", mksh: "posix", ash: "posix",
  iex: "powershell", "invoke-expression": "powershell", pwsh: "powershell", powershell: "powershell",
};

/**
 * `echo 'ah init --remove' | sh`, `'ah init --remove' | iex`, `bash <<< 'ah init --remove'`: literal
 * text fed to a shell that runs its stdin is a command line, parsed in that shell's dialect so that
 * every rule sees it.
 */
function pipedCommands(pipelines: readonly Pipeline[], budget: ParseBudget): Pipeline[] {
  const out: Pipeline[] = [];
  for (const p of pipelines) {
    for (let j = 0; j < p.stages.length; j++) {
      const stage = p.stages[j];
      for (const sink of entries(stage)) {
        const dialect = STDIN_SHELLS[sink.cmd];
        if (dialect === undefined || !readsStdinAsCode(sink)) continue;
        // A here-string on a group (`( sh ) <<< 'x'`) feeds the shell inside it.
        const fed = sink.hereStrings.length > 0 ? sink.hereStrings : stage.hereStrings;
        const text = fed.length > 0 ? fed.join("\n") : j > 0 ? outputOf(p.stages[j - 1]) : null;
        if (text === null) continue;
        // The text runs one shell deeper than the pipeline feeding it, so nesting counts on from there.
        const inner = parseShell(text, { dialect, budget, depth: p.depth + 1 });
        append(out, inner);
        append(out, pipedCommands(inner, budget));
      }
    }
  }
  return out;
}

/** What a stage pipes on when its output is literal text; a group pipes on what each command in it prints. */
function outputOf(s: Stage): string | null {
  const printed = exits(s).map(literalOutput).filter((t): t is string => t !== null);
  return printed.length > 0 ? printed.join("\n") : null;
}

const ECHOES = new Set(["echo", "write-output", "write", "printf"]);

/** The text a stage prints when all it prints is literal: `echo`, `printf` and `Write-Output` arguments, or a bare quoted string (PowerShell prints it). */
function literalOutput(s: Stage): string | null {
  const args = s.argv.slice(1);
  if (s.cmd === "printf") {
    const [format = "", ...values] = args;
    let k = 0;
    return format.replace(/%[sb]/g, () => values[k++] ?? "").replace(/\\n/g, "\n");
  }
  // `cat <<'EOF' | sh`: cat with no file passes its here-document through.
  if ((s.cmd === "cat" || s.cmd === "tee") && s.hereStrings.length > 0 && args.every((a) => a.startsWith("-") || s.cmd === "tee")) return s.hereStrings.join("\n");
  if (ECHOES.has(s.cmd)) {
    while (/^-(?:[neE]+|NoEnumerate|InputObject)$/i.test(args[0] ?? "")) args.shift();
    return args.join(" ").replace(/\\n/g, "\n");
  }
  return s.argv.length === 1 && /^\s*['"]/.test(s.raw) ? s.argv[0] : null;
}

/** The command as the reason text names it. A peeled wrapper such as `env` leaves argv empty, so fall back to the command name. */
function describe(s: Stage): string {
  return s.argv.length > 0 ? s.argv.slice(0, 2).join(" ") : s.cmd;
}

const SH_SINKS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"]);
const ALWAYS_CODE_SINKS = new Set(["iex", "invoke-expression", "source", "."]);
/** Flags after which the interpreter runs the given code or module instead of stdin. */
const INLINE_CODE_FLAGS: Record<string, string[]> = {
  python: ["-c", "-m"], python2: ["-c", "-m"], python3: ["-c", "-m"], py: ["-c", "-m"],
  node: ["-e", "--eval", "-p", "--print"], nodejs: ["-e", "--eval", "-p", "--print"], bun: ["-e", "--eval"],
  perl: ["-e", "-E"], ruby: ["-e"], php: ["-r"],
};
/** Flags that take a value which is not the script. */
const INTERPRETER_VALUED_FLAGS = new Set(["-r", "--require", "--import", "--loader", "--experimental-loader", "--env-file", "-W", "-X"]);

/**
 * True when the sink will execute what arrives on stdin: a shell with no script,
 * `python -`, bare `node`, `pwsh -Command -`, `iex`. A sink that runs a named
 * script, module or `-c`/`-e` string merely reads the download as data.
 */
function readsStdinAsCode(sink: Stage): boolean {
  const cmd = sink.cmd;
  const args = sink.argv.slice(1);
  if (ALWAYS_CODE_SINKS.has(cmd)) return true;
  if (SH_SINKS.has(cmd)) {
    // Hand-rolled: `-o pipefail` and `+o` take a value, and `-c` means the command string follows.
    let readsStdin = false;
    const positionals: string[] = [];
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === "--") { append(positionals, args.slice(i + 1)); break; }
      if (a === "--rcfile" || a === "--init-file") { i++; continue; }
      if (/^[-+][A-Za-z]+$/.test(a)) {
        if (a.includes("c")) return false;
        if (a.includes("s")) readsStdin = true;
        if (/[oO]$/.test(a)) i++;
        continue;
      }
      if (a.startsWith("--")) continue;
      positionals.push(a);
    }
    return readsStdin || positionals.length === 0 || positionals[0] === "-";
  }
  if (cmd === "pwsh" || cmd === "powershell") {
    const lower = args.map((a) => a.toLowerCase());
    if (lower.includes("-file") || lower.includes("-f")) return false;
    const ci = lower.findIndex((a) => a === "-command" || a === "-c");
    if (ci >= 0) return args[ci + 1] === undefined || args[ci + 1] === "-";
    return !args.some((a) => !a.startsWith("-"));
  }
  if (cmd === "deno" || cmd === "bun") {
    const p = args.filter((a) => !a.startsWith("-") || a === "-");
    if (cmd === "bun" && args.some((a) => a === "-e" || a === "--eval")) return false;
    if (p.length === 0 || p[0] === "-") return true;
    if (p[0] === "run") return p.length === 1 || p[1] === "-";
    return false;
  }
  const codeFlags = INLINE_CODE_FLAGS[cmd];
  if (!codeFlags) return true;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-") return true;
    if (a === "--") return args[i + 1] === undefined || args[i + 1] === "-";
    if (codeFlags.some((flag) => a === flag || (flag.length === 2 && a.startsWith(flag) && a.length > 2))) return false;
    if (a.startsWith("-")) {
      if (INTERPRETER_VALUED_FLAGS.has(a)) i++;
      continue;
    }
    return false;
  }
  return true;
}

const PIPE_TO_SHELL_FIX = "Download to a file, read it, then run it: `curl -fsSL URL -o install.sh && cat install.sh` first. Running remote content as code runs code nobody reviewed.";

/**
 * Downloaded code run without a pipe: as the command word (`bash -c "$(curl URL)"` and
 * `eval "$(curl URL)"` leave `$(curl URL)` as the command of the code they run), as the script a
 * shell or interpreter is given (`bash <(curl URL)`, `source <(curl URL)`), on its stdin
 * (`bash < <(curl URL)`), and PowerShell's `iex (iwr URL)` and `[scriptblock]::Create((irm URL))`.
 */
function downloadRunRules(s: Stage, ctx: Context): Decision[] {
  let found = DOWNLOAD_RUNS.get(s);
  if (found === undefined) {
    found = downloadRun(s, ctx.deadline);
    DOWNLOAD_RUNS.set(s, found);
  }
  return found === null ? [] : [deny("shell.pipe-to-shell", `${found.source} output is run as code by ${found.runner}`, PIPE_TO_SHELL_FIX)];
}

/** Per stage, not per directory: the answer does not depend on where the command runs. */
const DOWNLOAD_RUNS = new WeakMap<Stage, { runner: string; source: string } | null>();

function downloadRun(s: Stage, deadline: number | undefined): { runner: string; source: string } | null {
  const head = s.argv[0] ?? "";
  if (head.startsWith("$(") || head.startsWith("`")) {
    // A backtick pair is split into words (`` `curl URL` `` reads as "`curl" and "URL`"); `$( )` is one word.
    const source = fetchedIn(head.startsWith("`") ? s.argv.join(" ") : head, "posix", deadline, true);
    if (source !== null) return { runner: "the shell, as the command", source };
  }
  if (s.cmd === "iex" || s.cmd === "invoke-expression" || /\[scriptblock\]::create\s*\(/i.test(s.raw)) {
    const source = fetchedIn(s.cmd === "iex" || s.cmd === "invoke-expression" ? s.argv.slice(1).join(" ") : s.raw, "powershell", deadline);
    if (source !== null) return { runner: s.cmd === "iex" || s.cmd === "invoke-expression" ? s.argv[0] : "[scriptblock]::Create", source };
    return null;
  }
  if (!INTERPRETERS.has(s.cmd)) return null;
  const script = scriptOperand(s);
  if (script !== undefined && script.startsWith("<(")) {
    const source = fetchedIn(script, "posix", deadline);
    if (source !== null) return { runner: s.cmd, source };
  }
  if (readsStdinAsCode(s)) {
    for (const r of s.reads) {
      const source = r.startsWith("<(") ? fetchedIn(r, "posix", deadline) : null;
      if (source !== null) return { runner: s.cmd, source };
    }
  }
  return null;
}

/**
 * The downloader (or decoder) whose output one of `text`'s substitutions prints: `$(curl URL)`,
 * `` `wget -qO- URL` ``, `<(curl URL)`, and in PowerShell `(iwr URL)` and `.DownloadString(URL)`.
 */
function fetchedIn(text: string, dialect: ShellDialect, deadline: number | undefined, firstOnly = false): string | null {
  if (dialect === "powershell" && /\.Download(?:String|Data)\s*\(/i.test(text)) return "WebClient.DownloadString";
  const found = substitutionsIn(text, dialect);
  for (const inner of firstOnly ? found.slice(0, 1) : found) {
    // At any depth: what a substitution inside it prints may be what it prints (`<(echo "$(curl URL)")`).
    for (const p of parseShell(inner, { dialect, budget: parseBudget(deadline ?? Infinity) })) {
      for (const src of p.stages) {
        if (DOWNLOADERS.has(src.cmd)) return src.cmd;
        if (DECODERS.has(src.cmd) && src.argv.some((a) => /^(-d|--decode|-D|-r|enc)$/.test(a))) return src.cmd;
      }
    }
  }
  return null;
}

/** The text inside each top-level `$( )`, `<( )` and backtick pair in `text`, and each `( )` in PowerShell. Quotes are not tracked. */
function substitutionsIn(text: string, dialect: ShellDialect): string[] {
  const out: string[] = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "`" && dialect === "posix") {
      const end = text.indexOf("`", i + 1);
      if (end < 0) break;
      out.push(text.slice(i + 1, end));
      i = end;
      continue;
    }
    const open = text.startsWith("$(", i) || text.startsWith("<(", i) ? i + 2 : dialect === "powershell" && text[i] === "(" ? i + 1 : -1;
    if (open < 0) continue;
    let level = 1;
    let j = open;
    for (; j < text.length && level > 0; j++) {
      if (text[j] === "(") level++;
      else if (text[j] === ")") level--;
    }
    out.push(text.slice(open, level === 0 ? j - 1 : j));
    i = j - 1;
  }
  return out;
}

/** The script a shell or interpreter runs, when the command names one: `bash x.sh`, `source x`, `python3 x.py`; not `-c` code or stdin. */
function scriptOperand(s: Stage): string | undefined {
  const args = s.argv.slice(1);
  if (s.cmd === "source" || s.cmd === ".") return args.find((a) => a !== "--");
  if (s.cmd === "pwsh" || s.cmd === "powershell") {
    const run = pwshRun(s.argv);
    return run !== null && "script" in run ? run.script : undefined;
  }
  if (s.cmd === "deno" || s.cmd === "bun") {
    if (args.some((a) => a === "-e" || a === "--eval" || a === "eval")) return undefined;
    const p = args.filter((a) => !a.startsWith("-"));
    return p[0] === "run" ? p[1] : p[0];
  }
  const sh = SH_SINKS.has(s.cmd);
  const codeFlags = INLINE_CODE_FLAGS[s.cmd] ?? [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") return args[i + 1];
    if (sh && (a === "--rcfile" || a === "--init-file")) { i++; continue; }
    if (sh && /^[-+][A-Za-z]+$/.test(a)) {
      if (a.includes("c")) return undefined;
      if (/[oO]$/.test(a)) i++;
      continue;
    }
    if (codeFlags.some((flag) => a === flag || (flag.length === 2 && a.startsWith(flag) && a.length > 2))) return undefined;
    if (a.startsWith("-") && a !== "-") {
      if (!sh && INTERPRETER_VALUED_FLAGS.has(a)) i++;
      continue;
    }
    return a;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Stages

function stageRules(s: Stage, ctx: Context): Decision[] {
  const out: Decision[] = [];

  if (s.wrappers.includes("sudo") || s.wrappers.includes("doas") || s.cmd === "runas") {
    out.push(ask("shell.privilege-escalation", `${describe(s)} runs with elevated privileges`, "Elevated commands change the machine, not the project. Ask the user to run it, or explain why the project needs it."));
  }

  if (s.tooDeep) {
    out.push(ask("shell.nesting-limit", `part of this command sits more than ${MAX_DEPTH} levels deep in substitutions, subshells or shells it starts, too deep to check`, "Flatten the command so each part can be checked."));
  }

  if (s.unexpanded !== undefined) {
    out.push(ask("shell.brace-expansion-limit", `${s.unexpanded.slice(0, 60)} takes this command's brace expansion past ${BRACE_LIMIT} words, too many to check one by one`, "Spell the paths out, or split the command, so each word can be checked."));
  }

  if (REMOVERS.has(s.cmd)) append(out, removeRules(s, ctx));
  else if (s.cmd === "find") append(out, findRules(s, ctx));
  else if (s.cmd === "git") append(out, gitRules(s, ctx));
  else if (s.cmd === "chmod" || s.cmd === "chown" || s.cmd === "chgrp" || s.cmd === "icacls") append(out, permissionRules(s, ctx));
  else if (s.cmd === "dd" || s.cmd.startsWith("mkfs") || ["mkswap", "wipefs", "fdisk", "sfdisk", "parted", "diskpart", "format"].includes(s.cmd)) append(out, diskRules(s));
  else if (POWER.has(s.cmd) || s.cmd === "init" || s.cmd === "systemctl") append(out, powerRules(s));
  else if (s.cmd === "kill" || s.cmd === "killall5") append(out, killRules(s));
  else if (DOWNLOADERS.has(s.cmd) || ["scp", "rsync", "sftp", "nc", "ncat", "netcat", "socat"].includes(s.cmd)) append(out, uploadRules(s, ctx));
  else if (s.cmd === "docker" || s.cmd === "podman" || s.cmd === "docker-compose") append(out, dockerRules(s));
  else if (["pwsh", "powershell"].includes(s.cmd) && s.opaque) {
    out.push(ask("shell.encoded-command", "PowerShell is given an encoded command", "Pass the command as plain text so it can be reviewed."));
  }

  append(out, credentialReadRules(s, ctx));
  append(out, databaseRules(s));
  append(out, publishRules(s));
  append(out, baselineRefreshRules(s));
  append(out, interpreterRules(s));
  append(out, downloadRunRules(s, ctx));
  append(out, ahCliRules(s));
  append(out, nestedAgentRules(s));
  append(out, moveSourceRules(s, ctx));
  append(out, copySourceRules(s, ctx));

  // A redirected group is a `:` stand-in carrying the redirections; its reasons name the group.
  const writer = s.group === undefined ? s : { ...s, cmd: /^\s*\{/.test(s.raw) ? "{ ... }" : "( ... )" };
  const whole = recursiveCopy(s);
  for (const target of writeTargetsOf(s, ctx.deadline)) {
    onTime(ctx.deadline);
    append(out, writeRules(target, writer, ctx, whole));
  }
  return out;
}

/** A copy or move that takes directories whole: `cp -r`, `cp -a`, `Copy-Item -Recurse`, `rsync -a`, and every `mv`. */
function recursiveCopy(s: Stage): boolean {
  if (MOVERS.has(s.cmd)) return true;
  if (!COPIERS.has(s.cmd) && s.cmd !== "rsync") return false;
  return s.argv.slice(1).some((a) => /^-[a-zA-Z]*[rRa]/.test(a) && !a.startsWith("--") || /^--(recursive|archive)$/.test(a) || /^-rec(u(r(s(e)?)?)?)?$/i.test(a));
}

/**
 * Past this many paths, or this many characters of them, made by joining one list to another
 * (find's starts with its names, New-Item's paths with its names), the guard asks rather than
 * build them all: a few hundred KB of command could otherwise name billions. The lists come in
 * without repeats, so the joined paths need no Set, which hashes a string over 16 K characters
 * by its length alone and grows in the square of how many there are.
 */
const MAX_JOINED = 100_000;
const MAX_JOINED_CHARS = 10_000_000;

function joinAll(dirs: readonly string[], names: readonly string[], out: string[]): void {
  const sum = (xs: readonly string[]) => xs.reduce((n, x) => n + x.length + 1, 0);
  if (dirs.length * names.length > MAX_JOINED || names.length * sum(dirs) + dirs.length * sum(names) > MAX_JOINED_CHARS) {
    throw new TimeLimit(`it names more than ${MAX_JOINED} paths, or ${MAX_JOINED_CHARS} characters of them`);
  }
  if (dirs.length === 0 || names.length === 0) return;
  const trimmed = dirs.map(trimSeparators);
  for (const n of names) for (const d of trimmed) out.push(`${d}/${n}`);
}

// ---------------------------------------------------------------------------
// rm and friends

interface RemoveSpec {
  recursive: boolean;
  targets: string[];
  noPreserveRoot: boolean;
  /** Remove-Item's `-Include` and `-Filter` patterns, which narrow what the targets remove. */
  filters?: string[];
}

/**
 * Remove-Item parameters whose value is no path to delete: the filters (`-Include *.js` narrows
 * `-Path`, `-Exclude` names what stays) and the common parameters that take a value. PowerShell
 * takes any unambiguous prefix of a parameter's name.
 */
const PWSH_VALUED_PARAMS: readonly (readonly [string, number])[] = [
  ["include", 3], ["exclude", 2], ["filter", 2], ["credential", 2], ["stream", 1],
  ["erroraction", 6], ["errorvariable", 6], ["warningaction", 8], ["warningvariable", 8],
  ["informationaction", 12], ["informationvariable", 12], ["outvariable", 4], ["outbuffer", 4],
  ["pipelinevariable", 2], ["progressaction", 2],
];
const PWSH_VALUED_ALIASES = new Set(["ea", "ev", "wa", "wv", "infa", "iv", "ov", "ob", "pv", "proga"]);

function pwshValuedParam(a: string): boolean {
  const m = /^-([a-z]+)$/i.exec(a);
  if (m === null) return false;
  const p = m[1].toLowerCase();
  return PWSH_VALUED_ALIASES.has(p) || PWSH_VALUED_PARAMS.some(([name, min]) => p.length >= min && name.startsWith(p));
}

/**
 * Remove-Item's words with each `( )` subexpression put back together: `(Join-Path . 'dist')`
 * arrives as three words. A `Join-Path base child` becomes the path it builds; any other
 * subexpression becomes `$( )`, a value that cannot be checked.
 */
function pwshWords(argv: readonly string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("(") && !a.startsWith("$(")) { out.push(a); continue; }
    let group = a;
    let level = 0;
    for (const c of a) level += c === "(" ? 1 : c === ")" ? -1 : 0;
    while (level > 0 && i + 1 < argv.length) {
      const next = argv[++i];
      group += ` ${next}`;
      for (const c of next) level += c === "(" ? 1 : c === ")" ? -1 : 0;
    }
    const join = /^\(\s*join-path\s+(?:-path\s+)?([^\s()]+)\s+(?:-childpath\s+)?([^\s()]+)\s*\)$/i.exec(group);
    out.push(join !== null ? `${join[1]}\\${join[2]}` : group.startsWith("$(") ? group : `$${group}`);
  }
  return out;
}

function removeSpec(s: Stage, dialect: ShellDialect | undefined): RemoveSpec {
  const argv = s.argv.slice(1);
  // An alias (`rm`, `del`) given PowerShell parameters, or in a PowerShell command line a `( )` subexpression.
  const pwshStyle = s.cmd === "remove-item" || s.cmd === "ri" || argv.some((a) => /^-(Recurse|Force|fo|Path|LiteralPath|WhatIf|Confirm|Include|Exclude|Filter)$/i.test(a) || (dialect === "powershell" && a.startsWith("(")));
  if (pwshStyle) {
    const targets: string[] = [];
    const filters: string[] = [];
    let recursive = false;
    const words = pwshWords(argv);
    for (let i = 0; i < words.length; i++) {
      const a = words[i];
      // `-rf` is no PowerShell parameter, but an `rm -rf` that reached here is recursive.
      if (/^-(recurse|rec|r)$/i.test(a) || /^-(?=[rRfidv]*[rR])[rRfidv]{2,5}$/.test(a)) recursive = true;
      else if (/^-(inc|incl|inclu|includ|include|fi|fil|filt|filte|filter)$/i.test(a)) {
        if (words[i + 1] !== undefined) append(filters, words[i + 1].split(",").map((f) => f.trim()).filter((f) => f !== ""));
        i++;
      } else if (pwshValuedParam(a)) i++;
      else if (/^-(path|literalpath|lp|p)$/i.test(a)) {
        const v = argv[i + 1];
        if (v !== undefined) append(targets, v.split(","));
        i++;
      } else if (/^-(path|literalpath):(.+)$/i.test(a)) append(targets, a.replace(/^-[a-z]+:/i, "").split(","));
      else if (!a.startsWith("-")) append(targets, a.startsWith("$(") ? [a] : a.split(","));
    }
    return { recursive, targets, noPreserveRoot: false, filters };
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
  const spec = removeSpec(s, ctx.shellDialect);
  const out: Decision[] = [];
  if (spec.noPreserveRoot) {
    out.push(deny("shell.rm-recursive-root", `${s.cmd} --no-preserve-root`, "Nothing in a project needs the filesystem root deleted."));
  }
  const destructive = spec.recursive || s.cmd === "del" || s.cmd === "erase" || s.cmd === "shred";
  // `Remove-Item * -Include *.log` removes the matching files in the working directory, not all of
  // it: without -Recurse each pattern is judged as the path it names there. With -Recurse the
  // patterns apply at every depth, where a protected file may match them, so the wipe is judged.
  const filters = spec.filters ?? [];
  const narrowed = !spec.recursive && filters.length > 0 && filters.every((f) => !/^\*(\.\*)?$/.test(f));
  const targets = narrowed ? spec.targets.flatMap((t) => (CWD_WIPE_LITERAL.test(stripQuotes(t)) ? filters : [t])) : spec.targets;
  for (const t of targets) out.push(judgeRemoveTarget(t, destructive, spec.recursive, s, ctx));
  return out;
}

const ROOT_LITERAL = /^(\/|\/\*|\\|\\\*|[A-Za-z]:\\?\*?|[A-Za-z]:\/\*?)$/;
const HOME_LITERAL = /^(~|~\/\*?|~\\\*?|\$HOME([\\/]\*?)?|\$\{HOME(:[?-][^}]*)?\}([\\/]\*?)?|%USERPROFILE%([\\/]\*?)?|\$\{?env:(USERPROFILE|HOME|HOMEPATH)\}?([\\/]\*?)?|\$\{?env:HOMEDRIVE\}?\$\{?env:HOMEPATH\}?([\\/]\*?)?|%HOMEDRIVE%%HOMEPATH%([\\/]\*?)?)$/i;
/** The working directory and its "everything inside" globs, the hidden-file idioms (`.[!.]*`, `.[!.]?*`, `.??*`, `.?*`, `.???*`) included. */
const CWD_WIPE_LITERAL = /^(\.|\.\/|\.\\|\.\/\*|\.\\\*|\*|\*\.\*|\.\*|\*\*|\.\.|\.\.\/|\.\.\\|\.\.\/\*|:\/|(?:\.[\\/])?\.(?:\[[!^]\.\]|\?)[?*]*\*[\\/]*)$/;
/** A leading expansion that names the home directory. Rewritten to `~` so the rest of the path is classified. */
const HOME_PREFIX = /^(?:\$\{HOME(?::[?-][^}]*)?\}|\$HOME|\$\{?env:USERPROFILE\}?|%USERPROFILE%)(?=[\\/])/i;
/** A leading expansion that names the working directory. Rewritten to `.` so the rest of the path is classified. */
const CWD_PREFIX = /^(?:\$\{PWD(?::[?-][^}]*)?\}|\$PWD|\$\(\s*pwd\s*\)|`\s*pwd\s*`|%CD%)(?=[\\/])/;
const CWD_PREFIX_ANY_CASE = new RegExp(CWD_PREFIX.source, "i");
/** A guarded expansion (`VAR:?unset` in braces) or a command substitution: unverifiable, but safe once a literal sub-path follows. */
const GUARDED_PREFIX = /^(?:\$\{[A-Za-z_][A-Za-z0-9_]*:\?[^}]*\}|\$\([^()]*(?:\([^()]*\)[^()]*)*\)|`[^`]*`)(?=[\\/])/;
const SUBSTITUTION = /\$\(|`/;
/** "Everything inside" last components: `dir/*`, `dir/.*`, `dir/**`, `dir/*.*`, `dir/.`, `dir\*`, and the hidden-file globs (`dir/.[!.]*`, `dir/.[!.]?*`, `dir/.??*`, `dir/.?*`). */
const WIPE_PART = /^(?:\*|\.\*|\*\*|\*\.\*|\.|\.(?:\[[!^]\.\]|\?)[?*]*\*)$/;

const UNRESOLVED_REMEDIATION = "An empty or wrong variable turns this into `rm -rf /`. Use a literal path (`rm -rf dist`), anchor it to the working directory (`rm -rf \"$PWD/dist\"`), or brace the variable with a `:?unset` guard and append a sub-path, so an empty value aborts instead of deleting the parent.";
const SUBSTITUTION_REMEDIATION = "A command substitution cannot be checked before it runs. Use a literal path (`rm -rf dist`), or append a sub-path to the substitution (`rm -rf \"$(pwd)/dist\"`) so an empty result cannot delete the parent.";

/** Braced expansions shown as `$NAME` so reason text never carries `${`. */
function shownTarget(t: string): string {
  return t.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}/g, "$$$1");
}

/** The part of a target after a known prefix: non-empty, literal, inside that prefix, and not a wipe glob. */
function safeSubPath(rest: string): boolean {
  const sub = rest.replace(/^[\\/]+/, "");
  if (sub === "" || hasVariable(sub) || SUBSTITUTION.test(sub)) return false;
  const n = normalize(sub);
  return n !== "." && n !== ".." && !n.startsWith("../") && !CWD_WIPE_LITERAL.test(n);
}

/**
 * Strip trailing `/*`, `/.*`, `/**`, `/.` (and the Windows forms), repeatedly, so `dir/./*` becomes
 * `dir`. One walk back from the end: a RegExp ending in `[\\/]*$` read a long run of separators
 * again from each of them, and stripping one suffix at a time copied the path for each.
 */
function stripWipeSuffix(t: string): string {
  const sep = (i: number) => t[i] === "/" || t[i] === "\\";
  let end = t.length;
  for (;;) {
    let e = end;
    while (e > 0 && sep(e - 1)) e--;
    let start = e;
    while (start > 0 && !sep(start - 1)) start--;
    if (start === 0 || !WIPE_PART.test(t.slice(start, e))) return t.slice(0, end);
    let before = start;
    while (before > 0 && sep(before - 1)) before--;
    if (before === 0) return "/"; // `//*` is the root's contents
    end = before;
  }
}

/**
 * A path whose removal, move or permission change takes a whole directory
 * with it: one that holds hook wiring or agent settings counts as them
 * (`rm -rf .claude` removes `.claude/settings.json`), and a wildcard counts
 * as the protected path it expands to (`rm .claude/*`). `whole` is false for
 * a non-recursive rm, which leaves the directories a wildcard matches alone.
 */
function classifyWhole(t: string, ctx: Context, whole = true): PathInfo {
  const info = classifyPath(t, ctx);
  if (info.category !== "normal" && info.category !== "temp" && info.category !== "outside-project") return info;
  const inside = protectedInside(info.abs, ctx);
  if (inside !== undefined) return { ...info, category: inside.category, matched: `it holds ${inside.matched}` };
  return wildcardReach(t, ctx, whole) ?? info;
}

/**
 * `rename` is true for Rename-Item, ren and rename, which keep the file where
 * it is: wiping the working directory is not something they can do.
 */
function judgeRemoveTarget(target: string, destructive: boolean, recursive: boolean, s: Stage, ctx: Context, rename = false): Decision {
  let t = stripQuotes(target);
  if (t === "" || t === "--") return ALLOW;

  // `$HOME/x`, `$env:USERPROFILE\x`, `$PWD/x`, `$(pwd)/x`: the prefix is known, so classify the rest like `~/x` or `./x`.
  const home = HOME_PREFIX.exec(t);
  // PowerShell's variable names ignore case (`$pwd\dist`); bash's do not, where `$pwd` is another, likely empty, variable.
  const cwd = home ? null : (ctx.shellDialect === "powershell" ? CWD_PREFIX_ANY_CASE : CWD_PREFIX).exec(t);
  if (home) t = `~${t.slice(home[0].length)}`;
  else if (cwd) t = `.${t.slice(cwd[0].length)}`;

  if (ROOT_LITERAL.test(t)) {
    return deny("shell.rm-recursive-root", `${s.cmd} targets the filesystem root (${t})`, "Nothing in a project needs the filesystem root deleted. Name the specific directory.");
  }
  if (HOME_LITERAL.test(t)) {
    return deny("shell.rm-recursive-home", `${s.cmd} targets the home directory (${shownTarget(t)})`, "Deleting the home directory destroys the user's machine state. Name the specific directory inside the project.");
  }
  if (CWD_WIPE_LITERAL.test(t) && !rename) {
    if (!(recursive || /\*/.test(t) || s.cmd === "del" || s.cmd === "erase")) return ALLOW;
    // Where the agent's working directory is known and is not the project root (`cd dist && rm -rf *`),
    // what goes is that directory's contents, judged like the directory itself below.
    if (ctx.cwd === undefined || classifyPath(ctx.cwd, ctx).category === "project-root") {
      return deny("shell.rm-recursive-cwd", `${s.cmd} ${t} wipes the working directory`, "Delete specific paths (for example `rm -rf dist node_modules`), or join the cd with && (`cd dist && rm -rf *`) so nothing is deleted if the cd fails. If the whole tree must go, the user does that.");
    }
    t = ctx.cwd;
  }
  // `"${VAR:?unset}/sub"` or `"$(git rev-parse --show-toplevel)/sub"`: an empty value aborts, so the
  // sub-path is what gets deleted. Classify it as if it were under the working directory, so
  // `.../dist` passes and `.../.git` is still a repository delete.
  const guarded = GUARDED_PREFIX.exec(t);
  if (guarded && safeSubPath(t.slice(guarded[0].length))) t = `./${t.slice(guarded[0].length).replace(/^[\\/]+/, "")}`;
  if (hasVariable(t) || SUBSTITUTION.test(t)) {
    if (isTempPath(t)) return ALLOW;
    if (recursive) {
      const substitution = SUBSTITUTION.test(t) && !hasVariable(t);
      return ask("shell.rm-unresolved-variable", `${s.cmd} -r on ${shownTarget(t)}, whose value cannot be verified`, substitution ? SUBSTITUTION_REMEDIATION : UNRESOLVED_REMEDIATION);
    }
    return ALLOW;
  }

  // `rm -rf <dir>/*` is the same act as `rm -rf <dir>` when <dir> is the project, the home or the root.
  const base = stripWipeSuffix(t);
  if (base !== t && !rename) {
    const parent = classifyPath(base, ctx);
    if (parent.category === "filesystem-root") {
      return deny("shell.rm-recursive-root", `${s.cmd} ${t} empties the filesystem root`, "Nothing in a project needs the filesystem root emptied. Name the specific directory.");
    }
    if (parent.category === "home-root") {
      return deny("shell.rm-recursive-home", `${s.cmd} ${t} empties the home directory`, "Emptying the home directory destroys the user's machine state. Name the specific directory inside the project.");
    }
    if (parent.category === "project-root" && (destructive || /\*/.test(t))) {
      return deny("shell.rm-recursive-cwd", `${s.cmd} ${t} empties the project root`, "Delete specific paths (for example `rm -rf dist node_modules`). If the whole tree must go, the user does that.");
    }
  }

  const info = classifyWhole(t, ctx, recursive || destructive);
  switch (info.category) {
    case "filesystem-root":
      return deny("shell.rm-recursive-root", `${s.cmd} targets the filesystem root (${t})`, "Nothing in a project needs the filesystem root deleted.");
    case "home-root":
      return deny("shell.rm-recursive-home", `${s.cmd} targets the home directory (${t})`, "Deleting the home directory destroys the user's machine state.");
    case "project-root":
      return destructive && !rename ? deny("shell.rm-recursive-cwd", `${s.cmd} ${t} wipes the project`, "Delete specific paths instead.") : ALLOW;
    case "git-internals": {
      const rel = (info.gitRel ?? "").toLowerCase();
      // A stale lock file (`index.lock`, `HEAD.lock`, `refs/heads/x.lock`) is the one thing under .git/ git itself tells the user to remove.
      if (rel !== ".git" && /\.lock$/i.test(rel)) return ALLOW;
      return rel === ".git"
        ? deny("shell.rm-git-dir", `${s.cmd} ${t} removes the .git directory and with it the repository's history`, "Use git commands (git stash, git checkout, git reset --keep) to change state; never delete .git.")
        : deny("shell.rm-git-dir", `${s.cmd} ${t} removes repository state inside .git/`, "Use git commands (git stash, git checkout, git reset --keep) to change repository state; never delete files under .git/. A stale `*.lock` file is the one exception and is allowed.");
    }
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

/** Tests that narrow a `find -delete` to a subset of the tree. `-type f` does not: it deletes every file. */
const FIND_FILTERS = /^-(i?name|i?path|i?regex|i?wholename|i?lname|newer\w*|[acm](time|min|newer)|size|empty|user|group|perm|samefile)$/;
/**
 * A filter value that matches everything, so the filter narrows nothing: a glob made only of
 * wildcards with at least one `*` (`*`, `?*`, `**`, `*\/*`, with or without a leading `./`), or
 * the regexes `.*` and `.+`. `?`, `*.pyc` and `*\/*.o` still narrow.
 */
const FIND_MATCH_ALL = /^(?:(?:\.\/)?(?:[*?]*\*[*?]*|\*\/\*)|\^?\.[*+]\$?)$/;

/**
 * For an action at `actionAt`, which words before it are filters that actually narrow the delete:
 * the filter precedes the action (`-delete` placed first runs on every entry), is not negated
 * (`! -name x` matches everything else), is not a catch-all (`-name '*'`), and has no `-o` between
 * it and the action in the group that joins them (`-name x -o -delete` and `-name x -prune -o
 * -delete` act on the other branch). Each group that holds the filter but not the action must
 * narrow as a whole: `\( -name a -o -name b \) -delete` deletes only those two names,
 * `\( -name a -o -type f \) -delete` deletes every file. All that does not depend on the action
 * is worked out once, so each action costs one pass back from it.
 */
function narrowingFilters(argv: readonly string[], value: readonly boolean[], deadline: number | undefined): (actionAt: number) => boolean[] {
  // Only words find reads as its expression count: `-name '('` names a file called `(`.
  const is = (j: number, re: RegExp) => !value[j] && re.test(argv[j] ?? "");
  const negated = (j: number) => is(j - 1, /^(!|-not)$/);
  // `,` runs both sides, so like `-o` it puts a filter and the action in different branches.
  const or = argv.map((_, j) => is(j, /^(-o|-or|,)$/));
  // The depth before each word, and where each `(` closes.
  const depth = new Array<number>(argv.length + 1);
  const closeAt = new Map<number, number>();
  const opens: number[] = [];
  let d = 0;
  for (let j = 0; j < argv.length; j++) {
    if ((j & 4095) === 0) onTime(deadline);
    depth[j] = d;
    if (is(j, /^\($/)) {
      opens.push(j);
      d++;
    } else if (is(j, /^\)$/)) {
      d--;
      const o = opens.pop();
      if (o !== undefined) closeAt.set(o, j);
    }
  }
  depth[argv.length] = d;
  // Whether each closed group, not negated, matches only what some filter in it names: every `-o`
  // branch must hold a filter (or a group that does) that is not negated and not a catch-all.
  // `-type f`, `-true` or `! -name x` alone narrow nothing. Groups close inner first, so a group's
  // inner groups are judged before it, and each word is looked at for one group only.
  const groupNarrows = new Map<number, boolean>();
  for (const [o, c] of closeAt) {
    onTime(deadline);
    let branch = false;
    let narrows = false;
    for (let j = o + 1; j <= c; j++) {
      if (j === c || or[j]) {
        if (!branch) break;
        narrows = j === c;
        branch = false;
        continue;
      }
      if (closeAt.has(j)) {
        if (groupNarrows.get(j) === true) branch = true;
        j = closeAt.get(j) ?? c;
      } else if (is(j, /^-empty$/)) {
        if (!negated(j)) branch = true;
      } else if (is(j, FIND_FILTERS)) {
        if (!negated(j) && !FIND_MATCH_ALL.test(argv[j + 1] ?? "")) branch = true;
        // Step over its value, never over a `(` that a filter find would refuse left valueless.
        if (value[j + 1]) j++;
      }
    }
    groupNarrows.set(o, narrows && !negated(o));
  }
  // Each filter that narrows on its own, and the first place a group holding it closes without
  // narrowing: an action past that place is out of the filter's reach. A group never closed holds
  // every action after it.
  const filter = new Array<boolean>(argv.length).fill(false);
  const reach = new Array<number>(argv.length).fill(Infinity);
  const stack = [Infinity];
  for (let j = 0; j < argv.length; j++) {
    if ((j & 4095) === 0) onTime(deadline);
    const top = stack[stack.length - 1];
    if (is(j, /^\($/)) {
      const c = closeAt.get(j);
      stack.push(c !== undefined && groupNarrows.get(j) !== true ? Math.min(top, c) : top);
    } else if (is(j, /^\)$/)) {
      if (stack.length > 1) stack.pop();
    } else {
      filter[j] = is(j, FIND_FILTERS) && !negated(j) && (argv[j] === "-empty" || !FIND_MATCH_ALL.test(argv[j + 1] ?? ""));
      reach[j] = top;
    }
  }
  return (actionAt) => {
    const out = new Array<boolean>(actionAt).fill(false);
    // The group that joins a filter to the action is the shallowest depth on the way; an `-o` at that depth splits them.
    let joint = depth[actionAt];
    const ors = new Set<number>();
    for (let j = actionAt - 1; j >= 0; j--) {
      if ((j & 4095) === 0) onTime(deadline);
      out[j] = filter[j] && reach[j] > actionAt && !ors.has(joint);
      joint = Math.min(joint, depth[j]);
      if (or[j]) ors.add(depth[j]);
    }
    return out;
  };
}

/** Find words that take the next word as their value; -fprintf takes two, and -exec and its kin every word up to `;` or `{} +`. */
const FIND_VALUED = /^-(i?name|i?path|i?regex|i?wholename|i?lname|newer|anewer|cnewer|newer[aBcmt][aBcmt]|[acm](time|min)|used|size|user|group|uid|gid|perm|samefile|x?type|maxdepth|mindepth|fstype|inum|links|printf|fprint0?|fls|context|regextype|files0-from)$/;

/** Per word of find's arguments, true where it is another word's value rather than part of the expression. */
function findValues(argv: readonly string[]): boolean[] {
  const value = new Array<boolean>(argv.length).fill(false);
  for (let j = 0; j < argv.length; j++) {
    const a = argv[j];
    if (/^-(exec|execdir|ok|okdir)$/.test(a)) {
      let k = j + 1;
      for (; k < argv.length && argv[k] !== ";" && !(argv[k] === "+" && argv[k - 1] === "{}"); k++) value[k] = true;
      if (k < argv.length) value[k] = true;
      j = k;
    } else if (a === "-fprintf") {
      value.fill(true, j + 1, Math.min(j + 3, argv.length));
      j += 2;
    } else if (FIND_VALUED.test(a) && j + 1 < argv.length) value[++j] = true;
  }
  return value;
}

/** Past this many actions in one find, the guard does not work out what each deletes and judges the starts whole. */
const FIND_MAX_ACTIONS = 16;

function findRules(s: Stage, ctx: Context): Decision[] {
  const argv = s.argv.slice(1);
  const value = findValues(argv);
  const actions: number[] = [];
  argv.forEach((a, i) => {
    if (!value[i] && (a === "-delete" || (/^-exec(dir)?$/.test(a) && REMOVERS.has((argv[i + 1] ?? "").replace(/^\\/, ""))))) actions.push(i);
  });
  if (actions.length === 0) return [];
  // `-H`, `-L`, `-P`, `-D opts` and `-O3` come before the starting points.
  let k = 0;
  while (k < argv.length && /^-([HLP]|O\d*|D)$/.test(argv[k])) k += argv[k] === "-D" ? 2 : 1;
  const starts: string[] = [];
  for (const a of argv.slice(k)) {
    if (a.startsWith("-") || a === "(" || a === "!") break;
    starts.push(a);
  }
  if (starts.length === 0) starts.push(".");
  const stage = { ...s, cmd: "find -delete" };
  // Every action must be narrowed: `-name foo -delete -o -delete` deletes everything else too.
  const narrowedAt = actions.length > FIND_MAX_ACTIONS ? null : narrowingFilters(argv, value, ctx.deadline);
  const narrowing = narrowedAt === null ? [] : actions.map(narrowedAt);
  if (narrowing.length > 0 && narrowing.every((n) => n.includes(true))) {
    // A filter narrows what goes, but not where: a start inside a protected directory, or a filter
    // that names a protected file outright, still deletes it. A filter on the other side of `-o`
    // (`-path ./.git -prune -o ...`) keeps what it names.
    const named: string[] = [];
    const names = new Set<string>();
    for (let i = 0; i < argv.length; i++) {
      if ((i & 4095) === 0) onTime(ctx.deadline);
      if (!narrowing.some((n) => n[i])) continue;
      const v = argv[i + 1] ?? "";
      if (/^-i?name$/.test(argv[i]) && !/[*?[]/.test(v)) names.add(v);
      if (/^-i?(path|wholename)$/.test(argv[i]) && !/[*?[]/.test(v)) named.push(v);
    }
    const distinct = [...new Set(starts)];
    joinAll(distinct, [...names], named);
    const guarded = new Set(["git-internals", "harness", "hook-config", "home-config", "lint-config", "test-config"]);
    const out: Decision[] = [];
    for (const t of [...distinct, ...named]) {
      onTime(ctx.deadline);
      if (!guarded.has(classifyWhole(t, ctx).category)) continue;
      const d = judgeRemoveTarget(t, false, false, stage, ctx);
      if (d.verdict !== "allow") out.push(d);
    }
    return out;
  }
  return starts.map((t) => judgeRemoveTarget(t, true, true, stage, ctx));
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
    const value = v.trim();
    // husky and lefthook disable themselves only on 0; 1 and 2 enable or add debug output.
    if (k === "HUSKY" || k === "LEFTHOOK") {
      if (value !== "0") continue;
    } else if (value === "" || value === "0" || /^false$/i.test(value)) {
      continue;
    }
    return `${k}=${v}`;
  }
  return null;
}

function gitRules(s: Stage, ctx: Context): Decision[] {
  const out: Decision[] = [];
  const argv = s.argv;
  let i = 1;
  // `git -C dir rm x` removes dir/x; each -C is taken relative to the one before.
  let cdir = "";
  while (i < argv.length && argv[i].startsWith("-")) {
    const a = argv[i];
    if (a === "-c" && HOOK_CONFIG_KEY.test(argv[i + 1] ?? "")) {
      out.push(deny("shell.hook-bypass", `git -c ${argv[i + 1]} disables hooks for this command`, HOOK_BYPASS_REMEDIATION));
    }
    if (a === "-C" && argv[i + 1]) cdir = /^([\\/~]|[A-Za-z]:)/.test(argv[i + 1]) ? argv[i + 1] : cdir === "" ? argv[i + 1] : `${cdir}/${argv[i + 1]}`;
    if (["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"].includes(a)) i += 2;
    else i++;
  }
  const sub = argv[i];
  if (sub === undefined) return out;
  const rest = argv.slice(i + 1);
  const at = (p: string): string => (cdir === "" || /^([\\/~]|[A-Za-z]:)/.test(p) ? p : `${cdir}/${p}`);
  /** git rm, git mv and git clean delete from the work tree like rm and mv do. */
  const removes = (paths: string[], destructive: boolean, recursive: boolean): void => {
    for (const p of paths) {
      const d = judgeRemoveTarget(at(p), destructive, recursive, { ...s, cmd: `git ${sub}` }, ctx);
      // git touches only its own repository, which a subdirectory session shares with the paths above it.
      if (d.verdict !== "allow" && d.rule !== "shell.rm-outside-project") out.push(d);
    }
  };

  // Only the commands that run hooks take --no-verify; elsewhere (`git grep -e --no-verify`, `git log -S`) it is a search term.
  if (HOOK_RUNNERS.has(sub) && rest.includes("--no-verify")) {
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
      append(out, pushRules(rest, ctx));
      break;
    case "reset":
      if (rest.includes("--hard")) {
        out.push(deny("shell.git-discard-changes", "git reset --hard discards uncommitted work", "Run `git stash push -u` first if the changes might matter, use `git reset --keep`, or revert specific files after reading `git diff`."));
      }
      break;
    case "clean": {
      const f = flagsOf(rest, 0, ["-e", "--exclude"]);
      const dry = f.short.has("n") || f.long.has("dry-run") || f.short.has("i") || f.long.has("interactive");
      const ignoredOnly = f.short.has("X") && !f.short.has("x");
      const scoped = f.positionals.length > 0 && !f.positionals.some((p) => WIPE_PATHSPEC.test(p));
      if (!dry && !ignoredOnly && !scoped && (f.short.has("f") || f.long.has("force"))) {
        out.push(deny("shell.git-clean", `git clean ${rest.join(" ")} removes every untracked file in the tree`, "Run `git clean -n` to list what would go, then clean named paths (`git clean -f -- dist/`) or only ignored files (`git clean -fdX`). Untracked files may be the user's uncommitted work."));
      }
      if (!dry && scoped && (f.short.has("f") || f.long.has("force"))) removes(f.positionals, true, f.short.has("d"));
      break;
    }
    case "rm": {
      // --cached only untracks; the file stays where it is.
      const f = flagsOf(rest, 0, ["--pathspec-from-file"]);
      if (!f.long.has("cached") && !f.short.has("n") && !f.long.has("dry-run")) removes(f.positionals, f.short.has("r"), f.short.has("r"));
      break;
    }
    case "mv": {
      const f = flagsOf(rest, 0);
      if (f.short.has("n") || f.long.has("dry-run") || f.positionals.length < 2) break;
      removes(f.positionals.slice(0, -1), true, false);
      append(out, writeRules(at(f.positionals[f.positionals.length - 1]), { ...s, cmd: "git mv" }, ctx));
      break;
    }
    case "checkout":
      append(out, checkoutRules(rest));
      break;
    case "switch":
      append(out, switchRules(rest));
      break;
    case "restore":
      append(out, restoreRules(rest));
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
      out.push(deny("shell.git-rewrite-history", `git ${sub} rewrites history`, "History rewrites are a human decision made with a backup in hand."));
      break;
    case "replace": {
      const f = flagsOf(rest, 0, ["--format"]);
      if (f.short.has("l") || f.long.has("list")) break;
      if (f.short.has("d") || f.long.has("delete") || f.long.has("edit") || f.long.has("graft") || f.long.has("convert-graft-file") || f.positionals.length >= 2) {
        out.push(deny("shell.git-rewrite-history", `git replace ${rest.slice(0, 3).join(" ")} changes which objects history is read through`, "Replacement refs rewrite how history is read. That is a human decision made with a backup in hand; `git replace --list` is fine."));
      }
      break;
    }
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
      // git 2.46 spells the actions as subcommands (`git config get|list|set|unset KEY`); before that,
      // a key alone reads it and a mutating flag or a value changes it.
      const p = f.positionals;
      const action = ["get", "list", "set", "unset", "rename-section", "remove-section", "edit"].includes(p[0] ?? "") ? p[0] : undefined;
      const mutates = ["unset", "unset-all", "add", "replace-all", "edit", "rename-section", "remove-section"].some((flag) => f.long.has(flag)) || f.short.has("e");
      const readOnly = ["get", "get-all", "get-regexp", "get-urlmatch", "list", "show-origin", "show-scope"].some((flag) => f.long.has(flag)) || f.short.has("l")
        || action === "get" || action === "list" || (action === undefined && p.length === 1 && !mutates);
      if (readOnly) break;
      const key = (action === undefined ? p[0] : p[1]) ?? "";
      if (HOOK_CONFIG_KEY.test(key)) {
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

/** git commands that run hooks and take --no-verify to skip them. */
const HOOK_RUNNERS = new Set(["commit", "push", "merge", "am", "rebase", "pull", "cherry-pick", "revert", "switch", "checkout"]);

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
          out.push(ask("shell.git-force-push-review", `force push to ${r.dst} without --force-with-lease`, `Use \`git push --force-with-lease origin ${r.dst}\` so the push fails if someone else pushed first.`));
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

const WIPE_PATHSPEC = /^(\.|\.\/|\*|\*\*|:\/|:\/\.|\.\/\*|\.\*)$/;
const FORCE_SWITCH_REMEDIATION = "Commit or `git stash push -u` the local changes first and switch without --force, or confirm with the user that the uncommitted work can go.";

function checkoutRules(rest: string[]): Decision[] {
  const f = flagsOf(rest, 0, ["-b", "-B", "--orphan", "-t", "--track", "--conflict", "--pathspec-from-file", "--recurse-submodules"]);
  if (f.short.has("b") || f.short.has("B") || f.long.has("orphan") || f.long.has("detach")) return [];
  const dash = rest.indexOf("--");
  const paths = dash >= 0 ? rest.slice(dash + 1) : f.positionals.length >= 2 ? f.positionals.slice(1) : f.positionals.filter((p) => WIPE_PATHSPEC.test(p));
  if (paths.some((p) => WIPE_PATHSPEC.test(p))) {
    return [deny("shell.git-discard-changes", `git checkout ${paths.join(" ")} discards every uncommitted change`, "Read `git diff` first. Revert named files one at a time, or `git stash push -u` so the work can be recovered.")];
  }
  if (f.short.has("f") || f.long.has("force")) {
    return [ask("shell.git-discard-file", `git checkout ${rest.join(" ")} throws away uncommitted changes in the working tree`, FORCE_SWITCH_REMEDIATION)];
  }
  if (paths.length > 0) {
    return [ask("shell.git-discard-file", `git checkout -- ${paths.join(" ")} discards uncommitted changes to those files`, "Confirm the user does not need the current contents, or stash first.")];
  }
  return [];
}

/** `git switch -f`, `--force`, `--discard-changes`: a branch switch that drops local modifications, like `checkout -f`. */
function switchRules(rest: string[]): Decision[] {
  const f = flagsOf(rest, 0, ["-c", "-C", "--create", "--force-create", "--orphan", "-t", "--track", "--conflict"]);
  if (f.short.has("f") || f.long.has("force") || f.long.has("discard-changes")) {
    return [ask("shell.git-discard-file", `git switch ${rest.join(" ")} throws away uncommitted changes in the working tree`, FORCE_SWITCH_REMEDIATION)];
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

/** True for modes that give write to others or everyone: octal ending in 2, 3, 6 or 7, or a symbolic clause granting `w` to `o`, `a` or no named class. */
function grantsWorldWrite(mode: string): boolean {
  if (CHMOD_OCTAL.test(mode)) return /[2367]$/.test(mode);
  return mode.split(",").some((clause) => {
    const m = /^([ugoa]*)([-+=])([rwxXstugo]*)$/.exec(clause);
    return m !== null && m[2] !== "-" && m[3].includes("w") && (m[1] === "" || /[oa]/.test(m[1]));
  });
}

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
    const info = classifyWhole(t, ctx);
    if (info.category === "hook-config" || info.category === "git-internals") {
      if (s.cmd === "chmod" && /(^|,)[ugoa]*-[rwx]*x|^0*[0-6][0-6][0-6]$/.test(mode)) {
        out.push(deny("shell.hook-tamper", `chmod ${mode} ${t} disables a hook`, "Hooks stay executable. Tell the user if a hook blocks legitimate work."));
      }
      continue;
    }
    if (!recursive) continue;
    if (["filesystem-root", "home-root", "system"].includes(info.category)) {
      out.push(deny("shell.permissions-sweep", `${s.cmd} -R on ${t}`, "Recursive permission changes outside the project break the machine. Change the one path that needs it."));
    } else if (s.cmd === "chmod" && grantsWorldWrite(mode)) {
      out.push(ask("shell.permissions-world-writable", `chmod -R ${mode} ${t} makes the tree writable by every user`, "World-writable trees are a security hole. Grant write to the owner only (`chmod -R u+w`), or use the narrowest mode that works (755 for directories, 644 for files)."));
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
    // `shutdown -c`, `shutdown /a`, `shutdown --abort` cancel a pending shutdown.
    if (s.cmd === "shutdown" && argv.some((a) => /^(-c|\/a|--abort)$/i.test(a))) return [];
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

const PUBLIC_KEY = /\.pub$/i;

function credentialSourceOf(s: Stage, ctx: Context): string | null {
  const candidates = [...s.argv.slice(1), ...s.reads];
  if (!FILE_READERS.has(s.cmd) && s.reads.length === 0 && !NETWORK_SINKS.has(s.cmd)) return null;
  for (const a of candidates) {
    if (a.startsWith("-") || PUBLIC_KEY.test(a)) continue;
    const info = classifyPath(a, ctx);
    if (info.isTestFile) continue;
    if ((CRED_FILE.test(a) && !isPublicPem(a)) || info.category === "home-config" || info.category === "env-file") return a;
  }
  return null;
}

/** The label of a private key or credential store at `a`, or null for anything else (public keys, ssh config, test fixtures). */
function privateCredential(a: string, ctx: Context): string | null {
  const info = classifyPath(homeSpelling(a), ctx);
  if (info.isTestFile) return null;
  const rel = info.homeRel ?? info.rel ?? info.abs;
  const isPrivate = isPrivateFile(a) || (info.homeRel !== null && (sshPrivate(`/${info.homeRel}`) || isPrivateFile(`/${info.homeRel}`) || /^\.(npmrc|aws\/credentials)$/.test(info.homeRel)));
  return isPrivate ? rel : null;
}

/** `$HOME/x`, `${HOME:?}/x`, `$env:USERPROFILE\x`, `%USERPROFILE%\x` as `~/x`, so the home-relative classification sees them. */
function homeSpelling(a: string): string {
  const t = stripQuotes(a);
  const home = HOME_PREFIX.exec(t);
  return home ? `~${t.slice(home[0].length)}` : t;
}

/** `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube` as a whole, or the GnuPG secret-key directory: copying it copies every key in it. */
function credentialStoreDir(a: string, ctx: Context): string | null {
  const info = classifyPath(homeSpelling(a), ctx);
  if (info.homeRel === null) return null;
  const rel = info.homeRel.replace(/[\\/]+\.?$/, "");
  return /^\.(ssh|aws|gnupg|kube|azure)$|^\.config[\\/]gcloud$|^\.gnupg[\\/]private-keys-v1\.d$/i.test(rel) ? rel : null;
}

/** Filters, sorters and comparers that print the files they are given, beyond FILE_READERS. */
const CONTENT_READERS = new Set(["cut", "sort", "uniq", "diff", "comm", "join", "paste", "fold", "rev", "column", "fmt", "pr", "expand", "unexpand", "shuf", "iconv", "base32", "basenc", "zcat", "zless", "zmore", "sdiff"]);
/**
 * Readers whose first operand is a pattern or program, not a file: `grep PATTERN FILE`,
 * `sed SCRIPT FILE`, `awk PROGRAM FILE`, `jq FILTER FILE`. A flag that gives the pattern
 * another way (`grep -e`, `sed -f`, `awk -f`) makes every operand a file.
 */
const PATTERN_READERS: Record<string, RegExp> = {
  grep: /^(-[a-zA-Z]*[ef]|--regexp|--file)(=|$)/, egrep: /^(-[a-zA-Z]*[ef]|--regexp|--file)(=|$)/, fgrep: /^(-[a-zA-Z]*[ef]|--regexp|--file)(=|$)/,
  rg: /^(-[a-zA-Z]*[ef]|--regexp|--file)(=|$)/, ag: /^(-[a-zA-Z]*f|--file-search-regex)(=|$)/, ack: /^(--match)(=|$)/,
  sed: /^(-[a-zA-Z]*[ef]|--expression|--file)(=|$)/, awk: /^(-f|--file)(=|$)/, gawk: /^(-f|--file)(=|$)/, mawk: /^-f$/, nawk: /^-f$/,
  jq: /^(-f|--from-file)(=|$)/, "select-string": /^-pattern$/i, sls: /^-pattern$/i, findstr: /^\/[cg]:/i,
};
/** Searchers that walk a directory they are given: grep only with -r, the others always. */
const RECURSIVE_SEARCHERS = new Set(["rg", "ag", "ack", "select-string", "sls"]);
/** Searchers, and the flags after which they print file names, counts or nothing, not the lines they found. */
const SEARCHERS = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack", "select-string", "sls"]);
const LISTS_ONLY = /^(-[a-z]*[lcq][a-z]*|--files-with(out)?-match(es)?|--count|--quiet|--silent|--files)$/;
/** Commands that take a key on stdin to load or import it, not to print it. */
const KEY_CONSUMERS = new Set(["ssh-add", "ssh-keygen", "gpg", "gpg2", "ssh"]);

const CREDENTIAL_READ_FIX = "Private keys stay out of the transcript. Refer to the file by path; if a value is needed, the user supplies it through an environment variable.";

/**
 * `cat ~/.ssh/id_rsa`, and every other way to print a key: a filter or comparer given it,
 * `grep`/`sed`/`awk`/`jq` over it, a recursive search of a store such as `~/.ssh`,
 * `dd if=`, `openssl ... -in`, an archive of it, or any command with it on stdin (`sort < key`).
 */
function credentialReadRules(s: Stage, ctx: Context): Decision[] {
  const out: Decision[] = [];
  const hit = (a: string, rel: string, verb = "prints") => out.push(deny("shell.credential-read", `${s.cmd} ${a} ${verb} a private key or credential store (${rel})`, CREDENTIAL_READ_FIX));
  if (!KEY_CONSUMERS.has(s.cmd)) {
    for (const r of s.reads) {
      const rel = privateCredential(r, ctx);
      if (rel !== null) hit(`< ${r}`, rel);
    }
  }
  const args = s.argv.slice(1);
  if (FILE_READERS.has(s.cmd) || CONTENT_READERS.has(s.cmd)) {
    for (const a of args) {
      if (a.startsWith("-")) continue;
      const rel = privateCredential(a, ctx);
      if (rel !== null) hit(a, rel);
    }
    return out;
  }
  const pattern = PATTERN_READERS[s.cmd];
  if (pattern !== undefined) {
    const pwsh = s.cmd === "select-string" || s.cmd === "sls";
    if (SEARCHERS.has(s.cmd) && args.some((a) => (pwsh ? /^-(list|quiet)$/i : LISTS_ONLY).test(a))) return out;
    const recursive = RECURSIVE_SEARCHERS.has(s.cmd) || args.some((a) => /^(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive|--dereference-recursive|-Recurse)$/.test(a));
    const operands: string[] = [];
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === "--") { append(operands, args.slice(i + 1)); break; }
      // Select-String's -Path names a file wherever it stands.
      if (pwsh && /^-(path|literalpath)$/i.test(a)) { if (args[i + 1] !== undefined) operands.push(args[++i]); continue; }
      if (a.startsWith("-") || (s.cmd === "findstr" && /^\//.test(a))) continue;
      operands.push(a);
    }
    const files = args.some((a) => pattern.test(a)) ? operands : operands.slice(1);
    for (const a of files) {
      const rel = privateCredential(a, ctx) ?? (recursive ? credentialStoreDir(a, ctx) : null);
      if (rel !== null) hit(a, rel);
    }
    return out;
  }
  if (s.cmd === "dd") {
    for (const a of args) {
      const rel = a.startsWith("if=") ? privateCredential(a.slice(3), ctx) : null;
      if (rel !== null) hit(a, rel);
    }
    return out;
  }
  if (s.cmd === "openssl") {
    // `-pubout` and `-noout` print the public half or nothing.
    if (args.some((a) => a === "-pubout" || a === "-noout")) return out;
    for (const a of args) {
      if (a.startsWith("-")) continue;
      const rel = privateCredential(a, ctx);
      if (rel !== null) hit(a, rel);
    }
    return out;
  }
  if (["tar", "zip", "7z", "7za", "compress-archive", "jar"].includes(s.cmd)) {
    for (const a of args) {
      const v = a.startsWith("-") ? null : a;
      if (v === null) continue;
      const rel = privateCredential(v, ctx) ?? credentialStoreDir(v, ctx);
      if (rel !== null) hit(v, rel, "packs");
    }
  }
  return out;
}

/** Sources and destination of cp/mv and their Windows forms: `-t DIR`, `--target-directory=DIR`, `-Path`/`-Destination`, or positionals with the last as destination. */
function copyOperands(s: Stage): { sources: string[]; dest: string | undefined; intoDir: boolean } {
  const argv = s.argv.slice(1);
  const pwsh = s.cmd === "copy-item" || s.cmd === "move-item" || s.cmd === "cpi" || s.cmd === "mi";
  const sources: string[] = [];
  const positionals: string[] = [];
  let dest: string | undefined;
  let intoDir = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (/^-(path|literalpath|lp|p)$/i.test(a)) {
      for (const v of (argv[++i] ?? "").split(",")) if (v !== "") sources.push(v);
    } else if (pwsh && /^-(destination|d)$/i.test(a)) {
      dest = argv[++i];
    } else if (pwsh && /^-(exclude|include|filter|credential|tosession|fromsession)$/i.test(a)) {
      // Copy-Item's filters and sessions take a value that is not a path to copy.
      i++;
    } else if (!pwsh && (/^(-S|--suffix)$/.test(a) || (s.cmd === "install" && /^(-m|--mode|-o|--owner|-g|--group)$/.test(a)))) {
      // A backup suffix, and install's mode and ownership.
      i++;
    } else if ((s.cmd === "move" || s.cmd === "copy" || s.cmd === "xcopy") && /^\/-?[a-z]$/i.test(a)) {
      // cmd's switches (`move /y`, `copy /b`).
    } else if (a === "-t" || a === "--target-directory") {
      dest = argv[++i];
      intoDir = true;
    } else if (a.startsWith("--target-directory=")) {
      dest = a.slice("--target-directory=".length);
      intoDir = true;
    } else if (a === "--") {
      append(positionals, argv.slice(i + 1));
      break;
    } else if (!a.startsWith("-") || a === "-") {
      positionals.push(a);
    }
  }
  if (sources.length === 0 && dest === undefined) {
    // One operand names no destination (`ln -s target` links it into the working directory).
    if (positionals.length < 2) return { sources: positionals, dest: undefined, intoDir };
    dest = positionals[positionals.length - 1];
    append(sources, positionals.slice(0, -1));
  } else if (sources.length === 0) {
    append(sources, positionals);
  } else if (dest === undefined && positionals.length > 0) {
    dest = positionals[positionals.length - 1];
  }
  return { sources, dest, intoDir };
}

/** Moving a protected path away is the same act as deleting it, so a mv source is judged like an rm target. */
function moveSourceRules(s: Stage, ctx: Context): Decision[] {
  if (RENAMERS.has(s.cmd)) {
    let sources: string[];
    if (s.cmd === "rename") {
      // perl rename takes an expression (or -e/-E code) and the files; util-linux rename takes two strings and the files.
      const f = flagsOf(s.argv, 1, ["-e", "-E"]);
      if (f.short.has("n") || f.long.has("nono") || f.long.has("no-act") || f.long.has("dry-run")) return [];
      const perl = f.short.has("e") || f.short.has("E") ? 0 : /^(?:s|y|tr)([^\w\s]).*\1/s.test(f.positionals[0] ?? "") ? 1 : 2;
      sources = f.positionals.slice(perl);
    } else {
      if (s.argv.some((a) => /^-(whatif|wi)$/i.test(a))) return [];
      sources = copyOperands({ ...s, cmd: "move-item" }).sources;
    }
    // A wildcard renames whatever the expression matches, which only the expression knows; a named file is judged.
    return sources.filter((src) => !/[*?[]/.test(src)).map((src) => judgeRemoveTarget(src, true, false, s, ctx, true)).filter((d) => d.verdict !== "allow");
  }
  if (!MOVERS.has(s.cmd)) return [];
  const { sources } = copyOperands(s);
  return sources.map((src) => judgeRemoveTarget(src, true, false, s, ctx)).filter((d) => d.verdict !== "allow");
}

/** Copying a private key or credential store is reading it: the copy lands where it can be committed or printed. */
function copySourceRules(s: Stage, ctx: Context): Decision[] {
  const sources = COPIERS.has(s.cmd) ? copyOperands(s).sources : s.cmd === "rsync" || s.cmd === "scp" ? transferOperands(s).sources.filter((src) => !isRemote(src)) : [];
  const out: Decision[] = [];
  for (const src of sources) {
    const rel = privateCredential(src, ctx) ?? credentialStoreDir(src, ctx);
    if (rel !== null) {
      out.push(deny("shell.credential-read", `${s.cmd} ${src} copies a private key or credential store (${rel})`, "Private keys and credential stores stay where the user put them. Refer to the file by path (for example `ssh -i ~/.ssh/id_ed25519`); if a value is needed, the user supplies it through an environment variable."));
    }
  }
  return out;
}

function uploadRules(s: Stage, ctx: Context): Decision[] {
  const out: Decision[] = [];
  const argv = s.argv;
  const isCred = (p: string): boolean => {
    const clean = p.replace(/^@/, "").replace(/^[^=]*=@/, "");
    // A public key is made to be sent (`ssh-copy-id` by hand).
    if (!clean || clean === "-" || PUBLIC_KEY.test(clean)) return false;
    const info = classifyPath(clean, ctx);
    return !info.isTestFile && ((CRED_FILE.test(clean) && !isPublicPem(clean)) || info.category === "home-config" || info.category === "env-file");
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
    // scp and rsync send their sources to the destination; only a remote destination sends them off
    // the machine. Option values (`-i key`, `--exclude .env`) are not sources.
    if (s.cmd === "scp" || s.cmd === "rsync") {
      const { sources, dest } = transferOperands(s);
      if (dest !== undefined && isRemote(dest) && sources.some((p) => !isRemote(p) && isCred(p))) {
        out.push(deny("shell.credential-exfil", `${s.cmd} copies a credential file to a remote host`, "Credentials never leave the machine through an agent session."));
      }
    }
    for (const r of s.reads) if (isCred(r)) out.push(deny("shell.credential-exfil", `${s.cmd} sends ${r} over the network`, "Credentials never leave the machine through an agent session."));
  }
  return out;
}

// ---------------------------------------------------------------------------
// containers, databases, deploys

/**
 * Wholesale container, image or volume removal. `docker image|builder|container|network prune`
 * cannot touch data volumes and `docker volume rm <name>` is the named removal the remediation
 * asks for, so both pass.
 */
/** True when the command asks for its usage text: `--help`, `-help` or `-h` before any `--`. */
function asksForHelp(argv: readonly string[]): boolean {
  for (const a of argv.slice(1)) {
    if (a === "--") return false;
    if (a === "--help" || a === "-help" || a === "-h") return true;
  }
  return false;
}

function dockerRules(s: Stage): Decision[] {
  if (asksForHelp(s.argv)) return [];
  const a = s.argv.slice(1).filter((x) => !x.startsWith("-"));
  const joined = s.argv.join(" ");
  const volumes = /\s(-v|--volumes)\b/.test(joined);
  const head = [s.cmd, ...a.slice(0, 2)].join(" ");
  let what: string | null = null;
  if (a[0] === "system" && a[1] === "prune") what = `${head} removes every stopped container, unused network, dangling image and the build cache${volumes ? ", and every unused volume" : ""}`;
  else if (a[0] === "volume" && a[1] === "prune") what = `${head} removes every unused volume`;
  else if (a[0] === "volume" && a[1] === "rm" && /\$\(/.test(joined)) what = `${head} removes every volume the substitution lists`;
  else if ((a[0] === "compose" && a[1] === "down" && volumes) || (s.cmd === "docker-compose" && a[0] === "down" && volumes)) what = `${head} -v removes the stack's volumes`;
  else if (a[0] === "rm" && /\$\(\s*docker (ps|container ls)\b/.test(joined)) what = `${s.cmd} rm $(docker ps ...) removes every container`;
  else if (a[0] === "rmi" && /\$\(\s*docker (images|image ls)\b/.test(joined)) what = `${s.cmd} rmi $(docker images ...) removes every image`;
  if (what === null) return [];
  return [ask("shell.docker-destroy", what, "Volumes may hold local databases and stopped containers may hold unsaved state. Remove the named container, image or volume the task needs (`docker volume rm <name>`, `docker rm <name>`), or confirm with the user.")];
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

const DRY_RUN = /^(--dry-?run(=(client|server|true|1|yes|on))?|--what-if|-whatif)$/i;

function publishRules(s: Stage): Decision[] {
  const argv = s.argv;
  const tail = argv.slice(1).filter((x) => !x.startsWith("-"));
  const joined = argv.join(" ");
  // A dry run or what-if changes nothing remote; it is the check an agent should make before asking.
  // Only a bare flag or a value that means "dry" counts: `--dry-run=none` and `--dry-run=false` are the
  // real thing. A dry run excuses an ask; a destroy is excused only where the tool implements one
  // (`kubectl delete --dry-run=client|server`, `aws s3 rm --dryrun`).
  const dryRun = argv.some((a) => DRY_RUN.test(a));
  // `--help` prints usage and stops. A package manager hands the flags after a script's name to the script, so there it counts only for its own commands.
  if (asksForHelp(argv) && (!["npm", "pnpm", "yarn", "bun"].includes(s.cmd) || tail[0] === "publish" || tail[0] === "unpublish")) return [];
  const askIt = (what: string, why: string): Decision[] => (dryRun ? [] : [ask("shell.deploy-or-publish", `${what} reaches a shared destination`, why)]);
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
      if (tail[0] === "secret" || tail[0] === "variable") {
        if (["list", "get", "view"].includes(tail[1] ?? "")) return [];
        return askIt(`gh ${tail[0]} ${tail[1] ?? ""}`, "Repository secrets are set by the user.");
      }
      if (tail[0] === "api" && /\s-X\s+(DELETE|PUT|PATCH)\b/i.test(joined)) return askIt("gh api with a mutating method", human);
      return [];
    case "wrangler":
      if (tail[0] === "delete" || (tail[0] === "pages" && tail[1] === "project" && tail[2] === "delete")) return denyIt(`wrangler ${tail.slice(0, 3).join(" ")}`, never);
      if (["deploy", "publish", "rollback"].includes(tail[0] ?? "") || (tail[0] === "versions" && !["list", "view"].includes(tail[1] ?? "")) || (tail[0] === "pages" && tail[1] === "deploy") || (tail[0] === "secret" && tail[1] === "put") || (tail[0] === "d1" && tail[1] === "execute" && /--remote/.test(joined)) || /^kv:key$/.test(tail[0] ?? "") && tail[1] === "delete") return askIt(`wrangler ${tail.slice(0, 2).join(" ")}`, human);
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
      if (tail[0] === "deploy" || tail[0] === "scale" || (tail[0] === "secrets" && tail[1] !== "list")) return askIt(`fly ${tail[0]}`, human);
      return [];
    case "firebase":
      if (/^projects:delete$/.test(tail[0] ?? "")) return denyIt("firebase projects:delete", never);
      if (tail[0] === "deploy") return askIt("firebase deploy", human);
      return [];
    case "gcloud": {
      const words = gcloudCommand(argv);
      const g = words.join(" ");
      if (GCLOUD_DESTROY.test(g) || (words[0] === "storage" && words[1] === "rm" && RECURSIVE_FLAG.test(joined))) return denyIt(`gcloud ${words.slice(0, 3).join(" ")}`, never);
      if (words[1] === "deploy" || (words[0] === "deploy" && words.length > 2 && !/^(list|describe|get)/.test(words[2]))) return askIt(`gcloud ${words.slice(0, 3).join(" ")}`, human);
      return [];
    }
    case "gsutil":
      if (tail[0] === "rb" || (tail[0] === "rm" && RECURSIVE_FLAG.test(joined))) return denyIt(`gsutil ${tail.slice(0, 2).join(" ")}`, never);
      return [];
    case "aws": {
      const svc = tail[0] ?? "";
      const op = tail[1] ?? "";
      if ((svc === "s3" && op === "rb") || (svc === "s3" && op === "rm" && /--recursive\b/.test(joined) && !dryRun) || AWS_DESTROY.test(op)) return denyIt(`aws ${svc} ${op}`, never);
      // `aws s3 sync s3://bucket ./dir` downloads: the bucket comes first and is the only one named.
      const download = svc === "s3" && op === "sync" && /^s3:\/\//.test(tail[2] ?? "") && tail[3] !== undefined && argv.filter((a) => /^s3:\/\//.test(a)).length === 1;
      if ((svc === "s3" && op === "sync" && !download) || AWS_DEPLOY.test(op) || (svc === "deploy" && op !== "" && !/^(list|get|batch-get|describe)-/.test(op))) return askIt(`aws ${svc} ${op}`, human);
      return [];
    }
    case "az": {
      if (/^(repos|boards|pipelines|devops|artifacts)$/.test(tail[0] ?? "")) return [];
      const a = tail.join(" ");
      if (AZ_DESTROY.test(a)) return denyIt(`az ${tail.slice(0, 3).join(" ")}`, never);
      if (AZ_DEPLOY.test(a)) return askIt(`az ${tail.slice(0, 3).join(" ")}`, human);
      return [];
    }
    case "terraform":
    case "tofu":
      if (tail[0] === "destroy" || (tail[0] === "apply" && /-destroy\b/.test(joined))) return denyIt(`${s.cmd} destroy`, never);
      if (tail[0] === "apply" || (tail[0] === "state" && (tail[1] === "rm" || tail[1] === "mv")) || tail[0] === "import") return askIt(`${s.cmd} ${tail.slice(0, 2).join(" ")}`, human);
      return [];
    case "pulumi":
      if (tail[0] === "destroy") return denyIt("pulumi destroy", never);
      if (tail[0] === "up") return askIt("pulumi up", human);
      return [];
    case "kubectl": {
      const words = commandWords(argv, KUBECTL_VALUED);
      // The kinds come as `namespace x`, `ns,pod x` or `namespace/x`; each later word may be another `kind/name`.
      const namespace = /^(namespaces?|ns)(\/.*)?$/;
      const deletesNamespace = (words[1] ?? "").split(",").some((k) => namespace.test(k)) || words.slice(2).some((w) => /^(namespaces?|ns)\//.test(w));
      if (words[0] === "delete" && !dryRun && (deletesNamespace || /\s(--all|-A|--all-namespaces)\b/.test(joined))) return denyIt("kubectl delete across a namespace", never);
      if (words[0] === "delete" || words[0] === "apply" || words[0] === "drain" || (words[0] === "rollout" && !["status", "history"].includes(words[1] ?? ""))) return askIt(`kubectl ${words.slice(0, 2).join(" ")}`, human);
      return [];
    }
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

const RECURSIVE_FLAG = /(^|\s)(-r|-R|--recursive)(\s|$)/;
/** Operations that remove a whole account, project, cluster, database, bucket or app. Anything narrower (one blob, one image tag, one lock) passes. */
const AWS_DESTROY = /^(terminate-instances|delete-db-instance|delete-db-cluster|delete-stack|delete-function|delete-table|delete-bucket|delete-user|delete-role|delete-cluster)$/;
const AWS_DEPLOY = /^(deploy|update-function-code|update-service|put-bucket-policy|create-deployment)$/;
/** gcloud's global flags that take their value as the next word (`gcloud --project p projects delete p`). */
const GCLOUD_VALUED = new Set(["--project", "--account", "--configuration", "--verbosity", "--format", "--impersonate-service-account", "--billing-project", "--flags-file", "--trace-token", "--access-token-file", "--region", "--zone"]);

/** kubectl's flags that take their value as the next word (`kubectl delete -n ns pod web`). */
const KUBECTL_VALUED = new Set(["-n", "--namespace", "--context", "--cluster", "--kubeconfig", "--user", "-l", "--selector", "-f", "--filename", "-k", "--kustomize", "-o", "--output", "--field-selector", "--grace-period", "--timeout", "--cascade", "-s", "--server", "--as", "--as-group", "--token", "--request-timeout"]);

/** A command's words after argv[0], without flags or the values of the flags in `valued`. */
function commandWords(argv: readonly string[], valued: ReadonlySet<string>): string[] {
  const words: string[] = [];
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") break;
    if (a.startsWith("-")) {
      if (valued.has(a)) i++;
      continue;
    }
    words.push(a);
  }
  return words;
}

/** gcloud's command words, without the release track (`alpha`, `beta`, `preview`) that runs the same command. */
function gcloudCommand(argv: readonly string[]): string[] {
  const words = commandWords(argv, GCLOUD_VALUED);
  return /^(alpha|beta|preview)$/.test(words[0] ?? "") ? words.slice(1) : words;
}

const GCLOUD_DESTROY = /^(projects delete|sql instances delete|firestore databases delete|storage buckets delete|container clusters delete|compute (?:instances|disks) delete|run services delete|functions delete|iam service-accounts delete|spanner instances delete|bigtable instances delete|redis instances delete|filestore instances delete|artifacts repositories delete|app services delete)(\s|$)/;
const AZ_DESTROY = /^(group delete|aks delete|sql (?:server|db|mi) delete|storage account delete|vm delete|vmss delete|webapp delete|functionapp delete|keyvault (?:delete|purge)|cosmosdb delete|postgres (?:server|flexible-server) delete|mysql (?:server|flexible-server) delete|acr delete|containerapp delete|appservice plan delete|staticwebapp delete)(\s|$)/;
/** Deploy-shaped creates only: `az deployment ... create`, `az webapp up`, `az containerapp up`. Creating a tag, a work item or an app registration is not a deploy. */
const AZ_DEPLOY = /^(deployment(?: \S+)* create|webapp (?:up|deploy|deployment)|containerapp (?:up|create)|functionapp (?:deploy|deployment))(\s|$)/;

/** Snapshot and baseline refresh commands: `vitest -u`, `npm run typecheck:baseline`, `cargo insta accept`. */
function baselineRefreshRules(s: Stage): Decision[] {
  const argv = s.argv;
  const tail = argv.slice(1);
  const runners = new Set(["vitest", "jest", "playwright", "pytest", "ava", "mocha", "bun", "deno", "node"]);
  // mocha's `-u` is `--ui`; only its long forms update snapshots (through a plugin).
  const updateFlag = tail.some((a) => /^(--update|--updateSnapshot|--update-snapshots|--snapshot-update|--force-update-snapshots)$/.test(a) || (a === "-u" && s.cmd !== "mocha"));
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
  const what = destructiveCodeKind(code, s.cmd);
  if (what !== null) {
    out.push(ask("shell.interpreter-destructive", `${s.cmd} inline code ${what}`, "Inline code cannot be checked the way a shell command can. Run the deletion as a plain command (`rm -rf <path>`) so the target is visible, or ask the user."));
  }
  const tamper = EXEC_HINT.test(code) ? ahInitTamperInCode(code) : null;
  if (tamper !== null) {
    out.push(deny("shell.hook-tamper", `${s.cmd} inline code runs ah init ${tamper}`, AH_TAMPER_REMEDIATION));
  }
  return out;
}

/**
 * `ah init --remove` and `ah init --ask-fallback warn` are the sanctioned way to
 * unwire or weaken the guard, so an agent that was refused could reach for them.
 * Plain `ah init` (re-wiring) and `ah doctor` pass. Spelled as `ah`, `npx
 * @9thlevelsoftware/aegis`, `node .../dist/ah.mjs`, `./dist/ah.mjs`, `ah.ps1`,
 * `pwsh [-File] ah.ps1`, `pnpm ah` or `yarn run ah`; the parser unwraps runners,
 * `env -S`, `npx -c`, `iex`, `Start-Process`, compound commands and PowerShell
 * blocks, and shellRules parses text piped into a shell, before this sees the stage.
 */
function ahCliRules(s: Stage): Decision[] {
  const args = ahArgs(s);
  if (args === null || args[0] !== "init") return [];
  const what = ahInitTamper(args.slice(1));
  if (what === null) return [];
  return [deny("shell.hook-tamper", `ah init ${what}`, AH_TAMPER_REMEDIATION)];
}

const AH_TAMPER_REMEDIATION = "Hook wiring is how this project enforces its rules. Tell the user which refusal is in your way; changing the wiring is their call, made from their own terminal.";

/**
 * A nested agent started with hooks switched off, the per-run form of removing the wiring:
 * Claude Code's `--bare`, `--safe-mode`, `--restricted`, `--setting-sources` without every source,
 * `--settings '{"disableAllHooks": true}'`, `CLAUDE_CODE_SAFE_MODE` and `CLAUDE_CONFIG_DIR`; Codex's
 * `--disable hooks`, `-c features.hooks=false` and a `CODEX_HOME` with none of the user's trust.
 */
function nestedAgentRules(s: Stage): Decision[] {
  // Printing the version or usage starts no agent.
  if (asksForHelp(s.argv) || s.argv.slice(1).some((a) => a === "--version" || a === "-v" || a === "-V")) return [];
  const what = s.cmd === "claude" ? claudeHooksOff(s) : s.cmd === "codex" ? codexHooksOff(s) : null;
  return what === null ? [] : [deny("shell.hook-tamper", `${s.cmd} ${what} starts an agent without this project's hooks`, AH_TAMPER_REMEDIATION)];
}

function claudeHooksOff(s: Stage): string | null {
  if (/^(1|true|yes)$/i.test(s.env.CLAUDE_CODE_SAFE_MODE ?? "")) return "with CLAUDE_CODE_SAFE_MODE set";
  if (s.env.CLAUDE_CONFIG_DIR !== undefined) return "with CLAUDE_CONFIG_DIR set";
  const args = s.argv.slice(1);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") break;
    if (a === "--bare" || a === "--safe-mode" || a === "--restricted") return a;
    const [name, inline] = a.startsWith("--") && a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [a, undefined];
    if (name === "--setting-sources") {
      const sources = new Set((inline ?? args[i + 1] ?? "").split(",").map((x) => x.trim().toLowerCase()));
      if (!["user", "project", "local"].every((x) => sources.has(x))) return `${name} ${inline ?? args[i + 1] ?? ""}`.trim();
    }
    if (name === "--settings" && /"?disableAllHooks"?\s*:\s*true/.test(inline ?? args[i + 1] ?? "")) return "--settings with disableAllHooks";
  }
  return null;
}

function codexHooksOff(s: Stage): string | null {
  if (s.env.CODEX_HOME !== undefined) return "with CODEX_HOME set";
  const args = s.argv.slice(1);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") break;
    const [name, inline] = a.startsWith("--") && a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [a, undefined];
    const value = inline ?? args[i + 1] ?? "";
    if (name === "--disable" && value.toLowerCase() === "hooks") return "--disable hooks";
    if ((name === "-c" || name === "--config") && /^features\s*(\.\s*hooks\s*=\s*false|=\s*\{[^}]*\bhooks\s*=\s*false)/i.test(value)) return `${name} ${value}`;
  }
  return null;
}

/** What `ah init <options>` does to the guard's wiring, or null when it leaves the guard as strong as it is. */
function ahInitTamper(options: readonly string[]): string | null {
  // Walk the options the way `ah init` parses them, so a flag's value is never read as a flag.
  const flags = new Map<string, string | true>();
  for (let i = 0; i < options.length; i++) {
    const a = options[i];
    const eq = a.startsWith("--") ? a.indexOf("=") : -1;
    const name = eq > 0 ? a.slice(0, eq) : a;
    if (AH_INIT_VALUED_OPTIONS.has(name)) flags.set(name, eq > 0 ? a.slice(eq + 1) : (options[++i] ?? ""));
    else flags.set(name, true);
  }
  if (flags.has("--dry-run")) return null;
  if (flags.has("--remove") || flags.has("--uninstall")) return "--remove removes the guard's hook wiring";
  if (flags.get("--ask-fallback") === "warn") return "--ask-fallback warn turns the guard's asks into warnings on Codex";
  if (flags.has("--guard") || flags.has("--node")) return `${flags.has("--guard") ? "--guard" : "--node"} points the hook at a program other than the installed guard`;
  return null;
}

/** The ah CLI by its bin name, its `ah.ps1` shim, or the bundle file run through its shebang or an interpreter. `ah.cmd` arrives normalized to `ah`. */
const AH_COMMAND = /^(?:ah|aegis)(?:\.m?js|\.ps1)?$/;
/** Runtime options before the script that take the next word: `bun --cwd dir`, `deno run --config file`. */
const RUNTIME_OPTS_WITH_ARG: Record<string, Set<string>> = { bun: new Set(["--cwd"]), deno: new Set(["-c", "--config", "--import-map"]) };

/** The arguments after `ah` when the stage runs the ah CLI, else null. */
function ahArgs(s: Stage): string[] | null {
  if (AH_COMMAND.test(s.cmd)) return s.argv.slice(1);
  if (["node", "nodejs", "bun", "deno"].includes(s.cmd)) {
    for (let i = 1; i < s.argv.length; i++) {
      const a = s.argv[i];
      if (a === "run" && (s.cmd === "deno" || s.cmd === "bun")) continue;
      if (INTERPRETER_VALUED_FLAGS.has(a) || RUNTIME_OPTS_WITH_ARG[s.cmd]?.has(a)) {
        i++;
        continue;
      }
      if (a.startsWith("-")) continue;
      // `node dist/ah.mjs`, `node node_modules/.bin/ah` (the bin symlink), `bun ah`, `deno run npm:@9thlevelsoftware/aegis@0.0.1`.
      return AH_COMMAND.test(normalizeCmd(a.replace(/^(npm:.+)@[^@/]*$/, "$1"))) ? s.argv.slice(i + 1) : null;
    }
  }
  if (s.cmd === "pwsh" || s.cmd === "powershell") {
    // `pwsh -File node_modules/.bin/ah.ps1 init --remove`, `pwsh -NoProfile ./ah.ps1 init --remove`: the script's own arguments follow it.
    const run = pwshRun(s.argv);
    return run !== null && "script" in run && AH_COMMAND.test(normalizeCmd(run.script)) ? run.args : null;
  }
  if (s.cmd === "pnpm" || s.cmd === "yarn") {
    // `pnpm ah`, `yarn ah`, `yarn run ah`: the package manager runs a local bin by name.
    let k = subcommandIndex(s.argv);
    if (s.argv[k] === "run") k++;
    return AH_COMMAND.test(normalizeCmd(s.argv[k] ?? "")) ? s.argv.slice(k + 1) : null;
  }
  return null;
}

/**
 * An `ah init` command line inside code, as one string or an argv list: `'ah init --remove'`,
 * `` `ah init --remove` ``, `['ah', 'init', '--remove']`, `spawnSync('ah', ['init', '--remove'])`.
 * Runs to the end of the call or statement.
 */
const AH_INIT_IN_CODE = /(?<![\w.-])(?:ah|aegis)(?:\.m?js)?['"`]?(?:\s*,\s*\[?\s*['"`]?|\s+)init\b([^;)\n]*)/g;

/** What an `ah init` spelled in inline code does to the guard, or null when the code runs none that weakens it. */
function ahInitTamperInCode(code: string): string | null {
  for (const m of code.matchAll(AH_INIT_IN_CODE)) {
    const what = ahInitTamper(m[1].split(/[\s'"`,\][]+/).filter((w) => w !== ""));
    if (what !== null) return what;
  }
  return null;
}

/** What the inline code deletes, or null when it deletes nothing the guard recognises. */
function destructiveCodeKind(code: string, cmd: string): string | null {
  if (DESTRUCTIVE_CODE.test(code)) return "deletes a directory tree";
  if (NODE_FS_IMPORT.test(code) && FS_DELETE_CALL.test(code) && /\brecursive\b/.test(code)) return "deletes a directory tree";
  if (EXEC_HINT.test(code) && DESTRUCTIVE_SHELL.test(code)) return "runs a recursive delete through a shell";
  if (cmd === "perl" && /\bunlink\b/.test(code) && PERL_WALK.test(code)) return "unlinks every file a glob or directory walk finds";
  return null;
}

/** Parameters of the writing cmdlets that take a value, and their aliases; true for those whose value is a path. */
const CMDLET_VALUED: Record<string, boolean> = {
  path: true, literalpath: true, pspath: true, lp: true, filepath: true, name: true,
  value: false, target: false, inputobject: false, encoding: false, itemtype: false, type: false, filter: false, include: false, exclude: false,
  credential: false, stream: false, width: false, options: false, erroraction: false, ea: false, warningaction: false, wa: false, informationaction: false,
  infa: false, errorvariable: false, ev: false, warningvariable: false, wv: false, informationvariable: false, iv: false, outvariable: false,
  ov: false, outbuffer: false, ob: false, pipelinevariable: false, pv: false, progressaction: false, proga: false,
};
const CMDLET_SWITCHES = ["force", "nonewline", "append", "noclobber", "passthru", "whatif", "wi", "confirm", "cf", "asbytestream", "verbose", "vb", "debug", "db", "usetransaction", "usetx"];

type CmdletRole = "path" | "name" | "value";

/**
 * The files New-Item, Set-Content, Add-Content and Out-File write. Named parameters bind first
 * and may be cut to any prefix PowerShell can tell apart; the arguments left over bind in order
 * to the path and then the value (Out-File: the encoding), and any past those make PowerShell
 * refuse the command. A value, such as a here-string's body, is not a file. A parameter it does
 * not know, or a prefix that could be a switch, is read both as taking a value and as not.
 *
 * A comma joins words into one array (`a, b` and `a ,b` write both), but the quotes are gone by
 * now, so a word ending in `,` may instead have been `'x,'`, after which the next word stands on
 * its own, and a `-Path` after such a comma may be a parameter or text. Every reading is followed
 * at once, as a small set of states (positionals so far, an array still open, a value expected),
 * and a word is a file if any reading binds it to the path.
 */
function cmdletPaths(cmd: string, args: readonly string[], deadline: number | undefined): string[] {
  const params = args.map((w) => {
    const m = /^-([A-Za-z]+)(?::(.*))?$/s.exec(w);
    if (m === null) return null;
    const key = m[1].toLowerCase();
    const valued = Object.keys(CMDLET_VALUED).filter((n) => n.startsWith(key));
    const exact = Object.hasOwn(CMDLET_VALUED, key);
    const switches = CMDLET_SWITCHES.some((n) => n.startsWith(key));
    const takes = exact || (valued.length > 0 && !switches);
    // A known switch takes nothing; one it does not know, or a prefix of both kinds, may take a value.
    const maybeTakes = !takes && (valued.length > 0 || !switches);
    const isPath = exact ? CMDLET_VALUED[key] : valued.some((n) => CMDLET_VALUED[n]);
    const role: CmdletRole = !isPath ? "value" : (exact ? key === "name" : valued.every((n) => n === "name")) ? "name" : "path";
    return { takes, maybeTakes, role, inline: m[2] !== undefined && m[2] !== "" ? m[2] : undefined };
  });
  // Whether a named path parameter is bound: surely, when it follows no comma; maybe, when it does.
  const pathParam = (j: number) => params[j]?.takes === true && params[j]?.role === "path";
  const surely = args.some((w, j) => pathParam(j) && !(args[j - 1] ?? "").endsWith(","));
  const maybe = args.some((_, j) => pathParam(j));
  const full = cmd === "out-file" ? ["path", "encoding"] : cmd === "new-item" || cmd === "ni" ? ["path"] : ["path", "value"];
  const paths = new Set<string>();
  const names = new Set<string>();
  interface State { pos: number; open: CmdletRole | null; last: CmdletRole | null; expect: CmdletRole | null }
  for (const bound of surely ? [true] : maybe ? [true, false] : [false]) {
    const slots = full.filter((p) => p !== "path" || !bound);
    let states = new Map<string, State>([["0", { pos: 0, open: null, last: null, expect: null }]]);
    args.forEach((w, j) => {
      if ((j & 1023) === 0) onTime(deadline);
      const next = new Map<string, State>();
      const emit = (st: State) => next.set(`${st.pos}|${st.open}|${st.last}|${st.expect}`, st);
      // The word, or a parameter's inline value, takes a role; a trailing comma may keep its array open.
      const take = (role: CmdletRole, text: string, st: State) => {
        if (role === "path") paths.add(text);
        else if (role === "name") names.add(text);
        emit({ ...st, open: null, last: role, expect: null });
        if (text.endsWith(",")) emit({ ...st, open: role, last: role, expect: null });
      };
      const fresh = (st: State) => {
        const p = params[j];
        if (p === null) take(slots[st.pos] === "path" ? "path" : "value", w, { ...st, pos: Math.min(st.pos + 1, 3) });
        else if (!p.takes) {
          emit({ ...st, open: null, last: null, expect: null });
          if (p.maybeTakes && p.inline === undefined) emit({ ...st, open: null, last: null, expect: p.role });
        } else if (p.inline !== undefined) take(p.role, p.inline, st);
        else emit({ ...st, open: null, last: null, expect: p.role });
      };
      for (const st of states.values()) {
        if (st.expect !== null) take(st.expect, w, st);
        else if (st.open !== null) {
          take(st.open, w, st);
          if (params[j] !== null) fresh(st);
        } else {
          if (w.startsWith(",") && st.last !== null) take(st.last, w, st);
          fresh(st);
        }
      }
      states = next;
    });
  }
  const dirs = new Set<string>();
  for (const p of paths) {
    dirs.add(p);
    for (const q of p.split(",")) if (q !== "") dirs.add(q);
  }
  const out = [...dirs, ...names];
  joinAll([...dirs], [...names], out);
  return out;
}

function writeTargetsOf(s: Stage, deadline: number | undefined): string[] {
  const targets = [...s.writes];
  const positionals = s.argv.slice(1).filter((a) => !a.startsWith("-"));
  switch (s.cmd) {
    case "sed": {
      // `-i`, `-i.bak`, `-Ei`, `-ni`, `--in-place=.bak`; the script is the first operand unless -e or -f gave it.
      if (!s.argv.some((a) => /^-[nrEsuz]*i/.test(a) || /^--in-place(?:=|$)/.test(a))) break;
      const { positionals: files, values } = operands(s.argv, "efl", ["--expression", "--file", "--line-length"]);
      const scripted = values.has("-e") || values.has("-f") || values.has("--expression") || values.has("--file");
      append(targets, scripted ? files : files.slice(1));
      break;
    }
    case "perl":
    case "ruby": {
      // `perl -pi -e '...' file`, `perl -i.bak -pe`: the files after the code are rewritten in place.
      if (!s.argv.some((a) => /^-[pnalswWtTXcdDuUvx0-9]*i/.test(a))) break;
      const { positionals: files, values } = operands(s.argv, "eEIMmr", []);
      append(targets, values.has("-e") || values.has("-E") ? files : files.slice(1));
      break;
    }
    case "awk":
    case "gawk": {
      // `gawk -i inplace '{...}' file`: the inplace extension rewrites the files.
      const { positionals: files, values } = operands(s.argv, "fFvilEe", ["--file", "--field-separator", "--assign", "--include", "--load", "--exec", "--source"]);
      const included = [...(values.get("-i") ?? []), ...(values.get("--include") ?? [])];
      if (!included.some((v) => /^inplace(?:\.awk)?$/.test(v))) break;
      const program = values.has("-f") || values.has("--file") || values.has("-e") || values.has("--source") || values.has("-E") || values.has("--exec");
      append(targets, (program ? files : files.slice(1)).filter((f) => !/^[A-Za-z_]\w*=/.test(f)));
      break;
    }
    case "yq": {
      if (!s.argv.some((a) => a === "-i" || a === "--inplace" || /^-[a-zA-Z]*i$/.test(a) && !a.startsWith("--"))) break;
      const { positionals: files, values } = operands(s.argv, "oIpe", ["--output-format", "--indent", "--input-format", "--expression", "--front-matter"]);
      append(targets, values.has("-e") || values.has("--expression") || s.argv.includes("--from-file") ? files : files.slice(1));
      break;
    }
    case "sponge":
      append(targets, positionals);
      break;
    case "dd":
      for (const a of s.argv.slice(1)) if (a.startsWith("of=")) targets.push(a.slice(3));
      break;
    case "curl":
    case "wget":
    case "iwr":
    case "invoke-webrequest":
    case "irm":
    case "invoke-restmethod":
      append(targets, downloadTargets(s));
      break;
    case "rsync": {
      const { sources, dest } = transferOperands(s);
      if (dest !== undefined && !isRemote(dest)) append(targets, copyTargets(sources, dest, false, true));
      break;
    }
    case "cp":
    case "mv":
    case "install":
    case "ln":
    case "copy":
    case "move":
    case "copy-item":
    case "move-item":
    case "cpi":
    case "mi": {
      const { sources, dest, intoDir } = copyOperands(s);
      if (dest !== undefined) append(targets, copyTargets(sources, dest, intoDir));
      else if (s.cmd === "ln" && sources.length === 1) append(targets, copyTargets(sources, ".", true));
      break;
    }
    case "truncate":
    case "touch":
    case "mkdir":
      append(targets, positionals.filter((p) => p !== "-s" && !/^\d+$/.test(p)));
      break;
    case "new-item":
    case "ni":
    case "set-content":
    case "add-content":
    case "ac":
    case "out-file":
      append(targets, cmdletPaths(s.cmd, s.argv.slice(1), deadline));
      break;
    case "git":
      // `git diff --output=file`, `git log --output file`.
      append(targets, operands(s.argv, "", ["--output"]).values.get("--output") ?? []);
      break;
    default:
      break;
  }
  return targets;
}

/**
 * Positional arguments once options are set aside, and the values options took. `short` lists the
 * letters whose value is the rest of the word or else the next word (`-o f`, `-of`, `-sSLo f`), `long`
 * the long options whose value is the next word unless glued with `=`.
 */
function operands(argv: readonly string[], short: string, long: readonly string[]): { positionals: string[]; values: Map<string, string[]> } {
  const positionals: string[] = [];
  const values = new Map<string, string[]>();
  const put = (k: string, v: string | undefined) => {
    if (v === undefined) return;
    const l = values.get(k);
    if (l === undefined) values.set(k, [v]);
    else l.push(v);
  };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      append(positionals, argv.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const name = eq < 0 ? a : a.slice(0, eq);
      if (long.includes(name)) put(name, eq < 0 ? argv[++i] : a.slice(eq + 1));
      continue;
    }
    if (a.startsWith("-") && a.length > 1) {
      for (let l = 1; l < a.length; l++) {
        if (!short.includes(a[l])) continue;
        put(`-${a[l]}`, l === a.length - 1 ? argv[++i] : a.slice(l + 1));
        break;
      }
      continue;
    }
    positionals.push(a);
  }
  return { positionals, values };
}

/**
 * The files a copy to `dest` writes: `dest` itself, or `dest/<name>` for each source when `dest` is a
 * directory, which the text shows by a trailing separator, `.`, `..` or `~`, a target-directory
 * option, or several sources. A last segment with no extension (`.claude`, `config`) may be either,
 * so both count; one with an extension (`vitest.config.ts.bak`) is taken as the file.
 */
function copyTargets(sources: readonly string[], dest: string, intoDir: boolean, contents = false): string[] {
  const d = stripQuotes(dest);
  const last = trimSeparators(d).split(/[\\/]/).pop() ?? "";
  const dir = intoDir || sources.length > 1 || /[\\/]$/.test(d) || /^(?:\.{1,2}|~)$/.test(last) || last === "";
  const maybeDir = !dir && /^\.?[^.]+$/.test(last);
  const joined = sources.map((src) => {
    const s = stripQuotes(src);
    // rsync copies what a source ending in a separator holds, not the directory itself.
    if (contents && /[\\/]$/.test(s)) return d;
    const name = trimSeparators(s).split(/[\\/]/).pop() ?? "";
    return name === "" || name === "." || name === ".." ? d : `${trimSeparators(d) || "/"}/${name}`;
  });
  return dir ? joined : maybeDir ? [d, ...joined] : [d];
}

/** Hosts in an scp or rsync operand: `host:path`, `user@host:path`, `rsync://`; a Windows drive (`C:\x`) is local. */
function isRemote(p: string): boolean {
  return (/^[^\\/:]+:/.test(p) && !/^[A-Za-z]:(?:[\\/]|$)/.test(p)) || /^(?:rsync|scp|sftp):\/\//i.test(p);
}

/** Sources and destination of rsync and scp, their options' values set aside. */
function transferOperands(s: Stage): { sources: string[]; dest: string | undefined } {
  const { positionals } = s.cmd === "scp"
    ? operands(s.argv, "cFiJlmoPSX", [])
    : operands(s.argv, "efTBM@", ["--exclude", "--include", "--filter", "--exclude-from", "--include-from", "--files-from", "--rsh", "--rsync-path", "--log-file", "--log-file-format", "--partial-dir", "--temp-dir", "--backup-dir", "--suffix", "--chmod", "--chown", "--compare-dest", "--copy-dest", "--link-dest", "--password-file", "--out-format", "--bwlimit", "--timeout", "--contimeout", "--port", "--max-size", "--min-size", "--max-delete", "--modify-window", "--block-size", "--usermap", "--groupmap", "--info", "--debug", "--iconv", "--remote-option", "--address", "--sockopts", "--checksum-choice", "--compress-choice", "--compress-level", "--skip-compress", "--outbuf", "--stop-after", "--stop-at", "--write-batch", "--read-batch", "--only-write-batch", "--protocol"]);
  if (positionals.length < 2) return { sources: positionals, dest: undefined };
  return { sources: positionals.slice(0, -1), dest: positionals[positionals.length - 1] };
}

/** The files a download writes: `curl -o f`, `curl -O URL` (the URL's last segment), `wget -O f`, `wget URL`, `wget -o log`, `iwr -OutFile f`. */
function downloadTargets(s: Stage): string[] {
  const out: string[] = [];
  const argv = s.argv;
  const urlName = (u: string) => {
    const path = stripQuotes(u).replace(/[?#].*$/, "");
    return /^[a-z][\w+.-]*:\/\/[^/]+\/./i.test(path) ? (path.split("/").pop() ?? "") : "";
  };
  if (s.cmd === "curl") {
    const { positionals, values } = operands(argv, "oAbcCdDeEFHKmrTuUwxXyYzQtP", ["--output", "--output-dir", "--data", "--header", "--user", "--user-agent", "--referer", "--cookie", "--cookie-jar", "--config", "--form", "--request", "--upload-file", "--write-out", "--proxy", "--max-time", "--connect-timeout", "--retry", "--range", "--dump-header", "--cert", "--key", "--cacert", "--data-binary", "--data-raw", "--data-urlencode", "--json", "--url"]);
    const dir = values.get("--output-dir")?.[0];
    const at = (f: string) => (dir === undefined || /^[\\/~]/.test(f) ? f : `${trimSeparators(dir)}/${f}`);
    for (const f of [...(values.get("-o") ?? []), ...(values.get("--output") ?? [])]) if (f !== "-") out.push(at(f));
    if (argv.some((a) => /^-[a-zA-Z]*O[a-zA-Z]*$/.test(a) && !a.startsWith("--") || a === "--remote-name" || a === "--remote-name-all")) {
      for (const u of [...positionals, ...(values.get("--url") ?? [])]) {
        const name = urlName(u);
        if (name !== "") out.push(at(name));
      }
    }
    return out;
  }
  if (s.cmd === "wget") {
    const { positionals, values } = operands(argv, "OoaPeiBtTwUQ", ["--output-document", "--output-file", "--append-output", "--directory-prefix", "--input-file", "--base", "--tries", "--timeout", "--wait", "--user-agent", "--quota", "--header", "--post-data", "--post-file", "--user", "--password"]);
    const named = [...(values.get("-O") ?? []), ...(values.get("--output-document") ?? [])];
    for (const f of [...named, ...(values.get("-o") ?? []), ...(values.get("--output-file") ?? []), ...(values.get("-a") ?? []), ...(values.get("--append-output") ?? [])]) if (f !== "-") out.push(f);
    if (named.length === 0) {
      const dir = [...(values.get("-P") ?? []), ...(values.get("--directory-prefix") ?? [])][0];
      for (const u of positionals) {
        const name = urlName(u);
        if (name !== "") out.push(dir === undefined ? name : `${trimSeparators(dir)}/${name}`);
      }
    }
    return out;
  }
  for (let i = 1; i < argv.length; i++) {
    const m = /^-outf(?:i(?:le?)?)?(?::(.*))?$/i.exec(argv[i]);
    if (m !== null) out.push(m[1] ?? argv[++i] ?? "");
  }
  return out.filter((f) => f !== "");
}

function writeRules(target: string, s: Stage, ctx: Context, whole = false): Decision[] {
  if (isBlockDevice(target)) {
    return [deny("shell.disk-destroy", `${s.cmd} writes to ${target}`, "Raw devices are never written from a coding task.")];
  }
  if (PWSH_PROFILE.test(target)) {
    return [deny("shell.write-home-config", `${s.cmd} writes the PowerShell profile (${target}), a shell rc file in the home directory`, "The shell profile is the user's configuration, like ~/.bashrc. Agent sessions do not change it; ask the user.")];
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
    case "project-root":
      // Copying a tree's contents over the project root may replace its hook files too, but whether
      // the tree holds any only the filesystem knows.
      return [];
    default: {
      // A directory copied whole over `.claude` or `~/.claude` replaces the settings inside it.
      const inside = whole ? protectedInside(info.abs, ctx) : undefined;
      if (inside === undefined) return [];
      return inside.category === "hook-config"
        ? [deny("shell.hook-tamper", `${s.cmd} writes into ${shown}, which holds hook configuration (${inside.matched})`, "Hook wiring is how this project enforces its rules. Leave it as it is.")]
        : [deny("shell.write-home-config", `${s.cmd} writes into ${shown}, which holds the user's settings (${inside.matched})`, "Agent sessions do not change user-level credentials or agent settings. Ask the user.")];
    }
  }
}
