/**
 * A small, forgiving shell command parser.
 *
 * It is not a shell. It splits a command line into pipelines and stages,
 * tokenizes each stage with quote awareness, peels off wrappers such as
 * `sudo`, `env`, `xargs` and `timeout`, records redirection targets, and
 * recurses into `sh -c "..."`, `pwsh -Command "..."`, `cmd /c ...`, `eval`,
 * `iex`, `Start-Process`, `npx -c`, `$(...)` and backtick substitutions, so
 * that rules see every command that will actually run. On input it cannot
 * make sense of it degrades to a whitespace split rather than throwing: the
 * guard must never crash open.
 */

export interface Stage {
  /** Arguments after env assignments and wrappers were removed. `argv[0]` is the command. */
  argv: string[];
  /** Normalized command name: basename, lowercase, without `.exe`/`.cmd`/`.bat`/`.ps1`. */
  cmd: string;
  /** Leading `VAR=value` assignments and those passed through `env`/`sudo`. */
  env: Record<string, string>;
  /** Wrappers that were peeled off, in order (`sudo`, `xargs`, ...). */
  wrappers: string[];
  /** Files written through `>`, `>>`, `&>` or `tee`. `/dev/null` is dropped. */
  writes: string[];
  /** Files read through `<`. */
  reads: string[];
  /** True when the stage carries code the parser cannot see (encoded or interpreter one-liners). */
  opaque: boolean;
  raw: string;
}

export interface Pipeline {
  stages: Stage[];
  raw: string;
  /** True when this pipeline came out of a substitution, subshell or `-c` string. */
  nested: boolean;
}

const MAX_DEPTH = 6;

const SH_FAMILY = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "busybox"]);
const PWSH = new Set(["pwsh", "powershell"]);
const INTERPRETERS_WITH_INLINE_CODE: Record<string, string[]> = {
  node: ["-e", "--eval", "-p", "--print"],
  nodejs: ["-e", "--eval", "-p", "--print"],
  deno: ["eval"],
  bun: ["-e", "--eval"],
  python: ["-c"],
  python3: ["-c"],
  python2: ["-c"],
  py: ["-c"],
  perl: ["-e", "-E"],
  ruby: ["-e"],
  php: ["-r"],
};

const WRAPPERS = new Set([
  "sudo", "doas", "command", "exec", "nohup", "time", "nice", "ionice", "timeout",
  "env", "xargs", "builtin", "stdbuf", "chronic", "caffeinate", "unbuffer", "setsid",
]);
/** Options that consume the following token, per wrapper. */
const WRAPPER_OPTS_WITH_ARG: Record<string, Set<string>> = {
  sudo: new Set(["-u", "-g", "-U", "-h", "-p", "-C", "-r", "-t", "-T", "-D", "-R"]),
  doas: new Set(["-u", "-C"]),
  env: new Set(["-u", "-C", "-S", "--unset", "--chdir", "--split-string"]),
  timeout: new Set(["-s", "-k", "--signal", "--kill-after"]),
  nice: new Set(["-n", "--adjustment"]),
  ionice: new Set(["-c", "-n", "-p", "-P", "-u"]),
  xargs: new Set(["-a", "-d", "-E", "-I", "-i", "-L", "-n", "-P", "-s", "-S", "--arg-file", "--delimiter", "--eof", "--replace", "--max-lines", "--max-args", "--max-procs", "--max-chars"]),
  stdbuf: new Set(["-i", "-o", "-e", "--input", "--output", "--error"]),
  caffeinate: new Set(["-t", "-w"]),
  command: new Set(),
  exec: new Set(["-a"]),
  nohup: new Set(),
  time: new Set(["-f", "-o", "--format", "--output"]),
  builtin: new Set(),
  chronic: new Set(),
  unbuffer: new Set(),
  setsid: new Set(),
};
/** Wrappers whose first positional argument is not the command. */
const WRAPPER_POSITIONAL_SKIP: Record<string, number> = { timeout: 1 };

export type ShellDialect = "posix" | "powershell" | "cmd";

export interface ParseOptions {
  /** Which shell will run the top-level command line. Defaults to POSIX sh. */
  dialect?: ShellDialect;
}

export function parseShell(command: string, options: ParseOptions = {}): Pipeline[] {
  try {
    return parseInner(command, 0, false, options.dialect ?? "posix");
  } catch {
    const argv = command.trim().split(/\s+/).filter(Boolean);
    return [{ raw: command, nested: false, stages: [makeStage(argv, {}, [], [], false, command)] }];
  }
}

function parseInner(command: string, depth: number, nested: boolean, dialect: ShellDialect): Pipeline[] {
  if (depth > MAX_DEPTH) return [];
  const { commands, substitutions } = splitTop(command, dialect);
  const out: Pipeline[] = [];
  for (const stageStrings of commands) {
    const stages: Stage[] = [];
    const extra: Pipeline[] = [];
    for (const s of stageStrings) {
      const text = s.trim();
      if (!text) continue;
      const grouped = unwrapGroup(text);
      if (grouped !== null) {
        extra.push(...parseInner(grouped, depth + 1, true, dialect));
        continue;
      }
      const stage = buildStage(text, dialect);
      stages.push(stage);
      const inner = inlineCommandOf(stage, dialect);
      if (inner !== null) extra.push(...parseInner(inner.command, depth + 1, true, inner.dialect));
    }
    if (stages.length > 0) out.push({ stages, raw: stageStrings.join(" | "), nested });
    out.push(...extra);
  }
  for (const sub of substitutions) out.push(...parseInner(sub, depth + 1, true, dialect));
  return out;
}

/** `( ... )` subshells and `{ ...; }` groups: return the inner text, or null. */
function unwrapGroup(text: string): string | null {
  if (text.startsWith("(") && text.endsWith(")")) return text.slice(1, -1);
  if (text.startsWith("{") && text.endsWith("}")) {
    const inner = text.slice(1, -1).trim();
    return inner.endsWith(";") ? inner.slice(0, -1) : inner;
  }
  return null;
}

interface Split {
  commands: string[][];
  substitutions: string[];
}

/**
 * Split on `&&`, `||`, `;`, newline, `&` and `|` outside quotes, parentheses and
 * substitutions. Returns commands (each a list of pipe stages) and the text of
 * every `$(...)` and backtick substitution found at any depth.
 */
function splitTop(s: string, dialect: ShellDialect): Split {
  const escapeChar = dialect === "posix" ? "\\" : dialect === "powershell" ? "`" : "^";
  const commands: string[][] = [];
  const substitutions: string[] = [];
  let stages: string[] = [];
  let cur = "";
  let inSingle = false;
  let inDouble = false;
  let backtickStart = -1;
  // Open `$(` substitutions (start >= 0) and plain parentheses inside them (start -1).
  // `outerDouble` remembers whether the enclosing text was double-quoted, because
  // quoting starts afresh inside `$( )` and resumes when it closes.
  const subs: { start: number; outerDouble: boolean }[] = [];
  let parenDepth = 0;
  let braceDepth = 0;

  const endStage = () => {
    stages.push(cur);
    cur = "";
  };
  const endCommand = () => {
    endStage();
    commands.push(stages);
    stages = [];
  };

  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    const next = s[i + 1];
    const prev = i > 0 ? s[i - 1] : "";

    if (inSingle) {
      cur += c;
      if (c === "'") inSingle = false;
      continue;
    }
    if (c === escapeChar) {
      const skip = continuationLength(s, i);
      if (skip > 0) {
        // Line continuation: the escape and the newline produce nothing.
        i += skip - 1;
        continue;
      }
      cur += c + (next ?? "");
      i++;
      continue;
    }
    if (backtickStart >= 0) {
      cur += c;
      if (c === "`") {
        substitutions.push(s.slice(backtickStart, i));
        backtickStart = -1;
      }
      continue;
    }
    if (subs.length > 0) {
      cur += c;
      if (inDouble) {
        if (c === '"') inDouble = false;
        continue;
      }
      if (c === '"') inDouble = true;
      else if (c === "'") inSingle = true;
      else if (c === "(") subs.push({ start: -1, outerDouble: false });
      else if (c === ")") {
        const sub = subs.pop();
        if (sub !== undefined && sub.start >= 0) {
          inDouble = sub.outerDouble;
          // Only the outermost substitution is recorded; parsing it finds the inner ones once.
          if (subs.length === 0) substitutions.push(s.slice(sub.start, i));
        }
      } else if (c === "$" && next === "(") {
        subs.push({ start: i + 2, outerDouble: false });
        cur += next;
        i++;
      }
      continue;
    }
    if (c === '"') {
      inDouble = !inDouble;
      cur += c;
      continue;
    }
    if (c === "$" && next === "(") {
      subs.push({ start: i + 2, outerDouble: inDouble });
      inDouble = false;
      cur += c + next;
      i++;
      continue;
    }
    if (c === "`" && dialect === "posix") {
      backtickStart = i + 1;
      cur += c;
      continue;
    }
    if (inDouble) {
      cur += c;
      if (c === "'" ) { /* literal inside double quotes */ }
      continue;
    }
    if (c === "'") {
      inSingle = true;
      cur += c;
      continue;
    }
    if (c === "(") {
      // Process substitution `<(` / `>(` and subshells both nest.
      parenDepth++;
      cur += c;
      continue;
    }
    if (c === ")" && parenDepth > 0) {
      parenDepth--;
      cur += c;
      continue;
    }
    if (parenDepth > 0) {
      cur += c;
      continue;
    }
    if (c === "{" && (cur.trim() === "" ) && (next === " " || next === "\t" || next === "\n")) {
      braceDepth++;
      cur += c;
      continue;
    }
    if (c === "}" && braceDepth > 0 && /(^|[\s;])$/.test(cur)) {
      braceDepth--;
      cur += c;
      continue;
    }
    if (braceDepth > 0) {
      cur += c;
      continue;
    }

    if (c === "&" && next === "&") { endCommand(); i++; continue; }
    if (c === "|" && next === "|") { endCommand(); i++; continue; }
    if (c === ";" || c === "\n") { endCommand(); continue; }
    if (c === "|") {
      if (next === "&") i++;
      endStage();
      continue;
    }
    if (c === "&") {
      // `&>file`, `>&2`, `2>&1`, `<&0` are redirections; `sleep 1& rm x` backgrounds `sleep 1`.
      if (next === ">" || /[<>]\d*$/.test(cur)) {
        cur += c;
        continue;
      }
      if (dialect === "powershell" && cur.trim() === "") {
        // Call operator: `& "C:\\tool.exe" args`
        continue;
      }
      endCommand();
      continue;
    }
    cur += c;
  }
  endCommand();
  return {
    commands: commands.map((st) => st.filter((x) => x.trim() !== "")).filter((st) => st.length > 0),
    substitutions,
  };
}

/**
 * Length of a line continuation starting at the escape character at `i`
 * (`\` + newline in sh, backtick + newline in PowerShell, `^` + newline in cmd),
 * with or without a carriage return; 0 when it is not one.
 */
function continuationLength(s: string, i: number): number {
  if (s[i + 1] === "\n") return 2;
  if (s[i + 1] === "\r" && s[i + 2] === "\n") return 3;
  return 0;
}

interface Token {
  text: string;
  /** Set for unquoted redirection operators. */
  op?: string;
}

function tokenize(stage: string, dialect: ShellDialect): Token[] {
  const escapeChar = dialect === "posix" ? "\\" : dialect === "powershell" ? "`" : "^";
  const tokens: Token[] = [];
  let cur = "";
  let has = false;
  let inSingle = false;
  let inDouble = false;
  let depth = 0; // $( ) and ( ) nesting inside a token

  const flush = () => {
    if (has) tokens.push({ text: cur });
    cur = "";
    has = false;
  };

  for (let i = 0; i < stage.length; i++) {
    const c = stage[i];
    const next = stage[i + 1];
    if (inSingle) {
      if (c === "'") inSingle = false;
      else cur += c;
      continue;
    }
    if (c === escapeChar) {
      const skip = continuationLength(stage, i);
      if (skip > 0) {
        // Line continuation, inside double quotes too: it yields no character and no token.
        i += skip - 1;
        continue;
      }
    }
    if (c === escapeChar && next !== undefined && !(inDouble && dialect === "posix" && !'"$`\\'.includes(next))) {
      cur += next;
      has = true;
      i++;
      continue;
    }
    if (inDouble) {
      if (c === '"') inDouble = false;
      else cur += c;
      continue;
    }
    if (depth > 0) {
      cur += c;
      if (c === "'" || c === '"') {
        // A quoted `)` inside `$( )` does not close it; copy the quoted text through.
        const close = stage.indexOf(c, i + 1);
        if (close === -1) { cur += stage.slice(i + 1); break; }
        cur += stage.slice(i + 1, close + 1);
        i = close;
      } else if (c === "(") depth++;
      else if (c === ")") depth--;
      continue;
    }
    if (c === "'") { inSingle = true; has = true; continue; }
    if (c === '"') { inDouble = true; has = true; continue; }
    if (c === "$" && next === "(") { cur += "$("; has = true; depth = 1; i++; continue; }
    if ((c === "<" || c === ">") && next === "(") { cur += c + "("; has = true; depth = 1; i++; continue; }
    if (c === " " || c === "\t") { flush(); continue; }
    if (c === ">" || c === "<") {
      // Redirection. Fold a preceding bare fd number (`2>`) into the operator.
      let op = "";
      if (has && /^\d+$/.test(cur)) { op = cur; cur = ""; has = false; }
      else flush();
      op += c;
      if (next === c) { op += c; i++; }
      else if (c === ">" && (next === "&" || next === "|")) { op += next; i++; }
      tokens.push({ text: op, op });
      continue;
    }
    if (c === "&" && next === ">") {
      flush();
      let op = "&>";
      i++;
      if (stage[i + 1] === ">") { op += ">"; i++; }
      tokens.push({ text: op, op });
      continue;
    }
    cur += c;
    has = true;
  }
  flush();
  return tokens;
}

const ENV_ASSIGN = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s;

function buildStage(text: string, dialect: ShellDialect): Stage {
  const tokens = tokenize(text, dialect);
  const argv: string[] = [];
  const writes: string[] = [];
  const reads: string[] = [];
  const env: Record<string, string> = {};

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.op !== undefined) {
      const target = tokens[i + 1];
      const isOutput = t.op.includes(">") && !t.op.endsWith("&") && !t.op.startsWith("<");
      const isInput = t.op === "<";
      if (target && target.op === undefined) {
        i++;
        // A whitespace-only target (`> ""`) names no file.
        if (target.text.trim() === "") continue;
        if (isOutput && !target.text.startsWith("&") && target.text !== "/dev/null" && target.text.toLowerCase() !== "nul") {
          writes.push(target.text);
        }
        if (isInput) reads.push(target.text);
      }
      continue;
    }
    argv.push(t.text);
  }

  // Leading VAR=value assignments.
  while (argv.length > 0) {
    const m = ENV_ASSIGN.exec(argv[0]);
    if (!m) break;
    env[m[1]] = m[2];
    argv.shift();
  }

  const wrappers: string[] = [];
  let guard = 0;
  while (argv.length > 0 && guard++ < 8) {
    const name = normalizeCmd(argv[0]);
    if (!WRAPPERS.has(name)) break;
    if (name === "command" && (argv[1] === "-v" || argv[1] === "-V")) break;
    wrappers.push(name);
    argv.shift();
    const withArg = WRAPPER_OPTS_WITH_ARG[name] ?? new Set<string>();
    let skipPositional = WRAPPER_POSITIONAL_SKIP[name] ?? 0;
    while (argv.length > 0) {
      const a = argv[0];
      if (a === "--") { argv.shift(); break; }
      const envMatch = (name === "env" || name === "sudo" || name === "doas") ? ENV_ASSIGN.exec(a) : null;
      if (envMatch) { env[envMatch[1]] = envMatch[2]; argv.shift(); continue; }
      const split = name === "env" ? splitStringOf(argv) : null;
      if (split !== null) {
        // `env -S 'ah init --remove'`: env splits the string into words that take its place.
        argv.unshift(...tokenize(split, "posix").map((t) => t.text));
        continue;
      }
      if (a.startsWith("-") && a.length > 1) {
        argv.shift();
        const key = a.includes("=") ? a.slice(0, a.indexOf("=")) : a;
        if (withArg.has(key) && !a.includes("=")) {
          argv.shift();
        } else if (!a.startsWith("--") && a.length > 2 && withArg.has(a.slice(0, 2))) {
          // glued value, e.g. `-n1`, `-I{}`
        }
        continue;
      }
      if (skipPositional > 0) { skipPositional--; argv.shift(); continue; }
      break;
    }
  }

  // Package runners: `npx wrangler deploy` is a wrangler command.
  unwrapRunner(argv, wrappers);

  // tee writes its file arguments.
  const cmd = argv.length > 0 ? normalizeCmd(argv[0]) : (wrappers[wrappers.length - 1] ?? "");
  if (cmd === "tee") {
    for (const a of argv.slice(1)) if (!a.startsWith("-")) writes.push(a);
  }

  const opaque = isOpaque(cmd, argv);
  return makeStage(argv, env, wrappers, writes, opaque, text, reads);
}

/** The string of `env -S STR`, `-SSTR`, `--split-string STR` or `--split-string=STR` at argv[0], shifted off argv; null for any other word. */
function splitStringOf(argv: string[]): string | null {
  const a = argv[0];
  let value: string | undefined;
  if (a === "-S" || a === "--split-string") value = argv[1] ?? "";
  else if (a.startsWith("--split-string=")) value = a.slice("--split-string=".length);
  else if (a.startsWith("-S")) value = a.slice(2);
  if (value === undefined) return null;
  argv.splice(0, a === "-S" || a === "--split-string" ? 2 : 1);
  return value;
}

function makeStage(argv: string[], env: Record<string, string>, wrappers: string[], writes: string[], opaque: boolean, raw: string, reads: string[] = []): Stage {
  return {
    argv,
    cmd: argv.length > 0 ? normalizeCmd(argv[0]) : (wrappers[wrappers.length - 1] ?? ""),
    env,
    wrappers,
    writes,
    reads,
    opaque,
    raw,
  };
}

/** Runner options that consume the next word. `-c`/`--call` carry a command line and are read, not skipped. */
const RUNNER_OPTS_WITH_ARG = new Set(["-p", "--package", "--shell", "--from", "--with", "--python", "-w"]);
const TWO_WORD_RUNNERS: Record<string, Set<string>> = {
  npm: new Set(["exec", "x"]),
  pnpm: new Set(["dlx", "exec"]),
  yarn: new Set(["dlx", "exec"]),
  bun: new Set(["x"]),
  pipx: new Set(["run"]),
  poetry: new Set(["run"]),
  uv: new Set(["run"]),
  bundle: new Set(["exec"]),
};

/** Options a package manager takes before its subcommand that consume the next word: `pnpm -C dir exec`, `npm --prefix dir exec`, `yarn --cwd dir dlx`. */
const PM_OPTS_WITH_ARG: Record<string, Set<string>> = {
  npm: new Set(["-C", "--prefix", "-w", "--workspace", "--userconfig", "--cache", "--registry", "--loglevel"]),
  pnpm: new Set(["-C", "--dir", "-F", "--filter", "--loglevel", "--reporter"]),
  yarn: new Set(["--cwd"]),
  bun: new Set(["--cwd"]),
};

/** Index of a package manager's subcommand in `argv`: the first word after the options it takes before one. */
export function subcommandIndex(argv: readonly string[]): number {
  const valued = PM_OPTS_WITH_ARG[normalizeCmd(argv[0] ?? "")];
  let k = 1;
  while (k < argv.length && argv[k].startsWith("-") && argv[k] !== "--") k += valued?.has(argv[k]) ? 2 : 1;
  return k;
}

/** Strip `npx`, `pnpm dlx`, `uv run` and similar so the real command is `argv[0]`. */
function unwrapRunner(argv: string[], wrappers: string[]): void {
  let guard = 0;
  while (argv.length > 0 && guard++ < 4) {
    const name = normalizeCmd(argv[0]);
    let consumed = 0;
    if (name === "npx" || name === "pnpx" || name === "bunx" || name === "uvx") consumed = 1;
    else {
      const k = subcommandIndex(argv);
      if (TWO_WORD_RUNNERS[name]?.has(argv[k] ?? "")) consumed = k + 1;
    }
    if (consumed === 0) return;
    wrappers.push(consumed === 1 ? argv[0] : `${argv[0]} ${argv[consumed - 1]}`);
    argv.splice(0, consumed);
    while (argv.length > 0 && argv[0].startsWith("-")) {
      const opt = argv.shift() as string;
      if (opt === "-c" || opt === "--call" || opt.startsWith("--call=")) {
        // `npx -c 'cmd'`, `npm exec --call 'cmd'`, `pnpm exec -c cmd`: the rest runs as a shell
        // command line, so the stage becomes that shell's `-c` and the parser reads the command inside.
        const line = opt.startsWith("--call=") ? [opt.slice("--call=".length), ...argv] : [...argv];
        argv.splice(0, argv.length, "sh", "-c", line.join(" "));
        return;
      }
      if (RUNNER_OPTS_WITH_ARG.has(opt)) argv.shift();
      if (opt === "--") break;
    }
    if (argv.length > 0) {
      // `@scope/name@version` -> `name`
      argv[0] = argv[0].replace(/^@[^/]+\//, "").replace(/(.)@[^@]*$/, "$1");
      // `npm exec <pkg> -- <args>`: npm takes the `--` as the end of its own options.
      if ((name === "npx" || name === "npm") && argv[1] === "--") argv.splice(1, 1);
    }
  }
}

/**
 * Basename, lowercase, no leading backslash, no Windows executable suffix. `.ps1`
 * counts as one: npm installs `ah.ps1` beside `ah.cmd`, and PowerShell runs either by name.
 */
export function normalizeCmd(token: string): string {
  let s = token.startsWith("\\") ? token.slice(1) : token;
  s = s.replace(/\\/g, "/");
  s = s.slice(s.lastIndexOf("/") + 1).toLowerCase();
  s = s.replace(/\.(exe|cmd|bat|com|ps1)$/, "");
  return s;
}

function isOpaque(cmd: string, argv: string[]): boolean {
  if (PWSH.has(cmd)) {
    return argv.some((a) => /^-(e|ec|enc|encodedcommand)$/i.test(a));
  }
  const flags = INTERPRETERS_WITH_INLINE_CODE[cmd];
  if (flags) return argv.slice(1).some((a) => flags.includes(a));
  if (cmd === "base64" || cmd === "xxd") return false;
  return false;
}

interface Inline {
  command: string;
  dialect: ShellDialect;
}

const START_PROCESS = new Set(["start-process", "saps"]);
/** Start-Process switches; any other parameter takes a value. PowerShell accepts any unambiguous prefix of a name. */
const START_PROCESS_SWITCHES = ["wait", "nonewwindow", "passthru", "usenewenvironment", "loaduserprofile", "whatif", "confirm"];

/**
 * `Start-Process ah 'init --remove'`, `Start-Process -FilePath ah -ArgumentList 'init','--remove'`:
 * the program and its arguments as one command line, or null when no program is named.
 */
function startProcessCommand(argv: readonly string[]): string | null {
  let file: string | undefined;
  let list: string | undefined;
  const positional: string[] = [];
  for (let i = 1; i < argv.length; i++) {
    const m = /^-([a-z]+)(?::(.*))?$/i.exec(argv[i]);
    if (m === null) {
      positional.push(argv[i]);
      continue;
    }
    const p = m[1].toLowerCase();
    if (m[2] === undefined && START_PROCESS_SWITCHES.some((s) => s.startsWith(p))) continue;
    const value = m[2] ?? argv[++i] ?? "";
    if ("filepath".startsWith(p) || p === "path" || p === "pspath") file = value;
    else if ("argumentlist".startsWith(p) || p === "args") list = value;
  }
  file ??= positional.shift();
  list ??= positional.shift();
  if (file === undefined || file === "") return null;
  // The program is one word even with spaces in it; the arguments are a command line. An argument
  // array arrives as one comma-joined word: `'init','--remove'` is `init,--remove`.
  const program = /\s/.test(file) ? `'${file.replace(/'/g, "''")}'` : file;
  return [program, ...(list ?? "").split(","), ...positional].filter((w) => w !== "").join(" ");
}

/** The command string carried by `sh -c`, `pwsh -Command`, `cmd /c`, `eval`, `iex`, `Start-Process`, `su -c`. */
function inlineCommandOf(stage: Stage, dialect: ShellDialect): Inline | null {
  const { cmd, argv } = stage;
  if (SH_FAMILY.has(cmd)) {
    let start = 1;
    if (cmd === "busybox") {
      if (!SH_FAMILY.has(argv[1] ?? "")) return null;
      start = 2;
    }
    for (let i = start; i < argv.length; i++) {
      const a = argv[i];
      if (a === "--") break;
      // `bash -c -- 'cmd'`: the `--` after -c ends option parsing and the next token is still the command.
      if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(a)) {
        const j = argv[i + 1] === "--" ? i + 2 : i + 1;
        return argv[j] === undefined ? null : { command: argv[j], dialect: "posix" };
      }
      // `-o pipefail`, `-euo pipefail`, `+O shopt`, `--rcfile file`: the next token is a value, not the script.
      if (/^[-+][a-zA-Z]*[oO]$/.test(a) || /^--(rcfile|init-file)$/.test(a)) { i++; continue; }
      // Any other flag (`-l`, `-x`, `--noprofile`, `--norc`, `+e`) is skipped; the first positional is a script.
      if (a.startsWith("-") || (a.startsWith("+") && a.length > 1)) continue;
      break;
    }
    return null;
  }
  if (PWSH.has(cmd)) {
    for (let i = 1; i < argv.length; i++) {
      if (/^-(c|command)$/i.test(argv[i])) return { command: argv.slice(i + 1).join(" "), dialect: "powershell" };
    }
    const positional = argv.slice(1).filter((a) => !a.startsWith("-"));
    if (positional.length > 0 && !argv.some((a) => /^-(f|file)$/i.test(a))) {
      return { command: positional.join(" "), dialect: "powershell" };
    }
    return null;
  }
  if (cmd === "cmd") {
    for (let i = 1; i < argv.length; i++) {
      if (/^\/[ck]$/i.test(argv[i])) return { command: argv.slice(i + 1).join(" "), dialect: "cmd" };
    }
    return null;
  }
  if (cmd === "eval") return { command: argv.slice(1).join(" "), dialect };
  // PowerShell's eval: `iex 'cmd'`, `Invoke-Expression -Command 'cmd'`.
  if (cmd === "iex" || cmd === "invoke-expression") {
    const code = argv.slice(1).filter((a) => !/^-c(ommand)?$/i.test(a)).join(" ");
    return code === "" ? null : { command: code, dialect: "powershell" };
  }
  if (START_PROCESS.has(cmd) || (cmd === "start" && dialect === "powershell")) {
    const run = startProcessCommand(argv);
    return run === null ? null : { command: run, dialect: "powershell" };
  }
  if (cmd === "su") {
    const i = argv.indexOf("-c");
    if (i >= 0 && argv[i + 1] !== undefined) return { command: argv[i + 1], dialect: "posix" };
  }
  return null;
}

export interface Flags {
  short: Set<string>;
  long: Set<string>;
  /** Value of `--name=value` style flags. */
  longValues: Map<string, string>;
  positionals: string[];
}

/**
 * Split `argv.slice(start)` into short flags (each letter of `-abc`), long
 * flags and positionals. Stops treating tokens as flags after `--`.
 * `optsWithValue` lists flags whose following token is a value, not a positional.
 */
export function flagsOf(argv: readonly string[], start = 1, optsWithValue: readonly string[] = []): Flags {
  const short = new Set<string>();
  const long = new Set<string>();
  const longValues = new Map<string, string>();
  const positionals: string[] = [];
  const valued = new Set(optsWithValue);
  let flagsDone = false;
  for (let i = start; i < argv.length; i++) {
    const a = argv[i];
    if (flagsDone) { positionals.push(a); continue; }
    if (a === "--") { flagsDone = true; continue; }
    if (a.startsWith("--") && a.length > 2) {
      const eq = a.indexOf("=");
      if (eq > 0) { long.add(a.slice(2, eq)); longValues.set(a.slice(2, eq), a.slice(eq + 1)); }
      else {
        long.add(a.slice(2));
        if (valued.has(a)) { longValues.set(a.slice(2), argv[i + 1] ?? ""); i++; }
      }
      continue;
    }
    if (a.startsWith("-") && a.length > 1 && !/^-\d/.test(a)) {
      const letters = a.slice(1);
      for (const ch of letters) short.add(ch);
      if (valued.has(`-${letters[letters.length - 1]}`) && letters.length === 1) i++;
      else if (valued.has(`-${letters[0]}`) && letters.length > 1) { /* glued value, e.g. -ofile */ }
      continue;
    }
    positionals.push(a);
  }
  return { short, long, longValues, positionals };
}

/** Every stage from every pipeline, nested ones included. */
export function allStages(pipelines: readonly Pipeline[]): Stage[] {
  const out: Stage[] = [];
  for (const p of pipelines) out.push(...p.stages);
  return out;
}
