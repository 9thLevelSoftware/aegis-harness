/**
 * A small, forgiving shell command parser.
 *
 * It is not a shell. It splits a command line into pipelines and stages,
 * tokenizes each stage with quote awareness, peels off wrappers such as
 * `sudo`, `env`, `xargs` and `timeout` and the reserved words of compound
 * commands, records redirection targets, and recurses into `sh -c "..."`,
 * `pwsh -Command "..."`, `cmd /c ...`, `eval`, `iex`, `Start-Process`,
 * `npx -c`, `$(...)` and backtick substitutions, process substitutions and
 * PowerShell's `( )` and `{ }` blocks, so that rules see every command that
 * will actually run. On input it cannot make sense of it degrades to a
 * whitespace split rather than throwing: the guard must never crash open.
 */

export interface Stage {
  /** Arguments after env assignments and wrappers were removed. `argv[0]` is the command. */
  argv: string[];
  /** Normalized command name: basename, lowercase, without `.exe`/`.cmd`/`.bat`. */
  cmd: string;
  /** Leading `VAR=value` assignments and those passed through `env`/`sudo`. */
  env: Record<string, string>;
  /** Wrappers that were peeled off, in order (`sudo`, `xargs`, ...). */
  wrappers: string[];
  /** Files written through `>`, `>>`, `&>` or `tee`. `/dev/null` is dropped. */
  writes: string[];
  /** Files read through `<`. */
  reads: string[];
  /** Text fed to stdin through a `<<<` here-string. */
  hereStrings: string[];
  /** True when the stage carries code the parser cannot see (encoded or interpreter one-liners). */
  opaque: boolean;
  /** A word left unexpanded because its brace expansion would pass the command's BRACE_LIMIT words. */
  unexpanded?: string;
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
  "env", "xargs", "builtin", "stdbuf", "chronic", "caffeinate", "unbuffer", "setsid", "corepack",
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
  corepack: new Set(),
};
/** Wrappers whose first positional argument is not the command. */
const WRAPPER_POSITIONAL_SKIP: Record<string, number> = { timeout: 1 };

export type ShellDialect = "posix" | "powershell" | "cmd";

export interface ParseOptions {
  /** Which shell will run the top-level command line. Defaults to POSIX sh. */
  dialect?: ShellDialect;
  /**
   * Brace-expanded words the parse may still produce, shared by every parse of one command
   * (its substitutions, `sh -c` strings and the text it pipes into a shell), so a short command
   * cannot multiply into more words than the guard can judge before the hook times out.
   */
  budget?: BraceBudget;
}

export interface BraceBudget {
  words: number;
}

export function parseShell(command: string, options: ParseOptions = {}): Pipeline[] {
  try {
    return parseInner(command, 0, false, options.dialect ?? "posix", options.budget ?? { words: BRACE_LIMIT });
  } catch {
    const argv = command.trim().split(/\s+/).filter(Boolean);
    return [{ raw: command, nested: false, stages: [makeStage(argv, {}, [], [], false, command)] }];
  }
}

function parseInner(command: string, depth: number, nested: boolean, dialect: ShellDialect, budget: BraceBudget): Pipeline[] {
  if (depth > MAX_DEPTH) return [];
  const { commands, substitutions } = splitTop(command, dialect);
  const out: Pipeline[] = [];
  for (const stageStrings of commands) {
    const stages: Stage[] = [];
    const extra: Pipeline[] = [];
    for (const s of stageStrings) {
      const text = s.trim();
      if (!text) continue;
      const grouped = unwrapGroup(text, dialect);
      if (grouped !== null) {
        extra.push(...parseInner(grouped, depth + 1, true, dialect, budget));
        continue;
      }
      const stage = buildStage(text, dialect, budget);
      stages.push(stage);
      const inner = inlineCommandOf(stage, dialect);
      if (inner !== null) extra.push(...parseInner(inner.command, depth + 1, true, inner.dialect, budget));
    }
    if (stages.length > 0) out.push({ stages, raw: stageStrings.join(" | "), nested });
    out.push(...extra);
  }
  for (const sub of substitutions) out.push(...parseInner(sub, depth + 1, true, dialect, budget));
  return out;
}

/**
 * `( ... )` subshells and `{ ...; }` groups: return the inner text, or null. In sh a group's `{`
 * is a word of its own, so `{rm,-rf,x}` is one brace-expanded command, not a group.
 */
function unwrapGroup(text: string, dialect: ShellDialect): string | null {
  if (text.startsWith("(") && text.endsWith(")")) return text.slice(1, -1);
  if (text.startsWith("{") && text.endsWith("}") && (dialect !== "posix" || /^\{\s/.test(text))) {
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
  // Open `( )` groups, and `{ }` script blocks in PowerShell, with where their text starts and
  // whether it runs as a command where it stands: every group in PowerShell and cmd
  // (`$null = (ah x)`, `if ($c) { ah x }`, `1 | % { ah x }`), and in sh a subshell or process
  // substitution (`(rm -rf x) 2>/dev/null`, `diff <(ah x) y`), not an array (`a=(x y)`).
  const groups: { start: number; runs: boolean }[] = [];
  let braceDepth = 0;
  let braceStart = 0;

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
    if (c === "(" || (c === "{" && dialect === "powershell")) {
      // Process substitution `<(` / `>(` and subshells both nest.
      groups.push({ start: i + 1, runs: dialect !== "posix" || prev === "" || /[\s<>;&|(]/.test(prev) });
      cur += c;
      continue;
    }
    if ((c === ")" || (c === "}" && dialect === "powershell")) && groups.length > 0) {
      const group = groups.pop() as { start: number; runs: boolean };
      // Only the outermost group that runs is recorded; parsing it finds the inner ones once.
      if (group.runs && !groups.some((g) => g.runs)) substitutions.push(s.slice(group.start, i));
      cur += c;
      continue;
    }
    if (groups.length > 0) {
      cur += c;
      continue;
    }
    if (c === "{" && (cur.trim() === "" ) && (next === " " || next === "\t" || next === "\n")) {
      if (braceDepth++ === 0) braceStart = i + 1;
      cur += c;
      continue;
    }
    if (c === "}" && braceDepth > 0 && /(^|[\s;])$/.test(cur)) {
      // `{ rm -rf x; } > log`: a redirected group is not unwrapped whole, so its commands are recorded here.
      if (--braceDepth === 0) substitutions.push(s.slice(braceStart, i));
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
  /** No quote, escape or substitution anywhere in the word. */
  bare?: boolean;
  /** Per character of `text`: true where it was written unquoted and unescaped, so sh may brace-expand it. */
  live?: boolean[];
}

/** Brace-expanded words one command may yield before the guard stops expanding and asks instead. */
export const BRACE_LIMIT = 1024;

interface BraceGroup {
  start: number;
  end: number;
  parts: { text: string; live: boolean[] }[];
}

const SEQ_NUMBERS = /^([-+]?\d+)\.\.([-+]?\d+)(?:\.\.([-+]?\d+))?$/;
const SEQ_LETTERS = /^([A-Za-z])\.\.([A-Za-z])(?:\.\.([-+]?\d+))?$/;

/**
 * The words of a sequence expression (`1..3`, `01..10..2`, `a..e`), as bash writes them, or
 * null when `body` is none; more than `limit` words is `"overflow"`.
 */
function sequence(body: string, limit: number): string[] | "overflow" | null {
  const num = SEQ_NUMBERS.exec(body);
  const letters = num === null ? SEQ_LETTERS.exec(body) : null;
  const m = num ?? letters;
  if (m === null) return null;
  const from = num ? Number(m[1]) : m[1].charCodeAt(0);
  const to = num ? Number(m[2]) : m[2].charCodeAt(0);
  const step = Math.abs(Number(m[3] ?? 1)) || 1;
  if (Math.floor(Math.abs(to - from) / step) + 1 > limit) return "overflow";
  const width = num && (/^[-+]?0\d/.test(m[1]) || /^[-+]?0\d/.test(m[2])) ? Math.max(m[1].length, m[2].length) : 0;
  const out: string[] = [];
  for (let n = from; from <= to ? n <= to : n >= to; n += from <= to ? step : -step) {
    if (!num) out.push(String.fromCharCode(n));
    else out.push(n < 0 ? `-${String(-n).padStart(width - 1, "0")}` : String(n).padStart(width, "0"));
  }
  return out;
}

/** The first brace group sh expands in `word`, null when there is none, `"overflow"` when it alone yields more than `limit` words. */
function firstBraceGroup(word: string, live: readonly boolean[], limit: number): BraceGroup | "overflow" | null {
  for (let i = 0; i < word.length; i++) {
    if (word[i] !== "{" || !live[i] || (word[i - 1] === "$" && live[i - 1])) continue;
    const commas: number[] = [];
    for (let j = i, depth = 0; j < word.length; j++) {
      if (!live[j]) continue;
      if (word[j] === "{") depth++;
      else if (word[j] === "," && depth === 1) commas.push(j);
      else if (word[j] === "}" && --depth === 0) {
        if (commas.length > 0) {
          const parts: BraceGroup["parts"] = [];
          let from = i + 1;
          for (const to of [...commas, j]) {
            parts.push({ text: word.slice(from, to), live: live.slice(from, to) });
            from = to + 1;
          }
          return { start: i, end: j, parts };
        }
        const body = word.slice(i + 1, j);
        const seq = live.slice(i + 1, j).every(Boolean) ? sequence(body, limit) : null;
        if (seq === "overflow") return seq;
        if (seq !== null) return { start: i, end: j, parts: seq.map((text) => ({ text, live: Array.from(text, () => false) })) };
        break;
      }
    }
  }
  return null;
}

/**
 * sh brace expansion of one word: `.ruff.toml{,.bak}` is `.ruff.toml .ruff.toml.bak`,
 * `{rm,-rf,x}` is `rm -rf x`, `.claud{e..e}` is `.claude`. Only braces and commas marked
 * `live` (unquoted, unescaped) count, so `{a,"b,c"}` is `a b,c` and `"{a,b}"` stays as it is.
 * Alternatives nest; `${VAR}` and a group with neither a comma nor a sequence stay as they
 * are. Returns null rather than a partial list once the words would pass `limit`.
 */
export function braceExpand(word: string, live: readonly boolean[] = Array.from(word, () => true), limit = BRACE_LIMIT): string[] | null {
  const out: string[] = [];
  const expand = (w: string, l: readonly boolean[]): boolean => {
    const group = firstBraceGroup(w, l, limit);
    if (group === "overflow") return false;
    if (group === null) {
      out.push(w);
      return out.length <= limit;
    }
    for (const part of group.parts) {
      if (!expand(w.slice(0, group.start) + part.text + w.slice(group.end + 1), [...l.slice(0, group.start), ...part.live, ...l.slice(group.end + 1)])) return false;
    }
    return true;
  };
  return expand(word, live) ? out : null;
}

function tokenize(stage: string, dialect: ShellDialect): Token[] {
  const escapeChar = dialect === "posix" ? "\\" : dialect === "powershell" ? "`" : "^";
  const tokens: Token[] = [];
  let cur = "";
  let live: boolean[] = [];
  let has = false;
  let bare = true;
  /** Append text that sh will not brace-expand: quoted, escaped, or inside a substitution. */
  const dead = (text: string) => {
    cur += text;
    for (let k = 0; k < text.length; k++) live.push(false);
  };
  let inSingle = false;
  let inDouble = false;
  let depth = 0; // $( ) and ( ) nesting inside a token

  const flush = () => {
    if (has) tokens.push(bare ? { text: cur, bare, live } : { text: cur, live });
    cur = "";
    live = [];
    has = false;
    bare = true;
  };

  for (let i = 0; i < stage.length; i++) {
    const c = stage[i];
    const next = stage[i + 1];
    if (inSingle) {
      if (c === "'") inSingle = false;
      else dead(c);
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
      dead(next);
      has = true;
      bare = false;
      i++;
      continue;
    }
    if (inDouble) {
      if (c === '"') inDouble = false;
      else dead(c);
      continue;
    }
    if (depth > 0) {
      dead(c);
      if (c === "'" || c === '"') {
        // A quoted `)` inside `$( )` does not close it; copy the quoted text through.
        const close = stage.indexOf(c, i + 1);
        if (close === -1) { dead(stage.slice(i + 1)); break; }
        dead(stage.slice(i + 1, close + 1));
        i = close;
      } else if (c === "(") depth++;
      else if (c === ")") depth--;
      continue;
    }
    if (c === "'") { inSingle = true; has = true; bare = false; continue; }
    if (c === '"') { inDouble = true; has = true; bare = false; continue; }
    if (c === "$" && next === "(") { dead("$("); has = true; bare = false; depth = 1; i++; continue; }
    if ((c === "<" || c === ">") && next === "(") { dead(c + "("); has = true; bare = false; depth = 1; i++; continue; }
    if (c === " " || c === "\t") { flush(); continue; }
    if (c === ">" || c === "<") {
      // Redirection. Fold a preceding bare fd number (`2>`) into the operator.
      let op = "";
      if (has && /^\d+$/.test(cur)) { op = cur; cur = ""; live = []; has = false; }
      else flush();
      op += c;
      if (next === c) {
        op += c;
        i++;
        if (c === "<" && stage[i + 1] === "<") { op += c; i++; }
      }
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
    live.push(true);
    has = true;
  }
  flush();
  return tokens;
}

const ENV_ASSIGN = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s;
/** `$null = `, `$out += `, `[string]$x=`: PowerShell keeps or drops a command's output, and the command still runs. */
const PWSH_ASSIGNMENT = /^(?:\s*(?:\[[\w.]+\]\s*)*\$[\w:{}.[\]]+\s*(?:[-+*/%]|\?\?)?=(?!=)\s*)+/;
/** Words that lead a command inside a compound command once the splitter has cut it at `;`: `then cmd`, `do cmd`, `! cmd`. */
const COMPOUND_LEADS = new Set(["if", "then", "elif", "else", "while", "until", "do", "!", "{", "coproc"]);

/**
 * Drop what POSIX sh puts before a command inside a compound command: reserved words, `case x in`,
 * a case pattern (`x)`, `(x|y)`) and a function header (`f()`, `f ()`, `function f`), so that
 * `if true; then ah init --remove; fi` is seen as `ah init --remove`.
 */
function stripCompoundLeads(argv: string[]): void {
  for (let guard = 0; argv.length > 0 && guard < 8; guard++) {
    const a = argv[0];
    if (COMPOUND_LEADS.has(a)) argv.shift();
    else if (a === "case" && argv[2] === "in") argv.splice(0, 3);
    else if (a === "function" && argv.length > 1) argv.splice(0, argv[2] === "()" ? 3 : 2);
    else if (argv[1] === "()") argv.splice(0, 2);
    else if (/^\(?[^()]*\)$/.test(a) && a !== ")") argv.shift();
    else if (/^[^()]+\(\)$/.test(a)) argv.shift();
    else return;
  }
}

function buildStage(text: string, dialect: ShellDialect, budget: BraceBudget): Stage {
  let tokens = tokenize(dialect === "powershell" ? text.replace(PWSH_ASSIGNMENT, "") : text, dialect);
  let unexpanded: string | undefined;
  if (dialect === "posix") {
    tokens = tokens.flatMap((t) => {
      if (t.op !== undefined || t.live === undefined || !t.live.some((l, k) => l && t.text[k] === "{")) return [t];
      // A word with no group to expand stays one word, whatever the budget has left.
      const words = braceExpand(t.text, t.live, Math.max(budget.words, 1));
      if (words === null) {
        unexpanded ??= t.text;
        return [t];
      }
      if (words.length > 1) budget.words -= words.length;
      // sh drops a word that expands to nothing (`{,}`) unless part of it was quoted.
      return words.filter((w) => w !== "" || !t.bare).map((w) => ({ text: w }));
    });
  }
  const argv: string[] = [];
  const writes: string[] = [];
  const reads: string[] = [];
  const hereStrings: string[] = [];
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
        if (t.op === "<<<") hereStrings.push(target.text);
      }
      continue;
    }
    argv.push(t.text);
  }

  if (dialect === "posix") stripCompoundLeads(argv);

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
    // `corepack pnpm@9.1.0 ah`: corepack runs the package manager it names, at that version.
    if (name === "corepack" && argv.length > 0) argv[0] = argv[0].replace(/^(npm|pnpm|yarn)@.*$/i, "$1");
  }

  // Package runners: `npx wrangler deploy` is a wrangler command.
  unwrapRunner(argv, wrappers);

  // tee writes its file arguments.
  const cmd = argv.length > 0 ? normalizeCmd(argv[0]) : (wrappers[wrappers.length - 1] ?? "");
  if (cmd === "tee") {
    for (const a of argv.slice(1)) if (!a.startsWith("-")) writes.push(a);
  }

  const opaque = isOpaque(cmd, argv);
  const stage = makeStage(argv, env, wrappers, writes, opaque, text, reads, hereStrings);
  if (unexpanded !== undefined) stage.unexpanded = unexpanded;
  return stage;
}

/**
 * The string of `env -S STR`, `-SSTR`, `--split-string STR` or `--split-string=STR` at argv[0],
 * shifted off argv, with env's switches clustered before the S (`-iS STR`); null for any other word.
 */
function splitStringOf(argv: string[]): string | null {
  const a = argv[0];
  const short = /^-[iv0]*S(.*)$/s.exec(a);
  let value: string | undefined;
  let separate = false;
  if (a === "--split-string" || (short !== null && short[1] === "")) {
    value = argv[1] ?? "";
    separate = true;
  } else if (a.startsWith("--split-string=")) value = a.slice("--split-string=".length);
  else if (short !== null) value = short[1];
  if (value === undefined) return null;
  argv.splice(0, separate ? 2 : 1);
  return value;
}

function makeStage(argv: string[], env: Record<string, string>, wrappers: string[], writes: string[], opaque: boolean, raw: string, reads: string[] = [], hereStrings: string[] = []): Stage {
  return {
    argv,
    cmd: argv.length > 0 ? normalizeCmd(argv[0]) : (wrappers[wrappers.length - 1] ?? ""),
    env,
    wrappers,
    writes,
    reads,
    hereStrings,
    opaque,
    raw,
  };
}

/** Runner options that consume the next word. `-c`/`--call`/`--shell-mode` carry a command line and are read, not skipped. */
const RUNNER_OPTS_WITH_ARG = new Set(["-p", "--package", "--shell", "--from", "--with", "--python", "-w", "--workspace", "--prefix", "-C", "--dir", "-F", "--filter", "--cwd"]);
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
      if (opt === "-c" || opt === "--call" || opt.startsWith("--call=") || opt === "--shell-mode") {
        // `npx -c 'cmd'`, `npm exec --call 'cmd'`, `pnpm exec -c cmd` (`--shell-mode`): the rest runs as a shell
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
 * Basename, lowercase, no leading backslash, no Windows executable suffix. `.ps1` is
 * kept: a project's `scripts/shutdown.ps1` is its own script, not the system command.
 */
export function normalizeCmd(token: string): string {
  let s = token.startsWith("\\") ? token.slice(1) : token;
  s = s.replace(/\\/g, "/");
  s = s.slice(s.lastIndexOf("/") + 1).toLowerCase();
  s = s.replace(/\.(exe|cmd|bat|com)$/, "");
  return s;
}

function isOpaque(cmd: string, argv: string[]): boolean {
  if (PWSH.has(cmd)) {
    return argv.some((a) => /^-(e|ec|enc|encodedcommand)$/i.test(a));
  }
  const flags = INTERPRETERS_WITH_INLINE_CODE[cmd];
  if (flags) return argv.slice(1).some((a) => givesCode(a, flags));
  if (cmd === "base64" || cmd === "xxd") return false;
  return false;
}

/**
 * True when `a` hands the interpreter inline code: a code flag itself (`-e`, `--eval`), joined to
 * its code (`--eval=code`, `-cprint(1)`), or last in a cluster of short options (`-pe`, `-Ic`, `-le`).
 */
function givesCode(a: string, flags: readonly string[]): boolean {
  return flags.some((f) =>
    a === f ||
    (f.startsWith("--") && a.startsWith(`${f}=`)) ||
    (/^-[A-Za-z]$/.test(f) && (a.startsWith(f) || (/^-[A-Za-z]+$/.test(a) && a.endsWith(f[1])))),
  );
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
  // array arrives as one comma-joined word: `'init','--remove'` is `init,--remove`, and
  // `@('init','--remove')` or `('init','--remove')` is the same list in parentheses.
  const args = (list ?? "").replace(/^@?\((.*)\)$/s, "$1");
  return [programWord(file), ...args.split(","), ...positional].filter((w) => w !== "").join(" ");
}

/** A program path as one PowerShell word: quoted when it has spaces in it. */
function programWord(file: string): string {
  return /\s/.test(file) ? `'${file.replace(/'/g, "''")}'` : file;
}

/** cmd `start` options that take the next word. */
const CMD_START_VALUED = new Set(["/d", "/node", "/affinity", "/machine"]);

/** The command `start` runs in cmd: after a double-quoted window title and start's own `/` options. */
function cmdStartCommand(stage: Stage): string[] {
  const words = stage.argv.slice(1);
  if (/^\s*start\s+"/i.test(stage.raw)) words.shift();
  while (words.length > 0 && words[0].startsWith("/")) {
    if (CMD_START_VALUED.has((words.shift() as string).toLowerCase())) words.shift();
  }
  return words;
}

/** PowerShell host options that take a value, as [name, shortest prefix the host accepts]: `-ex` is -ExecutionPolicy, `-wd` -WorkingDirectory. */
const PWSH_VALUED: readonly (readonly [string, number])[] = [
  ["executionpolicy", 2], ["ep", 2], ["windowstyle", 1], ["workingdirectory", 2], ["wd", 2], ["outputformat", 1], ["of", 2],
  ["inputformat", 3], ["if", 2], ["version", 1], ["settingsfile", 8], ["configurationname", 6], ["configurationfile", 17],
  ["custompipename", 3], ["encodedarguments", 8], ["ea", 2], ["psconsolefile", 3],
];

/** What a `pwsh`/`powershell` command line runs: a command string, or a script and its arguments. */
export type PwshRun = { command: string } | { script: string; args: string[] };

/**
 * Read `pwsh`/`powershell` options the way the host does: any prefix it accepts (`-Comm`, `-Fi`),
 * the colon form (`-File:x`), and the values of valued options (`-ExecutionPolicy Bypass`). The
 * first word that is not an option is the script for pwsh 7 and the start of the command for
 * Windows PowerShell; either way it runs with the words after it. Null for an encoded command or none.
 */
export function pwshRun(argv: readonly string[]): PwshRun | null {
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("-")) return { script: a, args: argv.slice(i + 1) };
    const m = /^-([a-z?]+)(?::(.*))?$/is.exec(a);
    if (m === null) continue;
    const key = m[1].toLowerCase();
    const rest = argv.slice(i + 1);
    if ("commandwithargs".startsWith(key) || key === "cwa") return { command: (m[2] === undefined ? rest : [m[2], ...rest]).join(" ") };
    if ("file".startsWith(key)) {
      const script = m[2] ?? argv[i + 1];
      return script === undefined ? null : { script, args: m[2] === undefined ? rest.slice(1) : rest };
    }
    if ("encodedcommand".startsWith(key) || key === "ec") return null;
    if (m[2] === undefined && PWSH_VALUED.some(([name, min]) => key.length >= min && name.startsWith(key))) i++;
  }
  return null;
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
    // `pwsh -Command 'cmd'`, and a script with its arguments (`pwsh -File x.ps1 a`, `pwsh x.ps1 a`) as the command line it amounts to.
    const run = pwshRun(argv);
    if (run === null) return null;
    return { command: "command" in run ? run.command : [programWord(run.script), ...run.args].join(" "), dialect: "powershell" };
  }
  if (cmd === "cmd") {
    for (let i = 1; i < argv.length; i++) {
      if (/^\/[ck]$/i.test(argv[i])) return { command: argv.slice(i + 1).join(" "), dialect: "cmd" };
    }
    return null;
  }
  // cmd's `call cmd` and `start ["title"] [/b /wait ...] cmd`: the command after them runs.
  if (dialect === "cmd" && (cmd === "call" || cmd === "start")) {
    const run = cmd === "call" ? argv.slice(1) : cmdStartCommand(stage);
    return run.length === 0 ? null : { command: run.join(" "), dialect: "cmd" };
  }
  if (cmd === "eval") return { command: argv.slice(1).join(" "), dialect };
  // PowerShell's eval: `iex 'cmd'`, `Invoke-Expression -Command 'cmd'`, `-Comm 'cmd'`, `-Command:'cmd'`.
  if (cmd === "iex" || cmd === "invoke-expression") {
    const code = argv.slice(1).map((a) => {
      const m = /^-([a-z]+)(?::(.*))?$/is.exec(a);
      return m !== null && "command".startsWith(m[1].toLowerCase()) ? (m[2] ?? "") : a;
    }).filter((w) => w !== "").join(" ");
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
