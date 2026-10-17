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
 * will actually run. It throws rather than guess (TimeLimit once a parse
 * runs past its budget's deadline), and the guard asks when it does:
 * a call it cannot read must not pass unread. Work stays close to linear in
 * the command's length, since a hook that times out lets the call through.
 */

import { onTime, TIME_LIMIT_MS } from "./model.ts";

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
  /** Set on a stand-in for code nested past MAX_DEPTH, which the parser did not read. */
  tooDeep?: true;
  /**
   * Set when the stage is a `( )` or `{ }` group: the pipelines directly inside it. Its own argv is
   * `:`, carrying only the group's redirections; the commands inside are pipelines of their own,
   * and this lets a pipe into or out of the group reach them (`echo x | ( sh )`).
   */
  group?: Pipeline[];
  raw: string;
}

export interface Pipeline {
  stages: Stage[];
  raw: string;
  /** True when this pipeline came out of a substitution, subshell or `-c` string. */
  nested: boolean;
  /** How many substitutions, subshells, groups and shells it sits inside. */
  depth: number;
}

/** How deep substitutions, subshells, groups and `-c` strings are read; code below that asks rather than passes unread. */
export const MAX_DEPTH = 8;

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
  sudo: new Set(["-u", "-g", "-U", "-h", "-p", "-C", "-r", "-t", "-T", "-D", "-R", "--user", "--group", "--other-user", "--host", "--prompt", "--close-from", "--role", "--type", "--command-timeout", "--chdir", "--chroot"]),
  doas: new Set(["-u", "-C"]),
  env: new Set(["-u", "-C", "-S", "--unset", "--chdir", "--split-string"]),
  timeout: new Set(["-s", "-k", "--signal", "--kill-after"]),
  nice: new Set(["-n", "--adjustment"]),
  ionice: new Set(["-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"]),
  // `-i`, `-l` and `-e` take a value only glued to them (`-i{}`), so they are not here.
  xargs: new Set(["-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "-S", "--arg-file", "--delimiter", "--eof", "--replace", "--max-lines", "--max-args", "--max-procs", "--max-chars"]),
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
   * What the parse may still spend, shared by every parse of one command (its substitutions,
   * `sh -c` strings and the text it pipes into a shell), so a short command cannot multiply into
   * more work than the guard can do before the hook times out.
   */
  budget?: ParseBudget;
  /** How deep the text already sits, for text a shell reads from a pipe or here-string. */
  depth?: number;
}

export interface ParseBudget {
  /** Brace-expanded words left. */
  words: number;
  /** performance.now() past which parsing throws ParseTimeout. */
  deadline: number;
}

/** A fresh budget; without a deadline, the parse may take TIME_LIMIT_MS. */
export function parseBudget(deadline = performance.now() + TIME_LIMIT_MS): ParseBudget {
  return { words: BRACE_LIMIT, deadline };
}

/** Throws TimeLimit once the budget's deadline has passed. Loops call it every few thousand steps. */
export function checkTime(budget: ParseBudget): void {
  onTime(budget.deadline);
}

/** Parses a command line. It throws on input it cannot read, so that the caller asks rather than judging a guess. */
export function parseShell(command: string, options: ParseOptions = {}): Pipeline[] {
  const depth = options.depth ?? 0;
  return parseInner(command, depth, depth > 0, options.dialect ?? "posix", options.budget ?? parseBudget());
}

/** A stand-in for code the parser did not read because it sits past MAX_DEPTH. */
export function tooDeep(command: string, depth = MAX_DEPTH + 1): Pipeline {
  return { raw: command, nested: true, depth, stages: [{ ...makeStage([], {}, [], [], false, command), tooDeep: true }] };
}

/** `out.push(...more)` without spreading: a long list passed as arguments overflows the stack. */
export function append<T>(out: T[], more: readonly T[]): void {
  for (const x of more) out.push(x);
}

function parseInner(command: string, depth: number, nested: boolean, dialect: ShellDialect, budget: ParseBudget): Pipeline[] {
  if (depth > MAX_DEPTH) return [tooDeep(command, depth)];
  checkTime(budget);
  const { commands, substitutions } = splitTop(dialect === "posix" ? hereDocsAsStrings(command, budget) : command, dialect, budget);
  const out: Pipeline[] = [];
  for (const stageStrings of commands) {
    const stages: Stage[] = [];
    const extra: Pipeline[] = [];
    for (const s of stageStrings) {
      const text = s.text.trim();
      if (!text) continue;
      // A stage that is one `( )` or `{ }` group, maybe redirected: its commands, read once.
      if (s.group !== undefined) {
        const inner = parseInner(s.group, depth + 1, true, dialect, budget);
        append(extra, inner);
        const stage = buildStage(s.tail === undefined ? ":" : `: ${s.tail}`, dialect, budget);
        stage.group = inner.filter((p) => p.depth === depth + 1);
        stage.raw = text;
        stages.push(stage);
        continue;
      }
      const stage = buildStage(text, dialect, budget);
      stages.push(stage);
      const inner = inlineCommandOf(stage, dialect);
      if (inner !== null) append(extra, parseInner(inner.command, depth + 1, true, inner.dialect, budget));
    }
    if (stages.length > 0) out.push({ stages, raw: stageStrings.map((st) => st.text).join(" | "), nested, depth });
    append(out, extra);
  }
  for (const sub of substitutions) append(out, parseInner(sub, depth + 1, true, dialect, budget));
  return out;
}

interface HereDoc {
  op: number;
  opEnd: number;
  delim: string;
  quoted: boolean;
  strip: boolean;
  level: string;
  /** The body as one quoted word, once read. */
  body?: string;
}

/**
 * sh here-documents rewritten as here-strings: `cat > f <<'EOF'` + body + `EOF` becomes
 * `cat > f <<< '<body>'`, so the body is that command's stdin, as bash treats it, and not lines
 * of commands (a fixture's JSON, a commit message). A body under an unquoted delimiter keeps its
 * `$( )` and backticks live, since bash runs them; a quoted one is literal. Where this cannot
 * tell what bash would do, it leaves the text as it is and the body is judged line by line:
 * a `<<` inside quotes, a comment, `${ }` or arithmetic is no here-document, and one whose
 * delimiter line never comes, or whose body would start inside another nesting level, stays.
 */
export function hereDocsAsStrings(s: string, budget?: ParseBudget): string {
  if (!s.includes("<<")) return s;
  const missing = new Map<string, number>();
  type Frame = { kind: "cmd" | "arith" | "param" | "index"; dq: boolean; parens: number };
  const stack: Frame[] = [{ kind: "cmd", dq: false, parens: 0 }];
  const edits: { start: number; end: number; text: string }[] = [];
  let pending: HereDoc[] = [];
  let sq = false;
  let ansi = false;
  let backtick = false;
  let lastEscape = -1;
  const level = () => `${stack.length}:${stack[stack.length - 1].parens}`;

  for (let i = 0; i < s.length; i++) {
    if ((i & 4095) === 0 && budget !== undefined) checkTime(budget);
    const c = s[i];
    const top = stack[stack.length - 1];
    if (sq) {
      if (ansi && c === "\\") i++;
      else if (c === "'") sq = ansi = false;
      continue;
    }
    if (c === "\\") {
      lastEscape = ++i;
      continue;
    }
    if (backtick) {
      if (c === "`") backtick = false;
      else if (c === "\n") pending = [];
      continue;
    }
    if (c === "$" && s[i + 1] === "(" && s[i + 2] === "(") {
      stack.push({ kind: "arith", dq: false, parens: 0 });
      i += 2;
      continue;
    }
    if (c === "$" && s[i + 1] === "(") {
      stack.push({ kind: "cmd", dq: false, parens: 0 });
      i++;
      continue;
    }
    if (c === "$" && s[i + 1] === "{") {
      stack.push({ kind: "param", dq: false, parens: 0 });
      i++;
      continue;
    }
    if (c === "$" && s[i + 1] === "[") {
      stack.push({ kind: "index", dq: false, parens: 0 });
      i++;
      continue;
    }
    if (c === "`") {
      backtick = true;
      continue;
    }
    if (top.dq) {
      if (c === '"') top.dq = false;
      continue;
    }
    if (c === '"') {
      top.dq = true;
      continue;
    }
    if (c === "'") {
      sq = true;
      ansi = dollarQuotes(s, i, lastEscape);
      continue;
    }
    if (c === "\n") {
      if (pending.length === 0) continue;
      if (top.kind !== "cmd" || pending.some((h) => h.level !== level())) {
        pending = [];
        continue;
      }
      const end = hereDocBodies(s, i + 1, pending, missing, budget);
      if (end !== null) {
        for (const h of pending) edits.push({ start: h.op, end: h.opEnd, text: `<<< ${h.body}` });
        edits.push({ start: i + 1, end: Math.min(end, s.length), text: "" });
        i = end - 1;
      }
      pending = [];
      continue;
    }
    if (top.kind === "param") {
      if (c === "{") top.parens++;
      else if (c === "}" && top.parens-- === 0) stack.pop();
      continue;
    }
    if (top.kind === "index") {
      if (c === "[") top.parens++;
      else if (c === "]" && top.parens-- === 0) stack.pop();
      continue;
    }
    if (top.kind === "arith") {
      if (c === "(") top.parens++;
      else if (c === ")" && top.parens-- === 0) {
        stack.pop();
        if (s[i + 1] === ")") i++;
      }
      continue;
    }
    if (c === "(" && s[i + 1] === "(") {
      stack.push({ kind: "arith", dq: false, parens: 0 });
      i++;
      continue;
    }
    if (c === "(") {
      top.parens++;
      continue;
    }
    if (c === ")") {
      if (top.parens > 0) top.parens--;
      else if (stack.length > 1) {
        // A `$( )` that ends with here-documents still waiting has nothing bash would read them from.
        if (pending.some((h) => h.level.startsWith(`${stack.length}:`))) pending = [];
        stack.pop();
      }
      continue;
    }
    if (c === "#" && (i === 0 || /[\s;&|()]/.test(s[i - 1]))) {
      const nl = s.indexOf("\n", i);
      i = (nl < 0 ? s.length : nl) - 1;
      continue;
    }
    if (c === "<" && s[i + 1] === "<") {
      if (s[i + 2] === "<") {
        i += 2;
        continue;
      }
      const h = hereDocOperator(s, i, level());
      if (h !== null) {
        pending.push(h);
        i = h.opEnd - 1;
      } else i++;
    }
  }
  if (edits.length === 0) return s;
  let out = "";
  let at = 0;
  for (const e of edits.sort((a, b) => a.start - b.start)) {
    out += s.slice(at, e.start) + e.text;
    at = e.end;
  }
  return out + s.slice(at);
}

/** The `<<WORD`, `<<-WORD` or `<<'WORD'` at `i`, or null when no delimiter word follows. */
function hereDocOperator(s: string, i: number, level: string): HereDoc | null {
  let j = i + 2;
  const strip = s[j] === "-";
  if (strip) j++;
  while (s[j] === " " || s[j] === "\t") j++;
  let delim = "";
  let quoted = false;
  for (; j < s.length && !/[\s;&|<>()]/.test(s[j]); j++) {
    const c = s[j];
    if (c === "'" || c === '"') {
      const close = s.indexOf(c, j + 1);
      if (close < 0) return null;
      delim += s.slice(j + 1, close);
      quoted = true;
      j = close;
    } else if (c === "\\") {
      delim += s[j + 1] ?? "";
      quoted = true;
      j++;
    } else delim += c;
  }
  return delim === "" ? null : { op: i, opEnd: j, delim, quoted, strip, level };
}

/**
 * Read the bodies of `docs` from `from` on, in order, each up to the line that is its delimiter.
 * Each doc gets its body as a quoted word; returns where the last delimiter line ends, or null
 * when a delimiter line never comes (bash would then read to the end, which this does not guess).
 * Under an unquoted delimiter a line ending in `\` runs on into the next, as bash reads it.
 * `missing` remembers, per delimiter, an offset from which a search already found no delimiter
 * line, so that a command full of here-documents that never end is read once, not once per line.
 */
function hereDocBodies(s: string, from: number, docs: HereDoc[], missing: Map<string, number>, budget?: ParseBudget): number | null {
  let pos = from;
  let lines = 0;
  for (const h of docs) {
    const key = `${h.quoted ? "q" : "u"}${h.strip ? "-" : ""}:${h.delim}`;
    if ((missing.get(key) ?? Infinity) <= pos) return null;
    const start = pos;
    let found = false;
    let carry = "";
    while (pos <= s.length) {
      // Each delimiter that never comes is a search to the end: thousands of them ask in time.
      if (budget !== undefined && (++lines & 255) === 0) checkTime(budget);
      const nl = s.indexOf("\n", pos);
      const lineEnd = nl < 0 ? s.length : nl;
      const raw = s.slice(pos, lineEnd);
      if (!h.quoted && /(?:^|[^\\])(?:\\\\)*\\$/.test(raw) && nl >= 0) {
        carry += (h.strip ? raw.replace(/^\t+/, "") : raw).slice(0, -1);
        pos = nl + 1;
        continue;
      }
      const line = carry + (h.strip ? raw.replace(/^\t+/, "") : raw).replace(/\r$/, "");
      carry = "";
      if (line === h.delim) {
        let body = s.slice(start, Math.max(start, pos - 1));
        if (h.strip) body = body.replace(/^\t+/gm, "");
        h.body = h.quoted ? `'${body.replace(/'/g, "'\\''")}'` : `"${asDoubleQuoted(body)}"`;
        pos = lineEnd + 1;
        found = true;
        break;
      }
      if (nl < 0) break;
      pos = nl + 1;
    }
    if (!found) {
      missing.set(key, Math.min(missing.get(key) ?? Infinity, start));
      return null;
    }
  }
  return pos;
}

/**
 * An unquoted here-document body as the inside of a "..." word that bash reads the same way.
 * Both treat `\$`, `` \` ``, `\\` and `\`+newline as escapes and keep any other backslash, so
 * those stay as they are; only `"` differs, an escape in "..." and plain text in the body.
 */
function asDoubleQuoted(body: string): string {
  return body.replace(/\\[$`\\\n]|\\"|\\$|"/g, (m) => (m === '"' ? '\\"' : m === '\\"' ? '\\\\\\"' : m === "\\" ? "\\\\" : m));
}

interface SplitStage {
  text: string;
  /**
   * Set when the stage is one `( )` subshell or `{ }` group and nothing else: the text inside it.
   * In sh a group's `{` is a word of its own, so `{rm,-rf,x}` is one brace-expanded command.
   */
  group?: string;
  /** The redirections after such a group (`( a ) > log`), when there are any. */
  tail?: string;
}

interface Split {
  commands: SplitStage[][];
  substitutions: string[];
}

/**
 * Split on `&&`, `||`, `;`, newline, `&` and `|` outside quotes, parentheses and
 * substitutions. Returns commands (each a list of pipe stages) and the text of
 * every `$(...)` and backtick substitution found at any depth.
 */
function splitTop(s: string, dialect: ShellDialect, budget?: ParseBudget): Split {
  const escapeChar = dialect === "posix" ? "\\" : dialect === "powershell" ? "`" : "^";
  const commands: SplitStage[][] = [];
  // A group that makes up its whole stage is read through the stage, so its entry here is dropped.
  const substitutions: (string | null)[] = [];
  let stages: SplitStage[] = [];
  // The stage so far, a character at a time: a string grown with += and searched after every
  // character costs the square of its length.
  let cur: string[] = [];
  let blank = true;
  const add = (...xs: string[]) => {
    for (const x of xs) {
      if (x === "") continue;
      cur.push(x);
      if (blank && x.trim() !== "") blank = false;
    }
  };
  // The group that opened the stage, once it has closed: its entry in substitutions and how long
  // the stage was when it closed. The stage is that group alone if nothing but blanks follows.
  let opener: { sub: number; length: number } | null = null;
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
  const groups: { start: number; runs: boolean; opens: boolean }[] = [];
  let running = 0;
  let braceDepth = 0;
  let braceStart = 0;
  // Open `${ }` expansions, inside which `#` starts no comment (`${x:- #}`).
  let param = 0;
  // The stage's length when its last character went on a word rather than ending one: an
  // escaped character (`a\ #b`), or the `)` of `$( )`, `$(( ))` or `<( )` (`$(date)#x`).
  let goesOn = -1;
  // Inside a group that is recorded whole, whose text holds whatever is nested in it.
  const enclosed = () => running > 0 || braceDepth > 0;

  const endStage = () => {
    const text = cur.join("");
    const tail = opener === null ? "" : cur.slice(opener.length).join("").trim();
    if (opener !== null && (tail === "" || /^(?:\d*[<>]|&>)/.test(tail))) {
      stages.push({ text, group: substitutions[opener.sub] ?? "", ...(tail === "" ? {} : { tail }) });
      substitutions[opener.sub] = null;
    } else stages.push({ text });
    cur = [];
    blank = true;
    opener = null;
    goesOn = -1;
  };
  const endCommand = () => {
    endStage();
    commands.push(stages);
    stages = [];
  };

  // `$'...'`, bash's ANSI-C quoting, in which a backslash escapes the next character, `'` included.
  let ansi = false;
  let lastEscape = -1;
  const opensAnsi = (i: number) => dialect === "posix" && dollarQuotes(s, i, lastEscape);

  for (let i = 0; i < s.length; i++) {
    if ((i & 4095) === 0 && budget !== undefined) checkTime(budget);
    const c = s[i];
    const next = s[i + 1];
    const prev = i > 0 ? s[i - 1] : "";

    if (inSingle) {
      if (ansi && c === "\\") {
        add(c, next ?? "");
        i++;
        continue;
      }
      add(c);
      if (c === "'") inSingle = ansi = false;
      continue;
    }
    if (c === escapeChar) {
      const skip = continuationLength(s, i);
      if (skip > 0) {
        // Line continuation: the escape and the newline produce nothing.
        i += skip - 1;
        continue;
      }
      add(c, next ?? "");
      i++;
      lastEscape = i;
      goesOn = cur.length;
      continue;
    }
    if (backtickStart >= 0) {
      add(c);
      if (c === "`") {
        // Inside backticks `\``, `\$` and `\\` stand for the character itself: `\`rm x\`` runs when the outer one does.
        if (!enclosed()) substitutions.push(s.slice(backtickStart, i).replace(/\\([\\`$])/g, "$1"));
        backtickStart = -1;
      }
      continue;
    }
    if (!inDouble && dialect !== "cmd" && c === "$" && next === "{") {
      param++;
      add(c, next);
      i++;
      continue;
    }
    if (!inDouble && c === "}" && param > 0) {
      param--;
      add(c);
      continue;
    }
    if (!inDouble) {
      // A comment runs to the end of its line; a quote or bracket in it opens nothing. What
      // counts is the character before it as the shell reads it: a line continuation adds nothing.
      const tail = cur[cur.length - 1];
      const before = tail === undefined ? "" : cur.length === goesOn ? null : tail[tail.length - 1];
      const end = param > 0 ? -1 : commentEnd(s, i, dialect, before);
      if (end > i) {
        i = end - 1;
        continue;
      }
      const hs = dialect === "powershell" ? hereStringEnd(s, i) : -1;
      if (hs > i) {
        const body = s.slice(i, hs);
        add(body);
        if (s[i + 1] === '"' && !enclosed()) append(substitutions, subexpressions(body));
        i = hs - 1;
        continue;
      }
    }
    if (subs.length > 0) {
      add(c);
      if (inDouble) {
        if (c === '"') inDouble = false;
        continue;
      }
      if (c === '"') inDouble = true;
      else if (c === "'") {
        inSingle = true;
        ansi = opensAnsi(i);
      } else if (c === "(") subs.push({ start: -1, outerDouble: false });
      else if (c === ")") {
        const sub = subs.pop();
        if (sub !== undefined && sub.start >= 0) {
          inDouble = sub.outerDouble;
          goesOn = cur.length;
          // Only the outermost substitution is recorded; parsing it finds the inner ones once.
          if (subs.length === 0 && !enclosed()) substitutions.push(s.slice(sub.start, i));
        }
      } else if (c === "$" && next === "(") {
        subs.push({ start: i + 2, outerDouble: false });
        add(next);
        i++;
      }
      continue;
    }
    if (c === '"') {
      inDouble = !inDouble;
      add(c);
      continue;
    }
    if (c === "$" && next === "(") {
      subs.push({ start: i + 2, outerDouble: inDouble });
      inDouble = false;
      add(c, next);
      i++;
      continue;
    }
    if (c === "`" && dialect === "posix") {
      backtickStart = i + 1;
      add(c);
      continue;
    }
    if (inDouble) {
      add(c);
      continue;
    }
    if (c === "'") {
      inSingle = true;
      ansi = opensAnsi(i);
      add(c);
      continue;
    }
    if (c === "(" || (c === "{" && dialect === "powershell")) {
      // Process substitution `<(` / `>(` and subshells both nest.
      const runs = dialect !== "posix" || prev === "" || /[\s<>;&|(]/.test(prev);
      groups.push({ start: i + 1, runs, opens: runs && blank && groups.length === 0 && braceDepth === 0 });
      if (runs) running++;
      add(c);
      continue;
    }
    if ((c === ")" || (c === "}" && dialect === "powershell")) && groups.length > 0) {
      const group = groups.pop() as { start: number; runs: boolean; opens: boolean };
      if (group.runs) running--;
      add(c);
      // After `<( )`, `>( )` or an array the word goes on; after a subshell a comment may start.
      if (dialect === "posix" && (!group.runs || /[<>]/.test(s[group.start - 2] ?? ""))) goesOn = cur.length;
      // Only the outermost group that runs is recorded; parsing it finds the inner ones once.
      if (group.runs && running === 0 && braceDepth === 0) {
        substitutions.push(s.slice(group.start, i));
        if (group.opens) opener = { sub: substitutions.length - 1, length: cur.length };
      }
      continue;
    }
    if (groups.length > 0) {
      add(c);
      continue;
    }
    if (c === "{" && blank && (next === " " || next === "\t" || next === "\n")) {
      if (braceDepth++ === 0) braceStart = i + 1;
      add(c);
      continue;
    }
    if (c === "{" && braceDepth > 0 && /[\s;&|(]/.test(prev) && (next === " " || next === "\t" || next === "\n")) {
      // A group inside the group: `{ { rm -rf x; }; }` closes at the last `}`.
      braceDepth++;
      add(c);
      continue;
    }
    if (c === "}" && braceDepth > 0 && (cur.length === 0 || /[\s;&]/.test(cur[cur.length - 1]))) {
      // `{ rm -rf x; } > log`: a redirected group is not one whole stage, so its commands are recorded here.
      add(c);
      if (--braceDepth === 0) {
        substitutions.push(s.slice(braceStart, i));
        opener = { sub: substitutions.length - 1, length: cur.length };
      }
      continue;
    }
    if (braceDepth > 0) {
      add(c);
      continue;
    }

    if (c === "&" && next === "&") { endCommand(); i++; continue; }
    if (c === "|" && next === "|") { endCommand(); i++; continue; }
    if (c === ";" || c === "\n") { endCommand(); continue; }
    if (c === "|" && cur[cur.length - 1] === ">" && cur.length !== goesOn) {
      // `>|` writes over a file even under noclobber: a redirection, not a pipe.
      add(c);
      continue;
    }
    if (c === "|") {
      if (next === "&") i++;
      endStage();
      continue;
    }
    if (c === "&") {
      // `&>file`, `>&2`, `2>&1`, `<&0` are redirections; `sleep 1& rm x` backgrounds `sleep 1`.
      if (next === ">" || endsInRedirection(cur)) {
        add(c);
        continue;
      }
      if (dialect === "powershell" && blank) {
        // Call operator: `& "C:\\tool.exe" args`
        continue;
      }
      endCommand();
      continue;
    }
    add(c);
  }
  // Text left inside a construct that never closes is still read as commands; bash would refuse
  // the line, but the guard should not judge less than what it was shown.
  const open = [subs.find((x) => x.start >= 0)?.start, groups.find((g) => g.runs)?.start, backtickStart >= 0 ? backtickStart : undefined, braceDepth > 0 ? braceStart : undefined];
  // The first to open holds the others.
  const first = Math.min(...open.map((at) => at ?? Infinity));
  if (first !== Infinity) substitutions.push(s.slice(first));
  endCommand();
  return {
    commands: commands.map((st) => st.filter((x) => x.text.trim() !== "")).filter((st) => st.length > 0),
    substitutions: substitutions.filter((x): x is string => x !== null),
  };
}

/**
 * Where the comment starting at `i` ends (the newline after it, or the end of `s`), or -1 when
 * there is none: `#` at the start of a word, in sh and PowerShell, or PowerShell's `<# ... #>`.
 * `before` is the character before it as the shell reads it, "" at the start of a stage, and null
 * when the word goes on through it.
 */
function commentEnd(s: string, i: number, dialect: ShellDialect, before: string | null): number {
  if (dialect === "cmd") return -1;
  if (dialect === "powershell" && s[i] === "<" && s[i + 1] === "#") {
    const close = s.indexOf("#>", i + 2);
    return close < 0 ? s.length : close + 2;
  }
  if (s[i] !== "#" || before === null || !(before === "" || /[\s;&|()]/.test(before) || (dialect === "powershell" && /[{}]/.test(before)))) return -1;
  const nl = s.indexOf("\n", i);
  return nl < 0 ? s.length : nl;
}

/** Where a PowerShell here-string (`@'` or `@"`, a newline, ..., a newline and `'@` or `"@`) starting at `i` ends, or -1. */
function hereStringEnd(s: string, i: number): number {
  const q = s[i + 1];
  if (s[i] !== "@" || (q !== "'" && q !== '"')) return -1;
  const nl = s[i + 2] === "\r" ? i + 3 : i + 2;
  if (s[nl] !== "\n") return -1;
  const close = s.indexOf(`\n${q}@`, nl);
  return close < 0 ? -1 : close + 3;
}

/**
 * The `$( ... )` subexpressions in an expandable PowerShell string, which run when it is read, in
 * one pass: a backtick escapes the next character (`` `$( `` is text), quotes inside one hold
 * their parentheses, and the outermost holds any nested in it. One never closed runs nothing.
 */
function subexpressions(text: string): string[] {
  const out: string[] = [];
  let start = -1;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "`") i++;
    else if (start < 0) {
      if (c === "$" && text[i + 1] === "(") {
        start = i + 2;
        depth = 1;
        i++;
      }
    } else if (c === "'" || c === '"') {
      const close = text.indexOf(c, i + 1);
      if (close < 0) break;
      i = close;
    } else if (c === "(") depth++;
    else if (c === ")" && --depth === 0) {
      out.push(text.slice(start, i));
      start = -1;
    }
  }
  return out;
}

/** Whether the stage so far ends in `<` or `>` and digits, so that a `&` next is part of a redirection (`>&2`). */
function endsInRedirection(cur: readonly string[]): boolean {
  let k = cur.length - 1;
  while (k >= 0 && /^\d$/.test(cur[k])) k--;
  return k >= 0 && (cur[k] === "<" || cur[k] === ">");
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
/** Characters one word's brace expansion may yield: a long word times many alternatives is too. */
const BRACE_CHARS = 1 << 20;
/** Brace groups one word may hold, nested ones included, before the guard asks instead. */
const MAX_BRACE_GROUPS = 64;

interface BraceGroup {
  start: number;
  end: number;
  parts: { text: string; live: boolean[] }[];
}

const SEQ_NUMBERS = /^([-+]?\d+)\.\.([-+]?\d+)(?:\.\.([-+]?\d+))?$/;
/** A body that `sequence` expands: numbers or single letters. */
const SEQ_BODY = /^(?:[-+]?\d+\.\.[-+]?\d+|[A-Za-z]\.\.[A-Za-z])(?:\.\.[-+]?\d+)?$/;
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
  // Past 2^53 the numbers stop being exact and `n += step` can stop moving; such a sequence is too long to check anyway.
  if (![from, to, step].every(Number.isSafeInteger) || Math.floor(Math.abs(to - from) / step) + 1 > limit) return "overflow";
  const width = num && (/^[-+]?0\d/.test(m[1]) || /^[-+]?0\d/.test(m[2])) ? Math.max(m[1].length, m[2].length) : 0;
  const out: string[] = [];
  for (let n = from; from <= to ? n <= to : n >= to; n += from <= to ? step : -step) {
    if (!num) out.push(String.fromCharCode(n));
    else out.push(n < 0 ? `-${String(-n).padStart(width - 1, "0")}` : String(n).padStart(width, "0"));
  }
  return out;
}

/** The longest body a `{a..b..c}` sequence can have with safe integers; longer bodies are not tried as one. */
const SEQ_MAX_BODY = 64;

/**
 * The brace groups sh expands in `word`, in the order they close. One pass with a stack, so that a
 * word full of unclosed braces costs no more than its length: each `{` meets its `}` as sh pairs
 * them, `${` included so that its commas stay its own.
 */
function braceGroups(word: string, live: readonly boolean[]): { at: number; end: number; commas: number[] }[] {
  const open: { at: number; commas: number[]; param: boolean }[] = [];
  const out: { at: number; end: number; commas: number[] }[] = [];
  for (let j = 0; j < word.length; j++) {
    if (!live[j]) continue;
    const c = word[j];
    if (c === "{") open.push({ at: j, commas: [], param: word[j - 1] === "$" && live[j - 1] });
    else if (c === "," && open.length > 0) open[open.length - 1].commas.push(j);
    else if (c === "}" && open.length > 0) {
      const f = open.pop()!;
      if (f.param) continue;
      if (f.commas.length > 0 || (j - f.at - 1 <= SEQ_MAX_BODY && SEQ_BODY.test(word.slice(f.at + 1, j)) && live.slice(f.at + 1, j).every(Boolean))) {
        out.push({ at: f.at, end: j, commas: f.commas });
      }
    }
  }
  return out;
}

/**
 * The first brace group sh expands in `word` (the one that opens first), null when there is
 * none, `"overflow"` when it alone yields more than `limit` words.
 */
function firstBraceGroup(word: string, live: readonly boolean[], limit: number): BraceGroup | "overflow" | null {
  let best: { at: number; end: number; commas: number[] } | undefined;
  for (const g of braceGroups(word, live)) if (best === undefined || g.at < best.at) best = g;
  if (best === undefined) return null;
  const { at, end, commas } = best;
  if (commas.length > 0) {
    const parts: BraceGroup["parts"] = [];
    let from = at + 1;
    for (const to of [...commas, end]) {
      parts.push({ text: word.slice(from, to), live: live.slice(from, to) });
      from = to + 1;
    }
    return { start: at, end, parts };
  }
  const seq = sequence(word.slice(at + 1, end), limit);
  if (seq === "overflow") return seq;
  return { start: at, end, parts: (seq ?? []).map((text) => ({ text, live: Array.from(text, () => false) })) };
}

/**
 * sh brace expansion of one word: `.ruff.toml{,.bak}` is `.ruff.toml .ruff.toml.bak`,
 * `{rm,-rf,x}` is `rm -rf x`, `.claud{e..e}` is `.claude`. Only braces and commas marked
 * `live` (unquoted, unescaped) count, so `{a,"b,c"}` is `a b,c` and `"{a,b}"` stays as it is.
 * Alternatives nest; `${VAR}` and a group with neither a comma nor a sequence stay as they
 * are. Returns null rather than a partial list once the words would pass `limit`, or their
 * characters a million.
 */
export function braceExpand(word: string, live: readonly boolean[] = Array.from(word, () => true), limit = BRACE_LIMIT): string[] | null {
  // Each group is a level of copying the word, so a word with more groups than any real one is
  // refused at once: `{a,b}` ten thousand times would otherwise copy a long word ten thousand times
  // before its first word came out.
  if (braceGroups(word, live).length > MAX_BRACE_GROUPS) return null;
  const out: string[] = [];
  let chars = 0;
  const expand = (w: string, l: readonly boolean[]): boolean => {
    const group = firstBraceGroup(w, l, limit);
    if (group === "overflow") return false;
    if (group === null) {
      out.push(w);
      chars += w.length;
      return out.length <= limit && chars <= BRACE_CHARS;
    }
    for (const part of group.parts) {
      if (!expand(w.slice(0, group.start) + part.text + w.slice(group.end + 1), [...l.slice(0, group.start), ...part.live, ...l.slice(group.end + 1)])) return false;
    }
    return true;
  };
  return expand(word, live) ? out : null;
}

/** Whether the quote at `i` follows an unescaped `$` that makes it `$'...'`: `$$` is the pid, so the run of `$` must be odd. */
function dollarQuotes(s: string, i: number, lastEscape: number): boolean {
  let run = 0;
  for (let j = i - 1; j >= 0 && s[j] === "$" && j !== lastEscape; j--) run++;
  return run % 2 === 1;
}

const ANSI_SIMPLE: Record<string, string> = { a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v", "\\": "\\", "'": "'", '"': '"', "?": "?" };

/** The backslash escape at `i` inside `$'...'`, decoded as bash does (`\x2e` is `.`), and how many characters it spans. */
function ansiEscape(s: string, i: number): [string, number] {
  const c = s[i + 1];
  if (c === undefined) return ["\\", 1];
  if (c in ANSI_SIMPLE) return [ANSI_SIMPLE[c], 2];
  let m: RegExpExecArray | null;
  if ((m = /^[0-7]{1,3}/.exec(s.slice(i + 1, i + 4)))) return [String.fromCharCode(parseInt(m[0], 8) & 0xff), 1 + m[0].length];
  if (c === "x" && (m = /^[0-9A-Fa-f]{1,2}/.exec(s.slice(i + 2, i + 4)))) return [String.fromCharCode(parseInt(m[0], 16)), 2 + m[0].length];
  if ((c === "u" || c === "U") && (m = (c === "u" ? /^[0-9A-Fa-f]{1,4}/ : /^[0-9A-Fa-f]{1,8}/).exec(s.slice(i + 2, i + 10)))) {
    const code = parseInt(m[0], 16);
    return [code <= 0x10ffff ? String.fromCodePoint(code) : "", 2 + m[0].length];
  }
  if (c === "c" && s[i + 2] !== undefined) return [String.fromCharCode(s[i + 2].toUpperCase().charCodeAt(0) ^ 0x40), 3];
  return [`\\${c}`, 2];
}

function tokenize(stage: string, dialect: ShellDialect, budget?: ParseBudget): Token[] {
  const escapeChar = dialect === "posix" ? "\\" : dialect === "powershell" ? "`" : "^";
  const tokens: Token[] = [];
  // The word so far, a character at a time (see splitTop), and how many unquoted `$` end it.
  let cur: string[] = [];
  let live: boolean[] = [];
  let dollars = 0;
  let has = false;
  let bare = true;
  /** Append text that sh will not brace-expand: quoted, escaped, or inside a substitution. */
  const dead = (text: string) => {
    for (let k = 0; k < text.length; k++) {
      cur.push(text[k]);
      live.push(false);
    }
    if (text !== "") dollars = 0;
  };
  let inSingle = false;
  let ansi = false;
  let inDouble = false;
  let depth = 0; // $( ) and ( ) nesting inside a token
  /** A `$` just before a quote that makes it `$'...'` (ANSI-C) or `$"..."` (locale) in sh: the `$` is not part of the word. */
  const dropQuotingDollar = (): boolean => {
    // `$$'x'` is the shell's pid and then 'x'; only an odd run leaves a `$` to quote with.
    if (dialect !== "posix" || dollars % 2 === 0) return false;
    cur.pop();
    live.pop();
    dollars = 0;
    return true;
  };

  const flush = () => {
    const text = cur.join("");
    if (has) tokens.push(bare ? { text, bare, live } : { text, live });
    cur = [];
    live = [];
    dollars = 0;
    has = false;
    bare = true;
  };

  for (let i = 0; i < stage.length; i++) {
    if ((i & 4095) === 0 && budget !== undefined) checkTime(budget);
    const c = stage[i];
    const next = stage[i + 1];
    if (inSingle) {
      if (c === "'") inSingle = ansi = false;
      else if (ansi && c === "\\") {
        const [text, length] = ansiEscape(stage, i);
        dead(text);
        i += length - 1;
      } else dead(c);
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
    const hs = dialect === "powershell" ? hereStringEnd(stage, i) : -1;
    if (hs > i) {
      // A PowerShell here-string is one word, its body: the lines between `@'` and `'@`, quotes and all.
      dead(stage.slice(stage[i + 2] === "\r" ? i + 4 : i + 3, hs - 3).replace(/\r$/, ""));
      has = true;
      bare = false;
      i = hs - 1;
      continue;
    }
    if (c === "'") { ansi = dropQuotingDollar(); inSingle = true; has = true; bare = false; continue; }
    if (c === '"') { dropQuotingDollar(); inDouble = true; has = true; bare = false; continue; }
    if (c === "$" && next === "(") { dead("$("); has = true; bare = false; depth = 1; i++; continue; }
    if ((c === "<" || c === ">") && next === "(") { dead(c + "("); has = true; bare = false; depth = 1; i++; continue; }
    if (c === " " || c === "\t") { flush(); continue; }
    if (c === ">" || c === "<") {
      // Redirection. Fold a preceding bare fd number (`2>`) into the operator.
      let op = "";
      if (has && cur.length > 0 && cur.every((ch) => ch >= "0" && ch <= "9")) { op = cur.join(""); cur = []; live = []; dollars = 0; has = false; }
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
    cur.push(c);
    live.push(true);
    dollars = c === "$" ? dollars + 1 : 0;
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

function buildStage(text: string, dialect: ShellDialect, budget: ParseBudget): Stage {
  let tokens = tokenize(dialect === "powershell" ? text.replace(PWSH_ASSIGNMENT, "") : text, dialect, budget);
  let unexpanded: string | undefined;
  if (dialect === "posix") {
    tokens = tokens.flatMap((t, k) => {
      // bash brace-expands words, not redirection targets: `<<< {a,b}` feeds `{a,b}` to stdin.
      if (t.op !== undefined || tokens[k - 1]?.op !== undefined || t.live === undefined || !t.live.some((l, n) => l && t.text[n] === "{")) return [t];
      // A word with no group to expand stays one word, whatever the budget has left.
      const words = braceExpand(t.text, t.live, Math.max(budget.words, 1));
      if (words === null) {
        unexpanded ??= t.text;
        // The command already asks; later words need not each be expanded up to the limit to learn that again.
        budget.words = 0;
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

  // Leading VAR=value assignments. Words are counted off and cut in one splice throughout: a shift
  // per word takes time in the square of a long command's length.
  let lead = 0;
  for (let m; lead < argv.length && (m = ENV_ASSIGN.exec(argv[lead])) !== null; lead++) env[m[1]] = m[2];
  argv.splice(0, lead);

  const wrappers: string[] = [];
  let guard = 0;
  let splits = 0;
  let tooDeep = false;
  while (argv.length > 0 && guard++ < 8) {
    const name = normalizeCmd(argv[0]);
    if (!WRAPPERS.has(name)) break;
    if (name === "command" && (argv[1] === "-v" || argv[1] === "-V")) break;
    wrappers.push(name);
    argv.shift();
    const withArg = WRAPPER_OPTS_WITH_ARG[name] ?? new Set<string>();
    let skipPositional = WRAPPER_POSITIONAL_SKIP[name] ?? 0;
    let k = 0;
    while (k < argv.length) {
      const a = argv[k];
      if (a === "--") { k++; break; }
      const envMatch = (name === "env" || name === "sudo" || name === "doas") ? ENV_ASSIGN.exec(a) : null;
      if (envMatch) { env[envMatch[1]] = envMatch[2]; k++; continue; }
      const split = name === "env" ? splitStringAt(argv, k) : null;
      if (split !== null) {
        // `env -S 'ah init --remove'`: env splits the string into words that take its place, and
        // those can be `-S` again; past the nesting limit the stage asks.
        if (++splits > MAX_DEPTH) { tooDeep = true; break; }
        const rest = argv.splice(k + split.words);
        argv.length = k;
        append(argv, tokenize(envSplitText(split.value), "posix").map((t) => t.text));
        append(argv, rest);
        continue;
      }
      if (a.startsWith("--")) {
        k++;
        if (!a.includes("=") && withArg.has(a)) k++;
        continue;
      }
      if (a.startsWith("-") && a.length > 1) {
        // A cluster of short options (`-iu FOO`, `-vk 5`): the first that takes a value takes the
        // rest of the word (`-n1`, `-I{}`), or the next word when it ends the cluster.
        k++;
        for (let l = 1; l < a.length; l++) {
          if (!withArg.has(`-${a[l]}`)) continue;
          if (l === a.length - 1) k++;
          break;
        }
        continue;
      }
      if (skipPositional > 0) { skipPositional--; k++; continue; }
      break;
    }
    argv.splice(0, k);
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
  if (tooDeep) stage.tooDeep = true;
  return stage;
}

/**
 * An `env -S` string with env's own escapes made into what sh splitting reads the same way:
 * `\_` separates words outside quotes and is a space inside double quotes, as are `\t`, `\n`,
 * `\v`, `\f` and `\r` here, and `\c` ends the string. Single quotes keep their text.
 */
function envSplitText(v: string): string {
  const out: string[] = [];
  let sq = false;
  let dq = false;
  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if (sq) {
      if (c === "'") sq = false;
      out.push(c);
    } else if (c === "\\" && /[_tnvfr]/.test(v[i + 1] ?? "")) {
      out.push(" ");
      i++;
    } else if (c === "\\" && v[i + 1] === "c") break;
    else if (c === "\\" && i + 1 < v.length) {
      out.push(c, v[i + 1]);
      i++;
    } else {
      if (c === "'" && !dq) sq = true;
      else if (c === '"') dq = !dq;
      out.push(c);
    }
  }
  return out.join("");
}

/**
 * The string of `env -S STR`, `-SSTR`, `--split-string STR` or `--split-string=STR` at argv[k],
 * and how many words it takes, with env's switches clustered before the S (`-iS STR`); null for any other word.
 */
function splitStringAt(argv: string[], k: number): { value: string; words: number } | null {
  const a = argv[k];
  const short = /^-[iv0]*S(.*)$/s.exec(a);
  if (a === "--split-string" || (short !== null && short[1] === "")) return { value: argv[k + 1] ?? "", words: 2 };
  if (a.startsWith("--split-string=")) return { value: a.slice("--split-string=".length), words: 1 };
  if (short !== null) return { value: short[1], words: 1 };
  return null;
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
const RUNNER_OPTS_WITH_ARG = new Set([
  "-p", "--package", "--shell", "--from", "--with", "--python", "-w", "--workspace", "--prefix", "-C", "--dir", "-F", "--filter", "--cwd",
  // npm's own configuration, which npx and `npm exec` take before the package: `npx --loglevel silent -c '...'`.
  "--loglevel", "--registry", "--cache", "--userconfig", "--globalconfig", "--node-options", "--reporter", "--script-shell",
]);
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
    let k = 0;
    while (k < argv.length && argv[k].startsWith("-")) {
      const opt = argv[k++];
      if (opt === "-c" || opt === "--call" || opt.startsWith("--call=") || opt === "--shell-mode") {
        // `npx -c 'cmd'`, `npm exec --call 'cmd'`, `pnpm exec -c cmd` (`--shell-mode`): the rest runs as a shell
        // command line, so the stage becomes that shell's `-c` and the parser reads the command inside.
        const rest = argv.slice(k);
        const line = opt.startsWith("--call=") ? [opt.slice("--call=".length), ...rest] : rest;
        argv.length = 0;
        argv.push("sh", "-c", line.join(" "));
        return;
      }
      if (RUNNER_OPTS_WITH_ARG.has(opt)) k++;
      if (opt === "--") break;
    }
    argv.splice(0, k);
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
    // The rest of the line is copied only for the option that takes it: one copy per option is quadratic.
    if ("commandwithargs".startsWith(key) || key === "cwa") return { command: (m[2] === undefined ? argv.slice(i + 1) : [m[2], ...argv.slice(i + 1)]).join(" ") };
    if ("file".startsWith(key)) {
      const script = m[2] ?? argv[i + 1];
      return script === undefined ? null : { script, args: argv.slice(m[2] === undefined ? i + 2 : i + 1) };
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
  for (const p of pipelines) append(out, p.stages);
  return out;
}
