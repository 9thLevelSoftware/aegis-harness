/**
 * Lexical path handling. Nothing here touches the filesystem: a path is
 * classified from its text alone so the guard stays pure and fast.
 */
import type { Platform } from "./model.ts";

/** Forward slashes, no duplicate separators, no trailing slash (except root). */
export function toPosix(p: string): string {
  let s = p.trim().replace(/\\/g, "/");
  s = s.replace(/\/{2,}/g, "/");
  if (s.length > 1 && s.endsWith("/")) s = s.slice(0, -1);
  return s;
}

export function isAbsolute(p: string): boolean {
  return p.startsWith("/") || /^[A-Za-z]:(\/|$)/.test(p);
}

/** Text normalize would change: a backslash, a doubled slash, or a `.` or `..` segment (`C:.` included). */
const UNNORMAL = /\\|\/\/|(?:^|\/|^[A-Za-z]:)\.{1,2}(?:\/|$)/;

/** Resolve `.` and `..` segments lexically. Keeps a leading drive or `/`. */
export function normalize(p: string): string {
  // Most paths reach here already normal, many times each for a long command.
  if (p !== "" && !UNNORMAL.test(p) && !(p.length > 1 && p.endsWith("/")) && p.trim() === p) return p;
  const s = toPosix(p);
  const m = /^([A-Za-z]:)?(\/)?(.*)$/s.exec(s);
  const drive = m?.[1] ?? "";
  const rooted = m?.[2] ?? "";
  const rest = m?.[3] ?? "";
  const out: string[] = [];
  for (const seg of rest.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (out.length > 0 && out[out.length - 1] !== "..") out.pop();
      else if (!rooted) out.push("..");
      continue;
    }
    out.push(seg);
  }
  const body = out.join("/");
  if (rooted) return `${drive}/${body}`;
  return body === "" ? (drive || ".") : `${drive}${body}`;
}

/** True when the text still contains an unexpanded shell or cmd variable. */
export function hasVariable(p: string): boolean {
  return /\$\{?[A-Za-z_]/.test(p) || /%[A-Za-z_][A-Za-z0-9_]*%/.test(p);
}

/**
 * `$TMPDIR`, `${TMPDIR:-/tmp}` (default, assign or guard expansions), PowerShell
 * `$env:TEMP` and cmd `%TEMP%`, alone or followed by a separator.
 */
const TEMP_VARS = /^(\$\{?(TMPDIR|TMP|TEMP|RUNNER_TEMP)(:[-=?][^}]*)?\}?|\$env:(TMP|TEMP|RUNNER_TEMP)|%(TMP|TEMP|RUNNER_TEMP)%)(\/|$)/i;
const TEMP_DIRS = /^(\/tmp|\/var\/tmp|\/private\/tmp|\/private\/var\/tmp|\/dev\/shm|[A-Za-z]:\/Users\/[^/]+\/AppData\/Local\/Temp|[A-Za-z]:\/Windows\/Temp|[A-Za-z]:\/Temp)(\/|$)/i;

/** A location that is understood to be scratch space on any OS. */
export function isTempPath(p: string): boolean {
  const s = toPosix(p);
  return TEMP_VARS.test(s) || TEMP_DIRS.test(s);
}

/**
 * On Windows, Git Bash and Cygwin spell drive paths `/c/Users/dev` and
 * `/cygdrive/c/Users/dev`. Rewrite them to `C:/Users/dev` so they compare with
 * the project root and home directory. Not applied on POSIX, where `/c` is an
 * ordinary directory; `/mnt/c` (WSL) is a real path on a POSIX platform and is
 * left alone.
 */
export function driveForm(p: string, platform: Platform): string {
  if (platform !== "windows") return p;
  const s = toPosix(p);
  const m = /^\/(?:cygdrive\/)?([A-Za-z])(?=\/|$)/.exec(s);
  if (!m) return s;
  return `${m[1].toUpperCase()}:${s.slice(m[0].length)}`;
}

/**
 * Expand `~`, `$HOME`, `%USERPROFILE%` to the home directory when known, or to
 * the marker `~` when not, then make the path absolute against `base`.
 */
export function resolvePath(p: string, base: string, home?: string, platform: Platform = "posix"): string {
  let s = driveForm(toPosix(p), platform);
  s = s.replace(/^(~|\$\{?HOME\}?|%USERPROFILE%)(?=\/|$)/i, home ? toPosix(home) : "~");
  if (!isAbsolute(s) && !s.startsWith("~")) {
    s = `${toPosix(base)}/${s}`;
  }
  return normalize(s);
}

function fold(s: string, platform: Platform): string {
  return platform === "windows" ? s.toLowerCase() : s;
}

/** Project-relative path, or `null` when `abs` is not inside `root`. */
export function relativeTo(root: string, abs: string, platform: Platform): string | null {
  const r = normalize(driveForm(root, platform));
  const a = normalize(driveForm(abs, platform));
  if (fold(a, platform) === fold(r, platform)) return ".";
  const prefix = r.endsWith("/") ? r : `${r}/`;
  if (fold(a, platform).startsWith(fold(prefix, platform))) return a.slice(prefix.length);
  return null;
}

/** True when `abs` sits under the home directory (or the unexpanded `~`). */
export function relativeToHome(abs: string, home: string | undefined, platform: Platform): string | null {
  const a = normalize(driveForm(abs, platform));
  if (a === "~") return ".";
  if (a.startsWith("~/")) return a.slice(2);
  if (!home) return null;
  return relativeTo(home, a, platform);
}

const SYSTEM_DIRS = /^(\/(etc|usr|bin|sbin|lib|lib64|boot|sys|proc|dev|var|opt|root|System|Library|Applications)(\/|$)|[A-Za-z]:\/(Windows|Program Files( \(x86\))?|ProgramData)(\/|$))/i;

export function isSystemPath(abs: string): boolean {
  return SYSTEM_DIRS.test(normalize(abs));
}

export function isFilesystemRoot(abs: string): boolean {
  const s = normalize(abs);
  return s === "/" || /^[A-Za-z]:\/?$/.test(s);
}

/**
 * Convert a glob to a RegExp. `**` matches across separators, `*` and `?`
 * within one segment, `{a,b}` alternates. Matching is case-insensitive on Windows.
 */
export function globToRegExp(glob: string, platform: Platform): RegExp {
  const key = `${platform}\0${glob}`;
  let re = GLOB_CACHE.get(key);
  if (re === undefined) {
    re = compileGlob(glob, platform);
    GLOB_CACHE.set(key, re);
  }
  return re;
}

/** Compiled globs, keyed by platform and pattern. The policy lists are small and static. */
const GLOB_CACHE = new Map<string, RegExp>();

function compileGlob(glob: string, platform: Platform): RegExp {
  // `dir/**` protects the directory itself as well as everything under it:
  // `rm -rf .harness` is the same act as `rm -rf .harness/*`.
  if (glob.endsWith("/**")) {
    const inner = globToRegExp(glob.slice(0, -3), platform).source.replace(/^\^|\$$/g, "");
    return new RegExp(`^${inner}(?:/.*)?$`, platform === "windows" ? "is" : "s");
  }
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        i++;
        if (glob[i + 1] === "/") {
          i++;
          re += "(?:.*/)?";
        } else {
          re += ".*";
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else if (c === "{") {
      const end = glob.indexOf("}", i);
      if (end === -1) {
        re += "\\{";
      } else {
        const alts = glob
          .slice(i + 1, end)
          .split(",")
          .map((a) => a.replace(/[.+^${}()|[\]\\*?]/g, (m) => (m === "*" ? "[^/]*" : m === "?" ? "[^/]" : `\\${m}`)));
        re += `(?:${alts.join("|")})`;
        i = end;
      }
    } else if (/[.+^$()|[\]\\]/.test(c)) {
      re += `\\${c}`;
    } else {
      re += c;
    }
  }
  return new RegExp(`^${re}$`, platform === "windows" ? "is" : "s");
}

/**
 * Match a project-relative path against globs. A glob without `/` is matched
 * against the basename at any depth; a glob with `/` against the whole
 * relative path. Returns the first matching glob or `undefined`.
 */
export function matchGlobs(rel: string, globs: readonly string[], platform: Platform): string | undefined {
  const path = toPosix(rel);
  const base = path.slice(path.lastIndexOf("/") + 1);
  const compiled = compiledList(globs, platform);
  for (let i = 0; i < globs.length; i++) {
    const c = compiled[i];
    if (c.whole ? c.whole.test(path) : c.name(base)) return globs[i];
  }
  return undefined;
}

type CompiledGlob = { whole: RegExp; name?: undefined } | { whole?: undefined; name: (name: string) => boolean };

/** A policy list compiled once per platform; the lists are static and judged against every word of a command. */
const LIST_CACHE = new WeakMap<readonly string[], Partial<Record<Platform, CompiledGlob[]>>>();

/**
 * A glob with `/` as a RegExp (the policy's are a literal head and `/**`, which match in one pass);
 * a basename glob as a segment matcher, one per `{a,b}` alternative, since a RegExp of
 * `*baseline*.json` backtracks over a long name in time proportional to its square.
 */
function compiledList(globs: readonly string[], platform: Platform): CompiledGlob[] {
  let byPlatform = LIST_CACHE.get(globs);
  if (byPlatform === undefined) LIST_CACHE.set(globs, (byPlatform = {}));
  return (byPlatform[platform] ??= globs.map((g): CompiledGlob => {
    if (g.includes("/")) return { whole: globToRegExp(g, platform) };
    const each = alternatives(g).map((a) => segmentMatcher(a.replace(/\[/g, "[[]"), platform, true));
    return { name: (n) => each.some((m) => m(n)) };
  }));
}

/** `{a,b}` expanded as globToRegExp reads it: to the next `}`, one level, an unclosed `{` literal. */
function alternatives(glob: string): string[] {
  const open = glob.indexOf("{");
  const close = open < 0 ? -1 : glob.indexOf("}", open);
  if (close < 0) return [glob];
  const head = glob.slice(0, open);
  const tails = alternatives(glob.slice(close + 1));
  return glob.slice(open + 1, close).split(",").flatMap((a) => tails.map((t) => head + a + t));
}

export function basename(p: string): string {
  const s = toPosix(p);
  return s.slice(s.lastIndexOf("/") + 1);
}

type GlobToken = { kind: "star" } | { kind: "one" } | { kind: "class"; negate: boolean; test: (c: string) => boolean } | { kind: "lit"; ch: string };

/** The POSIX character classes of a bracket expression; a name sh does not know counts as any character. */
const POSIX_CLASSES: Record<string, RegExp> = Object.assign(Object.create(null) as Record<string, RegExp>, {
  alnum: /[\p{L}\p{N}]/u,
  alpha: /\p{L}/u,
  ascii: /[\x00-\x7f]/,
  blank: /[ \t]/,
  cntrl: /[\x00-\x1f\x7f]/,
  digit: /[0-9]/,
  graph: /[^\s\x00-\x1f\x7f]/,
  lower: /\p{Ll}/u,
  print: /[^\x00-\x1f\x7f]/,
  punct: /[!-/:-@[-`{-~]/,
  space: /\s/,
  upper: /\p{Lu}/u,
  word: /[\p{L}\p{N}_]/u,
  xdigit: /[0-9A-Fa-f]/,
});

/**
 * The bracket expressions of a sh glob segment: `bracketAt(i)` reads the one opening at `seg[i]`
 * as bash does (`!` or `^` negates, a `]` first is a member, ranges, `[:alpha:]`, `[=c=]` and
 * `[.c.]`) and gives where it closes and a membership test, or null when it never closes and the
 * `[` is a plain character. Past its first character a search goes the same way wherever it
 * started, so the positions a search that never closed passed through end any later search that
 * reaches them: a segment of thousands of `[` or `[[:x:]` costs its length, and where each `:]`,
 * `=]` and `.]` next closes is worked out once. A test is worked out once per character. A class
 * bash may not know (`[:x:]`, `[.space.]`) could match any character, negated or not, so the
 * bracket is taken to match every character: the guard asks what a glob may name.
 */
export function bracketReader(seg: string, platform: Platform): (i: number) => { end: number; negate: boolean; test: (c: string) => boolean } | null {
  const lastClose = seg.lastIndexOf("]");
  const nexts = new Map<string, Int32Array>();
  // Where the next `${kind}]` starts at or after each position, or -1.
  const nextClose = (kind: string, from: number): number => {
    let next = nexts.get(kind);
    if (next === undefined) {
      next = new Int32Array(seg.length + 1).fill(-1);
      for (let p = seg.length - 2; p >= 0; p--) next[p] = seg[p] === kind && seg[p + 1] === "]" ? p : next[p + 1];
      nexts.set(kind, next);
    }
    return from < seg.length ? next[from] : -1;
  };
  const folds = platform === "windows";
  const dead = new Uint8Array(seg.length);
  return (i) => {
    if (seg[i] !== "[" || lastClose <= i) return null;
    let k = i + 1;
    const negate = seg[k] === "!" || seg[k] === "^";
    if (negate) k++;
    const singles = new Set<string>();
    const ranges: [string, string][] = [];
    const classes: RegExp[] = [];
    const passed: number[] = [];
    let anything = false;
    for (let first = true; k < seg.length; k++, first = false) {
      if (!first) {
        if (dead[k] === 1) k = seg.length;
        if (k === seg.length) break;
        passed.push(k);
      }
      const c = seg[k];
      if (c === "]" && !first) break;
      const kind = seg[k + 1];
      const close = c === "[" && (kind === ":" || kind === "=" || kind === ".") ? nextClose(kind, k + 2) : -1;
      if (close >= 0) {
        // No class name is longer than "xdigit": a longer one is never sliced out.
        const name = close - k - 2 <= 8 ? seg.slice(k + 2, close) : "";
        if (kind !== ":" && name.length === 1) singles.add(name);
        else if (kind === ":" && Object.hasOwn(POSIX_CLASSES, name)) classes.push(POSIX_CLASSES[name]);
        else anything = true;
        k = close + 1;
      } else if (kind === "-" && k + 2 < seg.length && seg[k + 2] !== "]") {
        if (c <= seg[k + 2]) ranges.push([c, seg[k + 2]]);
        k += 2;
      } else singles.add(c);
    }
    if (k >= seg.length) {
      for (const at of passed) dead[at] = 1;
      return null;
    }
    const known = new Map<string, boolean>();
    const member = (ch: string) =>
      anything || singles.has(ch) || ranges.some(([a, b]) => ch >= a && ch <= b) || classes.some((re) => re.test(ch));
    const test = (ch: string): boolean => {
      let m = known.get(ch);
      if (m === undefined) known.set(ch, (m = member(ch) || (folds && (member(ch.toLowerCase()) || member(ch.toUpperCase())))));
      return m;
    };
    return { end: k, negate: negate && !anything, test };
  };
}

/**
 * One segment of a sh glob as a matcher. A wildcard does not match a leading dot unless the
 * pattern spells it (sh without dotglob, Git Bash included); with `dots` it does, as PowerShell
 * and cmd wildcards do. On Windows it case folds. A reversed range (`[z-a]`) matches nothing, as
 * in bash. It runs in time proportional to the name times the pattern, never backtracking more:
 * a RegExp of `*********Z` took seconds on a short name.
 */
export function segmentMatcher(seg: string, platform: Platform, dots: boolean): (name: string) => boolean {
  const fold = platform === "windows" ? (c: string) => c.toLowerCase() : (c: string) => c;
  const bracketAt = bracketReader(seg, platform);
  const toks: GlobToken[] = [];
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i];
    const bracket = c === "[" ? bracketAt(i) : null;
    if (c === "*") {
      if (toks[toks.length - 1]?.kind !== "star") toks.push({ kind: "star" });
    } else if (c === "?") toks.push({ kind: "one" });
    else if (bracket !== null) {
      toks.push({ kind: "class", negate: bracket.negate, test: bracket.test });
      i = bracket.end;
    } else toks.push({ kind: "lit", ch: fold(c) });
  }
  const one = (t: GlobToken, ch: string): boolean =>
    t.kind === "one" || (t.kind === "lit" && t.ch === fold(ch)) || (t.kind === "class" && t.test(ch) !== t.negate);
  const lead = !dots && /[*?[]/.test(seg[0] ?? "");
  return (name: string): boolean => {
    if (lead && name.startsWith(".")) return false;
    let p = 0;
    let n = 0;
    let star = -1;
    let resume = 0;
    while (n < name.length) {
      const t = toks[p];
      if (t !== undefined && t.kind === "star") {
        star = p++;
        resume = n;
      } else if (t !== undefined && one(t, name[n])) {
        p++;
        n++;
      } else if (star >= 0) {
        p = star + 1;
        n = ++resume;
      } else return false;
    }
    while (toks[p]?.kind === "star") p++;
    return p === toks.length;
  };
}
