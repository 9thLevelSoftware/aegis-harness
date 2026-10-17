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

/** Resolve `.` and `..` segments lexically. Keeps a leading drive or `/`. */
export function normalize(p: string): string {
  const s = toPosix(p);
  const m = /^([A-Za-z]:)?(\/)?(.*)$/.exec(s);
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
    return new RegExp(`^${inner}(?:/.*)?$`, platform === "windows" ? "i" : "");
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
  return new RegExp(`^${re}$`, platform === "windows" ? "i" : "");
}

/**
 * Match a project-relative path against globs. A glob without `/` is matched
 * against the basename at any depth; a glob with `/` against the whole
 * relative path. Returns the first matching glob or `undefined`.
 */
export function matchGlobs(rel: string, globs: readonly string[], platform: Platform): string | undefined {
  const path = toPosix(rel);
  const base = path.slice(path.lastIndexOf("/") + 1);
  for (const g of globs) {
    const target = g.includes("/") ? path : base;
    if (globToRegExp(g, platform).test(target)) return g;
  }
  return undefined;
}

export function basename(p: string): string {
  const s = toPosix(p);
  return s.slice(s.lastIndexOf("/") + 1);
}
