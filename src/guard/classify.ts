/**
 * Path classification shared by the edit rules and by the shell rules that
 * look at redirection and copy targets. Purely lexical.
 */
import type { Context, Platform } from "./model.ts";
import {
  driveForm,
  globToRegExp,
  hasVariable,
  isFilesystemRoot,
  isSystemPath,
  isTempPath,
  matchGlobs,
  normalize,
  relativeTo,
  relativeToHome,
  resolvePath,
} from "./paths.ts";

export type PathCategory =
  | "harness"
  | "git-internals"
  | "hook-config"
  | "home-config"
  | "system"
  | "lockfile"
  | "lint-config"
  | "test-config"
  | "baseline"
  | "manifest"
  | "ci-config"
  | "compiler-config"
  | "env-file"
  | "env-example"
  | "key-material"
  | "project-root"
  | "filesystem-root"
  | "home-root"
  | "outside-project"
  | "temp"
  | "normal";

export interface PathInfo {
  input: string;
  abs: string;
  /** Project-relative path, or null when outside the project. */
  rel: string | null;
  /** Home-relative path, or null when outside the home directory or home is unknown. */
  homeRel: string | null;
  category: PathCategory;
  /** The glob that decided the category, when one did. */
  matched?: string;
  /** For git-internals: the path from the repository's own directory, `.git` or `.git/...`. */
  gitRel?: string;
  isTestFile: boolean;
  hasVariable: boolean;
}

const HOME_SHAPED = /^(\/home\/[^/]+|\/Users\/[^/]+|\/root|[A-Za-z]:\/Users\/[^/]+)\/?$/i;
const KEY_GLOB = /\.(pem|key|p12|pfx|jks|keystore)$|^id_(rsa|ed25519|ecdsa)$/;

export function classifyPath(input: string, ctx: Context): PathInfo {
  const { policy, platform } = ctx;
  const stripped = input.replace(/^["']+|["']+$/g, "");
  const abs = resolvePath(stripped, ctx.projectRoot, ctx.homeDir, platform);
  const rel = relativeTo(ctx.projectRoot, abs, platform);
  const homeRel = relativeToHome(abs, ctx.homeDir, platform);
  const variable = hasVariable(stripped);
  const projectIsHome = ctx.homeDir !== undefined && relativeTo(ctx.homeDir, ctx.projectRoot, platform) === ".";

  const base = (category: PathCategory, matched?: string): PathInfo => ({
    input,
    abs,
    rel,
    homeRel,
    category,
    matched,
    isTestFile: matchGlobs(rel ?? abs, policy.testFilePaths, platform) !== undefined,
    hasVariable: variable,
  });

  if (isFilesystemRoot(abs)) return base("filesystem-root");
  if (variable && isTempPath(stripped)) return base("temp");
  if (homeRel === "." || (ctx.homeDir === undefined && HOME_SHAPED.test(abs)) || abs === "~") return base("home-root");

  if (homeRel !== null && (rel === null || projectIsHome)) {
    const m = matchGlobs(homeRel, policy.homeSensitivePaths, platform);
    if (m) return base("home-config", m);
  }

  if (rel !== null) {
    if (rel === ".") return base("project-root");
    let m: string | undefined;
    if ((m = matchGlobs(rel, policy.harnessPaths, platform))) return base("harness", m);
    if (isGitRel(rel, platform)) return { ...base("git-internals", ".git/**"), gitRel: rel };
    // A session started inside a hook directory (`<top>/.codex`) has the hook files themselves in the project.
    if ((m = matchGlobs(rel, policy.hookConfigPaths, platform) ?? hookConfigAbove(abs, ctx, true))) return base("hook-config", m);
    if ((m = matchGlobs(rel, policy.lockfilePaths, platform))) return base("lockfile", m);
    if ((m = matchGlobs(rel, policy.lintConfigPaths, platform))) return base("lint-config", m);
    if ((m = matchGlobs(rel, policy.testConfigPaths, platform))) return base("test-config", m);
    if ((m = matchGlobs(rel, policy.baselinePaths, platform))) return base("baseline", m);
    if ((m = matchGlobs(rel, policy.manifestPaths, platform))) return base("manifest", m);
    if ((m = matchGlobs(rel, policy.envExamplePaths, platform))) return base("env-example", m);
    if ((m = matchGlobs(rel, policy.askPaths, platform))) {
      if (m.startsWith(".env")) return base("env-file", m);
      if (/tsconfig|jsconfig/.test(m)) return base("compiler-config", m);
      if (KEY_GLOB.test(m.replace(/^\*/, "x"))) return base("key-material", m);
      return base("ci-config", m);
    }
    return base("normal");
  }

  const gitRel = gitDirAbove(abs, ctx);
  if (gitRel !== undefined) return { ...base("git-internals", ".git/**"), gitRel };
  const hook = hookConfigAbove(abs, ctx, false);
  if (hook !== undefined) return base("hook-config", hook);
  if (isSystemPath(abs)) return base("system");
  if (isTempPath(abs) || isTempPath(stripped)) return base("temp");
  return base("outside-project");
}

/**
 * Hook wiring an agent loads from above the directory a session started in.
 * Claude Code reads .claude/settings.local.json at the repository root and Codex
 * every .codex/ from the root down, so a session in <top>/sub still runs the
 * hooks `ah init` wired at <top>. The guard knows no git top level, so every
 * ancestor of the project root counts, each matched as if it were the project
 * (`lefthook.yml` directly in it, `.claude/settings.json` under it); in a linked
 * worktree so do the main checkout's twin of the project root and its ancestors.
 * Paths inside the project are matched too, since a session rooted in `<top>/.codex`
 * sees `hooks.json` as a project file, but only against layers below the home
 * directory: a project inside ~/.codex (Codex keeps its worktrees there) is not
 * made of hook files, and the home's own agent settings are home configuration.
 */
function hookConfigAbove(abs: string, ctx: Context, inProject: boolean): string | undefined {
  for (const dir of layersAbove(ctx)) {
    if (inProject && ctx.homeDir !== undefined && relativeTo(dir, ctx.homeDir, ctx.platform) !== null) continue;
    const r = relativeTo(dir, abs, ctx.platform);
    if (r === null || r === ".") continue;
    const m = ctx.policy.hookConfigPaths.find((g) => globToRegExp(g, ctx.platform).test(r));
    if (m !== undefined) return m;
  }
  return undefined;
}

/** Every directory above the project root, nearest first, then, in a linked worktree, the main checkout's twin and its ancestors. */
function layersAbove(ctx: Context): string[] {
  const layers = ancestors(ctx.projectRoot, ctx.platform).slice(1);
  if (ctx.mainCheckout !== undefined) layers.push(...ancestors(ctx.mainCheckout, ctx.platform));
  return layers;
}

/**
 * `abs` inside the `.git` of a directory above the project, as `.git` or
 * `.git/...`: a session in <top>/sub works in <top>'s repository, and one in
 * a linked worktree shares its main checkout's hooks.
 */
function gitDirAbove(abs: string, ctx: Context): string | undefined {
  for (const dir of layersAbove(ctx)) {
    const r = relativeTo(dir, abs, ctx.platform);
    if (r !== null && isGitRel(r, ctx.platform)) return r;
  }
  return undefined;
}

/** `.git` itself or a path inside it; Windows file systems fold case, so `.GIT` is the same directory there. */
function isGitRel(r: string, platform: Platform): boolean {
  const f = platform === "windows" ? r.toLowerCase() : r;
  return f === ".git" || f.startsWith(".git/");
}

const WILDCARD = /[*?[]/;

/**
 * One segment of a sh glob as a RegExp. A wildcard does not match a leading
 * dot unless the pattern spells it (sh without dotglob); on Windows it does,
 * as PowerShell and cmd wildcards do, and case folds.
 */
function segmentPattern(seg: string, platform: Platform): RegExp {
  let re = "";
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i];
    const close = c === "[" ? seg.indexOf("]", i + 2) : -1;
    if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else if (close > 0) {
      const body = seg.slice(i + 1, close);
      re += `[${/^[!^]/.test(body) ? "^" : ""}${body.replace(/^[!^]/, "").replace(/[\\\]^]/g, "\\$&")}]`;
      i = close;
    } else re += c.replace(/[.+^${}()|\\[\]]/g, "\\$&");
  }
  const lead = platform !== "windows" && WILDCARD.test(seg[0] ?? "") ? "(?!\\.)" : "";
  return new RegExp(`^${lead}${re}$`, platform === "windows" ? "i" : "");
}

/** Concrete names a basename glob stands for, to test a wildcard target against: `vitest.config.*` as `vitest.config.ts` and its kin. */
function spellings(glob: string): string[] {
  if (!WILDCARD.test(glob)) return [glob];
  return ["js", "ts", "mjs", "cjs", "json", "jsonc", "yml", "yaml", "toml", "x"].map((ext) => glob.replace(/\*+|\?/g, ext));
}

/**
 * The protected path a removal target with shell wildcards reaches, matched
 * the way sh expands it: `.claude/*` reaches `.claude/settings.json`,
 * `.eslintrc*` reaches `.eslintrc.json`. With `whole`, a target that matches
 * a directory above a protected path reaches it too (`rm -rf .c*` takes
 * `.claude` with it); without, only the path itself counts, since a
 * non-recursive rm leaves directories alone. The result is classified as the
 * protected path it reached.
 */
export function wildcardReach(input: string, ctx: Context, whole: boolean): PathInfo | undefined {
  const { policy, platform } = ctx;
  const stripped = input.replace(/^["']+|["']+$/g, "");
  if (!WILDCARD.test(stripped) || hasVariable(stripped)) return undefined;
  const pattern = resolvePath(stripped, ctx.projectRoot, ctx.homeDir, platform).split("/");
  const fixed = pattern.findIndex((seg) => WILDCARD.test(seg));
  const join = (dir: string, rest: string) => `${normalize(driveForm(dir, platform)).replace(/\/$/, "")}/${rest}`;
  const candidates: string[] = [];
  const root = normalize(driveForm(ctx.projectRoot, platform));
  for (const dir of [root, ...layersAbove(ctx)]) {
    for (const g of [...policy.hookConfigPaths, ...policy.harnessPaths]) {
      const head = literalHead(g);
      if (head !== null) candidates.push(join(dir, head));
    }
    candidates.push(join(dir, ".git"));
  }
  if (ctx.homeDir !== undefined) for (const g of policy.homeSensitivePaths) candidates.push(join(ctx.homeDir, literalHead(g) ?? g));
  // Basename globs match at any depth: try them in the project root and in the directory the wildcard
  // sits in, but only for a wildcard that names something (`.eslintrc*`, `*.toml`). A bare `*` or the
  // hidden-file `.[!.]*` matches any name, protected or not, and whether one is there only the filesystem knows.
  const parent = pattern.slice(0, fixed).join("/") || "/";
  const last = pattern[pattern.length - 1];
  const names = fixed === pattern.length - 1 && /[^.]/.test(last.replace(/\[[^\]]*\]|[*?]/g, ""));
  const basenames = [...policy.hookConfigPaths, ...policy.lintConfigPaths, ...policy.testConfigPaths].filter((g) => !g.includes("/"));
  // Names spelled out in the policy first, so `*.toml` reports ruff.toml rather than a made-up config name.
  const ordered = [...basenames.filter((g) => !WILDCARD.test(g)), ...basenames.filter((g) => WILDCARD.test(g))];
  for (const dir of names ? new Set([root, parent]) : []) {
    for (const g of ordered) for (const name of spellings(g)) candidates.push(join(dir, name));
  }
  for (const lit of candidates) {
    const segs = lit.split("/");
    if (segs.length < pattern.length || (!whole && segs.length !== pattern.length)) continue;
    const hit = pattern.every((p, i) => (WILDCARD.test(p) ? segmentPattern(p, platform).test(segs[i]) : platform === "windows" ? p.toLowerCase() === segs[i].toLowerCase() : p === segs[i]));
    if (!hit) continue;
    const info = classifyPath(lit, ctx);
    if (info.category === "normal" || info.category === "outside-project" || info.category === "temp") continue;
    const shown = relativeTo(ctx.projectRoot, lit, platform) ?? lit;
    return { ...info, input, abs: pattern.join("/"), matched: `it matches ${shown}` };
  }
  return undefined;
}

/** A glob's leading literal segments (`.claude/hooks` from `.claude/hooks/**`), or null for one that matches a basename at any depth. */
function literalHead(glob: string): string | null {
  if (!glob.includes("/")) return null;
  const head: string[] = [];
  for (const seg of glob.split("/")) {
    if (/[*?[{]/.test(seg)) break;
    head.push(seg);
  }
  return head.length === 0 ? null : head.join("/");
}

/**
 * What removing or moving the directory `abs` takes with it that the policy
 * protects, though no glob names the directory itself: `.claude` holds
 * `.claude/settings.json`, `~/.claude` the user's agent settings. Only a
 * glob's literal head counts; where a basename glob (`lefthook.yml`) sits in
 * a tree only the filesystem knows, and the guard is purely lexical.
 */
export function protectedInside(abs: string, ctx: Context): { category: "home-config" | "hook-config"; matched: string } | undefined {
  const holds = (dir: string, globs: readonly string[]): string | undefined =>
    globs.find((g) => {
      const head = literalHead(g);
      if (head === null) return false;
      const d = normalize(driveForm(dir, ctx.platform));
      const r = relativeTo(abs, `${d.endsWith("/") ? d : `${d}/`}${head}`, ctx.platform);
      return r !== null && r !== ".";
    });
  const home = holds(ctx.homeDir ?? "~", ctx.policy.homeSensitivePaths);
  if (home !== undefined) return { category: "home-config", matched: home };
  for (const dir of [normalize(driveForm(ctx.projectRoot, ctx.platform)), ...layersAbove(ctx)]) {
    const hook = holds(dir, ctx.policy.hookConfigPaths);
    if (hook !== undefined) return { category: "hook-config", matched: hook };
  }
  return undefined;
}

/** `dir` and every directory above it, nearest first, in the lexical form relativeTo compares. */
function ancestors(dir: string, platform: Platform): string[] {
  const out: string[] = [];
  for (let d = normalize(driveForm(dir, platform)); ; ) {
    out.push(d);
    const i = d.lastIndexOf("/");
    if (i < 0) return out;
    const up = i === 0 ? "/" : /^[A-Za-z]:$/.test(d.slice(0, i)) ? `${d.slice(0, i)}/` : d.slice(0, i);
    if (up === d) return out;
    d = up;
  }
}

/** Device nodes whose overwrite destroys a disk. */
export function isBlockDevice(p: string): boolean {
  return /^\/dev\/(sd[a-z]|hd[a-z]|nvme\d|disk\d|mmcblk\d|xvd[a-z]|vd[a-z]|loop\d)/i.test(p.replace(/\\/g, "/")) || /^\\\\\.\\PhysicalDrive\d/i.test(p);
}
