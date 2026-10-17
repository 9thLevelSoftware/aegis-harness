/**
 * Path classification shared by the edit rules and by the shell rules that
 * look at redirection and copy targets. Purely lexical.
 */
import { onTime, type Context, type Platform } from "./model.ts";
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
  segmentMatcher,
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
  onTime(ctx.deadline);
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
    const i = anchors(ctx).hookGlobs.findIndex((re) => re.test(r));
    if (i >= 0) return ctx.policy.hookConfigPaths[i];
  }
  return undefined;
}

/** Every directory above the project root, nearest first, then, in a linked worktree, the main checkout's twin and its ancestors. */
function layersAbove(ctx: Context): string[] {
  return anchors(ctx).layers;
}

/**
 * What the wildcard and directory checks compare a path against, worked out
 * once per context: a long command judges thousands of words against them.
 */
interface Anchors {
  layers: string[];
  /** The literal heads of protected trees, split into segments: `.git`, harness and hook heads at the project root and every layer, home-sensitive heads at home. */
  heads: string[][];
  /** The concrete names basename globs stand for, the names the policy spells out first, so `ruff*` reports ruff.toml rather than a made-up config name. */
  names: string[];
  /** `dir/head` for each glob with a literal head (case-folded on Windows), and what removing a directory above it removes. */
  holders: { folded: string; glob: string; category: "home-config" | "hook-config" }[];
  /** The policy's hook configuration globs, compiled, each matched against a whole path below a layer. */
  hookGlobs: RegExp[];
}

const ANCHORS = new WeakMap<Context, Anchors>();

function anchors(ctx: Context): Anchors {
  const cached = ANCHORS.get(ctx);
  if (cached !== undefined) return cached;
  const { policy, platform } = ctx;
  const layers = ancestors(ctx.projectRoot, platform).slice(1);
  if (ctx.mainCheckout !== undefined) layers.push(...ancestors(ctx.mainCheckout, platform));
  const join = (dir: string, rest: string) => `${normalize(driveForm(dir, platform)).replace(/\/$/, "")}/${rest}`;
  const fold = (p: string) => (platform === "windows" ? p.toLowerCase() : p);
  const heads: string[] = [];
  const holders: Anchors["holders"] = [];
  const home = ctx.homeDir ?? "~";
  for (const g of policy.homeSensitivePaths) {
    const head = literalHead(g);
    if (ctx.homeDir !== undefined) heads.push(join(ctx.homeDir, head ?? g));
    if (head !== null) holders.push({ folded: fold(join(home, head)), glob: g, category: "home-config" });
  }
  for (const dir of [normalize(driveForm(ctx.projectRoot, platform)), ...layers]) {
    // `.git` first, so `.g*\/hooks` reports the repository's hooks rather than a `.githooks` that may not exist.
    heads.push(join(dir, ".git"));
    for (const g of [...policy.harnessPaths, ...policy.hookConfigPaths]) {
      const head = literalHead(g);
      if (head === null) continue;
      heads.push(join(dir, head));
      if (policy.hookConfigPaths.includes(g)) holders.push({ folded: fold(join(dir, head)), glob: g, category: "hook-config" });
    }
  }
  const basenames = [...policy.hookConfigPaths, ...policy.lintConfigPaths, ...policy.testConfigPaths].filter((g) => !g.includes("/"));
  const names = [...basenames.filter((b) => !WILDCARD.test(b)), ...basenames.filter((b) => WILDCARD.test(b))].flatMap(spellings);
  const hookGlobs = policy.hookConfigPaths.map((g) => globToRegExp(g, platform));
  const a: Anchors = { layers, heads: heads.map((h) => h.split("/")), names, holders, hookGlobs };
  ANCHORS.set(ctx, a);
  return a;
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

/** The literal text of a glob segment, its wildcards and bracket classes dropped: `.eslintrc` from `.eslintrc*`, `.js` from `*.js`. */
function literalText(seg: string): string {
  return seg.replace(/\[[^\]]*\]|[*?]/g, "");
}

/**
 * True when a wildcarded file name names something more than a kind of file:
 * `.eslintrc*`, `ruff*`, `*.config.*` do; `*`, `.[!.]*` and an extension
 * alone (`*.js`, `*.json`) do not, since they match any file of that kind,
 * protected or not, and whether a protected one is there only the filesystem knows.
 */
function namesFile(seg: string): boolean {
  const text = literalText(seg);
  if (!/[^.]/.test(text)) return false;
  return !(WILDCARD.test(seg[0]) && /^\.[^.]*$/.test(text));
}

/** Concrete names a basename glob stands for, to test a wildcard target against: `vitest.config.*` as `vitest.config.ts` and its kin. */
function spellings(glob: string): string[] {
  if (!WILDCARD.test(glob)) return [glob];
  return ["js", "ts", "mjs", "cjs", "json", "jsonc", "yml", "yaml", "toml", "x"].map((ext) => glob.replace(/\*+|\?/g, ext));
}

/**
 * The protected path a target with shell wildcards reaches, matched the way
 * sh expands it. A protected tree is reached by a pattern that matches its
 * head (`.c*` matches `.codex`), a directory above it, or a path below it
 * (`.g*\/hooks/pre-commit` is in `.git`); a wildcard that names nothing (`*`)
 * does not count on the way down. A basename glob is reached by a last
 * segment that names it (`.eslintrc*` reaches `.eslintrc.json`, in whatever
 * directory the rest of the pattern names). With `whole`, a directory above a
 * protected path counts (`rm -rf .c*` takes `.claude` with it); without,
 * only the path itself, since a non-recursive rm leaves directories alone.
 * The result is classified as the protected path it reached.
 */
export function wildcardReach(input: string, ctx: Context, whole: boolean): PathInfo | undefined {
  const { platform } = ctx;
  const stripped = input.replace(/^["']+|["']+$/g, "");
  if (!WILDCARD.test(stripped) || hasVariable(stripped)) return undefined;
  const pattern = resolvePath(stripped, ctx.projectRoot, ctx.homeDir, platform).split("/");
  const compiled = new Map<string, (name: string) => boolean>();
  const dots = (ctx.shellDialect ?? (platform === "windows" ? "powershell" : "posix")) !== "posix";
  const same = (p: string, seg: string): boolean => {
    if (!WILDCARD.test(p)) return platform === "windows" ? p.toLowerCase() === seg.toLowerCase() : p === seg;
    let match = compiled.get(p);
    if (match === undefined) compiled.set(p, (match = segmentMatcher(p, platform, dots)));
    return match(seg);
  };
  const reached = (lit: string): PathInfo | undefined => {
    const info = classifyPath(lit, ctx);
    if (info.category === "normal" || info.category === "outside-project" || info.category === "temp") return undefined;
    const shown = relativeTo(ctx.projectRoot, lit, platform) ?? lit;
    return { ...info, input, abs: pattern.join("/"), matched: `it matches ${shown}` };
  };

  const { heads, names } = anchors(ctx);
  for (const segs of heads) {
    let hit: PathInfo | undefined;
    if (segs.length >= pattern.length) {
      if ((whole || segs.length === pattern.length) && pattern.every((p, i) => same(p, segs[i]))) hit = reached(segs.join("/"));
    } else if (segs.every((seg, i) => same(pattern[i], seg) && (!WILDCARD.test(pattern[i]) || literalText(pattern[i]) !== ""))) {
      hit = reached([...segs, ...pattern.slice(segs.length)].join("/"));
    }
    if (hit !== undefined) return hit;
  }

  const last = pattern[pattern.length - 1];
  if (!WILDCARD.test(last) || !namesFile(last)) return undefined;
  const dir = pattern.slice(0, -1).join("/");
  for (const name of names) {
    if (!same(last, name)) continue;
    const hit = reached(`${dir}/${name}`);
    if (hit !== undefined) return hit;
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
  const fold = (p: string) => (ctx.platform === "windows" ? p.toLowerCase() : p);
  const a = normalize(driveForm(abs, ctx.platform));
  const prefix = fold(a.endsWith("/") ? a : `${a}/`);
  for (const h of anchors(ctx).holders) if (h.folded.startsWith(prefix)) return { category: h.category, matched: h.glob };
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
