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
    if (rel === ".git" || rel.startsWith(".git/")) return base("git-internals", ".git/**");
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
  const layers = ancestors(ctx.projectRoot, ctx.platform).slice(1);
  if (ctx.mainCheckout !== undefined) layers.push(...ancestors(ctx.mainCheckout, ctx.platform));
  for (const dir of layers) {
    if (inProject && ctx.homeDir !== undefined && relativeTo(dir, ctx.homeDir, ctx.platform) !== null) continue;
    const r = relativeTo(dir, abs, ctx.platform);
    if (r === null || r === ".") continue;
    const m = ctx.policy.hookConfigPaths.find((g) => globToRegExp(g, ctx.platform).test(r));
    if (m !== undefined) return m;
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
