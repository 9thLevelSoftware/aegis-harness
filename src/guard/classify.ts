/**
 * Path classification shared by the edit rules and by the shell rules that
 * look at redirection and copy targets. Purely lexical.
 */
import type { Context } from "./model.ts";
import {
  hasVariable,
  isFilesystemRoot,
  isSystemPath,
  isTempPath,
  matchGlobs,
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
  const abs = resolvePath(stripped, ctx.projectRoot, ctx.homeDir);
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
    if ((m = matchGlobs(rel, policy.hookConfigPaths, platform))) return base("hook-config", m);
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

  if (isSystemPath(abs)) return base("system");
  if (isTempPath(abs) || isTempPath(stripped)) return base("temp");
  return base("outside-project");
}

/** Device nodes whose overwrite destroys a disk. */
export function isBlockDevice(p: string): boolean {
  return /^\/dev\/(sd[a-z]|hd[a-z]|nvme\d|disk\d|mmcblk\d|xvd[a-z]|vd[a-z]|loop\d)/i.test(p.replace(/\\/g, "/")) || /^\\\\\.\\PhysicalDrive\d/i.test(p);
}
