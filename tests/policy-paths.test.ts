import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyPath } from "../src/guard/classify.ts";
import { driveForm, globToRegExp, isTempPath, matchGlobs, normalize, relativeTo, resolvePath } from "../src/guard/paths.ts";
import { POSIX, WINDOWS_CODEX } from "./helpers.ts";

test("lexical normalisation", () => {
  assert.equal(normalize("/a/b/../c/./d"), "/a/c/d");
  assert.equal(normalize("C:\\Users\\dev\\..\\dev\\proj"), "C:/Users/dev/proj");
  assert.equal(normalize("a/../.."), "..");
  assert.equal(resolvePath("~/.ssh/id_rsa", "/home/dev/project", "/home/dev"), "/home/dev/.ssh/id_rsa");
  assert.equal(resolvePath("src/a.ts", "/home/dev/project"), "/home/dev/project/src/a.ts");
});

test("relativeTo is case-insensitive on Windows only", () => {
  assert.equal(relativeTo("C:\\Users\\dev\\project", "c:/users/DEV/project/src/a.ts", "windows"), "src/a.ts");
  assert.equal(relativeTo("/home/dev/project", "/home/dev/Project/src/a.ts", "posix"), null);
});

test("globs: ** crosses directories, basename patterns match at any depth", () => {
  assert.ok(globToRegExp(".harness/**", "posix").test(".harness/memory/bugs/x.yaml"));
  assert.ok(globToRegExp("release/*", "posix").test("release/1.2"));
  assert.ok(!globToRegExp("release/*", "posix").test("release/1/2"));
  assert.ok(globToRegExp("*.{yml,yaml}", "posix").test("a.yaml"));
});

test("classification examples", () => {
  const c = (p: string) => classifyPath(p, POSIX).category;
  assert.equal(c(".harness/state.json"), "harness");
  assert.equal(c(".git/hooks/pre-commit"), "git-internals");
  assert.equal(c(".husky/pre-commit"), "hook-config");
  assert.equal(c("packages/web/.eslintrc.cjs"), "lint-config");
  assert.equal(c("vitest.config.mts"), "test-config");
  assert.equal(c("package-lock.json"), "lockfile");
  assert.equal(c("typecheck-baseline.json"), "baseline");
  assert.equal(c("pyproject.toml"), "manifest");
  assert.equal(c(".github/workflows/ci.yml"), "ci-config");
  assert.equal(c("tsconfig.app.json"), "compiler-config");
  assert.equal(c(".env.local"), "env-file");
  assert.equal(c(".env.example"), "env-example");
  assert.equal(c("certs/dev.pem"), "key-material");
  assert.equal(c("/home/dev/.ssh/config"), "home-config");
  assert.equal(c("/etc/hosts"), "system");
  assert.equal(c("/tmp/x"), "temp");
  assert.equal(c("/home/dev/other/x"), "outside-project");
  assert.equal(c("src/a.ts"), "normal");
  assert.equal(c("/"), "filesystem-root");
  assert.equal(c("/home/dev"), "home-root");
  assert.equal(c("."), "project-root");
});

test("Windows classification folds case and handles drive paths", () => {
  const c = (p: string) => classifyPath(p, WINDOWS_CODEX).category;
  assert.equal(c("C:\\Users\\dev\\project\\.Harness\\x"), "harness");
  assert.equal(c("C:\\Users\\dev\\.codex\\config.toml"), "home-config");
  assert.equal(c("C:\\Windows\\System32\\drivers\\etc\\hosts"), "system");
  assert.equal(c("C:\\"), "filesystem-root");
  assert.equal(c("C:\\Users\\dev"), "home-root");
  assert.equal(c("%TEMP%\\ah"), "temp");
});

test("a project rooted at the home directory still protects home config", () => {
  const ctx = { ...POSIX, projectRoot: "/home/dev" };
  assert.equal(classifyPath(".ssh/id_rsa", ctx).category, "home-config");
  assert.equal(classifyPath(".npmrc", ctx).category, "home-config");
});

test("a project .npmrc is a normal file", () => {
  assert.equal(classifyPath(".npmrc", POSIX).category, "normal");
});

const WINDOWS_CLAUDE = { ...WINDOWS_CODEX, shellDialect: "posix" as const };

test("Git Bash drive paths resolve against the Windows root and home (BUG-2026-017)", () => {
  assert.equal(driveForm("/c/Users/dev/project/dist", "windows"), "C:/Users/dev/project/dist");
  assert.equal(driveForm("/cygdrive/e/work", "windows"), "E:/work");
  assert.equal(driveForm("/c", "windows"), "C:");
  assert.equal(driveForm("/c/Users/dev", "posix"), "/c/Users/dev");
  assert.equal(driveForm("/mnt/c/Users/dev", "windows"), "/mnt/c/Users/dev");
  assert.equal(driveForm("/tmp/x", "windows"), "/tmp/x");
  assert.equal(resolvePath("/c/Users/dev/project/dist", "C:\\Users\\dev\\project", "C:\\Users\\dev", "windows"), "C:/Users/dev/project/dist");
  assert.equal(relativeTo("C:\\Users\\dev\\project", "/c/Users/dev/project/src/a.ts", "windows"), "src/a.ts");
  assert.equal(relativeTo("/home/dev/project", "/c/Users/dev/project/src/a.ts", "posix"), null);

  const c = (p: string) => classifyPath(p, WINDOWS_CLAUDE);
  assert.equal(c("/c/Users/dev/project/dist").category, "normal");
  assert.equal(c("/c/Users/dev/project/dist").rel, "dist");
  assert.equal(c("/c/Users/dev/project/.harness/x").category, "harness");
  assert.equal(c("/c/Users/dev/project").category, "project-root");
  assert.equal(c("/c/Users/dev").category, "home-root");
  assert.equal(c("/cygdrive/c/Users/dev").category, "home-root");
  assert.equal(c("/c/Users/dev/.ssh/id_rsa").category, "home-config");
  assert.equal(c("/c/").category, "filesystem-root");
  assert.equal(c("/c").category, "filesystem-root");
  assert.equal(c("/c/Users/dev/AppData/Local/Temp/x").category, "temp");
  assert.equal(c("/c/Windows/System32/drivers/etc/hosts").category, "system");
  assert.equal(c("/c/Users/dev/other/x").category, "outside-project");
  // WSL paths are real on POSIX and are not drive paths on Windows either.
  assert.equal(c("/mnt/c/Users/dev/project/dist").category, "outside-project");
  assert.equal(classifyPath("/c/Users/dev/project/dist", POSIX).category, "outside-project");
});

test("temp variables with defaults and PowerShell $env: forms are temp (BUG-2026-017)", () => {
  for (const p of ["${TMPDIR:-/tmp}/ah-test", "${TMPDIR:=/tmp}/x", "${TMP:-/tmp}/x", "${TEMP:?unset}/x", "${TMPDIR:-/tmp}", "$TMPDIR/x", "$env:TEMP\\build", "$env:TMP/x", "$env:RUNNER_TEMP", "$env:temp\\x", "%TEMP%\\x"]) {
    assert.ok(isTempPath(p), `${p} should be temp`);
  }
  for (const p of ["${DIR:-/tmp}/x", "$env:TEMPLATE\\x", "$TMPDIRS/x", "$env:HOME\\x", "${TMPDIR:+/tmp}/x"]) {
    assert.ok(!isTempPath(p), `${p} should not be temp`);
  }
  assert.equal(classifyPath("${TMPDIR:-/tmp}/ah-test", POSIX).category, "temp");
  assert.equal(classifyPath("$env:TEMP\\build", WINDOWS_CODEX).category, "temp");
  assert.equal(classifyPath("~\\AppData\\Local\\Temp\\ah-test", WINDOWS_CODEX).category, "temp");
  assert.equal(classifyPath("C:\\Users\\dev\\AppData\\Local\\Temp\\ah-test", WINDOWS_CODEX).category, "temp");
});

test("globs are compiled once and classifyPath stays cheap", () => {
  assert.equal(globToRegExp("*.{yml,yaml}", "posix"), globToRegExp("*.{yml,yaml}", "posix"));
  assert.notEqual(globToRegExp("*.{yml,yaml}", "posix"), globToRegExp("*.{yml,yaml}", "windows"));
  classifyPath("src/warm-up.ts", POSIX);
  // Best of five rounds: one round on a busy CI runner can take twice as long.
  // Recompiling the globs on every call costs about three times as much, so the
  // fastest round still exceeds the budget then.
  let ms = Infinity;
  for (let round = 0; round < 5; round++) {
    const t = performance.now();
    for (let i = 0; i < 1000; i++) classifyPath(`src/file${i}.ts`, POSIX);
    ms = Math.min(ms, performance.now() - t);
  }
  assert.ok(ms < 150, `1000 classifyPath calls took ${ms.toFixed(0)} ms in the fastest of five rounds`);
});

test("basename globs match as their RegExp does, in time that grows with the name (BUG-2026-019)", () => {
  for (const [name, globs, want] of [
    ["x-baseline.json", ["*baseline*.json"], "*baseline*.json"],
    ["a.test.ts", ["*.test.*"], "*.test.*"],
    ["ESLINT.CONFIG.JS", ["eslint.config.*"], undefined],
    ["a.yaml", ["*.{yml,yaml}"], "*.{yml,yaml}"],
    ["a[b].js", ["a[b].js"], "a[b].js"],
    ["ab.js", ["a[b].js"], undefined],
    [".harness/x\ny", [".harness/**"], ".harness/**"],
  ] as const) {
    assert.equal(matchGlobs(name, globs, "posix"), want, name);
    assert.equal(matchGlobs(name, globs, "posix"), globs.find((g) => globToRegExp(g, "posix").test(g.includes("/") ? name : name.slice(name.lastIndexOf("/") + 1))), name);
  }
  assert.equal(matchGlobs("ESLINT.CONFIG.JS", ["eslint.config.*"], "windows"), "eslint.config.*");
  const t = performance.now();
  assert.equal(matchGlobs("baseline".repeat(20_000) + "x", ["*baseline*.json"], "posix"), undefined);
  assert.ok(performance.now() - t < 200, `took ${Math.round(performance.now() - t)} ms`);
});

test("normalize keeps a path with a newline, and returns a normal path unchanged (BUG-2026-019)", () => {
  assert.equal(normalize("/a/b\nc/../d"), "/a/d");
  assert.equal(normalize("/a/b\nc"), "/a/b\nc");
  assert.equal(normalize("C:."), "C:");
  assert.equal(normalize("C:./a"), "C:a");
  assert.equal(normalize("/a/b"), "/a/b");
  assert.equal(normalize(" /a"), "/a");
});
