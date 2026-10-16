import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyPath } from "../src/guard/classify.ts";
import { globToRegExp, normalize, relativeTo, resolvePath } from "../src/guard/paths.ts";
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
