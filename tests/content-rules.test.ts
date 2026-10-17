import assert from "node:assert/strict";
import { test } from "node:test";
import { ed, wr } from "./helpers.ts";
import { countUnguarded, stripComments } from "../src/guard/rules/content.ts";

function timed<T>(fn: () => T): { result: T; ms: number } {
  const started = performance.now();
  const result = fn();
  return { result, ms: performance.now() - started };
}

test("fit( is a Jasmine focus only as a bare call with a string title", () => {
  assert.equal(ed("src/model.test.ts", "const m = new Model();", "const m = new Model();\nm.fit(X, y);").verdict, "allow");
  assert.equal(ed("tests/test_model.py", "    model = Model()", "    model = Model()\n    model.fit(X_train, y_train)").verdict, "allow");
  assert.equal(ed("src/curve.test.ts", "// x", "const params = fit(points, { degree: 2 });").verdict, "allow");
  assert.equal(ed("src/layout.test.ts", "// x", "expect(box.fit(container)).toBe(true);").verdict, "allow");
  const d = ed("spec/sync.spec.js", "it('syncs', () => {", "fit('syncs', () => {");
  assert.equal(d.verdict, "deny");
  assert.equal(d.rule, "edit.test-only");
  assert.equal(ed("spec/sync.spec.js", "describe('x', () => {", "fdescribe(`x`, () => {").rule, "edit.test-only");
  assert.equal(ed("spec/sync.spec.js", "it('syncs', () => {", "it.only('syncs', () => {").rule, "edit.test-only");
});

test("a lint tool named as a dependency is not a lint section", () => {
  for (const name of ["jest", "mocha", "ava", "husky", "c8", "nyc", "xo", "standard", "lint-staged"]) {
    const d = ed("package.json", '"devDependencies": {', `"devDependencies": {\n    "${name}": "^1.0.0",`);
    assert.equal(d.verdict, "allow", `${name}: ${d.reason ?? ""}`);
  }
  assert.equal(wr("package.json", '{"name":"x","scripts":{"test":"jest"},"devDependencies":{"jest":"^29.7.0"}}').verdict, "allow");
  assert.equal(wr("package.json", '{"name":"x","jest": {}}').rule, "edit.manifest-lint-section");
  assert.equal(ed("package.json", '"name": "x",', '"name": "x",\n  "eslintConfig": {\n    "rules": {}\n  },').rule, "edit.manifest-lint-section");
  assert.equal(ed("package.json", '"name": "x",', '"name": "x",\n  "lint-staged": [\n  ],').rule, "edit.manifest-lint-section");
  assert.equal(ed("package.json", '"jest": {\n    "testPathIgnorePatterns": []', '"jest": {\n    "testPathIgnorePatterns": ["tests/integration"]').rule, "edit.manifest-lint-section");
});

test("[tool.<name>] matches the section, not a prefix of another tool's", () => {
  assert.equal(ed("pyproject.toml", "[tool.poetry]", '[tool.poetry]\n[tool.pytest-asyncio]\nmode = "auto"').verdict, "allow");
  assert.equal(ed("pyproject.toml", "[tool.poetry]", "[tool.poetry]\n[tool.ruff-lsp]\nx = 1").verdict, "allow");
  assert.equal(ed("pyproject.toml", "[tool.poetry]", '[tool.poetry]\n[tool.pytest.ini_options]\naddopts = "-q"').rule, "edit.manifest-lint-section");
  assert.equal(ed("pyproject.toml", "[tool.poetry]", "[tool.poetry]\n[tool.ruff]\nline-length = 120").rule, "edit.manifest-lint-section");
});

test("comment-only lines do not count as skips, focus or manifest sections", () => {
  assert.equal(ed("pyproject.toml", "[tool.poetry]", "# the [tool.ruff] section lives in ruff.toml\n[tool.poetry]").verdict, "allow");
  assert.equal(ed("src/foo.test.ts", "// x", "// it.skip( would be wrong here").verdict, "allow");
  assert.equal(ed("src/foo.test.ts", "// x", "/* describe.only( is forbidden by the guard */").verdict, "allow");
  assert.equal(ed("src/foo.test.ts", "// x", "/*\n * it.skip( would be wrong here\n * and so would describe.only(\n */").verdict, "allow");
  assert.equal(ed("tests/test_foo.py", "pass", "# pytest.skip('x') is not what we want").verdict, "allow");
  // Suppression pragmas live in comments by nature and still count.
  assert.equal(ed("src/foo.ts", "// x", "/* eslint-disable */").rule, "edit.lint-suppression-blanket");
  assert.equal(ed("src/foo.py", "x = 1", "# ruff: noqa\nx = 1").rule, "edit.lint-suppression-blanket");
  // Rust attributes start with # and are not comments.
  assert.equal(ed("src/lib_test.rs", "#[test]", "#[test]\n#[ignore]").rule, "edit.test-skip");
  assert.equal(stripComments("a\n  // b\n  # c\n#[ignore]\n/* d\n e */\nf"), "a\n\n\n#[ignore]\n\n\nf");
});

test("if: always() asks like any CI edit; if: false on a step or job is a weakened gate", () => {
  const upload = ed(".github/workflows/ci.yml", "      - run: npm test", "      - run: npm test\n      - uses: actions/upload-artifact@v4\n        if: always()\n        with:\n          name: test-results\n          path: test-results/");
  assert.equal(upload.verdict, "ask");
  assert.equal(upload.rule, "edit.ci-config");
  const step = ed(".github/workflows/ci.yml", "      - run: npm test", "      - run: npm test\n        if: false");
  assert.equal(step.verdict, "deny");
  assert.equal(step.rule, "edit.ci-gate-weakened");
  assert.equal(ed(".github/workflows/ci.yml", "  test:\n    runs-on: ubuntu-latest", "  test:\n    if: ${{ false }}\n    runs-on: ubuntu-latest").rule, "edit.ci-gate-weakened");
  assert.equal(ed(".github/workflows/ci.yml", "      - run: npm test", "      - run: npm test\n        continue-on-error: true").rule, "edit.ci-gate-weakened");
  assert.equal(ed(".github/workflows/ci.yml", "      - run: npm test", "      - run: npm test\n        if: false # temp").rule, "edit.ci-gate-weakened");
  assert.equal(ed(".github/workflows/ci.yml", "  test:\n    runs-on: ubuntu-latest", "  test:\n    if: ${{ false }}  # until the flake is fixed\n    runs-on: ubuntu-latest").rule, "edit.ci-gate-weakened");
  assert.equal(ed(".github/workflows/ci.yml", "      - run: npm test", "      - run: npm test\n        if: false || inputs.force").rule, "edit.ci-config");
  // A real condition is an ordinary CI edit.
  assert.equal(ed(".github/workflows/ci.yml", "      - run: npm test", "      - run: npm test\n        if: github.event_name == 'push'").rule, "edit.ci-config");
});

test("a skip under a visible condition is allowed; an unconditional skip is denied", () => {
  const allowed = [
    ["pkg/foo_test.go", "func TestX(t *testing.T) {", "func TestX(t *testing.T) {\n\tif testing.Short() {\n\t\tt.Skip(\"short mode\")\n\t}"],
    ["pkg/foo_test.go", "func TestX(t *testing.T) {", "func TestX(t *testing.T) {\n\tif runtime.GOOS == \"windows\" { t.Skip(\"no symlinks\") }"],
    ["pkg/foo_test.go", "func TestX(t *testing.T) {", "func TestX(t *testing.T) {\n\tif os.Getenv(\"CI\") == \"\" {\n\t\tt.Skipf(\"needs CI: %s\", why)\n\t}"],
    ["e2e/login.spec.ts", "// x", "test.skip(({ browserName }) => browserName === 'webkit', 'no webkit');"],
    ["src/foo.test.ts", "// x", "test.skip(process.platform === 'win32', 'symlinks');"],
    ["e2e/x.spec.ts", "// x", "test.fixme(({ browserName }) => browserName === 'webkit', 'tracked in #123');"],
    ["src/foo.test.ts", "// x", "describe.skip(!hasDocker, 'needs docker');"],
    ["tests/test_foo.py", "pass", "    if shutil.which('docker') is None:\n        pytest.skip('docker not installed')"],
    ["tests/test_foo.py", "pass", "        if sys.platform == 'win32':\n            self.skipTest('no fork')"],
    ["spec/foo_spec.rb", "# x", "  skip 'needs redis' unless redis?"],
    ["spec/foo_spec.rb", "# x", "  pending 'flaky on CI' if ENV['CI']"],
  ] as const;
  for (const [path, before, after] of allowed) {
    const d = ed(path, before, after);
    assert.equal(d.verdict, "allow", `${path}: ${after} -> ${d.reason ?? ""}`);
  }
  const denied = [
    ["pkg/foo_test.go", "func TestX(t *testing.T) {", "func TestX(t *testing.T) {\n\tt.Skip(\"flaky\")", "t.Skip("],
    ["pkg/foo_test.go", "func TestX(t *testing.T) {", "func TestX(t *testing.T) {\n\tt.SkipNow()", "t.Skip("],
    ["e2e/x.spec.ts", "// x", "test.skip('login works', async () => {})", ".skip("],
    ["e2e/x.spec.ts", "// x", "test.skip(() => {})", ".skip("],
    ["e2e/x.spec.ts", "// x", "test.skip(async () => {})", ".skip("],
    ["e2e/x.spec.ts", "// x", "test.skip();", ".skip("],
    ["e2e/x.spec.ts", "test('login', async ({ page }) => {", "test.fixme('login', async ({ page }) => {", "test.fixme"],
    ["tests/test_foo.py", "pass", "    pytest.skip('flaky')", "pytest.skip("],
    ["tests/test_foo.py", "pass", "        self.skipTest('no network in CI')", "self.skipTest("],
    ["tests/test_foo.py", "def test_x():", "@pytest.mark.skip(reason='flaky')\ndef test_x():", "@pytest.mark.skip"],
    ["src/FooTest.kt", "@Test", "@Disabled(\"flaky\") @Test", "@Ignore / @Disabled"],
    ["src/lib_test.rs", "#[test]", "#[test]\n#[ignore]", "#[ignore]"],
    ["spec/foo_spec.rb", "# x", "  skip 'needs redis'", "rspec pending/skip"],
  ] as const;
  for (const [path, before, after, what] of denied) {
    const d = ed(path, before, after);
    assert.equal(d.verdict, "deny", `${path}: ${after}`);
    assert.equal(d.rule, "edit.test-skip");
    assert.ok(d.reason?.includes(what), `${d.reason} should name ${what}`);
  }
  // A skip that was already conditional and stays so is not an addition.
  assert.equal(ed("pkg/foo_test.go", "\tif testing.Short() {\n\t\tt.Skip(\"short\")\n\t}", "\tif testing.Short() {\n\t\tt.Skip(\"short mode\")\n\t}").verdict, "allow");
  assert.equal(countUnguarded(/\bt\.Skip\s*\(/g, "if x {\n\tt.Skip(\"a\")\n}\nt.Skip(\"b\")\n\nt.Skip(\"c\")"), 2);
});

test("whitespace-heavy content decides in bounded time", () => {
  const cases: [string, string][] = [
    ["tests/big.test.ts", "\n".repeat(200_000)],
    ["src/big.ts", "  \n".repeat(70_000)],
    ["setup.cfg", "\n".repeat(100_000)],
    ["Cargo.toml", "\n".repeat(100_000)],
    [".github/workflows/ci.yml", "\n".repeat(100_000)],
    ["package.json", `{"scripts":{"test":"echo ${" ".repeat(100_000)}x&"}}`],
    ["package.json", `{"scripts":{"test":"a || ${" ".repeat(100_000)}true x"}}`],
    ["src/big.py", "# ruff: noqa x\n".repeat(20_000)],
  ];
  for (const [path, content] of cases) {
    const { ms } = timed(() => wr(path, content));
    assert.ok(ms < 500, `Write of ${path} (${content.length} bytes) took ${Math.round(ms)} ms`);
    const edit = timed(() => ed(path, content, `${content}\n`));
    assert.ok(edit.ms < 500, `Edit of ${path} took ${Math.round(edit.ms)} ms`);
  }
});

test("naming the PEM header is not writing a private key", () => {
  assert.equal(ed("src/crypto.ts", "// x", "const PEM_HEADER = '-----BEGIN RSA PRIVATE KEY-----';\nconst PEM_FOOTER = '-----END RSA PRIVATE KEY-----';").verdict, "allow");
  assert.equal(ed("src/crypto.ts", "// x", "export function isPrivateKey(s: string) { return s.startsWith('-----BEGIN PRIVATE KEY-----'); }").verdict, "allow");
  assert.equal(wr("scripts/scan-secrets.sh", "#!/bin/sh\ngrep -rn -- '-----BEGIN PRIVATE KEY-----' . && exit 1\n").verdict, "allow");
  const real = wr("src/keys.ts", "export const KEY = `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7vKk3xHd2x0bbr5fUi1G8ZPxu2pV1qFm1aSKj3sBqiz9Sj1\n-----END RSA PRIVATE KEY-----`;\n");
  assert.equal(real.verdict, "deny");
  assert.equal(real.rule, "edit.secret-literal");
  assert.equal(wr("src/keys.ts", "const k = \"-----BEGIN PRIVATE KEY-----\\nMIIEowIBAAKCAQEAx7vKk3xHd2x0bbr5fUi1G8ZPxu2pV1qFm1aSKj3sBqiz9Sj1\\n-----END PRIVATE KEY-----\";").rule, "edit.secret-literal");
});

test("the .harness/ remediation names a command that exists", () => {
  const d = wr(".harness/phase.json", "{}");
  assert.equal(d.rule, "edit.harness-dir");
  assert.ok(d.remediation?.includes("ah bug add --rule <rule> --title"), d.remediation);
  assert.ok(!d.remediation?.includes("phase set"), d.remediation);
});
