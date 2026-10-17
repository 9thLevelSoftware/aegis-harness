/**
 * Content inspection shared by Edit/Write rules: lint suppressions, test
 * skips, coverage exclusions, weakened gates. Each detector reports how many
 * times a pattern occurs so that callers can flag only what an edit adds.
 *
 * Line-anchored patterns use `[ \t]*` rather than `\s*` next to `^` and `$`:
 * with the m flag, `^\s*` re-scans a whole run of blank lines from every line
 * start in it, which is quadratic in the length of the run (a 200 KB file of
 * newlines took over a minute). `[ \t]*` cannot cross a line boundary, so each
 * line is scanned once. `[ \t\r]*$` keeps CRLF content matching.
 */

export interface ContentPattern {
  id: string;
  re: RegExp;
  /**
   * Counts occurrences in a text. Defaults to counting `re` matches; the skip
   * detectors that honour a visible guarding condition override it.
   */
  countIn?: (text: string) => number;
}

export const BLANKET_SUPPRESSIONS: readonly ContentPattern[] = [
  { id: "eslint-disable (file-wide)", re: /\/\*\s*eslint-disable\s*\*\/|\/\/\s*eslint-disable[ \t\r]*$/gm },
  { id: "@ts-nocheck", re: /@ts-nocheck\b/g },
  { id: "biome-ignore-all", re: /biome-ignore-all\b/g },
  { id: "pylint disable=all", re: /#\s*pylint:\s*(disable=all|skip-file)/gi },
  { id: "mypy ignore-errors", re: /#\s*mypy:\s*ignore-errors/g },
  { id: "file-level noqa", re: /^[ \t]*#[ \t]*(ruff|flake8):[ \t]*noqa[ \t\r]*$/gim },
  { id: "crate-level allow", re: /#!\[allow\((clippy::all|warnings|unused)\)\]/g },
  { id: "allow(clippy::all)", re: /#\[allow\(clippy::all\)\]/g },
  { id: "SuppressWarnings(all)", re: /@SuppressWarnings\(\s*"all"\s*\)/g },
  { id: "pragma warning disable (all)", re: /#pragma\s+warning\s+disable[ \t\r]*$/gm },
  { id: "coverage off for file", re: /\/\*\s*(istanbul|c8|v8)\s+ignore\s+file\s*\*\//g },
];

export const UNTARGETED_SUPPRESSIONS: readonly ContentPattern[] = [
  { id: "eslint-disable-line without a rule", re: /\/\/\s*eslint-disable-(next-)?line[ \t\r]*$/gm },
  { id: "eslint-disable for a whole file (one rule)", re: /\/\*\s*eslint-disable\s+[\w@/-]+/g },
  { id: "@ts-ignore", re: /@ts-ignore\b/g },
  { id: "bare noqa", re: /#\s*noqa[ \t\r]*$/gm },
  { id: "bare type: ignore", re: /#\s*type:\s*ignore[ \t\r]*$/gm },
  { id: "biome-ignore for a whole category", re: /biome-ignore\s+lint\s*:/g },
  { id: "bare nosec", re: /#\s*nosec[ \t\r]*$/gm },
  { id: "bare nolint", re: /\/\/\s*nolint[ \t\r]*$/gm },
  { id: "pylint disable without a code", re: /#\s*pylint:\s*disable[ \t\r]*$/gim },
];

/**
 * A `.skip(` / `.fixme(` whose first argument is a string title, nothing, or
 * the test body itself (`() =>`, `async () =>`, `function`) skips a test
 * unconditionally. Any other first argument is a visible condition, the form
 * Playwright and vitest document for platform- or fixture-dependent skips
 * (`test.skip(({ browserName }) => browserName === 'webkit', 'reason')`).
 */
const UNCONDITIONAL_FIRST_ARG = String.raw`\s*(?:['"\x60]|\)|(?:async\s+)?(?:\(\s*\)|function\b))`;

/**
 * A skip call on a line that carries a guarding condition, or whose nearest
 * preceding non-blank line does, is a conditional skip: `if testing.Short() {
 * t.Skip(...) }`, `if shutil.which('docker') is None: pytest.skip(...)`,
 * `skip 'needs redis' unless redis?`.
 */
const GUARDING_CONDITION = /\b(?:if|elif|unless)\s|testing\.Short\(\)|runtime\.GOOS|sys\.platform|os\.environ|os\.getenv|shutil\.which|platform\.system|[=!]=\s/;

/** Counts matches of `re` on lines that are not guarded by a visible condition. */
export function countUnguarded(re: RegExp, text: string): number {
  if (!text) return 0;
  let n = 0;
  let previous = "";
  let start = 0;
  while (start <= text.length) {
    const nl = text.indexOf("\n", start);
    const end = nl === -1 ? text.length : nl;
    const line = text.slice(start, end);
    const hits = count(re, line);
    if (hits > 0 && !GUARDING_CONDITION.test(line) && !GUARDING_CONDITION.test(previous)) n += hits;
    if (line.trim() !== "") previous = line;
    if (nl === -1) break;
    start = nl + 1;
  }
  return n;
}

function guarded(id: string, re: RegExp): ContentPattern {
  return { id, re, countIn: (text) => countUnguarded(re, text) };
}

export const TEST_SKIPS: readonly ContentPattern[] = [
  { id: ".skip(", re: new RegExp(String.raw`\b(it|test|describe|suite|context|bench)\.skip\s*\(` + UNCONDITIONAL_FIRST_ARG, "g") },
  { id: "xit/xtest/xdescribe", re: /\bx(it|test|describe|context)\s*\(/g },
  { id: "test.fixme", re: new RegExp(String.raw`\btest\.fixme\s*\(` + UNCONDITIONAL_FIRST_ARG, "g") },
  { id: "@pytest.mark.skip", re: /@pytest\.mark\.skip\b(?!if)/g },
  guarded("pytest.skip(", /\bpytest\.skip\s*\(/g),
  { id: "@unittest.skip", re: /@unittest\.skip\b/g },
  guarded("self.skipTest(", /\bself\.skipTest\s*\(/g),
  { id: "#[ignore]", re: /#\[ignore(\s*=\s*"[^"]*")?\]/g },
  guarded("t.Skip(", /\bt\.Skip(Now|f)?\s*\(/g),
  { id: "@Ignore / @Disabled", re: /@(Ignore|Disabled)\b/g },
  guarded("rspec pending/skip", /^[ \t]*(pending|skip)[ \t]+["']/g),
];

export const TEST_FOCUS: readonly ContentPattern[] = [
  { id: ".only(", re: /\b(it|test|describe|suite|context)\.only\s*\(/g },
  // A bare call with a string title: `fit('name', ...)`. `model.fit(X, y)` and `fit(points)` are ordinary code.
  { id: "fit/fdescribe/ftest", re: /(?<![.\w$])f(it|describe|test)\s*\(\s*['"`]/g },
];

export const COVERAGE_EXCLUSIONS: readonly ContentPattern[] = [
  { id: "istanbul/c8/v8 ignore", re: /\b(istanbul|c8|v8)\s+ignore\s+(next|start|stop|else|if)\b/g },
  { id: "pragma: no cover", re: /#\s*pragma:\s*no\s*cover\b/g },
  { id: "LCOV_EXCL", re: /LCOV_EXCL_(LINE|START|STOP|BR_LINE)/g },
  { id: "coverage:ignore", re: /coverage:\s*ignore/gi },
  { id: "ExcludeFromCodeCoverage", re: /\[ExcludeFromCodeCoverage\]/g },
];

/** Manifest sections that configure linters or test runners. */
export const MANIFEST_LINT_SECTIONS: readonly ContentPattern[] = [
  // `[tool.pytest]` and `[tool.pytest.ini_options]`, not `[tool.pytest-asyncio]`.
  { id: "[tool.<linter>]", re: /\[tool\.(ruff|pytest|mypy|pylint|coverage|pyright|flake8|bandit|isort)(\]|\.)/gi },
  { id: "setup.cfg lint section", re: /^[ \t]*\[(flake8|mypy|pylint|tool:pytest|coverage:[a-z]+|isort)\]/gim },
  // The key must open a config object or array; `"jest": "^29.7.0"` is a dependency.
  { id: "package.json lint key", re: /"(eslintConfig|jest|lint-staged|husky|nyc|c8|mocha|ava|xo|standard)"\s*:\s*[[{]/g },
  { id: "Cargo lints", re: /^[ \t]*\[(workspace\.)?lints(\.[a-z]+)?\]/gim },
];

/** Scripts whose job is to fail when something is wrong. */
export const GATE_SCRIPT = /"((?:pre)?(?:test|lint|typecheck|type-check|check|verify|validate|ci)(?::[\w:-]*)?)"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
export const NOOP_SCRIPT = /^[ \t]*(echo\b[^&|;]*|exit[ \t]+0[ \t]*|true[ \t]*|:[ \t]*)$|\|\|[ \t]*(true|exit[ \t]+0)[ \t]*$/;

export const CI_WEAKENERS: readonly ContentPattern[] = [
  { id: "continue-on-error: true", re: /continue-on-error:\s*true/g },
  { id: "allow_failure: true", re: /allow_failure:\s*true/g },
  { id: "run step ending in || true", re: /^[ \t]*(-[ \t]*)?run:.*\|\|[ \t]*(true|exit[ \t]+0)[ \t\r]*$/gm },
  // A step or job that never runs cannot fail. `if: always()` is not here: it does not change whether the step's failure fails the job.
  { id: "if: false (step or job never runs)", re: /^[ \t]*(-[ \t]+)?if:[ \t]*['"]?(false|\$\{\{[ \t]*false[ \t]*\}\})['"]?(?:[ \t]+#.*)?[ \t\r]*$/gm },
];

export const COMPILER_LOOSENERS: readonly ContentPattern[] = [
  { id: "strict: false", re: /"strict"\s*:\s*false/g },
  { id: "noImplicitAny: false", re: /"noImplicitAny"\s*:\s*false/g },
  { id: "strictNullChecks: false", re: /"strictNullChecks"\s*:\s*false/g },
  { id: "noEmitOnError: false", re: /"noEmitOnError"\s*:\s*false/g },
  { id: "noUnusedLocals: false", re: /"noUnusedLocals"\s*:\s*false/g },
  { id: "useUnknownInCatchVariables: false", re: /"useUnknownInCatchVariables"\s*:\s*false/g },
];

export function count(re: RegExp, text: string): number {
  if (!text) return 0;
  re.lastIndex = 0;
  let n = 0;
  while (re.exec(text) !== null) {
    n++;
    if (re.lastIndex === 0) break;
  }
  return n;
}

/** How often a pattern occurs in a text, honouring the pattern's own counter when it has one. */
export function occurrences(p: ContentPattern, text: string): number {
  return p.countIn ? p.countIn(text) : count(p.re, text);
}

/** Patterns that occur more often in `after` than in `before`. */
export function added(patterns: readonly ContentPattern[], before: string, after: string): ContentPattern[] {
  const out: ContentPattern[] = [];
  for (const p of patterns) {
    if (occurrences(p, after) > occurrences(p, before)) out.push(p);
  }
  return out;
}

/**
 * Drops comment-only lines: `# ...`, `// ...`, `/* ... *\/` blocks and the
 * `* ...` continuation lines inside them. A comment cannot skip a test or
 * configure a linter, so the skip, focus and manifest-section detectors read
 * the text without them. Rust attributes (`#[ignore]`, `#![allow]`) are kept.
 * Suppression pragmas live in comments by nature and are counted on the raw text.
 */
export function stripComments(text: string): string {
  if (!text || !/[#/*]/.test(text)) return text;
  const out: string[] = [];
  let inBlock = false;
  let start = 0;
  while (start <= text.length) {
    const nl = text.indexOf("\n", start);
    const end = nl === -1 ? text.length : nl;
    const line = text.slice(start, end);
    const t = line.trimStart();
    let drop = false;
    if (inBlock) {
      drop = true;
      if (t.includes("*/")) inBlock = false;
    } else if (t.startsWith("//") || t.startsWith("*")) {
      drop = true;
    } else if (t.startsWith("/*")) {
      drop = true;
      if (!t.includes("*/", 2)) inBlock = true;
    } else if (t.startsWith("#") && !t.startsWith("#[") && !t.startsWith("#!")) {
      drop = true;
    }
    out.push(drop ? "" : line);
    if (nl === -1) break;
    start = nl + 1;
  }
  return out.join("\n");
}

export interface GateScript {
  name: string;
  value: string;
}

export function gateScripts(text: string): GateScript[] {
  const out: GateScript[] = [];
  GATE_SCRIPT.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = GATE_SCRIPT.exec(text)) !== null) out.push({ name: m[1], value: m[2] });
  return out;
}
