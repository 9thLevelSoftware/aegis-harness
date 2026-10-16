/**
 * Content inspection shared by Edit/Write rules: lint suppressions, test
 * skips, coverage exclusions, weakened gates. Each detector reports how many
 * times a pattern occurs so that callers can flag only what an edit adds.
 */

export interface ContentPattern {
  id: string;
  re: RegExp;
}

export const BLANKET_SUPPRESSIONS: readonly ContentPattern[] = [
  { id: "eslint-disable (file-wide)", re: /\/\*\s*eslint-disable\s*\*\/|\/\/\s*eslint-disable\s*$/gm },
  { id: "@ts-nocheck", re: /@ts-nocheck\b/g },
  { id: "biome-ignore-all", re: /biome-ignore-all\b/g },
  { id: "pylint disable=all", re: /#\s*pylint:\s*(disable=all|skip-file)/gi },
  { id: "mypy ignore-errors", re: /#\s*mypy:\s*ignore-errors/g },
  { id: "file-level noqa", re: /^\s*#\s*(ruff|flake8):\s*noqa\s*$/gim },
  { id: "crate-level allow", re: /#!\[allow\((clippy::all|warnings|unused)\)\]/g },
  { id: "allow(clippy::all)", re: /#\[allow\(clippy::all\)\]/g },
  { id: "SuppressWarnings(all)", re: /@SuppressWarnings\(\s*"all"\s*\)/g },
  { id: "pragma warning disable (all)", re: /#pragma\s+warning\s+disable\s*$/gm },
  { id: "coverage off for file", re: /\/\*\s*(istanbul|c8|v8)\s+ignore\s+file\s*\*\//g },
];

export const UNTARGETED_SUPPRESSIONS: readonly ContentPattern[] = [
  { id: "eslint-disable-line without a rule", re: /\/\/\s*eslint-disable-(next-)?line\s*$/gm },
  { id: "eslint-disable for a whole file (one rule)", re: /\/\*\s*eslint-disable\s+[\w@/-]+/g },
  { id: "@ts-ignore", re: /@ts-ignore\b/g },
  { id: "bare noqa", re: /#\s*noqa\s*$/gm },
  { id: "bare type: ignore", re: /#\s*type:\s*ignore\s*$/gm },
  { id: "biome-ignore for a whole category", re: /biome-ignore\s+lint\s*:/g },
  { id: "bare nosec", re: /#\s*nosec\s*$/gm },
  { id: "bare nolint", re: /\/\/\s*nolint\s*$/gm },
  { id: "pylint disable without a code", re: /#\s*pylint:\s*disable\s*$/gim },
];

export const TEST_SKIPS: readonly ContentPattern[] = [
  { id: ".skip(", re: /\b(it|test|describe|suite|context|bench)\.skip\s*\(/g },
  { id: "xit/xtest/xdescribe", re: /\bx(it|test|describe|context)\s*\(/g },
  { id: "test.fixme", re: /\btest\.fixme\s*\(/g },
  { id: "@pytest.mark.skip", re: /@pytest\.mark\.skip\b(?!if)/g },
  { id: "pytest.skip(", re: /\bpytest\.skip\s*\(/g },
  { id: "@unittest.skip", re: /@unittest\.skip\b/g },
  { id: "self.skipTest(", re: /\bself\.skipTest\s*\(/g },
  { id: "#[ignore]", re: /#\[ignore(\s*=\s*"[^"]*")?\]/g },
  { id: "t.Skip(", re: /\bt\.Skip(Now)?\s*\(/g },
  { id: "@Ignore / @Disabled", re: /@(Ignore|Disabled)\b/g },
  { id: "rspec pending/skip", re: /^\s*(pending|skip)\s+["']/gm },
];

export const TEST_FOCUS: readonly ContentPattern[] = [
  { id: ".only(", re: /\b(it|test|describe|suite|context)\.only\s*\(/g },
  { id: "fit/fdescribe/ftest", re: /\bf(it|describe|test)\s*\(/g },
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
  { id: "[tool.<linter>]", re: /\[tool\.(ruff|pytest|mypy|pylint|coverage|pyright|flake8|bandit|isort)\b/gi },
  { id: "setup.cfg lint section", re: /^\s*\[(flake8|mypy|pylint|tool:pytest|coverage:[a-z]+|isort)\]/gim },
  { id: "package.json lint key", re: /"(eslintConfig|jest|lint-staged|husky|nyc|c8|mocha|ava|xo|standard)"\s*:/g },
  { id: "Cargo lints", re: /^\s*\[(workspace\.)?lints(\.[a-z]+)?\]/gim },
];

/** Scripts whose job is to fail when something is wrong. */
export const GATE_SCRIPT = /"((?:pre)?(?:test|lint|typecheck|type-check|check|verify|validate|ci)(?::[\w:-]*)?)"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
export const NOOP_SCRIPT = /^\s*(echo\b[^&|;]*|exit\s+0|true|:)\s*$|\|\|\s*(true|exit\s+0)\s*$/;

export const CI_WEAKENERS: readonly ContentPattern[] = [
  { id: "continue-on-error: true", re: /continue-on-error:\s*true/g },
  { id: "allow_failure: true", re: /allow_failure:\s*true/g },
  { id: "run step ending in || true", re: /^\s*(-\s*)?run:.*\|\|\s*(true|exit\s+0)\s*$/gm },
  { id: "if: always() on a gate", re: /^\s*if:\s*always\(\)/gm },
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

/** Patterns that occur more often in `after` than in `before`. */
export function added(patterns: readonly ContentPattern[], before: string, after: string): ContentPattern[] {
  const out: ContentPattern[] = [];
  for (const p of patterns) {
    if (count(p.re, after) > count(p.re, before)) out.push(p);
  }
  return out;
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
