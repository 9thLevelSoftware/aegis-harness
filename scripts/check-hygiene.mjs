// Fail when a tracked file carries a maintainer's machine into the repository:
// home directories, user names, scratch mounts, drive letters from one laptop.
// Prior attempts in this family shipped `C:/Users/<name>` paths in docs and
// tests; a public tool cannot. Add patterns here, never exceptions in files.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const PATTERNS = [
  { re: /dasbl/i, why: "maintainer user name" },
  { re: /\/home\/claude\b/, why: "cloud session home" },
  { re: /\/mnt\/project-files/, why: "cloud session mount" },
  { re: /claude-0\//, why: "cloud session scratchpad" },
  { re: /\bD:[\\/](?!$)/, why: "maintainer drive letter" },
  { re: /C:[\\/]+Users[\\/]+(?![\\/])(?!dev\b|[^\\/"' ]+[\\/]+AppData|\$)/i, why: "a real Windows user profile (fixtures use C:\\Users\\dev)" },
  // Case-insensitive: macOS homes are usually capitalised (`/Users/John`), and `dev`,
  // `user` and `runner` stay allowed in any case.
  { re: /\/Users\/(?!dev\b)[a-z][a-z0-9_.-]*[\\/]/i, why: "a real macOS home directory (fixtures use /Users/dev)" },
  { re: /\/home\/(?!dev\b|user\b|runner\b|[^\\/"' ]+\/\.(?:ssh|aws|npmrc|netrc|bashrc)\b)[a-z][a-z0-9_.-]*[\\/]/i, why: "a real Linux home directory (fixtures use /home/dev)" },
];

const SKIP = /^(node_modules|dist)\//;
const BINARY = /\.(png|jpg|jpeg|gif|ico|woff2?|ttf|zip|gz|pdf)$/i;

let files;
try {
  files = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { encoding: "utf8" }).split("\0").filter(Boolean);
} catch {
  console.error("check-hygiene: not a git checkout; nothing scanned");
  process.exit(2);
}

let bad = 0;
for (const f of files) {
  if (SKIP.test(f) || BINARY.test(f) || f === "scripts/check-hygiene.mjs") continue;
  let text;
  try {
    text = readFileSync(f, "utf8");
  } catch {
    continue;
  }
  const lines = text.split("\n");
  lines.forEach((line, i) => {
    for (const p of PATTERNS) {
      if (p.re.test(line)) {
        bad++;
        console.log(`${f}:${i + 1}: ${p.why}: ${line.trim().slice(0, 120)}`);
      }
    }
  });
}
if (bad > 0) {
  console.log(`\ncheck-hygiene: ${bad} line(s) carry a maintainer's environment. Replace them with neutral values.`);
  process.exit(1);
}
console.log(`check-hygiene: ${files.length} files clean`);
