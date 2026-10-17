// Bundle three entry points with esbuild. The guard bundle has no runtime
// dependencies and is the file agents execute on every tool call, so keep it
// small and dependency-free: a hook that takes 300 ms is a hook people remove.
import { build } from "esbuild";
import { chmodSync, readFileSync, rmSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
rmSync("dist", { recursive: true, force: true });

const common = {
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  sourcemap: false,
  minify: false,
  legalComments: "none",
  define: { __AH_VERSION__: JSON.stringify(pkg.version) },
  logLevel: "warning",
};

await build({ ...common, entryPoints: ["src/guard/entry.ts"], outfile: "dist/guard.mjs", banner: { js: "#!/usr/bin/env node" } });
await build({ ...common, entryPoints: ["src/cli/entry.ts"], outfile: "dist/ah.mjs", banner: { js: "#!/usr/bin/env node" } });
await build({ ...common, entryPoints: ["src/index.ts"], outfile: "dist/index.mjs" });

for (const f of ["dist/guard.mjs", "dist/ah.mjs"]) chmodSync(f, 0o755);
const size = (f) => `${(readFileSync(f).length / 1024).toFixed(1)} KiB`;
// Progress goes to stderr: `prepack` runs this build, and `npm pack --silent > pack.txt`
// (the CI smoke test) must receive only the tarball name on stdout.
console.error(`built dist/guard.mjs (${size("dist/guard.mjs")}), dist/ah.mjs (${size("dist/ah.mjs")}), dist/index.mjs (${size("dist/index.mjs")})`);
