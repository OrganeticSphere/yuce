// Bundles src/ into the single delivery file dist/yuce-verify.mjs (task statement, section 5).
// esbuild is a development tool only; the output has no runtime dependencies.
import { build } from "esbuild";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const pkg = JSON.parse(readFileSync(here("../package.json"), "utf8"));

await build({
  entryPoints: [here("../src/index.ts")],
  outfile: here("../dist/yuce-verify.mjs"),
  bundle: true,
  format: "esm",
  platform: "neutral",
  target: "es2022",
  external: ["node:*"],
  legalComments: "none",
  banner: {
    js: [
      "#!/usr/bin/env node",
      `// yuce-verify ${pkg.version}: independent verifier of YuCe journals, delivery 1 (levels J0, J1).`,
      "// Built from src/ by scripts/build.mjs. No runtime dependencies.",
    ].join("\n"),
  },
  logLevel: "warning",
});
console.log("built dist/yuce-verify.mjs");
