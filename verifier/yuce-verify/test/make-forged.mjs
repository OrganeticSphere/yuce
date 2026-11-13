#!/usr/bin/env node
// Writes the forged journals of acceptance A6 into test/fixtures/forged/.
// Each one changes a single value of a real journal and recomputes every hash,
// the seals included (test/forge.mjs). Run: node test/make-forged.mjs
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { forge, parseLine } from "./forge.mjs";

export const FORGED = [
  {
    file: "forged-quote.wal",
    from: "inputs/valid/withdrawal-version-close.wal",
    frame: 1,
    path: "body.command.lines.0.exact_quote",
    value: '"Title: Tai chi for knee pain."',
  },
  {
    file: "forged-revoke.wal",
    from: "inputs/valid/live-server-unsealed-tail.wal",
    frame: 8,
    path: "body.command.record",
    value: `"${"ab".repeat(32)}"`,
  },
  {
    file: "forged-checkpoint.wal",
    from: "inputs/valid/gap-second-exhausted.wal",
    frame: 2,
    path: "body.actor",
    value: '"w2"',
  },
];

const room = (p) => fileURLToPath(new URL(`../../${p}`, import.meta.url));
const out = (p) => fileURLToPath(new URL(`./fixtures/forged/${p}`, import.meta.url));

export async function makeForged(spec) {
  return forge(readFileSync(room(spec.from), "utf8"), spec.frame, spec.path, parseLine(spec.value));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  mkdirSync(out(""), { recursive: true });
  for (const spec of FORGED) {
    writeFileSync(out(spec.file), await makeForged(spec));
    console.log(`wrote test/fixtures/forged/${spec.file}`);
  }
}
