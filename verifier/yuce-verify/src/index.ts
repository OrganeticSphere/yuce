// yuce-verify: independent verifier of YuCe journals (sbgk-session-log/3),
// delivery 1, levels J0 and J1. Built from the specification text only.
//
// This module is the single delivery file `yuce-verify.mjs`. Under Node.js,
// run as a script, it is the command line; imported (Node.js or a browser),
// it exports the verifier. It has no runtime dependencies.

export { runCli, USAGE } from "./cli.ts";
export type { CliIo } from "./cli.ts";
export { defaultHashAdapter, nodeHashAdapter, subtleHashAdapter, toHex, fromHex, utf8 } from "./hash.ts";
export type { HashAdapter, Sha256Stream } from "./hash.ts";
export { depthExceeds, fromPlain, hasExactKeys, isHashText, isObject, jcs, jcsString, parseJson } from "./json.ts";
export type { JsonObject, JsonValue, ParseResult } from "./json.ts";
export { EXIT, NOT_VERIFIED, SPEC_ID, VERIFIER_VERSION, computeVerdict, exitCodeFor, humanLine, reportToJcs } from "./report.ts";
export type { Anchor, Failure, HeadAnchor, Report, SealAnchor, SealEntry, Tail } from "./report.ts";
export { DOMAIN, LogTree, domainHash, logRootRecursive, recordLeaf, recordsRoot } from "./trees.ts";
export { checkVectors } from "./vectors.ts";
export type { VectorOutcome } from "./vectors.ts";
export {
  DEFAULT_MAX_DEPTH,
  DEFAULT_MAX_LINE_BYTES,
  JOURNAL_FORMAT,
  ReadError,
  SEAL_FORMAT_ID,
  ZERO_HASH,
  verifyJournal,
} from "./verify.ts";
export type { ByteSource, VerifyOptions } from "./verify.ts";

import { runCli } from "./cli.ts";
import { nodeHashAdapter } from "./hash.ts";
import { ReadError } from "./verify.ts";

interface NodeProcess {
  argv: string[];
  versions: { node?: string };
  stdout: { write(s: string): boolean };
  stderr: { write(s: string): boolean };
  exitCode?: number;
}

/** Runs the command line with node:fs and node:crypto. */
export async function nodeMain(proc: NodeProcess): Promise<number> {
  const fs = await import("node:fs");
  const adapter = await nodeHashAdapter();
  const code = await runCli(
    proc.argv.slice(2),
    {
      stdout: (t) => void proc.stdout.write(t),
      stderr: (t) => void proc.stderr.write(t),
      readFile: async (path) => fs.promises.readFile(path),
      openJournal: async (path) => {
        const st = await fs.promises.stat(path);
        if (!st.isFile()) throw new ReadError("not a regular file");
        return fs.createReadStream(path, { highWaterMark: 1 << 16 });
      },
    },
    adapter,
  );
  proc.exitCode = code;
  return code;
}

// Run as a script under Node.js: this file is the entry point.
const proc = (globalThis as { process?: NodeProcess }).process;
if (proc?.versions?.node !== undefined && proc.argv[1] !== undefined) {
  const { pathToFileURL } = await import("node:url");
  const { realpathSync } = await import("node:fs");
  let entry: string | undefined;
  try {
    entry = pathToFileURL(realpathSync(proc.argv[1])).href;
  } catch {
    entry = undefined;
  }
  if (entry === import.meta.url) await nodeMain(proc);
}
