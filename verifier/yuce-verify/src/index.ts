// yuce-verify: independent verifier of YuCe journals (sbgk-session-log/3),
// delivery 3: levels J0-J3 and J4a, the cut check, the observation report.
// Built from the specification text only.
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
export { EXIT, NOT_VERIFIED, NOT_VERIFIED_AFTER_J3, SPEC_ID, VERIFIER_VERSION, exitCodeFor, humanLine, reportToJcs } from "./report.ts";
export type { Anchor, Failure, HeadAnchor, J2Level, J3Level, Report, SealAnchor, SealEntry, Tail } from "./report.ts";
export { CDC_MAX_CHUNK, CDC_WINDOW, anchorBytes, chunksOf, cutPoints, documentChunks, gearHex, occurrences, segmentsOf } from "./cdc.ts";
export type { Chunk, DocumentChunks, Segment } from "./cdc.ts";
export {
  EMPTY_RECORDS_ROOT,
  GENESIS_FORMATS,
  J2Checker,
  RULES_VERSIONS,
  RULES_VERSION_4,
  commandKind,
  gitDocumentId,
  isIdentifier,
  isSubmitResult,
  requestHash,
} from "./j2.ts";
export { LINE_KEYS, LINE_REQUIRED, MAX_QUOTE_BYTES, QUESTION_KEYS_RULES_4, RecordEngine, lineFormProblem, uniqueByPrefix } from "./j3.ts";
export type { AcceptedRecord, DocumentFiles, RewriteOptions } from "./j3.ts";
export { DOMAIN, LogTree, domainHash, logRootRecursive, recordLeaf, recordsRoot } from "./trees.ts";
export { Cascade, EMPTY_PROJECTIONS, LINK_DOMAIN, PROJECTION_DOMAIN, linkId, projectionHashes } from "./j4a.ts";
export type { CascadeRecord, CascadeStatus, DependencyPair, Link, Observation, RevocationReason, StatusRow } from "./j4a.ts";
export { QUITTANCE_FORMAT, checkQuittance, parseQuittance } from "./quittance.ts";
export { PROJECTION_KEYS, SEAL_HASH_FIELDS, SEAL_KEYS, sealFormProblem } from "./seal.ts";
export type { ParsedQuittance, QuittanceFailure } from "./quittance.ts";
export {
  CUT_DOMAIN,
  CUT_FORMAT,
  CUT_NOT_VERIFIED,
  CUT_REPORT_FORMAT,
  EXPORT_FORMAT,
  checkManifest,
  parseManifest,
  cutHash,
  cutHumanLine,
  exportEscape,
  exportParagraph,
  exportParagraphs,
  exportText,
  verifyCut,
} from "./cut.ts";
export type { CutBundle, CutFailure, CutJournalState, CutReport, CutResult, DeliveredExport, Manifest } from "./cut.ts";
export {
  OBS_REPORT_DOMAIN,
  OBS_REPORT_FORMAT,
  checkReport,
  firstDifference,
  observationReport,
  observationReportForCut,
  observationReportForJournal,
  partThroughSeal,
  reportHash,
} from "./obs.ts";
export type { ObsDelivery, ObsInput, ObsJournal, ObsOutcome, ReportCheck } from "./obs.ts";
export { checkVectors } from "./vectors.ts";
export type { VectorOutcome } from "./vectors.ts";
export {
  DEFAULT_MAX_DEPTH,
  DEFAULT_MAX_LINE_BYTES,
  JOURNAL_FORMAT,
  ReadError,
  SEAL_FORMAT_ID,
  ZERO_HASH,
  indexDocuments,
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
      readDocs: async (path) => {
        const st = await fs.promises.stat(path);
        if (!st.isDirectory()) throw new ReadError("not a folder");
        const out: Uint8Array[] = [];
        const walk = async (dir: string): Promise<void> => {
          const entries = await fs.promises.readdir(dir, { withFileTypes: true });
          entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
          for (const e of entries) {
            const full = dir + "/" + e.name;
            if (e.isDirectory()) await walk(full);
            else if (e.isFile()) out.push(await fs.promises.readFile(full)); // regular files only (P3-2)
          }
        };
        await walk(path);
        return out;
      },
      writeFile: async (path, text) => fs.promises.writeFile(path, text),
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
