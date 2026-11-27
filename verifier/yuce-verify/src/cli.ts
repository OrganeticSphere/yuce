// Command line (the task statement v5, section 2):
//   yuce-verify journal <file> [--docs <folder>] [--expect-seal <hex>] [--expect-head <hex>]
//                              [--quittance <file>]... [--dump-projections <file>]
//                              [--max-line-bytes <n>] [--max-depth <n>] [--json] [--quiet]
//   yuce-verify cut <folder> [--json] [--quiet]
//   yuce-verify report <journal> --seal-frame <n> [--docs <folder>] [--check <report>] [--json] [--quiet]
//   yuce-verify report <cut folder> [--check <report>] [--json] [--quiet]
//   yuce-verify vectors <file.json> [--json] [--quiet]

import type { CutBundle } from "./cut.ts";
import { checkManifest, cutHumanLine, parseManifest, verifyCut } from "./cut.ts";
import type { HashAdapter } from "./hash.ts";
import { fromPlain, jcs, parseJson } from "./json.ts";
import type { Plain } from "./json.ts";
import type { ObsOutcome } from "./obs.ts";
import { checkReport, observationReportForCut, observationReportForJournal } from "./obs.ts";
import { EXIT, exitCodeFor, humanLine, reportToJcs } from "./report.ts";
import { checkVectors } from "./vectors.ts";
import type { ByteSource, ProjectionPoint } from "./verify.ts";
import { ReadError, verifyJournal } from "./verify.ts";

export interface CliIo {
  stdout(text: string): void;
  stderr(text: string): void;
  /** Whole file (the vectors file, a quittance, a cut's files, a report). */
  readFile(path: string): Promise<Uint8Array>;
  /** Streaming read of a journal. May throw; errors become exit code 2. */
  openJournal(path: string): Promise<ByteSource>;
  /** Every regular file of a folder and its subfolders (`--docs`). May throw; errors become exit code 2. */
  readDocs(path: string): Promise<Uint8Array[]>;
  /** Writes a file (`--dump-projections`). May throw; errors become exit code 2. */
  writeFile?(path: string, text: string): Promise<void>;
}

export const USAGE = [
  "usage:",
  "  yuce-verify journal <file> [--docs <folder>] [--expect-seal <hex>] [--expect-head <hex>]",
  "                             [--quittance <file>]... [--dump-projections <file>]",
  "                             [--max-line-bytes <n>] [--max-depth <n>] [--json] [--quiet]",
  "  yuce-verify cut <folder> [--json] [--quiet]",
  "  yuce-verify report <journal> --seal-frame <n> [--docs <folder>] [--check <report>] [--json] [--quiet]",
  "  yuce-verify report <cut folder> [--check <report>] [--json] [--quiet]",
  "  yuce-verify vectors <file.json> [--json] [--quiet]",
].join("\n");

class UsageError extends Error {}

type Command = "journal" | "vectors" | "cut" | "report";

interface ParsedArgs {
  command: Command;
  file: string;
  docs?: string;
  expectSeal?: string;
  expectHead?: string;
  maxLineBytes?: number;
  maxDepth?: number;
  quittances: string[];
  dumpProjections?: string;
  sealFrame?: number;
  check?: string;
  json: boolean;
  quiet: boolean;
}

/** The options that take a value, per command; `--quittance` may be repeated. */
const VALUE_FLAGS: Record<Command, ReadonlySet<string>> = {
  journal: new Set(["--docs", "--expect-seal", "--expect-head", "--max-line-bytes", "--max-depth", "--quittance", "--dump-projections"]),
  vectors: new Set(),
  cut: new Set(),
  report: new Set(["--docs", "--seal-frame", "--check"]),
};
const REPEATABLE = new Set(["--quittance"]);

function parseArgs(argv: readonly string[]): ParsedArgs {
  const [command, ...rest] = argv;
  if (command !== "journal" && command !== "vectors" && command !== "cut" && command !== "report") {
    throw new UsageError(command === undefined ? "missing command" : `unknown command ${JSON.stringify(command)}`);
  }
  const values = new Map<string, string[]>();
  const switches = new Set<string>();
  const positional: string[] = [];
  for (let k = 0; k < rest.length; k++) {
    const arg = rest[k]!;
    if (arg === "--") {
      positional.push(...rest.slice(k + 1));
      break;
    }
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const eqAt = arg.indexOf("=");
    const name = eqAt < 0 ? arg : arg.slice(0, eqAt);
    if (VALUE_FLAGS[command].has(name)) {
      let value: string | undefined;
      if (eqAt >= 0) value = arg.slice(eqAt + 1);
      else value = rest[++k];
      if (value === undefined) throw new UsageError(`${name} needs a value`);
      const list = values.get(name) ?? [];
      if (list.length > 0 && !REPEATABLE.has(name)) throw new UsageError(`${name} given twice`);
      list.push(value);
      values.set(name, list);
    } else if ((name === "--json" || name === "--quiet") && eqAt < 0) {
      switches.add(name);
    } else throw new UsageError(`unknown option ${JSON.stringify(arg)}`);
  }
  if (positional.length !== 1) throw new UsageError(`expected exactly one ${command === "cut" ? "folder" : "file"}, got ${positional.length}`);

  const one = (name: string): string | undefined => values.get(name)?.[0];
  const parsed: ParsedArgs = { command, file: positional[0]!, quittances: values.get("--quittance") ?? [], json: switches.has("--json"), quiet: switches.has("--quiet") };
  const docs = one("--docs");
  if (docs !== undefined) {
    if (docs === "") throw new UsageError("--docs needs a folder");
    parsed.docs = docs;
  }
  const seal = one("--expect-seal");
  if (seal !== undefined) parsed.expectSeal = hashArg("--expect-seal", seal);
  const head = one("--expect-head");
  if (head !== undefined) parsed.expectHead = hashArg("--expect-head", head);
  const mlb = one("--max-line-bytes");
  if (mlb !== undefined) parsed.maxLineBytes = positiveInt("--max-line-bytes", mlb);
  const md = one("--max-depth");
  if (md !== undefined) parsed.maxDepth = positiveInt("--max-depth", md);
  for (const q of parsed.quittances) if (q === "") throw new UsageError("--quittance needs a file");
  const dump = one("--dump-projections");
  if (dump !== undefined) {
    if (dump === "") throw new UsageError("--dump-projections needs a file");
    parsed.dumpProjections = dump;
  }
  const sf = one("--seal-frame");
  if (sf !== undefined) parsed.sealFrame = positiveInt("--seal-frame", sf);
  const check = one("--check");
  if (check !== undefined) {
    if (check === "") throw new UsageError("--check needs a file");
    parsed.check = check;
  }
  return parsed;
}

/** SPEC section 3: lowercased, then it must be [0-9a-f]{64}. */
function hashArg(name: string, value: string): string {
  const v = value.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new UsageError(`${name} must be 64 hex characters`);
  return v;
}

function positiveInt(name: string, value: string): number {
  if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value))) {
    throw new UsageError(`${name} must be a positive integer`);
  }
  return Number(value);
}

/** A failure to read the input: exit code 2. */
class InputError extends Error {}

/** Runs one command and returns the exit code. */
export async function runCli(argv: readonly string[], io: CliIo, adapter: HashAdapter): Promise<number> {
  const quiet = argv.includes("--quiet");
  const say = (text: string): void => {
    if (!quiet) io.stdout(text + "\n");
  };
  const complain = (text: string): void => {
    if (!quiet) io.stderr(`yuce-verify: ${text}\n`);
  };

  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help")) {
    io.stdout(USAGE + "\n");
    return EXIT.pass;
  }

  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    complain(`${e.message}\n${USAGE}`);
    return EXIT.usage;
  }

  try {
    if (args.command === "vectors") return await runVectors(args, io, adapter, say, complain);
    if (args.command === "cut") return await runCut(args, io, adapter, say);
    if (args.command === "report") return await runReport(args, io, adapter, say, complain, quiet);
    return await runJournal(args, io, adapter, say);
  } catch (e) {
    if (e instanceof InputError) {
      complain(e.message);
      return EXIT.usage;
    }
    throw e;
  }
}

const read = async (io: CliIo, path: string, what = path): Promise<Uint8Array> => {
  try {
    return await io.readFile(path);
  } catch (e) {
    throw new InputError(`cannot read ${what}: ${(e as Error).message}`);
  }
};

const readDocs = async (io: CliIo, path: string): Promise<Uint8Array[]> => {
  try {
    return await io.readDocs(path);
  } catch (e) {
    throw new InputError(`cannot read the documents folder ${path}: ${(e as Error).message}`);
  }
};

async function runJournal(args: ParsedArgs, io: CliIo, adapter: HashAdapter, say: (t: string) => void): Promise<number> {
  const documents = args.docs === undefined ? undefined : await readDocs(io, args.docs);
  const quittances: { file: string; bytes: Uint8Array }[] = [];
  for (const q of args.quittances) quittances.push({ file: q, bytes: await read(io, q) });
  const points: ProjectionPoint[] = [];
  let report;
  try {
    const source = await io.openJournal(args.file);
    report = await verifyJournal(
      source,
      {
        expectSeal: args.expectSeal,
        expectHead: args.expectHead,
        maxLineBytes: args.maxLineBytes,
        maxDepth: args.maxDepth,
        documents,
        quittances,
        onProjections: args.dumpProjections === undefined ? undefined : (p) => void points.push(p),
      },
      adapter,
    );
  } catch (e) {
    if (e instanceof ReadError || isNodeFsError(e)) throw new InputError(`cannot read ${args.file}: ${(e as Error).message}`);
    throw e;
  }
  if (args.dumpProjections !== undefined) {
    // Amendment 6, P6-1: the rows and pairs of every seal, in the form of the vectors' rows files.
    const dump = {
      journal: args.file.split(/[\\/]/).pop() ?? args.file,
      mismatches: points.filter((p) => !p.equals_seal).length,
      pair_form: "[record, ground]",
      points: points as unknown as Plain,
      row_form: "[id, kind, grounded, established, fallen_by]",
      seals: points.length,
    };
    if (io.writeFile === undefined) throw new InputError("--dump-projections: this environment cannot write files");
    try {
      await io.writeFile(args.dumpProjections, jcs(fromPlain(dump)) + "\n");
    } catch (e) {
      throw new InputError(`cannot write ${args.dumpProjections}: ${(e as Error).message}`);
    }
  }
  say(args.json ? reportToJcs(report) : humanLine(report));
  return exitCodeFor(report.verdict);
}

/** The files of a cut in the layout of the vectors: cut.json, <journal>/run.wal, <journal>/docs/, <export>.txt. */
async function readCut(io: CliIo, folder: string): Promise<CutBundle> {
  const manifest = await read(io, `${folder}/cut.json`);
  const journals = new Map<string, { journal: Uint8Array; documents: Uint8Array[] }>();
  const exports = new Map<string, Uint8Array>();
  // Files are read only for a manifest that passes B0: its names are [A-Za-z0-9._-]{1,64}, never "." or "..".
  const parsed = parseManifest(manifest);
  const m = parsed !== null && !parsed.badNumber && !parsed.duplicateKey ? checkManifest(parsed.value) : null;
  if (m === null) return { manifest, journals, exports };
  for (const j of m.journals) {
    const journal = await read(io, `${folder}/${j.name}/run.wal`);
    let documents: Uint8Array[] = [];
    try {
      documents = await io.readDocs(`${folder}/${j.name}/docs`);
    } catch {
      documents = [];
    }
    journals.set(j.name, { journal, documents });
  }
  for (const e of m.exports) exports.set(e.name, await read(io, `${folder}/${e.name}.txt`));
  return { manifest, journals, exports };
}

async function runCut(args: ParsedArgs, io: CliIo, adapter: HashAdapter, say: (t: string) => void): Promise<number> {
  const bundle = await readCut(io, args.file);
  const { report } = await verifyCut(bundle, adapter);
  say(args.json ? jcs(fromPlain(report as unknown as Plain)) : cutHumanLine(report));
  return report.verdict === "PASS" ? EXIT.pass : EXIT.fail;
}

async function runReport(
  args: ParsedArgs,
  io: CliIo,
  adapter: HashAdapter,
  say: (t: string) => void,
  complain: (t: string) => void,
  quiet: boolean,
): Promise<number> {
  let out: ObsOutcome;
  if (args.sealFrame !== undefined) {
    const documents = args.docs === undefined ? [] : await readDocs(io, args.docs);
    out = await observationReportForJournal(await read(io, args.file), documents, args.sealFrame, adapter);
  } else {
    if (args.docs !== undefined) throw new InputError("--docs is for a journal (with --seal-frame); a cut has its documents in <journal>/docs");
    out = await observationReportForCut(await readCut(io, args.file), adapter);
  }
  const given = args.check === undefined ? null : await read(io, args.check);
  if (!out.ok) {
    complain(`cannot compute the report: ${out.reason}`);
    return EXIT.fail;
  }
  if (given === null) {
    // Section 7: the canonical bytes, without a trailing newline.
    if (!quiet) io.stdout(out.text);
    return EXIT.pass;
  }
  const check = await checkReport(given, out.value, adapter);
  if (args.json) say(jcs(fromPlain(check as unknown as Plain)));
  else if (check.verdict === "PASS") say("Report PASS: the given report equals the report recomputed from the journals.");
  else say(`Report FAIL: ${check.code}${check.path === null ? "" : ` at ${check.path}`}.`);
  return check.verdict === "PASS" ? EXIT.pass : EXIT.fail;
}

async function runVectors(
  args: ParsedArgs,
  io: CliIo,
  adapter: HashAdapter,
  say: (t: string) => void,
  complain: (t: string) => void,
): Promise<number> {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(await io.readFile(args.file));
  } catch (e) {
    complain(`cannot read ${args.file}: ${(e as Error).message}`);
    return EXIT.usage;
  }
  const parsed = parseJson(text);
  if (!parsed.ok) {
    complain(`${args.file} is not JSON: ${parsed.error}`);
    return EXIT.usage;
  }
  let outcomes;
  try {
    outcomes = await checkVectors(parsed.value, adapter);
  } catch (e) {
    complain(`${args.file}: ${(e as Error).message}`);
    return EXIT.usage;
  }
  const count = (s: string): number => outcomes.filter((o) => o.status === s).length;
  const passed = count("PASS");
  const failed = count("FAIL");
  const skipped = count("SKIP");
  if (args.json) {
    say(
      jcs(
        fromPlain({
          vectors: outcomes.map((o) => ({ name: o.name, status: o.status, detail: o.detail })),
          passed,
          failed,
          skipped,
        }),
      ),
    );
  } else {
    for (const o of outcomes) say(o.detail === "" ? `${o.status} ${o.name}` : `${o.status} ${o.name}: ${o.detail}`);
    say(`Vectors: ${passed} passed, ${failed} failed, ${skipped} skipped.`);
  }
  return failed === 0 ? EXIT.pass : EXIT.fail;
}

function isNodeFsError(e: unknown): boolean {
  return e instanceof Error && typeof (e as { code?: unknown }).code === "string" && "syscall" in e;
}
