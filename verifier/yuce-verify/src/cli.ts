// Command line (task statement, section 4):
//   yuce-verify journal <file> [--expect-seal <hex>] [--expect-head <hex>]
//                              [--max-line-bytes <n>] [--max-depth <n>] [--json] [--quiet]
//   yuce-verify vectors <file.json> [--json] [--quiet]

import type { HashAdapter } from "./hash.ts";
import { fromPlain, jcs, parseJson } from "./json.ts";
import { EXIT, exitCodeFor, humanLine, reportToJcs } from "./report.ts";
import { checkVectors } from "./vectors.ts";
import type { ByteSource } from "./verify.ts";
import { ReadError, verifyJournal } from "./verify.ts";

export interface CliIo {
  stdout(text: string): void;
  stderr(text: string): void;
  /** Whole file, for the vectors file. */
  readFile(path: string): Promise<Uint8Array>;
  /** Streaming read of a journal. May throw; errors become exit code 2. */
  openJournal(path: string): Promise<ByteSource>;
}

export const USAGE = [
  "usage:",
  "  yuce-verify journal <file> [--expect-seal <hex>] [--expect-head <hex>]",
  "                             [--max-line-bytes <n>] [--max-depth <n>] [--json] [--quiet]",
  "  yuce-verify vectors <file.json> [--json] [--quiet]",
].join("\n");

class UsageError extends Error {}

interface ParsedArgs {
  command: "journal" | "vectors";
  file: string;
  expectSeal?: string;
  expectHead?: string;
  maxLineBytes?: number;
  maxDepth?: number;
  json: boolean;
  quiet: boolean;
}

const VALUE_FLAGS = new Set(["--expect-seal", "--expect-head", "--max-line-bytes", "--max-depth"]);

function parseArgs(argv: readonly string[]): ParsedArgs {
  const [command, ...rest] = argv;
  if (command !== "journal" && command !== "vectors") {
    throw new UsageError(command === undefined ? "missing command" : `unknown command ${JSON.stringify(command)}`);
  }
  const values = new Map<string, string>();
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
    if (VALUE_FLAGS.has(name) && command === "journal") {
      let value: string | undefined;
      if (eqAt >= 0) value = arg.slice(eqAt + 1);
      else value = rest[++k];
      if (value === undefined) throw new UsageError(`${name} needs a value`);
      if (values.has(name)) throw new UsageError(`${name} given twice`);
      values.set(name, value);
    } else if ((name === "--json" || name === "--quiet") && eqAt < 0) {
      switches.add(name);
    } else throw new UsageError(`unknown option ${JSON.stringify(arg)}`);
  }
  if (positional.length !== 1) throw new UsageError(`expected exactly one file, got ${positional.length}`);

  const parsed: ParsedArgs = { command, file: positional[0]!, json: switches.has("--json"), quiet: switches.has("--quiet") };
  const seal = values.get("--expect-seal");
  if (seal !== undefined) parsed.expectSeal = hashArg("--expect-seal", seal);
  const head = values.get("--expect-head");
  if (head !== undefined) parsed.expectHead = hashArg("--expect-head", head);
  const mlb = values.get("--max-line-bytes");
  if (mlb !== undefined) parsed.maxLineBytes = positiveInt("--max-line-bytes", mlb);
  const md = values.get("--max-depth");
  if (md !== undefined) parsed.maxDepth = positiveInt("--max-depth", md);
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

  if (args.command === "vectors") return runVectors(args, io, adapter, say, complain);

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
      },
      adapter,
    );
  } catch (e) {
    if (e instanceof ReadError || isNodeFsError(e)) {
      complain(`cannot read ${args.file}: ${(e as Error).message}`);
      return EXIT.usage;
    }
    throw e;
  }
  say(args.json ? reportToJcs(report) : humanLine(report));
  return exitCodeFor(report.verdict);
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
