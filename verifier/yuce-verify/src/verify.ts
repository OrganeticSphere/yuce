// Levels J0 ... J3 (SPEC sections 5 and 6; amendment 3, P3-5 and P3-10) and
// J4a (amendment 6), in one streaming pass.
//
// Order of failures (SPEC 5.0, 9; amendment 3, P3-10). One failure is
// reported: the first J0 failure anywhere in the file; otherwise the first J1
// failure (ANCHOR_NOT_FOUND last); otherwise the first J2 failure; otherwise,
// with --docs, the first J3 failure; otherwise the first J4a failure (a seal
// whose projections differ, then a quittance). Every level runs frame by frame in the
// same pass and keeps its first failure; a level stops once an earlier level
// has failed, since its result is then not reported.
//
// Memory: J0 and J1 hold one line, the O(log n) log-tree stack and the list of
// seals. J2 holds the pairs (actor, submission_id); J3 the documents and the
// ids, anchors and local names of accepted records (TZ v4, section 5); J4a,
// for every accepted record, what amendment 6, P6-2 lists.

import type { HashAdapter } from "./hash.ts";
import { concatBytes, fromHex, toHex, utf8 } from "./hash.ts";
import type { JsonObject, JsonValue } from "./json.ts";
import { depthExceeds, hasExactKeys, isHashText, isObject, jcs, parseJson } from "./json.ts";
import type {
  Anchor,
  CascadeReach,
  Failure,
  HeadAnchor,
  J1Level,
  J2Level,
  J3Level,
  J4aLevel,
  QuittanceResult,
  Report,
  SealAnchor,
  SealEntry,
  Tail,
} from "./report.ts";
import { NOT_VERIFIED, NOT_VERIFIED_AFTER_J3, SPEC_ID, VERIFIER_NAME, VERIFIER_VERSION } from "./report.ts";
import type { Cascade, CascadeStatus, DependencyPair, StatusRow } from "./j4a.ts";
import type { ParsedQuittance } from "./quittance.ts";
import { checkQuittance, parseQuittance } from "./quittance.ts";
import { sealFormProblem } from "./seal.ts";
import { DOMAIN, LogTree, domainHash } from "./trees.ts";
import { J2Checker } from "./j2.ts";
import type { DocumentFiles } from "./j3.ts";
import { RecordEngine } from "./j3.ts";

export const JOURNAL_FORMAT = "sbgk-session-log/3";
export const SEAL_FORMAT_ID = "r2r-seal/2";
export const ZERO_HASH = "0".repeat(64);
/**
 * Amendment 1, P1-1: a frame line with its LF is at most 64 MiB, so a line
 * without its LF (what J0-1 measures) is at most 67108863 bytes.
 */
export const DEFAULT_MAX_LINE_BYTES = 64 * 1024 * 1024 - 1;
/** Amendment 1, P1-2: a frame nests at most 64 levels of JSON (outermost object = 1). */
export const DEFAULT_MAX_DEPTH = 64;

const OUTER_KEYS = ["body", "hash", "header"] as const;
const HEADER_KEYS = ["body_hash", "format", "previous", "records_root", "seq", "wal_op"] as const;

export interface VerifyOptions {
  /** Lowercase 64-hex seal hash obtained outside this file (`--expect-seal`). */
  expectSeal?: string | undefined;
  /** Lowercase 64-hex journal head obtained separately (`--expect-head`). */
  expectHead?: string | undefined;
  maxLineBytes?: number | undefined;
  maxDepth?: number | undefined;
  /**
   * The files of the documents folder (`--docs`), as bytes; names do not
   * matter (amendment 3, P3-2). Absent: J3 is NOT_CHECKED.
   */
  documents?: readonly Uint8Array[] | undefined;
  /** Amendment 6, P6-11: quittances given with the journal (`--quittance`), checked by J4a. */
  quittances?: readonly { file: string; bytes: Uint8Array }[] | undefined;
  /** Amendment 6, P6-1: receives the rows and pairs computed at every seal (`--dump-projections`). */
  onProjections?: ((point: ProjectionPoint) => void) | undefined;
  /** Called at every seal J4a compared and found equal, with the state before the seal frame (for a cut). */
  onSeal?: ((n: number, status: CascadeStatus, cascade: Cascade) => void | Promise<void>) | undefined;
}

/** Amendment 6, P6-1: what `--dump-projections` writes for one seal, in the form of the vectors' rows. */
export interface ProjectionPoint {
  seal_position: number;
  status_hash: string;
  dependencies_hash: string;
  status_rows: StatusRow[];
  dependency_pairs: DependencyPair[];
  equals_seal: boolean;
}

/** The report, and the state of J4a after the last frame (null when J4a did not run). */
export interface DetailedResult {
  report: Report;
  cascade: Cascade | null;
}

/** Indexes document files by the SHA-256 of their bytes (P3-6). */
export async function indexDocuments(files: readonly Uint8Array[], adapter: HashAdapter): Promise<DocumentFiles> {
  const map: DocumentFiles = new Map();
  for (const f of files) map.set(toHex(await adapter.sha256(f)), f);
  return map;
}

/** A failure to read the input (exit code 2), as opposed to a verification failure. */
export class ReadError extends Error {}

/** Chunks of the journal: an (async) iterable, or a WHATWG ReadableStream such as File.stream(). */
export type ByteSource = AsyncIterable<Uint8Array> | Iterable<Uint8Array> | ReadableStream<Uint8Array>;

/**
 * Verifies a journal given as a stream of byte chunks and returns the report.
 * Errors thrown by the source are rethrown as ReadError.
 */
export async function verifyJournal(source: ByteSource, options: VerifyOptions, adapter: HashAdapter): Promise<Report> {
  return (await verifyJournalDetailed(source, options, adapter)).report;
}

/** As verifyJournal, and also returns the state of J4a after the last frame. */
export async function verifyJournalDetailed(source: ByteSource, options: VerifyOptions, adapter: HashAdapter): Promise<DetailedResult> {
  const maxLineBytes = options.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES;
  const fileHash = adapter.createSha256();
  const files = options.documents === undefined ? null : await indexDocuments(options.documents, adapter);
  const v = new FrameVerifier(adapter, options, files);
  let bytes = 0;
  let lines = 0;
  let pending: Uint8Array[] = [];
  let pendingLen = 0;

  const iterator = toAsyncIterator(source);
  for (;;) {
    let next: IteratorResult<Uint8Array>;
    try {
      next = await iterator.next();
    } catch (e) {
      throw new ReadError(e instanceof Error ? e.message : String(e));
    }
    if (next.done === true) break;
    const chunk = next.value;
    fileHash.update(chunk);
    bytes += chunk.length;
    let start = 0;
    for (;;) {
      const lf = chunk.indexOf(0x0a, start);
      if (lf < 0) break;
      lines++;
      if (!v.j0Stopped) {
        const piece = chunk.subarray(start, lf);
        if (pendingLen + piece.length > maxLineBytes) v.lineTooLong(maxLineBytes);
        else await v.line(pending.length === 0 ? piece : concatBytes([...pending, piece]));
      }
      pending = [];
      pendingLen = 0;
      start = lf + 1;
    }
    if (start < chunk.length) {
      pendingLen += chunk.length - start;
      if (!v.j0Stopped) {
        if (pendingLen > maxLineBytes) {
          v.lineTooLong(maxLineBytes);
          pending = [];
        } else pending.push(chunk.slice(start));
      }
    }
  }

  if (!v.j0Stopped) {
    if (bytes === 0) v.failJ0(null, "EMPTY_JOURNAL", "the file has 0 bytes");
    else if (pendingLen > 0) {
      v.failJ0(v.position, "TORN_TAIL", `${pendingLen} bytes after the last LF are not a frame`);
    }
  }
  const report = v.finish(toHex(await fileHash.digest()), bytes, lines, options.documents === undefined ? null : options.documents.length);
  return { report, cascade: report.levels.J4a.result === "NOT_RUN" ? null : v.cascade };
}

function toAsyncIterator(source: ByteSource): AsyncIterator<Uint8Array> | Iterator<Uint8Array> {
  const s = source as Partial<AsyncIterable<Uint8Array>> & Partial<Iterable<Uint8Array>> & Partial<ReadableStream<Uint8Array>>;
  if (typeof s[Symbol.asyncIterator] === "function") return s[Symbol.asyncIterator]!();
  if (typeof s[Symbol.iterator] === "function") return s[Symbol.iterator]!();
  if (typeof s.getReader === "function") {
    // Browsers whose ReadableStream is not async-iterable.
    const reader = s.getReader();
    return {
      async next(): Promise<IteratorResult<Uint8Array>> {
        const r = await reader.read();
        return r.done ? { done: true, value: undefined } : { done: false, value: r.value };
      },
    };
  }
  throw new TypeError("the journal source is not iterable");
}

class FrameVerifier {
  private readonly decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  private readonly maxDepth: number;

  // J0 state
  private i = 0;
  private prevHash: string | null = null;
  private j0Failure: Failure | null = null;
  private format: string | null = null;

  // J1 state
  private j1Failure: Failure | null = null;
  private readonly tree: LogTree;
  private prevBodyAuditRoot: JsonValue | undefined = undefined;
  private prevBodyEngineRoot: JsonValue | undefined = undefined;
  private prevWasSeal = false;
  private readonly seals: SealEntry[] = [];
  private genesisRunId: string | null = null;
  private lastSealPos = -1;
  private closedAt = -1;
  private lastIsClose = false;

  // J2 state
  private j2Failure: Failure | null = null;
  private readonly j2: J2Checker;

  // J3 state (only with --docs)
  private j3Failure: Failure | null = null;
  private j3NotSupplied: string | null = null;
  private readonly j3: RecordEngine | null;

  // J4a state (with --docs)
  private j4aFailure: Failure | null = null;
  private sealsCompared = 0;
  private lastCompared: number | null = null;
  private readonly quittances: ParsedQuittance[];
  /** The seals the quittances name: the header and body of the frame, and the rows J4a computed there. */
  private readonly quittanceSeals = new Map<number, { header: string; body: string; rows: StatusRow[] }>();

  constructor(
    private readonly adapter: HashAdapter,
    private readonly options: VerifyOptions,
    files: DocumentFiles | null,
  ) {
    this.maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
    this.tree = new LogTree(adapter);
    this.j2 = new J2Checker(adapter);
    this.j3 = files === null ? null : new RecordEngine(adapter, files, null, true);
    this.quittances = (options.quittances ?? []).map((q) => parseQuittance(q.file, q.bytes));
  }

  get cascade(): Cascade | null {
    return this.j3?.cascade ?? null;
  }

  get j0Stopped(): boolean {
    return this.j0Failure !== null;
  }

  get position(): number {
    return this.i;
  }

  failJ0(frame: number | null, code: string, detail: string): void {
    this.j0Failure ??= { level: "J0", frame, code, detail };
  }

  lineTooLong(max: number): void {
    this.failJ0(this.i, "LIMIT_EXCEEDED", `line longer than ${max} bytes`);
  }

  private failJ1(frame: number | null, code: string, detail: string): void {
    this.j1Failure ??= { level: "J1", frame, code, detail };
  }

  /** One complete line (without its LF) at position this.i. */
  async line(bytes: Uint8Array): Promise<void> {
    const i = this.i;
    const fail = (code: string, detail: string): void => this.failJ0(i, code, detail);

    // J0-1 (nesting; the length was checked while reading)
    if (depthExceeds(bytes, this.maxDepth)) return fail("LIMIT_EXCEEDED", `nesting deeper than ${this.maxDepth}`);
    // J0-3
    let text: string;
    try {
      text = this.decoder.decode(bytes);
    } catch {
      return fail("INVALID_UTF8", "the line is not valid UTF-8");
    }
    // J0-4
    const parsed = parseJson(text);
    if (!parsed.ok) return fail("INVALID_JSON", parsed.error);
    const frame = parsed.value;
    if (!isObject(frame)) return fail("INVALID_JSON", "the line is not a JSON object");
    // J0-5
    if (parsed.badNumber) return fail("BAD_NUMBER", "a number that is not an integer from 0 to 2^53-1 in plain digits");
    // J0-6
    const canonical = jcs(frame);
    if (canonical !== text) {
      return fail("NOT_CANONICAL", `the line differs from its canonical form at character ${firstDifference(canonical, text)}`);
    }
    // J0-7
    const header = frame.get("header");
    if (isObject(header)) {
      const fmt = header.get("format");
      if (i === 0 && typeof fmt === "string") this.format = fmt;
      if (typeof fmt === "string" && fmt !== JOURNAL_FORMAT) {
        return i === 0
          ? fail("UNSUPPORTED_FORMAT", `header.format is ${quoted(fmt)}`)
          : fail("MIXED_FORMAT", `header.format is ${quoted(fmt)}, frame 0 is ${quoted(this.format)}`);
      }
    }
    // J0-8
    if (!hasExactKeys(frame, OUTER_KEYS)) return fail("OUTER_KEYS", "the frame must have exactly the keys body, hash, header");
    // J0-9
    if (!isObject(header) || !hasExactKeys(header, HEADER_KEYS)) {
      return fail("HEADER_KEYS", "header must be an object with exactly the keys body_hash, format, previous, records_root, seq, wal_op");
    }
    // J0-10
    const hash = frame.get("hash");
    const body = frame.get("body");
    const seq = header.get("seq");
    const walOp = header.get("wal_op");
    const previous = header.get("previous");
    const bodyHash = header.get("body_hash");
    if (!isHashText(hash)) return fail("BAD_TYPE", "hash is not 64 lowercase hex characters");
    for (const k of ["body_hash", "previous", "records_root"] as const) {
      if (!isHashText(header.get(k))) return fail("BAD_TYPE", `header.${k} is not 64 lowercase hex characters`);
    }
    if (typeof seq !== "number") return fail("BAD_TYPE", "header.seq is not a number");
    if (typeof header.get("format") !== "string") return fail("BAD_TYPE", "header.format is not a string");
    if (typeof walOp !== "string") return fail("BAD_TYPE", "header.wal_op is not a string");
    if (!isObject(body)) return fail("BAD_TYPE", "body is not an object");
    // J0-11
    if (seq !== i) return fail("SEQ_MISMATCH", `header.seq is ${seq}, expected ${i}`);
    // J0-12
    const expectedOp = i === 0 ? "genesis" : "audit";
    if (walOp !== expectedOp) return fail("WAL_OP_MISMATCH", `header.wal_op is ${quoted(walOp)}, expected "${expectedOp}"`);
    // J0-13
    const expectedPrevious = i === 0 ? ZERO_HASH : this.prevHash;
    if (previous !== expectedPrevious) {
      return fail(
        "PREVIOUS_MISMATCH",
        i === 0 ? "header.previous of frame 0 is not 64 zeros" : `header.previous is not the hash of frame ${i - 1}`,
      );
    }
    // J0-14
    const computedBodyHash = toHex(await domainHash(this.adapter, DOMAIN.frameBody, utf8(jcs(body))));
    if (bodyHash !== computedBodyHash) return fail("BODY_HASH_MISMATCH", `header.body_hash is not H("${DOMAIN.frameBody}", JCS(body))`);
    // J0-15
    const computedHash = toHex(await domainHash(this.adapter, DOMAIN.frameHeader, utf8(jcs(header))));
    if (hash !== computedHash) return fail("FRAME_HASH_MISMATCH", `hash is not H("${DOMAIN.frameHeader}", JCS(header))`);

    // Level J1 for this frame, until its first failure.
    if (this.j1Failure === null) await this.j1Frame(i, body, hash, this.prevHash);
    // Level J2, while J1 has not failed.
    if (this.j1Failure === null && this.j2Failure === null) {
      const f = i === 0 ? await this.j2.frame0(header, body) : await this.j2.frame(body);
      if (f !== null) this.j2Failure = { level: "J2", frame: i, code: f.code, detail: f.detail };
    }
    // Level J3, with --docs, while J1 and J2 have not failed.
    if (this.j3 !== null && this.j1Failure === null && this.j2Failure === null && this.j3Failure === null && this.j3NotSupplied === null) {
      const r = i === 0 ? await this.j3.genesis(body) : await this.j3.frame(header, body, i);
      if (r !== null && "notSupplied" in r) this.j3NotSupplied = r.notSupplied;
      else if (r !== null) this.j3Failure = { level: "J3", frame: i, code: r.code, detail: r.detail };
      // Level J4a at a seal frame J1 accepted, while J3 has not failed (amendment 6, P6-1).
      else if (this.lastSealPos === i) await this.j4aSeal(i, header, body);
    }

    this.prevHash = hash;
    this.i++;
  }

  // -------------------------------------------------------------------------
  // J1
  // -------------------------------------------------------------------------

  /** Level J1 for the frame at position i, in the order of SPEC 6.2. */
  private async j1Frame(i: number, body: JsonObject, hash: string, prevHash: string | null): Promise<void> {
    // SPEC 6.1: the body of frame 0 is the genesis record; its run id is body.run_id.
    if (i === 0) {
      const runId = body.get("run_id");
      this.genesisRunId = typeof runId === "string" ? runId : null;
    }

    // 1. J1-14: no frame after the close frame.
    if (this.closedAt >= 0) {
      return this.failJ1(i, "FRAME_AFTER_CLOSE", `a frame after the close frame at position ${this.closedAt}`);
    }

    const actor = body.get("actor");
    const command = body.get("command");
    const isKernel = actor === "kernel";
    // The kind of command: body.command.kind when command is an object and kind a string.
    const kindValue = isObject(command) ? command.get("kind") : undefined;
    const kind = typeof kindValue === "string" ? kindValue : undefined;

    // 2. J1-13: only the kernel writes a seal or a close.
    if ((kind === "seal" || kind === "close") && !isKernel) {
      return this.failJ1(
        i,
        "KERNEL_COMMAND_NOT_FROM_KERNEL",
        `a ${kind} command from the actor ${typeof actor === "string" ? quoted(actor) : "(missing or not a string)"}`,
      );
    }

    // 3. J1-1 ... J1-9 for a seal candidate.
    let isSeal = false;
    if (isKernel && kind === "seal") {
      if (!(await this.checkSeal(i, body, command as JsonObject, prevHash))) return;
      isSeal = true;
    }

    // 4. J1-10, J1-11, J1-12 for kernel frames.
    let isClose = false;
    if (isKernel) {
      const sid = body.get("submission_id");
      // J1-10 (amendment 2, P2-2): any string id starting with "seal-" (exact, case-sensitive)
      // belongs to a seal only. Equality with the position is checked by J1-4.
      if (typeof sid === "string" && sid.startsWith("seal-") && !isSeal) {
        return this.failJ1(i, "KERNEL_ID_MISUSE", `a kernel frame takes the id ${quoted(sid)} but is not a seal`);
      }
      // J1-11
      isClose = kind === "close";
      if (isClose && (command as JsonObject).size !== 1) {
        return this.failJ1(i, "KERNEL_ID_MISUSE", 'the close frame has a command other than {"kind":"close"}');
      }
      if (isClose !== (sid === "audit-close")) {
        return this.failJ1(
          i,
          "KERNEL_ID_MISUSE",
          isClose ? 'the close frame has a submission_id other than "audit-close"' : 'submission_id "audit-close" on a frame that is not the close frame',
        );
      }
      // J1-12
      if (isClose) {
        if (!this.prevWasSeal) return this.failJ1(i, "CLOSE_WITHOUT_SEAL", `the close frame is not preceded by a seal at position ${i - 1}`);
        this.closedAt = i;
      }
    }

    this.prevWasSeal = isSeal;
    this.lastIsClose = isClose;
    this.prevBodyAuditRoot = body.get("audit_root");
    this.prevBodyEngineRoot = body.get("engine_root");
    await this.tree.push(fromHex(hash));
  }

  /** SPEC 6.3, J1-1 ... J1-9. Returns false after recording a failure. */
  private async checkSeal(i: number, body: JsonObject, command: JsonObject, prevHash: string | null): Promise<boolean> {
    const fail = (code: string, detail: string): false => {
      this.failJ1(i, code, detail);
      return false;
    };
    const form = (detail: string): false => fail("SEAL_FORM", detail);

    // J1-1 (shared with the seal body of a quittance, amendment 6, P6-11)
    const outcome = body.get("outcome");
    const problem = sealFormProblem(command, outcome);
    if (problem !== null) return form(problem);
    const result = (outcome as JsonObject).get("result") as JsonObject;
    const seal = command.get("seal") as JsonObject;
    const sealHash = result.get("seal_hash") as string;
    // J1-2
    const sealJcs = jcs(seal);
    if (jcs(result.get("seal")!) !== sealJcs) return form("outcome.result.seal differs from command.seal");
    // J1-3
    if (seal.get("format") !== SEAL_FORMAT_ID) return fail("SEAL_FORMAT", `seal.format is not "${SEAL_FORMAT_ID}"`);
    // J1-4
    if (i < 1 || seal.get("log_size") !== i || body.get("submission_id") !== `seal-${i}`) {
      return fail("SEAL_LOG_SIZE", `a seal at position ${i} must have log_size ${i} and submission_id "seal-${i}"`);
    }
    // J1-5
    if (seal.get("wal_head") !== prevHash) return fail("SEAL_WAL_HEAD", `seal.wal_head is not the hash of frame ${i - 1}`);
    // J1-6 (the tree holds frames 0 .. i-1: the leaf of frame i is added after)
    const root = await this.tree.root();
    if (root === null || seal.get("log_root") !== toHex(root)) {
      return fail("SEAL_LOG_ROOT", `seal.log_root is not the log root over frames 0..${i - 1}`);
    }
    // J1-7
    if (seal.get("audit_root") !== this.prevBodyAuditRoot || seal.get("engine_root") !== this.prevBodyEngineRoot) {
      return fail("SEAL_ROOT_CONTINUITY", `seal.audit_root and seal.engine_root must equal those of the body of frame ${i - 1}`);
    }
    // J1-8
    const computed = toHex(await domainHash(this.adapter, DOMAIN.seal, utf8(sealJcs)));
    if (sealHash !== computed) return fail("SEAL_HASH_MISMATCH", `outcome.result.seal_hash is not H("${DOMAIN.seal}", JCS(seal))`);
    // J1-9
    if (this.genesisRunId === null) return fail("SEAL_RUN_ID", "the body of frame 0 has no string run_id");
    if (seal.get("run_id") !== this.genesisRunId) return fail("SEAL_RUN_ID", "seal.run_id differs from body.run_id of frame 0");

    this.seals.push({ n: i, seal_hash: computed });
    this.lastSealPos = i;
    return true;
  }

  // -------------------------------------------------------------------------
  // J4a
  // -------------------------------------------------------------------------

  /** Amendment 6, P6-1: the projections over the state after frames 0 ... n-1, compared with the seal at n. */
  private async j4aSeal(n: number, header: JsonObject, body: JsonObject): Promise<void> {
    const cascade = this.j3!.cascade!;
    // The first failing seal ends J4a; later seals are computed only for a dump.
    if (this.j4aFailure !== null && this.options.onProjections === undefined) return;
    const st = await cascade.status();
    const projections = ((body.get("command") as JsonObject).get("seal") as JsonObject).get("projections") as JsonObject;
    const statusOk = st.status === projections.get("status");
    const dependenciesOk = st.dependencies === projections.get("dependencies");
    this.options.onProjections?.({
      seal_position: n,
      status_hash: st.status,
      dependencies_hash: st.dependencies,
      status_rows: st.rows,
      dependency_pairs: st.pairs,
      equals_seal: statusOk && dependenciesOk,
    });
    if (this.j4aFailure !== null) return;
    this.sealsCompared++;
    this.lastCompared = n;
    if (!statusOk) {
      this.j4aFailure = {
        level: "J4a",
        frame: n,
        code: "PROJECTION_STATUS_MISMATCH",
        detail: `the status projection computed over frames 0..${n - 1} is ${st.status}, the seal names ${String(projections.get("status"))}`,
      };
      return;
    }
    if (!dependenciesOk) {
      this.j4aFailure = {
        level: "J4a",
        frame: n,
        code: "PROJECTION_DEPENDENCIES_MISMATCH",
        detail: `the dependency projection computed over frames 0..${n - 1} is ${st.dependencies}, the seal names ${String(projections.get("dependencies"))}`,
      };
      return;
    }
    if (this.quittances.some((q) => q.n === n)) this.quittanceSeals.set(n, { header: jcs(header), body: jcs(body), rows: st.rows });
    await this.options.onSeal?.(n, st, cascade);
  }

  /** Amendment 6, P6-11: every quittance, in the order given, after the last frame. */
  private checkQuittances(j4aRan: boolean): QuittanceResult[] {
    const out: QuittanceResult[] = [];
    for (const q of this.quittances) {
      if (!j4aRan) {
        out.push({ file: q.file, verdict: "NOT_RUN", code: null });
        continue;
      }
      let failure;
      if (q.problem !== null || q.n === null) failure = checkQuittance(q, undefined);
      else {
        // The check needs J4a to pass up to the quittance's seal.
        const f = this.j4aFailure;
        if (f !== null && f.frame !== null && q.n >= f.frame) {
          out.push({ file: q.file, verdict: "NOT_RUN", code: null });
          continue;
        }
        failure = checkQuittance(q, this.quittanceSeals.get(q.n));
      }
      out.push({ file: q.file, verdict: failure === null ? "PASS" : "FAIL", code: failure === null ? null : failure.code });
      if (failure !== null) this.j4aFailure ??= { level: "J4a", frame: null, code: failure.code, detail: `${q.file}: ${failure.detail}` };
    }
    return out;
  }

  /** Amendment 6, P6-1: the reach of the cascade check. */
  private reach(n: number): CascadeReach {
    if (this.lastCompared === null) return { seals_checked: 0, checked_through_frame: null, unchecked_frames: n - 1 };
    const after = n - 1 - this.lastCompared;
    const close = this.closedAt === this.lastCompared + 1 ? 1 : 0;
    return { seals_checked: this.sealsCompared, checked_through_frame: this.lastCompared, unchecked_frames: after - close };
  }

  // -------------------------------------------------------------------------
  // End of file
  // -------------------------------------------------------------------------

  finish(journalSha256: string, bytes: number, lines: number, documentFiles: number | null): Report {
    const n = this.i;
    const { expectSeal, expectHead } = this.options;

    // SPEC 5.3: the last check of J0
    if (this.j0Failure === null && expectHead !== undefined && expectHead !== this.prevHash) {
      this.failJ0(null, "HEAD_MISMATCH", "the journal head differs from --expect-head");
    }
    const j0Pass = this.j0Failure === null;

    // SPEC 6.5: the external seal, the last check of J1
    let anchorSeal: SealEntry | undefined;
    if (j0Pass && this.j1Failure === null && expectSeal !== undefined) {
      anchorSeal = this.seals.find((s) => s.seal_hash === expectSeal);
      if (anchorSeal === undefined) this.failJ1(null, "ANCHOR_NOT_FOUND", "no seal of this journal has the --expect-seal hash");
    }
    const j1Pass = j0Pass && this.j1Failure === null;

    let j1: J1Level;
    let tail: Tail | null = null;
    if (!j0Pass) j1 = { result: "NOT_CHECKABLE", reason: "J0 failed" };
    else if (!j1Pass) j1 = { result: "FAIL" };
    else {
      tail = this.tail(n);
      j1 = { result: "PASS", seals: this.seals, tail };
    }

    // SPEC 8.2: anchor.seal and anchor.head
    let seal: SealAnchor = { given: false, matched: null };
    if (expectSeal !== undefined) {
      if (anchorSeal !== undefined && j1Pass) {
        seal = { given: true, matched: true, at_n: anchorSeal.n, frames_after: n - 1 - anchorSeal.n };
      } else seal = { given: true, matched: this.j1Failure?.code === "ANCHOR_NOT_FOUND" ? false : null };
    }
    let head: HeadAnchor = { given: false, matched: null };
    if (expectHead !== undefined) {
      head = { given: true, matched: j0Pass ? true : this.j0Failure?.code === "HEAD_MISMATCH" ? false : null };
    }
    const anchor: Anchor = { seal, head };

    // Amendment 3, P3-10: J2 and J3.
    const j2Pass = j1Pass && this.j2Failure === null;
    let j2: J2Level;
    if (!j0Pass) j2 = { result: "NOT_CHECKABLE", reason: "J0 failed" };
    else if (!j1Pass) j2 = { result: "NOT_CHECKABLE", reason: "J1 failed" };
    else if (!j2Pass) j2 = { result: "FAIL" };
    else j2 = { result: "PASS", documents: this.j2.genesis!.documents, settings_hash: this.j2.genesis!.settingsHash };

    let j3: J3Level;
    if (this.j3 === null) j3 = { result: "NOT_CHECKED" };
    else if (!j0Pass) j3 = { result: "NOT_CHECKABLE", reason: "J0 failed" };
    else if (!j1Pass) j3 = { result: "NOT_CHECKABLE", reason: "J1 failed" };
    else if (!j2Pass) j3 = { result: "NOT_CHECKABLE", reason: "J2 failed" };
    else if (this.j3Failure !== null) j3 = { result: "FAIL" };
    else if (this.j3NotSupplied !== null) j3 = { result: "NOT_CHECKABLE", reason: `document ${this.j3NotSupplied} not supplied` };
    else j3 = { result: "PASS", records: this.j3.recordCount, quotes: this.j3.quotes };

    // Amendment 6, P6-1 and P6-11: J4a runs only when J3 passed.
    const j3Pass = j3.result === "PASS";
    let j4a: J4aLevel;
    let cascade: CascadeReach | null = null;
    const quittances = this.checkQuittances(j3Pass);
    if (!j3Pass) j4a = { result: "NOT_RUN", reason: j3.result === "NOT_CHECKED" ? "J3 not run" : j3.result === "FAIL" ? "J3 failed" : "J3 not checkable" };
    else {
      j4a = { result: this.j4aFailure === null ? "PASS" : "FAIL" };
      cascade = this.reach(n);
    }

    let notVerified: string[];
    if (!j3Pass) notVerified = [...NOT_VERIFIED];
    else if (j4a.result !== "PASS" || cascade!.checked_through_frame === null) notVerified = [...NOT_VERIFIED_AFTER_J3];
    else if (cascade!.unchecked_frames > 0) notVerified = ["withdrawal_cascade_after_last_seal", "signatures"];
    else notVerified = ["signatures"];
    if (this.quittances.length > 0) notVerified.splice(notVerified.indexOf("signatures"), 0, "quittance_inclusion");

    const j0Result = j0Pass ? "PASS" : "FAIL";
    const results = [j0Result, j1.result, j2.result, j3.result, j4a.result];
    const verdict = results.includes("FAIL") ? "FAIL" : this.j3NotSupplied !== null && j3.result === "NOT_CHECKABLE" ? "INCOMPLETE" : "PASS";
    return {
      verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION, spec: SPEC_ID },
      input: {
        journal_sha256: journalSha256,
        bytes,
        frames: lines,
        format: this.format,
        sources: documentFiles === null ? { given: false } : { given: true, files: documentFiles },
      },
      levels: {
        J0: { result: j0Result },
        J1: j1,
        J2: j2,
        J3: j3,
        J4a: j4a,
        J5: { result: "NOT_CHECKED" },
      },
      cascade,
      quittances,
      anchor,
      computed: {
        wal_head: j0Pass ? this.prevHash : null,
        closed: tail === null ? null : tail.kind === "closed",
      },
      not_verified: notVerified,
      verdict,
      first_failure: this.j0Failure ?? this.j1Failure ?? (j1Pass ? this.j2Failure : null) ?? (j2Pass ? this.j3Failure : null) ?? (j3Pass ? this.j4aFailure : null),
    };
  }

  /** SPEC 6.5: the tail after the last seal. */
  private tail(n: number): Tail {
    if (this.lastSealPos < 0) return { kind: "no_seals" };
    const k = n - 1 - this.lastSealPos;
    if (k === 0) return { kind: "sealed", frames_after_last_seal: 0 };
    if (k === 1 && this.lastIsClose) return { kind: "closed", frames_after_last_seal: 1 };
    return { kind: "unsealed", frames_after_last_seal: k };
  }
}

/** A value from the journal, quoted and cut short for a failure detail (the journal is untrusted input). */
function quoted(v: string | null): string {
  if (v === null) return "null";
  return JSON.stringify(v.length > 80 ? v.slice(0, 80) + "..." : v);
}

function firstDifference(a: string, b: string): number {
  const m = Math.min(a.length, b.length);
  for (let k = 0; k < m; k++) if (a.charCodeAt(k) !== b.charCodeAt(k)) return k;
  return m;
}
