// A cut of several journals and its offline check (SPEC_CUT_AND_BUNDLE_v1):
// the manifest (B0), each journal at its seal (B1), each export (B2), the
// deliveries (B3) and a withdrawal across journals (B4), and the report
// `yuce-cut-report/1`.

import { documentChunks } from "./cdc.ts";
import type { HashAdapter } from "./hash.ts";
import { toHex, utf8 } from "./hash.ts";
import type { Cascade, CascadeRecord, CascadeStatus } from "./j4a.ts";
import { cmp } from "./j4a.ts";
import type { JsonObject, JsonValue } from "./json.ts";
import { hasExactKeys, isHashText, isObject, jcs, parseJson } from "./json.ts";
import type { Report } from "./report.ts";
import { domainHash } from "./trees.ts";
import { verifyJournalDetailed } from "./verify.ts";

export const CUT_FORMAT = "yuce-cut/1";
export const CUT_REPORT_FORMAT = "yuce-cut-report/1";
export const EXPORT_FORMAT = "yuce-export/1";
export const CUT_DOMAIN = "YUCE-CUT/1";
export const CUT_NOT_VERIFIED = ["meaning", "undeclared_dependencies", "signatures"] as const;

/** Section 1: a name, other than "." and ".." (a journal's name is also a folder of the bundle). */
const NAME = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,64}$/;
const MANIFEST_KEYS = ["deliveries", "exports", "format", "journals", "mode", "previous_cut"] as const;
const JOURNAL_KEYS = ["closed", "log_size", "name", "rules_version", "run_id", "seal_hash", "wal_head"] as const;
const EXPORT_KEYS = ["journal", "name", "records", "seal_hash", "sha256"] as const;
const DELIVERY_KEYS = ["doc_id", "export", "frame", "journal"] as const;

/** The files of a bundle (section 4). How they lie on disk is a matter of the command line. */
export interface CutBundle {
  manifest: Uint8Array;
  /** Per journal name: the journal file and the files of its documents folder. */
  journals: ReadonlyMap<string, { journal: Uint8Array; documents: readonly Uint8Array[] }>;
  /** Per export name: the export file. */
  exports: ReadonlyMap<string, Uint8Array>;
}

export interface ManifestJournal {
  name: string;
  run_id: string;
  rules_version: string;
  seal_hash: string;
  log_size: number;
  wal_head: string;
  closed: boolean;
}
export interface ManifestExport {
  name: string;
  journal: string;
  seal_hash: string;
  sha256: string;
  records: number;
}
export interface ManifestDelivery {
  export: string;
  journal: string;
  doc_id: string;
  frame: number;
}
export interface Manifest {
  journals: ManifestJournal[];
  exports: ManifestExport[];
  deliveries: ManifestDelivery[];
}

export type CutFailure = { code: string } & Record<string, string | number | null>;

/** What the observation report needs of a journal of a verified cut. */
export interface CutJournalState {
  name: string;
  seal_hash: string;
  log_size: number;
  report: Report;
  cascade: Cascade;
  /** The status at the cut's seal (the state after frames 0 ... log_size - 1). */
  status: CascadeStatus;
}

/** A delivery that passed B3.1: its delivered bytes and version, and the paragraphs of the export in them. */
export interface DeliveredExport {
  delivery: ManifestDelivery;
  bytes: Uint8Array;
  version: string;
  /** Each paragraph: the record it names and its byte range [start, end) in the delivered bytes. */
  paragraphs: { record: string; start: number; end: number }[];
}

export interface CutReport {
  format: string;
  cut_hash: string | null;
  verdict: "PASS" | "FAIL";
  journals: { name: string; verdict: "PASS" | "FAIL"; levels: Report["levels"] | null }[];
  exports: { name: string; verdict: "PASS" | "FAIL"; paragraphs: number; fallen_at_cut: number }[];
  deliveries: { export: string; journal: string; verdict: "PASS" | "FAIL" }[];
  across: { paragraphs_fallen: number; observations_checked: number };
  failures: CutFailure[];
  not_verified: string[];
}

export interface CutResult {
  report: CutReport;
  manifest: Manifest | null;
  /** Per journal name, for journals whose part passed B1.5. */
  states: Map<string, CutJournalState>;
  delivered: DeliveredExport[];
}

/** cut_hash = hex(H("YUCE-CUT/1", JCS(manifest))). */
export async function cutHash(adapter: HashAdapter, manifest: JsonValue): Promise<string> {
  return toHex(await domainHash(adapter, CUT_DOMAIN, utf8(jcs(manifest))));
}

/** Section 2.2: the escapes of an export. */
export function exportEscape(s: string): string {
  return s.replaceAll("\\", "\\\\").replaceAll("\n", "\\n").replaceAll("\r", "\\r");
}

/** Section 2.2: the paragraph of a claim. */
export function exportParagraph(claim: CascadeRecord, recordOf: (id: string) => CascadeRecord | undefined): string {
  // In based_on order and without duplicates, each ground at its first place.
  const grounds = [...new Set(claim.grounds)].map((id) => recordOf(id));
  const rests = grounds.filter((g) => g !== undefined && g.kind === "claim").map((g) => g!.id);
  const quotes = grounds.filter((g) => g !== undefined && g.obs !== null).map((g) => `[${exportEscape(g!.obs!.docId)}] "${exportEscape(g!.obs!.quote)}"`);
  let p = `Record ${claim.id}: ${exportEscape(claim.text ?? "")}`;
  if (rests.length > 0) p += ` Rests on: ${rests.join(", ")}`;
  if (quotes.length > 0) p += ` Quotes: ${quotes.join(" ; ")}`;
  return p;
}

/** Section 2.1: the bytes of an export. */
export function exportText(runId: string, sealHash: string, paragraphs: readonly string[]): string {
  let t = `${EXPORT_FORMAT} run=${exportEscape(runId)} seal=${sealHash} records=${paragraphs.length}\n`;
  for (const p of paragraphs) t += `\n${p}\n`;
  return t;
}

const PARAGRAPH = /^Record ([0-9a-f]{64}): /;

/** Section 2.2: the paragraphs of export bytes, with their ranges; only the prefix `Record <id>: ` is read. */
export function exportParagraphs(bytes: Uint8Array): { record: string | null; start: number; end: number }[] | null {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  const out: { record: string | null; start: number; end: number }[] = [];
  const firstLf = text.indexOf("\n");
  if (firstLf < 0) return null;
  // Byte offsets: walk the lines after the header; paragraphs are the non-empty lines.
  let offset = utf8(text.slice(0, firstLf + 1)).length;
  const rest = text.slice(firstLf + 1);
  const lines = rest.split("\n");
  for (let k = 0; k < lines.length; k++) {
    const line = lines[k]!;
    const len = utf8(line).length;
    if (line !== "") {
      const m = PARAGRAPH.exec(line);
      out.push({ record: m === null ? null : m[1]!, start: offset, end: offset + len });
    }
    offset += len + 1;
  }
  return out;
}

// ---------------------------------------------------------------------------
// B0
// ---------------------------------------------------------------------------

/**
 * Section 3: the manifest file is one JSON object (RFC 8259) in UTF-8. Its bytes
 * are read as they are: a byte-order mark or bytes that are not UTF-8 make it no
 * JSON (null). Layout is free; a repeated key is reported in duplicateKey.
 */
export function parseManifest(bytes: Uint8Array): { value: JsonValue; badNumber: boolean; duplicateKey: boolean } | null {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
  const p = parseJson(text);
  return p.ok ? { value: p.value, badNumber: p.badNumber, duplicateKey: p.duplicateKey } : null;
}

const isInt = (v: JsonValue | undefined): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/** B0: the manifest; null when it fails. */
export function checkManifest(m: JsonValue): Manifest | null {
  if (!isObject(m) || !hasExactKeys(m, MANIFEST_KEYS)) return null;
  if (m.get("format") !== CUT_FORMAT || m.get("mode") !== "observe") return null;
  const prev = m.get("previous_cut");
  if (prev !== null && !isHashText(prev)) return null;
  const js = m.get("journals");
  const es = m.get("exports");
  const ds = m.get("deliveries");
  if (!Array.isArray(js) || !Array.isArray(es) || !Array.isArray(ds)) return null;
  const journals: ManifestJournal[] = [];
  for (const j of js) {
    if (!isObject(j) || !hasExactKeys(j, JOURNAL_KEYS)) return null;
    const name = j.get("name");
    const runId = j.get("run_id");
    const rules = j.get("rules_version");
    const seal = j.get("seal_hash");
    const size = j.get("log_size");
    const head = j.get("wal_head");
    const closed = j.get("closed");
    if (typeof name !== "string" || !NAME.test(name) || typeof runId !== "string" || typeof rules !== "string") return null;
    if (!isHashText(seal) || !isInt(size) || !isHashText(head) || typeof closed !== "boolean") return null;
    journals.push({ name, run_id: runId, rules_version: rules, seal_hash: seal, log_size: size, wal_head: head, closed });
  }
  const exports: ManifestExport[] = [];
  for (const e of es) {
    if (!isObject(e) || !hasExactKeys(e, EXPORT_KEYS)) return null;
    const name = e.get("name");
    const journal = e.get("journal");
    const seal = e.get("seal_hash");
    const sha = e.get("sha256");
    const records = e.get("records");
    if (typeof name !== "string" || !NAME.test(name) || typeof journal !== "string" || !NAME.test(journal)) return null;
    if (!isHashText(seal) || !isHashText(sha) || !isInt(records)) return null;
    exports.push({ name, journal, seal_hash: seal, sha256: sha, records });
  }
  const deliveries: ManifestDelivery[] = [];
  for (const d of ds) {
    if (!isObject(d) || !hasExactKeys(d, DELIVERY_KEYS)) return null;
    const exp = d.get("export");
    const journal = d.get("journal");
    const docId = d.get("doc_id");
    const frame = d.get("frame");
    if (typeof exp !== "string" || !NAME.test(exp) || typeof journal !== "string" || !NAME.test(journal)) return null;
    if (typeof docId !== "string" || !isInt(frame)) return null;
    deliveries.push({ export: exp, journal, doc_id: docId, frame });
  }
  // Sorted, names unique.
  for (let k = 1; k < journals.length; k++) if (cmp(journals[k - 1]!.name, journals[k]!.name) >= 0) return null;
  for (let k = 1; k < exports.length; k++) if (cmp(exports[k - 1]!.name, exports[k]!.name) >= 0) return null;
  const deliveryOrder = (a: ManifestDelivery, b: ManifestDelivery): number => cmp(a.journal, b.journal) || a.frame - b.frame || cmp(a.doc_id, b.doc_id);
  for (let k = 1; k < deliveries.length; k++) if (deliveryOrder(deliveries[k - 1]!, deliveries[k]!) > 0) return null;
  // Which deliveries may coexist.
  const seen = new Set<string>();
  for (const d of deliveries) {
    const key = d.frame === 0 ? jcs([d.journal, 0, d.doc_id]) : jcs([d.journal, d.frame]);
    if (seen.has(key)) return null;
    seen.add(key);
  }
  // References resolve.
  const journalNames = new Set(journals.map((j) => j.name));
  const exportNames = new Set(exports.map((e) => e.name));
  if (!exports.every((e) => journalNames.has(e.journal))) return null;
  if (!deliveries.every((d) => journalNames.has(d.journal) && exportNames.has(d.export))) return null;
  return { journals, exports, deliveries };
}

// ---------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------

interface JournalPart {
  /** The frames of the part, parsed loosely (null when a line is not a JSON object). */
  frames: (JsonObject | null)[];
  bytes: Uint8Array;
}

/** The part of a journal: frames 0 ... n, and n + 1 when closed (section 3). */
function journalPart(file: Uint8Array, n: number, closed: boolean): JournalPart {
  const want = n + 1 + (closed ? 1 : 0);
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const frames: (JsonObject | null)[] = [];
  let start = 0;
  let end = file.length;
  while (frames.length < want) {
    const lf = file.indexOf(0x0a, start);
    if (lf < 0) break;
    const parsed = parseJson(decoder.decode(file.subarray(start, lf)));
    frames.push(parsed.ok && isObject(parsed.value) ? parsed.value : null);
    start = lf + 1;
    if (frames.length === want) end = start;
  }
  return { frames, bytes: file.subarray(0, end) };
}

const get = (o: JsonValue | undefined, ...path: string[]): JsonValue | undefined => {
  let v = o;
  for (const k of path) v = isObject(v) ? v.get(k) : undefined;
  return v;
};

/** Every document a frame brings in and that ran: [doc_id, bytes] (a put_document frame, or batch operations with a result). */
function putsOf(frame: JsonObject | null): { docId: string; text: string }[] {
  const body = get(frame, "body");
  const command = get(body, "command");
  const outcome = get(body, "outcome");
  const kind = get(command, "kind");
  const out: { docId: string; text: string }[] = [];
  const put = (c: JsonValue | undefined): void => {
    const d = get(c, "doc_id");
    const t = get(c, "text");
    if (get(c, "kind") === "put_document" && typeof d === "string" && typeof t === "string") out.push({ docId: d, text: t });
  };
  if (get(outcome, "kind") !== "value") return out;
  if (kind === "put_document") put(command);
  else if (kind === "batch") {
    const ops = get(command, "operations");
    const results = get(outcome, "result", "results");
    if (Array.isArray(ops) && Array.isArray(results)) for (let k = 0; k < results.length && k < ops.length; k++) put(ops[k]);
  }
  return out;
}

export async function verifyCut(bundle: CutBundle, adapter: HashAdapter): Promise<CutResult> {
  const failures: CutFailure[] = [];
  const states = new Map<string, CutJournalState>();
  const delivered: DeliveredExport[] = [];
  const report: CutReport = {
    format: CUT_REPORT_FORMAT,
    cut_hash: null,
    verdict: "FAIL",
    journals: [],
    exports: [],
    deliveries: [],
    across: { paragraphs_fallen: 0, observations_checked: 0 },
    failures,
    not_verified: [...CUT_NOT_VERIFIED],
  };
  const result: CutResult = { report, manifest: null, states, delivered };

  // B0
  const m = parseManifest(bundle.manifest);
  // Section 3: only a file that is one JSON object, without a repeated key, has a single value to hash. A number
  // outside specification version 3, section 2 has no canonical form either. Otherwise cut_hash stays null.
  if (m !== null && isObject(m.value) && !m.badNumber && !m.duplicateKey) report.cut_hash = await cutHash(adapter, m.value);
  // Numbers as in specification version 3, section 2; no key repeated at any depth (section 3).
  const manifest = m === null || m.badNumber || m.duplicateKey ? null : checkManifest(m.value);
  if (manifest === null) {
    failures.push({ code: "CUT_FORM" });
    return result;
  }
  result.manifest = manifest;

  // B1
  const parts = new Map<string, JournalPart>();
  const sealGrounded = new Map<string, Map<number, boolean[]>>();
  const genesisDocs = new Map<string, Map<string, Uint8Array>>();
  for (const j of manifest.journals) {
    const files = bundle.journals.get(j.name);
    const jf = (field: string): void => void failures.push({ code: "CUT_JOURNAL_MISMATCH", journal: j.name, field });
    const n = j.log_size;
    const part = journalPart(files?.journal ?? new Uint8Array(), n, j.closed);
    parts.set(j.name, part);
    const seal = part.frames[n];
    const isSealFrame = (f: JsonObject | null | undefined): boolean =>
      get(f, "body", "actor") === "kernel" && get(f, "body", "command", "kind") === "seal" && get(f, "body", "outcome", "kind") === "value";
    // 1.
    if (n < 1 || !isSealFrame(seal) || get(seal, "body", "outcome", "result", "seal_hash") !== j.seal_hash) jf("seal_hash");
    // 2.
    const previous = n >= 1 ? part.frames[n - 1] : undefined;
    if (j.wal_head !== get(seal, "body", "command", "seal", "wal_head") || j.wal_head !== get(previous, "hash")) jf("wal_head");
    // 3.
    if (j.closed) {
      const close = part.frames[n + 1];
      if (!(get(close, "body", "actor") === "kernel" && get(close, "body", "command", "kind") === "close" && get(close, "body", "outcome", "kind") === "value")) jf("closed");
    }
    // 4.
    const genesis = get(part.frames[0], "body");
    if (get(genesis, "run_id") !== j.run_id) jf("run_id");
    if (get(genesis, "rules_version") !== j.rules_version) jf("rules_version");
    // 5.
    const grounded = new Map<number, boolean[]>();
    const detailed = await verifyJournalDetailed(
      [part.bytes],
      {
        expectSeal: j.seal_hash,
        documents: files?.documents ?? [],
        onSeal: (pos, st) => void grounded.set(pos, st.grounded.slice()),
      },
      adapter,
    );
    const r = detailed.report;
    const passed = r.verdict === "PASS" && r.levels.J3.result === "PASS" && r.levels.J4a.result === "PASS";
    report.journals.push({ name: j.name, verdict: "PASS", levels: r.levels });
    if (!passed) {
      failures.push({ code: "CUT_JOURNAL_FAILED", journal: j.name, failure: r.first_failure?.code ?? null });
      continue;
    }
    sealGrounded.set(j.name, grounded);
    states.set(j.name, { name: j.name, seal_hash: j.seal_hash, log_size: n, report: r, cascade: detailed.cascade!, status: await detailed.cascade!.status() });
    // The documents of the genesis record, by doc_id, for B3.
    const docs = new Map<string, Uint8Array>();
    const byHash = new Map<string, Uint8Array>();
    for (const f of files?.documents ?? []) byHash.set(toHex(await adapter.sha256(f)), f);
    const sources = get(genesis, "source_documents");
    if (isObject(sources)) {
      for (const [docId, desc] of sources) {
        const b = byHash.get(get(desc, "raw_sha256") as string);
        if (b !== undefined) docs.set(docId, b);
      }
    }
    genesisDocs.set(j.name, docs);
  }
  for (const entry of report.journals) {
    if (failures.some((f) => f.journal === entry.name && (f.code === "CUT_JOURNAL_MISMATCH" || f.code === "CUT_JOURNAL_FAILED"))) entry.verdict = "FAIL";
  }

  // B2
  const journalOf = new Map(manifest.journals.map((j) => [j.name, j]));
  for (const e of manifest.exports) {
    const before = failures.length;
    const file = bundle.exports.get(e.name) ?? new Uint8Array();
    const state = states.get(e.journal);
    const j = journalOf.get(e.journal)!;
    let mismatch = false;
    const fail = (code: string, extra: Record<string, string> = {}): void => {
      if (code === "EXPORT_MISMATCH") {
        if (mismatch) return;
        mismatch = true;
      }
      failures.push({ code, export: e.name, ...extra });
    };
    const paragraphs = exportParagraphs(file);
    let fallen = 0;
    const sha = toHex(await adapter.sha256(file));
    const header = `${EXPORT_FORMAT} run=${exportEscape(j.run_id)} seal=${e.seal_hash} records=${e.records}\n`;
    const headerBytes = utf8(header);
    const headerOk = file.length >= headerBytes.length && headerBytes.every((b, k) => file[k] === b);
    if (sha !== e.sha256 || !headerOk) fail("EXPORT_MISMATCH");
    if (state !== undefined) {
      const seals = state.report.levels.J1.result === "PASS" ? state.report.levels.J1.seals : [];
      const seal = seals.find((s) => s.seal_hash === e.seal_hash);
      if (seal === undefined) fail("EXPORT_SEAL_UNKNOWN");
      else {
        const grounded = sealGrounded.get(e.journal)!.get(seal.n)!;
        const named: CascadeRecord[] = [];
        if (paragraphs === null) fail("EXPORT_MISMATCH");
        else {
          for (const p of paragraphs) {
            const r = p.record === null ? undefined : state.cascade.record(p.record);
            if (r === undefined || r.kind !== "claim" || r.frame >= seal.n || named.includes(r)) {
              fail("EXPORT_MISMATCH");
              continue;
            }
            named.push(r);
          }
          for (const r of named) if (grounded[r.index] !== true) fail("EXPORT_NOT_STANDING", { record: r.id });
          const ordered = [...named].sort((a, b) => a.index - b.index);
          const canonical = exportText(j.run_id, e.seal_hash, ordered.map((r) => exportParagraph(r, (id) => state.cascade.record(id))));
          const cb = utf8(canonical);
          if (cb.length !== file.length || !cb.every((b, k) => file[k] === b)) fail("EXPORT_MISMATCH");
          fallen = named.filter((r) => state.status.grounded[r.index] !== true).length;
        }
      }
    }
    report.exports.push({ name: e.name, verdict: failures.length === before ? "PASS" : "FAIL", paragraphs: paragraphs?.length ?? 0, fallen_at_cut: fallen });
  }

  // B3.1
  const exportOf = new Map(manifest.exports.map((e) => [e.name, e]));
  const deliveryFailed = new Set<ManifestDelivery>();
  for (const d of manifest.deliveries) {
    const state = states.get(d.journal);
    if (state === undefined) {
      deliveryFailed.add(d);
      continue; // B3 needs the journal's part (B1.5).
    }
    const e = exportOf.get(d.export)!;
    const part = parts.get(d.journal)!;
    const j = journalOf.get(d.journal)!;
    let bytes: Uint8Array | null = null;
    let version: string | null = null;
    const inPart = d.frame <= j.log_size + (j.closed ? 1 : 0) && d.frame < part.frames.length;
    if (inPart && d.frame === 0) {
      const desc = get(part.frames[0], "body", "source_documents", d.doc_id);
      const b = genesisDocs.get(d.journal)!.get(d.doc_id);
      if (isObject(desc) && desc.get("raw_sha256") === e.sha256 && b !== undefined) {
        bytes = b;
        version = toHex((await documentChunks(adapter, b)).version);
      }
    } else if (inPart) {
      const body = get(part.frames[d.frame], "body");
      const command = get(body, "command");
      const text = get(command, "text");
      if (get(command, "kind") === "put_document" && get(body, "outcome", "kind") === "value" && get(command, "doc_id") === d.doc_id && typeof text === "string") {
        const b = utf8(text);
        const v = toHex((await documentChunks(adapter, b)).version);
        if (toHex(await adapter.sha256(b)) === e.sha256 && get(body, "outcome", "result", "document_version") === v) {
          bytes = b;
          version = v;
        }
      }
    }
    if (bytes === null || version === null) {
      failures.push({ code: "DELIVERY_MISSING", export: d.export, journal: d.journal, doc_id: d.doc_id, frame: d.frame });
      deliveryFailed.add(d);
      continue;
    }
    const paragraphs = (exportParagraphs(bytes) ?? []).filter((p): p is { record: string; start: number; end: number } => p.record !== null);
    delivered.push({ delivery: d, bytes, version, paragraphs });
  }

  // B3.2
  const exportShas = manifest.exports;
  const undeclared: CutFailure[] = [];
  for (const j of manifest.journals) {
    if (!states.has(j.name)) continue;
    const part = parts.get(j.name)!;
    const found: { frame: number; doc_id: string; export: string }[] = [];
    const sources = get(part.frames[0], "body", "source_documents");
    if (isObject(sources)) {
      for (const [docId, desc] of sources) {
        const e = exportShas.find((x) => x.sha256 === get(desc, "raw_sha256"));
        if (e !== undefined) found.push({ frame: 0, doc_id: docId, export: e.name });
      }
    }
    for (let f = 1; f < part.frames.length; f++) {
      for (const p of putsOf(part.frames[f]!)) {
        const sha = toHex(await adapter.sha256(utf8(p.text)));
        const e = exportShas.find((x) => x.sha256 === sha);
        if (e !== undefined) found.push({ frame: f, doc_id: p.docId, export: e.name });
      }
    }
    found.sort((a, b) => a.frame - b.frame || cmp(a.doc_id, b.doc_id));
    for (const imp of found) {
      const declared = manifest.deliveries.some((d) => d.journal === j.name && d.frame === imp.frame && (imp.frame !== 0 || d.doc_id === imp.doc_id));
      if (declared) continue;
      const fl: CutFailure = { code: "CUT_UNDECLARED_DELIVERY", journal: j.name, frame: imp.frame, doc_id: imp.doc_id, export: imp.export };
      if (!undeclared.some((u) => jcs(u as unknown as JsonValue) === jcs(fl as unknown as JsonValue))) undeclared.push(fl);
    }
  }
  failures.push(...undeclared);

  // B3.3
  for (const dx of delivered) {
    const d = dx.delivery;
    const part = parts.get(d.journal)!;
    const named = (f: number): boolean =>
      (f === 0 && isObject(get(part.frames[0], "body", "source_documents", d.doc_id))) || (f > 0 && putsOf(part.frames[f]!).some((p) => p.docId === d.doc_id));
    let at: number | null = null;
    for (let f = 0; f < d.frame && at === null; f++) if (named(f)) at = d.frame;
    for (let f = d.frame + 1; f < part.frames.length && at === null; f++) if (named(f)) at = f;
    if (at !== null) {
      failures.push({ code: "CUT_IMPORT_MODIFIED", journal: d.journal, doc_id: d.doc_id, frame: at });
      deliveryFailed.add(d);
    }
  }

  // B4
  for (const dx of delivered) {
    const d = dx.delivery;
    const source = states.get(exportOf.get(d.export)!.journal);
    const target = states.get(d.journal)!;
    if (source === undefined) continue;
    const seen = new Set<string>();
    for (const p of dx.paragraphs) {
      const r = source.cascade.record(p.record);
      if (r !== undefined && source.status.grounded[r.index] === true) continue;
      report.across.paragraphs_fallen++;
      for (const o of target.cascade.accepted) {
        if (o.obs === null || o.obs.docId !== d.doc_id || o.obs.version !== dx.version) continue;
        if (!(o.obs.start < p.end && p.start < o.obs.end)) continue;
        if (!seen.has(o.id)) {
          seen.add(o.id);
          report.across.observations_checked++;
        }
        if (target.status.grounded[o.index] === true) {
          failures.push({ code: "WITHDRAWAL_NOT_DELIVERED", export: d.export, record: p.record, observation: o.id });
          deliveryFailed.add(d);
        }
      }
    }
  }
  for (const d of manifest.deliveries) report.deliveries.push({ export: d.export, journal: d.journal, verdict: deliveryFailed.has(d) ? "FAIL" : "PASS" });

  report.verdict = failures.length === 0 ? "PASS" : "FAIL";
  return result;
}

/** The human line of a cut report, built only from fixed parts. */
export function cutHumanLine(r: CutReport): string {
  const nv = `Not verified: ${r.not_verified.map((s) => s.replaceAll("_", " ")).join(", ")}.`;
  if (r.verdict === "PASS") {
    return `Cut PASS. Journals: ${r.journals.length}. Exports: ${r.exports.length}. Deliveries: ${r.deliveries.length}. Paragraphs fallen: ${r.across.paragraphs_fallen}; observations checked: ${r.across.observations_checked}. ${nv}`;
  }
  const first = r.failures[0]!;
  const fields = Object.entries(first)
    .filter(([k]) => k !== "code")
    .map(([k, v]) => `${k} ${String(v)}`)
    .join(", ");
  const more = r.failures.length > 1 ? ` (${r.failures.length} failures)` : "";
  return `Cut FAIL: ${first.code}${fields === "" ? "" : ` (${fields})`}${more}. ${nv}`;
}
