// Level J3 (amendment 3, P3-6 ... P3-10): the documents, the records each
// frame accepted, the bytes of every accepted quote in its source, the record
// ids and the records root of every frame.

import type { DocumentChunks } from "./cdc.ts";
import { AnchorEncodingError, anchorBytes, documentChunks, occurrences, segmentsOf } from "./cdc.ts";
import type { HashAdapter } from "./hash.ts";
import { toHex, utf8 } from "./hash.ts";
import { RULES_VERSION_4, commandKind, isIdentifier } from "./j2.ts";
import type { JsonObject, JsonValue } from "./json.ts";
import { isObject, jcs } from "./json.ts";
import { DOMAIN, domainHash, recordsRoot } from "./trees.ts";

/** P3-7: the keys each kind of line may have. */
export const LINE_KEYS: Record<string, readonly string[]> = {
  observe: ["kind", "local_id", "doc_id", "exact_quote", "terms"],
  claim: ["kind", "local_id", "text", "subject", "predicate", "object", "stance", "as_of", "based_on"],
  relation: ["kind", "local_id", "from", "rel", "to", "based_on"],
  hypothesis: ["kind", "local_id", "text", "falsifier", "subject", "stance", "based_on"],
  question: ["kind", "local_id", "text", "about", "needed"],
  done: ["kind", "local_id", "rq_id", "directive_id", "answer_ids", "outcome", "text"],
};

/** Amendment 5, P5-2: under the rules 4 a question may also name the record it is about. */
export const QUESTION_KEYS_RULES_4: readonly string[] = [...LINE_KEYS["question"]!, "about_record"];

/** P3-10, J3-2: the keys each kind must have. */
export const LINE_REQUIRED: Record<string, readonly string[]> = {
  observe: ["doc_id", "exact_quote"],
  claim: ["text", "subject", "stance", "based_on"],
  relation: ["from", "rel", "to", "based_on"],
  hypothesis: ["text", "based_on"],
  question: ["text", "about"],
  done: ["answer_ids"],
};

const STRING_FIELDS = ["doc_id", "exact_quote", "text", "subject", "object", "stance", "from", "rel", "to", "about_record"] as const;
/** Amendment 4, P4-4: the longest exact_quote, in bytes of UTF-8. */
export const MAX_QUOTE_BYTES = 16384;
const STRING_ARRAY_FIELDS = ["terms", "based_on", "about", "answer_ids"] as const;

/** A document as identified by the SHA-256 of its bytes (P3-6). */
export type DocumentFiles = Map<string, Uint8Array>;

export interface J3Failure {
  code: string;
  detail: string;
}

/** Missing document: J3 cannot be checked (P3-6). */
export interface J3NotCheckable {
  notSupplied: string;
}

export interface AcceptedRecord {
  id: string;
  kind: string;
  /** The evidence object of an observe record; null otherwise. */
  evidence: JsonObject | null;
  /** The id the journal named, when the writer replaced it (forger only). */
  originalId: string;
}

/**
 * Hooks of the forger in the tests: write the computed ids, roots and document
 * versions into the journal instead of refusing it. Not used by `journal`.
 */
export interface RewriteOptions {
  /** Evidence of records of the original journal by their id, used when a changed quote is no longer found. */
  originalEvidence?: Map<string, JsonObject>;
}

interface CurrentDocument {
  bytes: Uint8Array;
  chunks: DocumentChunks | null;
}

type Group = { actor: string; command: JsonObject; accepted: JsonValue[] };

/** State of level J3 across frames. */
export class RecordEngine {
  private readonly current = new Map<string, CurrentDocument>();
  private readonly records: AcceptedRecord[] = [];
  private readonly byId = new Map<string, AcceptedRecord>();
  private readonly byName = new Map<string, AcceptedRecord>();
  private readonly ordinals = new Map<string, number>();
  /** Leaves of the last frame, in order (for the forger and the tests). */
  lastFrameLeaves: { L: JsonObject; leaf: Uint8Array }[] = [];
  quotes = 0;
  /** Amendment 5, P5-2: the genesis record names the rules 4. */
  private rules4 = false;

  constructor(
    private readonly adapter: HashAdapter,
    private readonly files: DocumentFiles,
    private readonly rewrite: RewriteOptions | null = null,
  ) {}

  get recordCount(): number {
    return this.records.length;
  }

  /** All records accepted so far, in order. */
  get accepted(): readonly AcceptedRecord[] {
    return this.records;
  }

  /** J3-0 on the genesis record (already checked by J2). */
  async genesis(body: JsonObject): Promise<J3Failure | J3NotCheckable | null> {
    this.rules4 = body.get("rules_version") === RULES_VERSION_4;
    const sources = body.get("source_documents") as JsonObject;
    for (const docId of [...sources.keys()].sort()) {
      const desc = sources.get(docId) as JsonObject;
      const bytes = this.files.get(desc.get("raw_sha256") as string);
      if (bytes === undefined) return { notSupplied: docId };
      if (desc.get("kind") === "git_manifest" && bytes.length !== desc.get("size_bytes")) {
        return { code: "SOURCE_IDENTITY", detail: `the file of ${JSON.stringify(docId)} has ${bytes.length} bytes, size_bytes says ${String(desc.get("size_bytes"))}` };
      }
      this.current.set(docId, { bytes, chunks: null });
    }
    return null;
  }

  /** The steps of P3-7 for a frame at position i >= 1, then J3-9. */
  async frame(header: JsonObject, body: JsonObject): Promise<J3Failure | null> {
    this.lastFrameLeaves = [];
    const leaves: Uint8Array[] = [];
    const actor = body.get("actor") as string;
    const command = body.get("command")!;
    const outcome = body.get("outcome") as JsonObject;
    const outcomeKind = outcome.get("kind");
    const kind = commandKind(command);

    if (outcomeKind === "records") {
      const result = outcome.get("result") as JsonObject;
      const f = await this.group({ actor, command: command as JsonObject, accepted: result.get("accepted") as JsonValue[] }, leaves);
      if (f !== null) return f;
    } else if (kind === "batch" && outcomeKind === "value") {
      const ops = (command as JsonObject).get("operations") as JsonValue[];
      const results = (outcome.get("result") as JsonObject).get("results") as JsonValue[];
      for (let k = 0; k < results.length; k++) {
        const op = ops[k]!;
        const opKind = commandKind(op);
        let f: J3Failure | null = null;
        if (opKind === "submit") {
          f = await this.group({ actor, command: op as JsonObject, accepted: (results[k] as JsonObject).get("accepted") as JsonValue[] }, leaves);
        } else if (opKind === "put_document") {
          f = await this.putDocument(op as JsonObject, results[k]!, (v) => this.setVersion(results[k]!, v));
        }
        if (f !== null) return f;
      }
    } else if (kind === "put_document" && outcomeKind === "value") {
      const f = await this.putDocument(command as JsonObject, outcome.get("result")!, (v) => this.setVersion(outcome.get("result")!, v));
      if (f !== null) return f;
    }

    // J3-9
    const root = toHex(await recordsRoot(this.adapter, leaves));
    if (root !== header.get("records_root")) {
      if (this.rewrite === null) return { code: "RECORDS_ROOT_MISMATCH", detail: "the records root of the frame's accepted records is not header.records_root" };
      header.set("records_root", root);
    }
    return null;
  }

  private setVersion(result: JsonValue, version: string): void {
    if (this.rewrite !== null && isObject(result)) result.set("document_version", version);
  }

  /** J3-8: a new version of a document. */
  private async putDocument(command: JsonObject, result: JsonValue, rewriteVersion: (v: string) => void): Promise<J3Failure | null> {
    const docId = command.get("doc_id");
    const text = command.get("text");
    if (!isIdentifier(docId) || typeof text !== "string" || !isObject(result)) {
      return { code: "DOCUMENT_VERSION_MISMATCH", detail: "put_document needs an identifier doc_id, a string text and an object result" };
    }
    const bytes = utf8(text);
    const chunks = await documentChunks(this.adapter, bytes);
    const version = toHex(chunks.version);
    if (result.get("document_version") !== version) {
      if (this.rewrite === null) return { code: "DOCUMENT_VERSION_MISMATCH", detail: `the version of the new bytes of ${JSON.stringify(docId)} is not document_version` };
      rewriteVersion(version);
    }
    this.current.set(docId, { bytes, chunks });
    return null;
  }

  private async chunksOf(doc: CurrentDocument): Promise<DocumentChunks> {
    doc.chunks ??= await documentChunks(this.adapter, doc.bytes);
    return doc.chunks;
  }

  /** J3-1 ... J3-7 for the records of one group. */
  private async group(g: Group, leaves: Uint8Array[]): Promise<J3Failure | null> {
    const fail = (code: string, detail: string): J3Failure => ({ code, detail });
    // J3-1
    const directive = g.command.get("directive");
    const scope = g.command.get("scope");
    const lines = g.command.get("lines");
    if (typeof directive !== "string") return fail("RECORD_FORM", "directive is not a string");
    if (!isScope(scope)) return fail("RECORD_FORM", "scope is not an object with an array of strings docs and an array of [string, number, number] ranges");
    if (!Array.isArray(lines)) return fail("RECORD_FORM", "lines is not an array");
    if (g.accepted.length > lines.length) return fail("RECORD_FORM", "more accepted ids than lines");

    for (let j = 0; j < g.accepted.length; j++) {
      const f = await this.line(g, directive, scope, lines[j]!, j, leaves);
      if (f !== null) return f;
    }
    return null;
  }

  private async line(g: Group, directive: string, scope: JsonObject, line: JsonValue, j: number, leaves: Uint8Array[]): Promise<J3Failure | null> {
    const fail = (code: string, detail: string): J3Failure => ({ code, detail: `line ${j}: ${detail}` });
    // J3-2
    const form = lineFormProblem(line, this.rules4);
    if (form !== null) return fail("RECORD_FORM", form);
    const l = line as JsonObject;
    const kind = l.get("kind") as string;
    // J3-2a (amendment 4, P4-2): a local name is used once by an author in a task.
    if (this.byName.has(jcs([g.actor, directive, l.get("local_id")!]))) {
      return fail("DUPLICATE_LOCAL_ID", `local_id ${quoted(l.get("local_id") as string)} already names an accepted record of this actor and directive`);
    }

    // J3-3, in the order based_on, from, to, answer_ids
    const resolve = (name: string, where: (newRef: string) => void): AcceptedRecord | null => this.resolve(g.actor, directive, name, where);
    const supports: AcceptedRecord[] = [];
    let from: AcceptedRecord | null = null;
    let to: AcceptedRecord | null = null;
    if (kind === "claim" || kind === "relation" || kind === "hypothesis") {
      const arr = l.get("based_on") as JsonValue[];
      for (let k = 0; k < arr.length; k++) {
        const r = resolve(arr[k] as string, (v) => (arr[k] = v));
        if (r === null) return fail("UNRESOLVED_REFERENCE", `based_on ${quoted(arr[k] as string)} does not resolve`);
        supports.push(r);
      }
    }
    if (kind === "relation") {
      from = resolve(l.get("from") as string, (v) => l.set("from", v));
      if (from === null) return fail("UNRESOLVED_REFERENCE", `from ${quoted(l.get("from") as string)} does not resolve`);
      to = resolve(l.get("to") as string, (v) => l.set("to", v));
      if (to === null) return fail("UNRESOLVED_REFERENCE", `to ${quoted(l.get("to") as string)} does not resolve`);
    }
    if (kind === "done") {
      const arr = l.get("answer_ids") as JsonValue[];
      for (let k = 0; k < arr.length; k++) {
        const r = resolve(arr[k] as string, (v) => (arr[k] = v));
        if (r === null) return fail("UNRESOLVED_REFERENCE", `answer_ids ${quoted(arr[k] as string)} does not resolve`);
        supports.push(r);
      }
    }
    // Amendment 5, P5-2: the record a question is about. An address in the body, not a ground of the record.
    let about: AcceptedRecord | null = null;
    if (kind === "question" && l.has("about_record")) {
      about = resolve(l.get("about_record") as string, (v) => l.set("about_record", v));
      if (about === null) return fail("UNRESOLVED_REFERENCE", `about_record ${quoted(l.get("about_record") as string)} does not resolve`);
    }

    // J3-4 ... J3-6, and the evidence of an observe line
    let evidence: JsonObject | null = null;
    if (kind === "observe") {
      const docId = l.get("doc_id") as string;
      const doc = this.current.get(docId);
      if (doc === undefined) return fail("UNKNOWN_DOCUMENT", `document ${quoted(docId)} is not among the current documents`);
      const q = utf8(l.get("exact_quote") as string);
      const found = occurrences(doc.bytes, q, 2);
      let fallback: JsonObject | undefined;
      if (found.length !== 1 && this.rewrite?.originalEvidence !== undefined) fallback = this.rewrite.originalEvidence.get(g.accepted[j] as string);
      if (fallback !== undefined) {
        evidence = fallback;
      } else {
        if (found.length === 0) return fail("QUOTE_NOT_IN_SOURCE", `the quote has no occurrence in the current bytes of ${quoted(docId)}`);
        if (found.length > 1) return fail("QUOTE_AMBIGUOUS", `the quote occurs more than once in ${quoted(docId)}`);
        const start = found[0]!;
        const end = start + q.length;
        if (!inScope(scope, docId, start, end, doc.bytes.length)) return fail("QUOTE_OUTSIDE_SCOPE", `the quote [${start}, ${end}) of ${quoted(docId)} is outside the scope of the task`);
        const chunks = await this.chunksOf(doc);
        let bytes: Uint8Array;
        try {
          bytes = await anchorBytes(this.adapter, docId, q, segmentsOf(chunks, start, end));
        } catch (e) {
          if (e instanceof AnchorEncodingError) return fail("RECORD_ID_MISMATCH", `the evidence anchor cannot be written: ${e.message}`);
          throw e;
        }
        evidence = new Map<string, JsonValue>([
          ["id", toHex(await this.adapter.sha256(bytes))],
          ["span", [start, end]],
          ["version", toHex(chunks.version)],
        ]);
      }
    }

    // The body: the line without local_id, references replaced (P3-7).
    const body: JsonObject = new Map();
    for (const [k, v] of l) if (k !== "local_id") body.set(k, v);
    const at = (r: AcceptedRecord): string => "@" + r.id;
    if (Array.isArray(l.get("based_on")) && (l.get("based_on") as JsonValue[]).length > 0 && kind !== "done") body.set("based_on", supports.map(at));
    if (kind === "relation") {
      body.set("from", at(from!));
      body.set("to", at(to!));
    }
    if (kind === "done") body.set("answer_ids", supports.map(at));
    if (about !== null) body.set("about_record", at(about));
    if (evidence !== null) {
      body.set("evidence_id", evidence.get("id")!);
      body.set("document_version", evidence.get("version")!);
    }

    // J3-7: the record id
    const ordinalKey = jcs([g.actor, directive]);
    const ordinal = (this.ordinals.get(ordinalKey) ?? 0) + 1;
    const id = toHex(await this.adapter.sha256(utf8(jcs(["r2r.audit.record.v1", g.actor, directive, ordinal, body]))));
    const named = g.accepted[j] as string;
    if (id !== named) {
      if (this.rewrite === null) return fail("RECORD_ID_MISMATCH", "the record id computed from the line is not the id in the outcome");
      g.accepted[j] = id;
    }

    // The record is accepted: remember it for the next lines and frames.
    this.ordinals.set(ordinalKey, ordinal);
    const record: AcceptedRecord = { id, kind, evidence, originalId: named };
    this.records.push(record);
    this.byId.set(id, record);
    this.byName.set(jcs([g.actor, directive, l.get("local_id")!]), record);
    if (kind === "observe") this.quotes++;

    const L = recordValue(record, this.records.length, g.actor, directive, l, body, supports, from, to);
    const leaf = await domainHash(this.adapter, DOMAIN.recordLeaf, utf8(jcs(L)));
    leaves.push(leaf);
    this.lastFrameLeaves.push({ L, leaf });
    return null;
  }

  /** P3-7: a reference by local name, else by "@" and 16 to 64 hex digits. */
  private resolve(actor: string, directive: string, name: string, rewriteRef: (newRef: string) => void): AcceptedRecord | null {
    const byName = this.byName.get(jcs([actor, directive, name]));
    if (byName !== undefined) return byName;
    const r = uniqueByPrefix(this.records, (x) => x.id, name);
    if (r !== null || this.rewrite === null) return r;
    // Forger: the line names an id of the original journal; point it at the new id.
    const old = uniqueByPrefix(this.records, (x) => x.originalId, name);
    if (old !== null) rewriteRef("@" + old.id);
    return old;
  }
}

/**
 * P3-7, rule 2: name is "@" and 16 to 64 hex digits in any case; after
 * lowercasing, exactly one id among the items must start with them.
 */
export function uniqueByPrefix<T>(items: readonly T[], id: (t: T) => string, name: string): T | null {
  if (!/^@[0-9a-fA-F]{16,64}$/.test(name)) return null;
  const prefix = name.slice(1).toLowerCase();
  let found: T | null = null;
  for (const item of items) {
    if (id(item).startsWith(prefix)) {
      if (found !== null) return null;
      found = item;
    }
  }
  return found;
}

function quoted(s: string): string {
  return JSON.stringify(s.length > 80 ? s.slice(0, 80) + "..." : s);
}

function isScope(v: JsonValue | undefined): v is JsonObject {
  if (!isObject(v)) return false;
  const docs = v.get("docs");
  const ranges = v.get("ranges");
  return (
    Array.isArray(docs) &&
    docs.every((d) => typeof d === "string") &&
    Array.isArray(ranges) &&
    ranges.every((r) => Array.isArray(r) && r.length === 3 && typeof r[0] === "string" && typeof r[1] === "number" && typeof r[2] === "number")
  );
}

/** P3-8: the document is in scope.docs, and inside a range if ranges are given. */
function inScope(scope: JsonObject, docId: string, start: number, end: number, length: number): boolean {
  const docs = scope.get("docs") as JsonValue[];
  if (!docs.includes(docId)) return false;
  const ranges = scope.get("ranges") as JsonValue[][];
  if (ranges.length === 0) return true;
  return ranges.some(([d, a, z]) => d === docId && (a as number) <= start && end <= (z as number) && (a as number) < (z as number) && (z as number) <= length);
}

/** J3-2: null when the line has the right form. `rules4`: the journal names the rules 4 (amendment 5, P5-2). */
export function lineFormProblem(line: JsonValue, rules4 = false): string | null {
  if (!isObject(line)) return "the line is not an object";
  const kind = line.get("kind");
  if (typeof kind !== "string" || !Object.hasOwn(LINE_KEYS, kind)) return "kind is not one of the six kinds";
  const allowed = rules4 && kind === "question" ? QUESTION_KEYS_RULES_4 : LINE_KEYS[kind]!;
  for (const k of line.keys()) if (!allowed.includes(k)) return `key ${JSON.stringify(k)} is not allowed for ${kind}`;
  if (typeof line.get("local_id") !== "string") return "local_id is not a string";
  for (const k of STRING_FIELDS) if (line.has(k) && typeof line.get(k) !== "string") return `${k} is not a string`;
  for (const k of STRING_ARRAY_FIELDS) {
    if (!line.has(k)) continue;
    const v = line.get(k);
    if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) return `${k} is not an array of strings`;
  }
  for (const k of LINE_REQUIRED[kind]!) if (!line.has(k)) return `${kind} needs ${k}`;
  const quote = line.get("exact_quote");
  if (typeof quote === "string" && utf8(quote).length > MAX_QUOTE_BYTES) return `exact_quote is longer than ${MAX_QUOTE_BYTES} bytes`;
  return null;
}

/** P3-7: terms, in order of appearance, without repeats. */
function termsOf(kind: string, line: JsonObject): string[] {
  const raw: string[] = [];
  if (kind === "observe") raw.push(...((line.get("terms") as string[] | undefined) ?? []));
  else if (kind === "claim") {
    raw.push(line.get("subject") as string);
    if (line.has("object")) raw.push(line.get("object") as string);
  } else if (kind === "hypothesis") {
    if (line.has("subject")) raw.push(line.get("subject") as string);
  } else if (kind === "question") raw.push(...(line.get("about") as string[]));
  return raw.filter((t, k) => raw.indexOf(t) === k);
}

/** P3-7: the value L of an accepted record. */
function recordValue(
  record: AcceptedRecord,
  seq: number,
  actor: string,
  directive: string,
  line: JsonObject,
  body: JsonObject,
  supports: AcceptedRecord[],
  from: AcceptedRecord | null,
  to: AcceptedRecord | null,
): JsonObject {
  const kind = record.kind;
  const str = (k: string): JsonValue => (line.has(k) ? (line.get(k) as string) : null);
  let text: JsonValue = null;
  if (kind === "claim" || kind === "hypothesis" || kind === "question") text = line.get("text") as string;
  else if (kind === "done") text = str("text");
  let stance: JsonValue = null;
  if (kind === "claim") stance = line.get("stance") as string;
  else if (kind === "hypothesis") stance = str("stance");

  const L: JsonObject = new Map<string, JsonValue>([
    ["id", record.id],
    ["seq", seq],
    ["kind", kind],
    ["author", actor],
    ["directive", directive],
    ["doc_id", kind === "observe" ? (line.get("doc_id") as string) : null],
    ["quote", kind === "observe" ? (line.get("exact_quote") as string) : null],
    ["terms", termsOf(kind, line)],
    ["text", text],
    ["stance", stance],
    ["based_on", supports.map((s) => s.id)],
    ["ends", kind === "relation" ? [from!.id, line.get("rel") as string, to!.id] : null],
    ["body", body],
  ]);
  if (record.evidence !== null) L.set("evidence", record.evidence);
  if (supports.length > 0) {
    L.set(
      "grounds",
      supports.map((s) => {
        const g: JsonObject = new Map<string, JsonValue>([["id", s.id]]);
        if (s.kind === "observe" && s.evidence !== null) g.set("evidence", s.evidence);
        return g;
      }),
    );
  }
  return L;
}
