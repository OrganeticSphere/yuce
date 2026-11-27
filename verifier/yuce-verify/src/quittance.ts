// A quittance given with the journal (amendment 6, P6-11): J4a reads its
// target, the record ids it lists, the seal it was cut at and, if present,
// the status rows of that seal. Everything else in it is the quittance's own
// check, not J4a's.

import type { JsonObject, JsonValue } from "./json.ts";
import { hasExactKeys, isHashText, isObject, jcs, parseJson } from "./json.ts";
import type { StatusRow } from "./j4a.ts";
import { sealFormProblem } from "./seal.ts";

export const QUITTANCE_FORMAT = "yuce-proof/1";
const SEAL_HEADER_KEYS = ["body_hash", "format", "previous", "records_root", "seq", "wal_op"] as const;

export interface ParsedQuittance {
  file: string;
  /** Why the form fails (step 1), or null. */
  problem: string | null;
  /** The position of the seal: seal.body.command.seal.log_size. */
  n: number | null;
  target: string | null;
  /** records[i].value.id, in order. */
  ids: string[];
  header: JsonObject | null;
  body: JsonObject | null;
  status: JsonValue | undefined;
}

export interface QuittanceFailure {
  code: "QUITTANCE_FORM" | "QUITTANCE_SEAL_UNKNOWN" | "QUITTANCE_STATUS_MISMATCH";
  detail: string;
}

/** Step 1 of P6-11, the form. */
export function parseQuittance(file: string, bytes: Uint8Array): ParsedQuittance {
  const q: ParsedQuittance = { file, problem: null, n: null, target: null, ids: [], header: null, body: null, status: undefined };
  const bad = (problem: string): ParsedQuittance => ({ ...q, problem });
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return bad("the file is not UTF-8");
  }
  const parsed = parseJson(text);
  if (!parsed.ok) return bad(`the file is not JSON: ${parsed.error}`);
  if (parsed.badNumber) return bad("a number that is not an integer from 0 to 2^53-1");
  const v = parsed.value;
  if (!isObject(v)) return bad("the quittance is not an object");
  if (v.get("format") !== QUITTANCE_FORMAT) return bad(`format is not "${QUITTANCE_FORMAT}"`);
  const target = v.get("target");
  if (!isHashText(target)) return bad("target is not a 64-digit id");
  const records = v.get("records");
  if (!Array.isArray(records) || records.length === 0) return bad("records is not a non-empty list");
  const ids: string[] = [];
  for (const r of records) {
    const value = isObject(r) ? r.get("value") : undefined;
    const id = isObject(value) ? value.get("id") : undefined;
    if (!isHashText(id)) return bad("an element of records has no object value with a 64-digit id");
    ids.push(id);
  }
  if (!ids.includes(target)) return bad("the target is not among the ids of records");
  const seal = v.get("seal");
  if (!isObject(seal)) return bad("seal is not an object");
  const header = seal.get("header");
  if (!isObject(header) || !hasExactKeys(header, SEAL_HEADER_KEYS)) return bad("seal.header is not an object with exactly the six keys of a header");
  const body = seal.get("body");
  const problem = sealBodyProblem(body);
  if (problem !== null) return bad(`seal.body is not a seal body: ${problem}`);
  const n = ((body as JsonObject).get("command") as JsonObject).get("seal") as JsonObject;
  return { file, problem: null, n: n.get("log_size") as number, target, ids, header, body: body as JsonObject, status: v.get("status") };
}

/**
 * P6-11, step 1: a seal body is the body of a frame of specification version 3,
 * section 6.1, with actor "kernel" and command.kind "seal", that passes the form
 * and types of J1-1. Checked before the journal is looked at.
 */
function sealBodyProblem(body: JsonValue | undefined): string | null {
  if (!isObject(body)) return "not an object";
  if (body.get("actor") !== "kernel") return 'actor is not "kernel"';
  const command = body.get("command");
  if (!isObject(command) || command.get("kind") !== "seal") return 'command.kind is not "seal"';
  return sealFormProblem(command, body.get("outcome"));
}

/**
 * Steps 2 to 4 of P6-11. `seal` is the seal frame of the journal at position n
 * (its header and body in canonical JSON) with the rows J4a computed there, or
 * undefined when the journal has no seal frame there.
 */
export function checkQuittance(q: ParsedQuittance, seal: { header: string; body: string; rows: readonly StatusRow[] } | undefined): QuittanceFailure | null {
  if (q.problem !== null || q.n === null) return { code: "QUITTANCE_FORM", detail: q.problem ?? "no seal position" };
  // 2. Which journal and which seal.
  if (seal === undefined || seal.header !== jcs(q.header!) || seal.body !== jcs(q.body!)) {
    return { code: "QUITTANCE_SEAL_UNKNOWN", detail: `the journal has no seal frame at position ${q.n} equal to the quittance's seal` };
  }
  // 3. Every listed id stands at that seal; the first that does not, in record order.
  const wanted = new Set(q.ids);
  const known = new Set<string>();
  for (const row of seal.rows) {
    if (!wanted.has(row[0])) continue;
    known.add(row[0]);
    if (row[2] !== true) return { code: "QUITTANCE_STATUS_MISMATCH", detail: `record ${row[0]} does not stand at the seal of frame ${q.n}` };
  }
  const missing = q.ids.find((id) => !known.has(id));
  if (missing !== undefined) return { code: "QUITTANCE_STATUS_MISMATCH", detail: `record ${missing} is not a record of the journal at the seal of frame ${q.n}` };
  // 4. The status rows, row for row.
  if (q.status !== undefined) {
    const given = Array.isArray(q.status) ? q.status : [];
    const count = Math.max(given.length, seal.rows.length);
    for (let k = 0; k < count; k++) {
      const mine = seal.rows[k];
      const theirs = given[k];
      if (mine !== undefined && theirs !== undefined && jcs(mine as unknown as JsonValue) === jcs(theirs)) continue;
      const id = mine !== undefined ? mine[0] : Array.isArray(theirs) && typeof theirs[0] === "string" ? theirs[0] : `#${k}`;
      return { code: "QUITTANCE_STATUS_MISMATCH", detail: `status row ${k} (record ${id}) differs from the rows computed at the seal of frame ${q.n}` };
    }
  }
  return null;
}
