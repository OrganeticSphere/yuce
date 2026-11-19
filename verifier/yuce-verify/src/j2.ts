// Level J2 (amendment 3, P3-3 ... P3-5): the genesis record, the body of
// every frame, the request hash, and batches.

import type { HashAdapter } from "./hash.ts";
import { toHex, utf8 } from "./hash.ts";
import type { JsonObject, JsonValue } from "./json.ts";
import { hasExactKeys, isHashText, isObject, jcs } from "./json.ts";

/** E = H("R2R-REC-EMPTY/2"), the records root of a frame without records (P3-1, vector V1). */
export const EMPTY_RECORDS_ROOT = "fe7c90ca2214e168f5ffe6cccb15729c3b8a03c403e48c406441cd589fdd8c41";

export const GENESIS_FORMATS = {
  format: "r2r-audit-genesis/3",
  rules_version: "r2r-audit-rules/3",
  state_root_format: "r2r-state-root/2",
  seal_format: "r2r-seal/2",
} as const;

const GENESIS_KEYS = [
  "format",
  "rules_version",
  "state_root_format",
  "seal_format",
  "run_id",
  "source_mode",
  "source_documents",
  "questions",
  "operator_meta",
  "settings_hash",
  "manifest_hash",
  "engine_root",
  "audit_root",
  "engine_container_hex",
  "base_ontology",
] as const;

const BODY_KEYS = ["actor", "submission_id", "command", "request_hash", "outcome", "engine_root", "audit_root"] as const;

const OPAQUE_KEYS = ["doc_id", "kind", "raw_sha256"] as const;
const GIT_KEYS = ["commit", "kind", "path", "raw_sha256", "repo", "size_bytes", "revision_refs"] as const;
const GIT_OPTIONAL_KEYS = ["date"] as const;

export const OPERATOR_META_MAX_BYTES = 4096;
export const BATCH_MAX_OPERATIONS = 256;

/** Whitespace of the identifier rule (P3-1). */
const WHITESPACE = new Set([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009,
  0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);

/** P3-1: 1 to 1024 bytes of UTF-8, no control characters, at least one non-whitespace character. */
export function isIdentifier(v: JsonValue | undefined): v is string {
  if (typeof v !== "string") return false;
  const n = utf8(v).length;
  if (n < 1 || n > 1024) return false;
  let visible = false;
  for (const ch of v) {
    const c = ch.codePointAt(0)!;
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f)) return false;
    if (!WHITESPACE.has(c)) visible = true;
  }
  return visible;
}

/** The kind of a command: command.kind when command is an object and kind a string. */
export function commandKind(command: JsonValue | undefined): string | undefined {
  if (!isObject(command)) return undefined;
  const k = command.get("kind");
  return typeof k === "string" ? k : undefined;
}

/** P3-3/P3-4: {"accepted":[hash…],"error":null|object,"failed_index":null|number}. */
export function isSubmitResult(r: JsonValue | undefined): r is JsonObject {
  if (!isObject(r) || !hasExactKeys(r, ["accepted", "error", "failed_index"])) return false;
  const accepted = r.get("accepted");
  const error = r.get("error");
  const failed = r.get("failed_index");
  return (
    Array.isArray(accepted) &&
    accepted.every((x) => isHashText(x)) &&
    (error === null || isObject(error)) &&
    (failed === null || typeof failed === "number")
  );
}

/** P3-3: one of the three forms of an outcome, keys exactly as listed. */
function isOutcomeForm(o: JsonValue | undefined): o is JsonObject {
  if (!isObject(o)) return false;
  switch (o.get("kind")) {
    case "records":
      return hasExactKeys(o, ["kind", "result"]) && isSubmitResult(o.get("result"));
    case "value":
      return hasExactKeys(o, ["kind", "result"]);
    case "error":
      return hasExactKeys(o, ["kind", "error"]);
    default:
      return false;
  }
}

/** doc_id of a git_manifest description (P3-6). */
export async function gitDocumentId(adapter: HashAdapter, repo: string, commit: string, path: string, rawSha256: string): Promise<string> {
  const preimage = jcs(["R2R-AUDIT-GIT-DOCUMENT/1", repo, commit, path, rawSha256]);
  return "d_" + toHex(await adapter.sha256(utf8(preimage)));
}

/** request_hash = hex(SHA256(JCS(["r2r-audit-request/1", actor, command]))) (P3-3). */
export async function requestHash(adapter: HashAdapter, actor: JsonValue, command: JsonValue): Promise<string> {
  return toHex(await adapter.sha256(utf8(jcs(["r2r-audit-request/1", actor, command]))));
}

export interface J2Failure {
  code: string;
  detail: string;
}

export interface GenesisSummary {
  documents: number;
  settingsHash: string;
}

/** State of level J2 across frames: the pairs (actor, submission_id) seen so far. */
export class J2Checker {
  private readonly pairs = new Set<string>();
  genesis: GenesisSummary | null = null;

  constructor(private readonly adapter: HashAdapter) {}

  /** J2-1 ... J2-5 on frame 0. */
  async frame0(header: JsonObject, body: JsonObject): Promise<J2Failure | null> {
    const fail = (code: string, detail: string): J2Failure => ({ code, detail });
    // J2-1
    if (header.get("records_root") !== EMPTY_RECORDS_ROOT) return fail("GENESIS_RECORDS_ROOT", "header.records_root of frame 0 is not the empty records root");
    // J2-2
    if (!hasExactKeys(body, GENESIS_KEYS)) return fail("GENESIS_KEYS", "the genesis record must have exactly its 15 keys");
    // J2-3
    for (const [k, v] of Object.entries(GENESIS_FORMATS)) {
      if (body.get(k) !== v) return fail("GENESIS_FORMAT", `${k} is not "${v}"`);
    }
    // J2-4
    const field = (k: string, ok: boolean, what: string): J2Failure | null => (ok ? null : fail("GENESIS_FIELD", `${k} is not ${what}`));
    const mode = body.get("source_mode");
    const docs = body.get("source_documents");
    const meta = body.get("operator_meta");
    const container = body.get("engine_container_hex");
    const problem =
      field("run_id", isIdentifier(body.get("run_id")), "an identifier") ??
      field("source_mode", mode === "opaque" || mode === "git_manifest", '"opaque" or "git_manifest"') ??
      field("source_documents", isObject(docs), "an object") ??
      field("questions", Array.isArray(body.get("questions")), "an array") ??
      field("operator_meta", meta === null || (isObject(meta) && utf8(jcs(meta)).length <= OPERATOR_META_MAX_BYTES), `null or an object of at most ${OPERATOR_META_MAX_BYTES} bytes in JCS`) ??
      field("settings_hash", isHashText(body.get("settings_hash")), "a hash") ??
      field("manifest_hash", isHashText(body.get("manifest_hash")), "a hash") ??
      field("engine_root", isHashText(body.get("engine_root")), "a hash") ??
      field("audit_root", isHashText(body.get("audit_root")), "a hash") ??
      field("engine_container_hex", typeof container === "string" && /^(?:[0-9a-fA-F]{2})*$/.test(container), "an even number of hex digits") ??
      field("base_ontology", isObject(body.get("base_ontology")), "an object");
    if (problem !== null) return problem;
    // J2-5, in the JCS order of the keys
    const sources = docs as JsonObject;
    for (const key of [...sources.keys()].sort()) {
      const desc = sources.get(key)!;
      const formProblem = this.descriptionForm(mode as string, key, desc);
      if (formProblem !== null) return fail("GENESIS_FIELD", `source_documents[${JSON.stringify(key)}]: ${formProblem}`);
      const d = desc as JsonObject;
      const id =
        mode === "opaque"
          ? (d.get("doc_id") as string)
          : await gitDocumentId(this.adapter, d.get("repo") as string, d.get("commit") as string, d.get("path") as string, d.get("raw_sha256") as string);
      if (id !== key) return fail("SOURCE_ID_MISMATCH", `source_documents[${JSON.stringify(key)}] describes the document ${JSON.stringify(id)}`);
    }
    this.genesis = { documents: sources.size, settingsHash: body.get("settings_hash") as string };
    return null;
  }

  /** P3-6 and amendment 4, P4-3: the form of one description and its key; null when it is right. */
  private descriptionForm(mode: string, key: string, desc: JsonValue): string | null {
    if (!isIdentifier(key)) return "the key is not an identifier";
    if (!isObject(desc)) return "not an object";
    if (desc.get("kind") !== mode) return "its kind is not the source_mode";
    if (mode === "opaque") {
      if (!hasExactKeys(desc, OPAQUE_KEYS)) return "an opaque description has exactly the keys doc_id, kind, raw_sha256";
      if (typeof desc.get("doc_id") !== "string") return "doc_id is not a string";
      if (!isHashText(desc.get("raw_sha256"))) return "raw_sha256 is not a hash";
      return null;
    }
    for (const k of desc.keys()) {
      if (!(GIT_KEYS as readonly string[]).includes(k) && !(GIT_OPTIONAL_KEYS as readonly string[]).includes(k)) return `unknown key ${JSON.stringify(k)}`;
    }
    for (const k of GIT_KEYS) if (!desc.has(k)) return `missing key ${k}`;
    const commit = desc.get("commit");
    if (typeof commit !== "string" || !/^[0-9a-f]{40}$/.test(commit)) return "commit is not 40 characters [0-9a-f]";
    if (typeof desc.get("path") !== "string") return "path is not a string";
    if (!isHashText(desc.get("raw_sha256"))) return "raw_sha256 is not a hash";
    if (typeof desc.get("repo") !== "string") return "repo is not a string";
    if (typeof desc.get("size_bytes") !== "number") return "size_bytes is not a number";
    // P4-3: revision_refs is an object; its content and date are not parsed.
    if (!isObject(desc.get("revision_refs"))) return "revision_refs is not an object";
    return null;
  }

  /** J2-6 ... J2-11 on a frame at position i >= 1. */
  async frame(body: JsonObject): Promise<J2Failure | null> {
    const fail = (code: string, detail: string): J2Failure => ({ code, detail });
    // J2-6
    if (!hasExactKeys(body, BODY_KEYS)) return fail("BODY_KEYS", "the body must have exactly the keys actor, submission_id, command, request_hash, outcome, engine_root, audit_root");
    // J2-7
    const actor = body.get("actor")!;
    const sid = body.get("submission_id")!;
    const command = body.get("command")!;
    const outcome = body.get("outcome");
    if (!isIdentifier(actor)) return fail("BODY_FIELD", "actor is not an identifier");
    if (!isIdentifier(sid)) return fail("BODY_FIELD", "submission_id is not an identifier");
    for (const k of ["request_hash", "engine_root", "audit_root"] as const) {
      if (!isHashText(body.get(k))) return fail("BODY_FIELD", `${k} is not a hash`);
    }
    if (!isOutcomeForm(outcome)) return fail("BODY_FIELD", "outcome is not one of the three forms");
    const kind = commandKind(command);
    if (outcome.get("kind") === "records" && kind !== "submit") return fail("BODY_FIELD", 'an outcome "records" on a command that is not submit');
    // Amendment 4, P4-6: a submit has the outcome records, or error when refused whole.
    if (kind === "submit" && outcome.get("kind") === "value") return fail("BODY_FIELD", 'an outcome "value" on a submit');
    // J2-8
    if (body.get("request_hash") !== (await requestHash(this.adapter, actor, command))) {
      return fail("REQUEST_HASH_MISMATCH", 'request_hash is not hex(SHA256(JCS(["r2r-audit-request/1", actor, command])))');
    }
    // J2-9
    const pair = jcs([actor, sid]);
    if (this.pairs.has(pair)) return fail("DUPLICATE_SUBMISSION", "the pair (actor, submission_id) is used by an earlier frame");
    this.pairs.add(pair);
    // J2-10, J2-11
    if (kind === "batch" && outcome.get("kind") === "value") return batchProblem(command as JsonObject, outcome.get("result"));
    return null;
  }
}

/** J2-10 (BATCH_FORM), then J2-11 (KERNEL_OP_IN_BATCH), on an executed batch. */
function batchProblem(command: JsonObject, result: JsonValue | undefined): J2Failure | null {
  const form = (detail: string): J2Failure => ({ code: "BATCH_FORM", detail });
  for (const k of command.keys()) if (k !== "kind" && k !== "operations" && k !== "checkpoint") return form(`unknown key ${JSON.stringify(k)} in the batch`);
  const ops = command.get("operations");
  if (!Array.isArray(ops)) return form("operations is not an array");
  if (ops.length > BATCH_MAX_OPERATIONS) return form(`more than ${BATCH_MAX_OPERATIONS} operations`);
  if (!isObject(result)) return form("outcome.result is not an object");
  const results = result.get("results");
  if (!Array.isArray(results)) return form("outcome.result.results is not an array");
  if (result.get("accepted_operations") !== results.length) return form("accepted_operations is not the length of results");
  if (results.length > ops.length) return form("more results than operations");
  for (let k = 0; k < results.length; k++) {
    if (commandKind(ops[k]) === "submit" && !isSubmitResult(results[k])) return form(`results[${k}] is not the result of a submit`);
  }
  for (let k = 0; k < results.length; k++) {
    const kind = commandKind(ops[k]);
    if (kind === "batch" || kind === "seal" || kind === "close") {
      return { code: "KERNEL_OP_IN_BATCH", detail: `operation ${k} (${kind}) was executed inside a batch` };
    }
  }
  return null;
}
