// B3: the substitution matrix for J2 and J3 on valid/kinds-batch-put.wal (and,
// for git_manifest descriptions, valid/baicalin-n3-shard1.wal). Every case
// changes the journal, recomputes the frame hashes, request hashes and seals
// (test/forge.mjs), and runs J0-J3 with the documents.
import { test } from "node:test";
import assert from "node:assert/strict";
import { getPath, loadFrames, rechain, saveFrames, setPath } from "./forge.mjs";
import { OTHER_HASH, docsOf, outcome, readRoom, textOf, verify, yv } from "./helpers.mjs";

const KBP = textOf(readRoom("inputs/valid/kinds-batch-put.wal"));
const KBP_DOCS = docsOf("valid/kinds-batch-put.docs");
const BAI = textOf(readRoom("inputs/valid/baicalin-n3-shard1.wal"));
const BAI_DOCS = docsOf("valid/baicalin-n3-shard1.docs");

const cases = [];
const PASS = { verdict: "PASS" };
const fail = (level, code, frame) => ({ verdict: "FAIL", level, code, frame });
/** One case: edit the parsed frames, recompute per `how`, verify with the documents. */
const add = (name, edit, want, { how = { reseal: true }, base = KBP, docs = KBP_DOCS } = {}) => cases.push({ name, edit, want, how, base, docs });

const del = (path) => (f) => {
  const keys = path.split(".");
  const last = keys.pop();
  getPath(f, keys.join(".")).delete(last);
};
const set = (path, value) => (f) => setPath(f, path, value);
const both = (...edits) => (f) => edits.forEach((e) => e(f));

// ---------------------------------------------------------------------------
// J2, frame 0: every key of the genesis record (P3-3, J2-1 ... J2-5)
// ---------------------------------------------------------------------------
const GENESIS = loadFrames(KBP)[0].get("body");
const WRONG_KIND = {
  format: 3,
  rules_version: "r2r-audit-rules/2",
  state_root_format: "r2r-state-root/1",
  seal_format: "r2r-seal/1",
  source_mode: "other",
  source_documents: [],
  questions: new Map(),
  operator_meta: "a note",
  settings_hash: GENESIS.get("settings_hash").toUpperCase(),
  manifest_hash: "x",
  engine_root: 5,
  audit_root: null,
  engine_container_hex: "abc",
  base_ontology: [],
};
const FORMAT_KEYS = new Set(["format", "rules_version", "state_root_format", "seal_format"]);
for (const key of GENESIS.keys()) {
  // run_id is also J1-9's: removing it is refused by J1 first.
  add(`genesis: ${key} removed`, del(`0.body.${key}`), key === "run_id" ? fail("J1", "SEAL_RUN_ID", 6) : fail("J2", "GENESIS_KEYS", 0));
  if (key !== "run_id") add(`genesis: ${key} of a wrong kind`, set(`0.body.${key}`, WRONG_KIND[key]), fail("J2", FORMAT_KEYS.has(key) ? "GENESIS_FORMAT" : "GENESIS_FIELD", 0));
}
add("genesis: an extra key", set("0.body.extra", 1), fail("J2", "GENESIS_KEYS", 0));
add("genesis: run_id not an identifier (the seal names the same, J1 passes)", both(set("0.body.run_id", "   "), set("6.body.command.seal.run_id", "   ")), fail("J2", "GENESIS_FIELD", 0));
add("genesis: run_id with a control character", both(set("0.body.run_id", "run\u0007"), set("6.body.command.seal.run_id", "run\u0007")), fail("J2", "GENESIS_FIELD", 0));
add("genesis: header.records_root not empty", set("0.header.records_root", OTHER_HASH), fail("J2", "GENESIS_RECORDS_ROOT", 0));
add("genesis: operator_meta of 4096 bytes in JCS passes", set("0.body.operator_meta", new Map([["note", "x".repeat(4096 - 11)]])), PASS);
add("genesis: operator_meta of 4097 bytes in JCS", set("0.body.operator_meta", new Map([["note", "x".repeat(4097 - 11)]])), fail("J2", "GENESIS_FIELD", 0));
add("genesis: operator_meta null passes", set("0.body.operator_meta", null), PASS);
add("genesis: engine_container_hex in capitals passes", set("0.body.engine_container_hex", "ABCDEF"), PASS);
add("genesis: engine_container_hex empty passes", set("0.body.engine_container_hex", ""), PASS);
add("genesis: engine_container_hex not hex", set("0.body.engine_container_hex", "zz"), fail("J2", "GENESIS_FIELD", 0));
// Descriptions (P3-6, J2-5); doc_ids contain dots, so no dotted paths here.
const sources = (f) => f[0].get("body").get("source_documents");
const descB = (f) => sources(f).get("vector-b.txt");
add("description: raw_sha256 removed", (f) => descB(f).delete("raw_sha256"), fail("J2", "GENESIS_FIELD", 0));
add("description: an extra key", (f) => descB(f).set("extra", 1), fail("J2", "GENESIS_FIELD", 0));
add("description: kind not the source_mode", (f) => descB(f).set("kind", "git_manifest"), fail("J2", "GENESIS_FIELD", 0));
add("description: raw_sha256 in capitals", (f) => descB(f).set("raw_sha256", descB(f).get("raw_sha256").toUpperCase()), fail("J2", "GENESIS_FIELD", 0));
add("description: doc_id not its key", (f) => descB(f).set("doc_id", "vector-z.txt"), fail("J2", "SOURCE_ID_MISMATCH", 0));
add("description: not an object", (f) => sources(f).set("vector-b.txt", "vector-b.txt"), fail("J2", "GENESIS_FIELD", 0));
add("description: a document of the run removed from the genesis", (f) => sources(f).delete("vector-c.txt"), fail("J3", "UNKNOWN_DOCUMENT", 1));
// Amendment 4, P4-3: a key of source_documents is an identifier, checked before the id.
const renameDoc = (from, to) => (f) => {
  const m = sources(f);
  const d = m.get(from);
  d.set("doc_id", to);
  m.delete(from);
  m.set(to, d);
};
add("description: a key that is not an identifier (control character)", renameDoc("vector-c.txt", "vector-c\u0001"), fail("J2", "GENESIS_FIELD", 0));
add("description: a key of whitespace only", renameDoc("vector-c.txt", "\u00a0 "), fail("J2", "GENESIS_FIELD", 0));
add("description: a key of 1025 bytes", renameDoc("vector-c.txt", "d".repeat(1025)), fail("J2", "GENESIS_FIELD", 0));
// git_manifest descriptions, on baicalin-n3-shard1.wal
const gitKey = [...loadFrames(BAI)[0].get("body").get("source_documents").keys()].sort()[0];
const g = (rest) => `0.body.source_documents.${gitKey}.${rest}`;
const onBai = { base: BAI, docs: BAI_DOCS };
add("git description: commit changed", set(g("commit"), "0".repeat(40)), fail("J2", "SOURCE_ID_MISMATCH", 0), onBai);
add("git description: path changed", set(g("path"), "other.md"), fail("J2", "SOURCE_ID_MISMATCH", 0), onBai);
add("git description: commit in capitals", (f) => setPath(f, g("commit"), getPath(f, g("commit")).toUpperCase()), fail("J2", "GENESIS_FIELD", 0), onBai);
add("git description: size_bytes not a number", set(g("size_bytes"), "1"), fail("J2", "GENESIS_FIELD", 0), onBai);
add("git description: revision_refs removed", del(g("revision_refs")), fail("J2", "GENESIS_FIELD", 0), onBai);
add("git description: date removed passes (not always present)", del(g("date")), PASS, onBai);
add("git description: date is not parsed", set(g("date"), 5), PASS, onBai);
add("git description: revision_refs content is not parsed", set(g("revision_refs"), new Map([["any", [1, 2]]])), PASS, onBai);
add("git description: revision_refs not an object (amendment 4, P4-3)", set(g("revision_refs"), "x"), fail("J2", "GENESIS_FIELD", 0), onBai);
add("git description: an unknown key", set(g("extra"), 1), fail("J2", "GENESIS_FIELD", 0), onBai);
add("git description: size_bytes not the size of the file", (f) => setPath(f, g("size_bytes"), getPath(f, g("size_bytes")) + 1), fail("J3", "SOURCE_IDENTITY", 0), onBai);

// ---------------------------------------------------------------------------
// J2, frames >= 1: the 7 keys of a body, request_hash, pairs, batches
// ---------------------------------------------------------------------------
const BODY = loadFrames(KBP)[1].get("body");
const WRONG_BODY = { actor: "", submission_id: "w1\u0000", command: "a string", request_hash: "x", outcome: { kind: "value" }, engine_root: 1, audit_root: "X" };
for (const key of BODY.keys()) {
  add(`body: ${key} removed`, del(`1.body.${key}`), fail("J2", "BODY_KEYS", 1));
  const value = WRONG_BODY[key];
  const wrong = typeof value === "object" && value !== null ? new Map(Object.entries(value)) : value;
  add(`body: ${key} of a wrong kind`, set(`1.body.${key}`, wrong), fail("J2", "BODY_FIELD", 1), key === "request_hash" ? { how: { reseal: true, requestHash: false } } : {});
}
add("body: an extra key", set("1.body.extra", 1), fail("J2", "BODY_KEYS", 1));
add("body: actor of 1025 bytes", set("1.body.actor", "w".repeat(1025)), fail("J2", "BODY_FIELD", 1));
add("body: actor of 1024 bytes passes J2 (J3 then sees another author)", set("1.body.actor", "w".repeat(1024)), fail("J3", "RECORD_ID_MISMATCH", 1));
add("body: actor of whitespace only (U+3000)", set("1.body.actor", "\u3000 \u00a0"), fail("J2", "BODY_FIELD", 1));
add("body: actor with U+0085", set("1.body.actor", "w\u0085"), fail("J2", "BODY_FIELD", 1));
add("body: request_hash not of the formula", set("1.body.request_hash", OTHER_HASH), fail("J2", "REQUEST_HASH_MISMATCH", 1), { how: { reseal: true, requestHash: false } });
add("body: request_hash of the seal frame", set("6.body.request_hash", OTHER_HASH), fail("J2", "REQUEST_HASH_MISMATCH", 6), { how: { reseal: true, requestHash: false } });
add("body: the pair (actor, submission_id) repeated", set("2.body.submission_id", "seed"), fail("J2", "DUPLICATE_SUBMISSION", 2));
add("body: the same submission_id from another actor passes", set("3.body.submission_id", "seed"), PASS);
add("outcome: records on a command that is not submit", set("5.body.outcome", new Map([["kind", "records"], ["result", new Map([["accepted", []], ["error", null], ["failed_index", null]])]])), fail("J2", "BODY_FIELD", 5));
add("outcome: records with a non-hash id", set("1.body.outcome.result.accepted.0", "x"), fail("J2", "BODY_FIELD", 1));
add("outcome: records with an extra key", set("1.body.outcome.result.extra", 1), fail("J2", "BODY_FIELD", 1));
add("outcome: records with failed_index a string", set("1.body.outcome.result.failed_index", "2"), fail("J2", "BODY_FIELD", 1));
add("outcome: an unknown kind", set("5.body.outcome.kind", "done"), fail("J2", "BODY_FIELD", 5));
add("outcome: error form passes J2; a refused frame accepts no records (J3 root)", set("1.body.outcome", new Map([["kind", "error"], ["error", new Map([["code", "X"]])]])), fail("J3", "RECORDS_ROOT_MISMATCH", 1));
add("outcome: value on a submit (amendment 4, P4-6)", set("1.body.outcome", new Map([["kind", "value"], ["result", null]])), fail("J2", "BODY_FIELD", 1));
// Batches (P3-4, J2-10, J2-11) on frame 4: [submit, put_document, submit], all executed.
const op = (k) => `4.body.command.operations.${k}`;
for (const kind of ["seal", "close", "batch"]) {
  add(`batch: an executed ${kind} operation`, set(`${op(0)}.kind`, kind), fail("J2", "KERNEL_OP_IN_BATCH", 4));
  add(`batch: a ${kind} operation refused by the kernel passes`, (f) => getPath(f, "4.body.command.operations").push(new Map([["kind", kind]])), PASS);
}
add("batch: an unknown key", set("4.body.command.extra", 1), fail("J2", "BATCH_FORM", 4));
add("batch: operations not an array", set("4.body.command.operations", "x"), fail("J2", "BATCH_FORM", 4));
add("batch: 256 operations pass", (f) => { const ops = getPath(f, "4.body.command.operations"); while (ops.length < 256) ops.push(new Map([["kind", "noop"]])); }, PASS);
add("batch: 257 operations", (f) => { const ops = getPath(f, "4.body.command.operations"); while (ops.length < 257) ops.push(new Map([["kind", "noop"]])); }, fail("J2", "BATCH_FORM", 4));
add("batch: accepted_operations not the length of results", set("4.body.outcome.result.accepted_operations", 2), fail("J2", "BATCH_FORM", 4));
add("batch: more results than operations", (f) => getPath(f, "4.body.outcome.result.results").push(new Map()), fail("J2", "BATCH_FORM", 4));
add("batch: a submit result of a wrong form", del("4.body.outcome.result.results.0.error"), fail("J2", "BATCH_FORM", 4));
add("batch: results not an array", set("4.body.outcome.result.results", new Map()), fail("J2", "BATCH_FORM", 4));
add("batch: refused whole (error outcome) is not a batch result", set("4.body.outcome", new Map([["kind", "error"], ["error", null]])), fail("J3", "RECORDS_ROOT_MISMATCH", 4));

// ---------------------------------------------------------------------------
// J3: every key of every kind of line (P3-7, J3-2), on the lines of frames 1 and 2
// ---------------------------------------------------------------------------
const LINES = [
  [1, 0],
  [1, 1],
  [1, 2],
  [1, 3],
  [1, 4],
  [1, 5],
  [2, 0],
  [2, 1],
];
const TYPED_STRING = new Set(["doc_id", "exact_quote", "text", "subject", "object", "stance", "from", "rel", "to"]);
const TYPED_ARRAY = new Set(["terms", "based_on", "about", "answer_ids"]);
const frames = loadFrames(KBP);
const kindsSeen = new Set();
for (const [fr, j] of LINES) {
  const line = getPath(frames[fr], `body.command.lines.${j}`);
  const kind = line.get("kind");
  kindsSeen.add(kind);
  const path = `${fr}.body.command.lines.${j}`;
  const required = new Set(["kind", "local_id", ...yv.LINE_REQUIRED[kind]]);
  for (const key of yv.LINE_KEYS[kind]) {
    if (line.has(key)) {
      add(`line ${fr}/${j} (${kind}): ${key} removed`, del(`${path}.${key}`), fail("J3", required.has(key) ? "RECORD_FORM" : "RECORD_ID_MISMATCH", fr));
    }
    const typed = TYPED_STRING.has(key) || TYPED_ARRAY.has(key) || key === "kind" || key === "local_id";
    const wrong = TYPED_STRING.has(key) || key === "kind" || key === "local_id" ? 5 : TYPED_ARRAY.has(key) ? "x" : new Map([["x", 1]]);
    add(`line ${fr}/${j} (${kind}): ${key} of a wrong type`, set(`${path}.${key}`, wrong), fail("J3", typed ? "RECORD_FORM" : "RECORD_ID_MISMATCH", fr));
  }
  add(`line ${fr}/${j} (${kind}): a key not allowed`, set(`${path}.extra`, 1), fail("J3", "RECORD_FORM", fr));
}
add("line: kind not one of the six", set("1.body.command.lines.5.kind", "remark"), fail("J3", "RECORD_FORM", 1));
add("line: an array of strings with a number", set("1.body.command.lines.0.terms.0", 7), fail("J3", "RECORD_FORM", 1));
add("line: not an object", set("1.body.command.lines.0", "o1"), fail("J3", "RECORD_FORM", 1));
add("line: a rejected line is not checked", set("2.body.command.lines.2.extra", 1), PASS);
// J3-2a (amendment 4, P4-2): a local name is used once per (actor, directive)
add("local_id: repeated in the same group", set("1.body.command.lines.2.local_id", "o1"), fail("J3", "DUPLICATE_LOCAL_ID", 1));
add("local_id: repeated in a later frame of the same actor and directive", set("2.body.command.lines.0.local_id", "c1"), fail("J3", "DUPLICATE_LOCAL_ID", 2));
add("local_id: the same name in another directive passes", both(set("3.body.command.lines.0.local_id", "o1"), set("3.body.command.lines.1.based_on.1", "o1")), PASS);
add("local_id: a rejected line may repeat a name", set("2.body.command.lines.2.local_id", "o1"), PASS);
// J3-2 (amendment 4, P4-4): exact_quote at most 16384 bytes
add("quote: 16384 bytes passes the form (then it is not in the source)", set("1.body.command.lines.0.exact_quote", "q".repeat(16384)), fail("J3", "QUOTE_NOT_IN_SOURCE", 1));
add("quote: 16385 bytes", set("1.body.command.lines.0.exact_quote", "q".repeat(16385)), fail("J3", "RECORD_FORM", 1));
add("quote: 16385 bytes of UTF-8 in fewer characters", set("1.body.command.lines.0.exact_quote", "\u00e9".repeat(8192) + "q"), fail("J3", "RECORD_FORM", 1));
// J3-1
add("group: directive not a string", set("1.body.command.directive", 1), fail("J3", "RECORD_FORM", 1));
add("group: scope without ranges", del("1.body.command.scope.ranges"), fail("J3", "RECORD_FORM", 1));
add("group: a range not [string, number, number]", set("3.body.command.scope.ranges.0", ["vector-a.txt", 678]), fail("J3", "RECORD_FORM", 3));
add("group: more accepted ids than lines", (f) => getPath(f, "3.body.outcome.result.accepted").push(OTHER_HASH), fail("J3", "RECORD_FORM", 3));

// References (P3-7, J3-3)
add("reference: a local name that does not exist", set("1.body.command.lines.2.based_on.0", "o7"), fail("J3", "UNRESOLVED_REFERENCE", 1));
add("reference: a name of another directive", set("3.body.command.lines.1.based_on.1", "o1"), fail("J3", "UNRESOLVED_REFERENCE", 3));
add("reference: a name before it is accepted (a later line)", set("1.body.command.lines.2.based_on.0", "c2"), fail("J3", "UNRESOLVED_REFERENCE", 1));
add("reference: '@' and 15 hex digits", set("3.body.command.lines.1.based_on.0", "@479c73e57790c6f"), fail("J3", "UNRESOLVED_REFERENCE", 3));
add("reference: '@' and 65 hex digits", set("3.body.command.lines.1.based_on.0", "@479c73e57790c6f3e0ca560b92486076da84a5689cefb15a26f0ed4fac7cab7e0"), fail("J3", "UNRESOLVED_REFERENCE", 3));
add("reference: '@' and a non-hex digit", set("3.body.command.lines.1.based_on.0", "@479c73e57790c6fg"), fail("J3", "UNRESOLVED_REFERENCE", 3));
add("reference: '@' prefix of no accepted id", set("3.body.command.lines.1.based_on.0", "@0000000000000000"), fail("J3", "UNRESOLVED_REFERENCE", 3));
add("reference: '@' in capitals resolves", set("3.body.command.lines.1.based_on.0", "@479C73E57790C6F3"), PASS);
add("reference: '@' with the full id resolves", set("3.body.command.lines.1.based_on.0", "@479c73e57790c6f3e0ca560b92486076da84a5689cefb15a26f0ed4fac7cab7e"), PASS);
add("reference: relation from not resolved", set("2.body.command.lines.0.from", "c9"), fail("J3", "UNRESOLVED_REFERENCE", 2));
add("reference: relation to not resolved", set("2.body.command.lines.0.to", "c9"), fail("J3", "UNRESOLVED_REFERENCE", 2));
add("reference: done answer_ids not resolved", set("2.body.command.lines.1.answer_ids.0", "c9"), fail("J3", "UNRESOLVED_REFERENCE", 2));

// Quotes (P3-8, J3-4 ... J3-6)
add("quote: not in the source", set("1.body.command.lines.0.exact_quote", "a fact no document states"), fail("J3", "QUOTE_NOT_IN_SOURCE", 1));
add("quote: empty", set("1.body.command.lines.0.exact_quote", ""), fail("J3", "QUOTE_NOT_IN_SOURCE", 1));
add("quote: twice in the source", set("1.body.command.lines.0.exact_quote", "the vector document states fact number"), fail("J3", "QUOTE_AMBIGUOUS", 1));
add("quote: unknown document", set("1.body.command.lines.0.doc_id", "vector-z.txt"), fail("J3", "UNKNOWN_DOCUMENT", 1));
add("quote: document outside scope.docs", (f) => setPath(f, "1.body.command.scope.docs", ["vector-b.txt", "vector-c.txt"]), fail("J3", "QUOTE_OUTSIDE_SCOPE", 1));
add("quote: outside the ranges of the task", set("3.body.command.scope.ranges", [["vector-a.txt", 678, 700]]), fail("J3", "QUOTE_OUTSIDE_SCOPE", 3));
add("quote: a range of another document", set("3.body.command.scope.ranges", [["vector-b.txt", 0, 9000]]), fail("J3", "QUOTE_OUTSIDE_SCOPE", 3));
add("quote: a range beyond the document", set("3.body.command.scope.ranges", [["vector-a.txt", 0, 9251]]), fail("J3", "QUOTE_OUTSIDE_SCOPE", 3));
add("quote: a range to the end of the document passes", set("3.body.command.scope.ranges", [["vector-a.txt", 0, 9250]]), PASS);
add("quote: the new version of a document is used after put_document", set(`${op(1)}.kind`, "put_documentx"), fail("J3", "QUOTE_NOT_IN_SOURCE", 4));

// put_document, ids, roots (J3-7 ... J3-9)
add("put_document: another version in its result", set("4.body.outcome.result.results.1.document_version", OTHER_HASH), fail("J3", "DOCUMENT_VERSION_MISMATCH", 4));
add("put_document: text not a string", set(`${op(1)}.text`, 5), fail("J3", "DOCUMENT_VERSION_MISMATCH", 4));
add("put_document: doc_id not an identifier (amendment 4, P4-4)", set(`${op(1)}.doc_id`, ""), fail("J3", "DOCUMENT_VERSION_MISMATCH", 4));
add("record id: another id in the outcome", set("1.body.outcome.result.accepted.2", OTHER_HASH), fail("J3", "RECORD_ID_MISMATCH", 1));
add("record id: ids of a batch submit", set("4.body.outcome.result.results.2.accepted.0", OTHER_HASH), fail("J3", "RECORD_ID_MISMATCH", 4));
add("records root: another root on a frame with records", set("1.header.records_root", OTHER_HASH), fail("J3", "RECORDS_ROOT_MISMATCH", 1));
add("records root: another root on a frame without records", set("5.header.records_root", OTHER_HASH), fail("J3", "RECORDS_ROOT_MISMATCH", 5));
add("records root: the root of another frame", (f) => setPath(f, "4.header.records_root", getPath(loadFrames(KBP)[3], "header.records_root")), fail("J3", "RECORDS_ROOT_MISMATCH", 4));

test("B3 matrix covers every kind of line and every genesis and body key", () => {
  assert.deepEqual([...kindsSeen].sort(), ["claim", "done", "hypothesis", "observe", "question", "relation"]);
  assert.equal(GENESIS.size, 15);
  assert.equal(BODY.size, 7);
  assert.ok(cases.length > 200, `${cases.length} cases`);
});

for (const c of cases) {
  test(`B3: ${c.name} -> ${c.want.code ?? c.want.verdict}${c.want.frame !== undefined ? ` @ ${c.want.frame}` : ""}`, async () => {
    const f = loadFrames(c.base);
    c.edit(f);
    await rechain(f, c.how);
    const report = await verify(saveFrames(f), { documents: c.docs });
    assert.deepEqual(outcome(report), c.want, JSON.stringify(report.first_failure));
  });
}

test("B3: '@' resolution needs exactly one id with the prefix (ambiguous prefix, synthetic ids)", () => {
  const ids = ["479c73e57790c6f3aaaa", "479c73e57790c6f3bbbb", "5000000000000000cccc"].map((s) => s.padEnd(64, "0"));
  const pick = (name) => yv.uniqueByPrefix(ids, (x) => x, name);
  assert.equal(pick("@479c73e57790c6f3"), null); // two ids start with it
  assert.equal(pick("@479c73e57790c6f3a"), ids[0]);
  assert.equal(pick("@479C73E57790C6F3B"), ids[1]);
  assert.equal(pick("@5000000000000000"), ids[2]);
  assert.equal(pick("@500000000000000"), null); // 15 digits
  assert.equal(pick("5000000000000000"), null); // no "@"
});

test("B3: occurrences of a quote are counted at every start, overlapping ones included (P3-8)", () => {
  const e = (t) => new TextEncoder().encode(t);
  assert.deepEqual(yv.occurrences(e("aaa"), e("aa"), 5), [0, 1]);
  assert.deepEqual(yv.occurrences(e("abab"), e("aba"), 5), [0]);
  assert.deepEqual(yv.occurrences(e("ababa"), e("aba"), 5), [0, 2]);
  assert.deepEqual(yv.occurrences(e("abc"), e(""), 5), []);
  assert.deepEqual(yv.occurrences(e("ab"), e("abc"), 5), []);
});
