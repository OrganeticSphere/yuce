// The cut of several journals and its offline check (SPEC_CUT_AND_BUNDLE_v1):
// the vectors V-CUT-1 ... V-CUT-26, variants of their manifests, the export
// format and the command line.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { BUNDLE, ROOM, adapter, room, yv } from "./helpers.mjs";

const walk = (d) =>
  readdirSync(d)
    .sort()
    .flatMap((n) => {
      const p = join(d, n);
      return statSync(p).isDirectory() ? walk(p) : [p];
    });
const bytes = (p) => new Uint8Array(readFileSync(p));
const enc = new TextEncoder();

/** The bundle of a vector, read in the layout of the vectors; `edit` changes its manifest (a plain object). */
function bundle(n, edit = null) {
  const dir = room(`inputs/cut/V-CUT-${n}`);
  const plain = JSON.parse(readFileSync(join(dir, "cut.json"), "utf8"));
  const journals = new Map();
  for (const name of readdirSync(dir).filter((x) => existsSync(join(dir, x, "run.wal")))) {
    journals.set(name, { journal: bytes(join(dir, name, "run.wal")), documents: walk(join(dir, name, "docs")).map(bytes) });
  }
  const exports = new Map(
    readdirSync(dir)
      .filter((x) => x.endsWith(".txt"))
      .map((x) => [x.slice(0, -4), bytes(join(dir, x))]),
  );
  let manifest = bytes(join(dir, "cut.json"));
  if (edit !== null) {
    const m = structuredClone(plain);
    edit(m);
    manifest = enc.encode(JSON.stringify(m)); // B0 reads JSON; cut_hash is over its JCS
  }
  return { manifest, journals, exports, plain };
}
const check = async (b) => (await yv.verifyCut(b, adapter)).report;

// ---------------------------------------------------------------------------
// The vectors (section 7)
// ---------------------------------------------------------------------------

for (let n = 1; n <= 26; n++) {
  const want = JSON.parse(readFileSync(room(`inputs/cut/V-CUT-${n}/expected.json`), "utf8"));
  test(`V-CUT-${n}: ${want.verdict}${want.failures === undefined ? "" : " " + want.failures.map((f) => f.code).join(", ")}; failures, across and cut_hash as expected`, async () => {
    const r = await check(bundle(n));
    assert.equal(r.format, "yuce-cut-report/1");
    assert.equal(r.verdict, want.verdict);
    // V-CUT-22 names no cut_hash: a file with a repeated key has no single value to hash.
    assert.equal(r.cut_hash, want.cut_hash ?? null);
    assert.deepEqual(r.failures, want.failures ?? []);
    if (want.across !== undefined) assert.deepEqual(r.across, want.across);
    assert.deepEqual(r.not_verified, ["meaning", "undeclared_dependencies", "signatures"]);
  });
}

test("V-CUT-1: the report lists every journal, export and delivery with its verdict", async () => {
  const r = await check(bundle(1));
  assert.deepEqual(
    r.journals.map((j) => [j.name, j.verdict, j.levels.J4a.result]),
    [
      ["a", "PASS", "PASS"],
      ["b", "PASS", "PASS"],
    ],
  );
  assert.deepEqual(r.exports, [{ name: "e1", verdict: "PASS", paragraphs: 2, fallen_at_cut: 1 }]);
  assert.deepEqual(r.deliveries, [{ export: "e1", journal: "b", verdict: "PASS" }]);
});

test("V-CUT-2, V-CUT-10: the verdict of the failing delivery is FAIL", async () => {
  assert.deepEqual((await check(bundle(2))).deliveries, [{ export: "e1", journal: "b", verdict: "FAIL" }]);
  assert.deepEqual((await check(bundle(10))).deliveries, [{ export: "e1", journal: "b", verdict: "FAIL" }]);
  assert.equal((await check(bundle(3))).exports[0].verdict, "FAIL");
  assert.equal((await check(bundle(6))).journals.find((j) => j.name === "a").verdict, "FAIL");
});

// ---------------------------------------------------------------------------
// B0: the manifest
// ---------------------------------------------------------------------------

test("B0, section 3: a manifest that is not JSON, or JSON but not an object (V-CUT-24), is CUT_FORM with cut_hash null", async () => {
  const b = bundle(1);
  for (const text of ["{", "null", "[]", "1", '"x"', "true", " null\n"]) {
    const r = await check({ ...b, manifest: enc.encode(text) });
    assert.deepEqual([r.failures, r.cut_hash], [[{ code: "CUT_FORM" }], null], JSON.stringify(text));
  }
  // An object that fails B0 later still has a single value, and its cut_hash (V-CUT-8, V-CUT-19).
  const keys = await check(bundle(1, (m) => void (m.extra = 1)));
  assert.match(keys.cut_hash, /^[0-9a-f]{64}$/);
});

const B0_CASES = [
  ["an extra key", (m) => void (m.extra = 1)],
  ["a missing key", (m) => void delete m.previous_cut],
  ["another format", (m) => void (m.format = "yuce-cut/2")],
  ["mode govern (reserved)", (m) => void (m.mode = "govern")],
  ["previous_cut not a hash", (m) => void (m.previous_cut = "abc")],
  ["a journal name with a space", (m) => void (m.journals[0].name = "a b")],
  ["a journal name of 65 characters", (m) => void (m.journals[0].name = "a".repeat(65))],
  // Section 1 (answer to SPEC-DEFECT-26.7): "." and ".." are no names; V-CUT-21 names an export ".".
  ["an export named .", (m) => void ((m.exports[0].name = "."), (m.deliveries[0].export = "."))],
  ["an export named ..", (m) => void ((m.exports[0].name = ".."), (m.deliveries[0].export = ".."))],
  ["a journal named ..", (m) => void ((m.journals[0].name = ".."), (m.exports[0].journal = ".."))],
  ["journals not sorted", (m) => void m.journals.reverse()],
  ["two exports with one name", (m) => void m.exports.push({ ...m.exports[0] })],
  ["log_size not an integer", (m) => void (m.journals[0].log_size = 6.5)],
  ["closed not a boolean", (m) => void (m.journals[0].closed = "true")],
  ["wal_head in upper case", (m) => void (m.journals[0].wal_head = m.journals[0].wal_head.toUpperCase())],
  ["a delivery to a journal not in the cut", (m) => void (m.deliveries[0].journal = "c")],
  ["a delivery of an unknown export", (m) => void (m.deliveries[0].export = "e9")],
  ["an export of a journal not in the cut", (m) => void (m.exports[0].journal = "z")],
  ["a delivery listed twice (V-CUT-8)", (m) => void m.deliveries.push({ ...m.deliveries[0] })],
];
for (const [what, edit] of B0_CASES) {
  test(`B0: ${what} -> CUT_FORM, and nothing else is checked`, async () => {
    const r = await check(bundle(1, edit));
    assert.deepEqual(r.failures, [{ code: "CUT_FORM" }]);
    assert.deepEqual([r.journals, r.exports, r.deliveries], [[], [], []]);
  });
}

test("B0: two deliveries of frame 0 out of order (V-CUT-18) -> CUT_FORM; in order they pass", async () => {
  assert.equal((await check(bundle(18))).verdict, "PASS");
  const r = await check(bundle(18, (m) => void m.deliveries.reverse()));
  assert.deepEqual(r.failures, [{ code: "CUT_FORM" }]);
});

test("3 (review of PR 74): V-CUT-23, the manifest of V-CUT-1 indented and reordered, has the cut_hash of V-CUT-1", async () => {
  const one = await check(bundle(1));
  const r = await check(bundle(23));
  assert.equal(r.verdict, "PASS");
  assert.equal(r.cut_hash, one.cut_hash);
  assert.notDeepEqual(bundle(23).manifest, bundle(1).manifest);
});

test("3 (review of PR 74): a key repeated at any depth, a byte-order mark, or bytes that are not UTF-8 -> CUT_FORM", async () => {
  const b = bundle(1);
  const text = new TextDecoder().decode(b.manifest);
  const cases = [
    ["mode twice at the top (V-CUT-22)", text.replace('"mode":"observe"', '"mode":"observe","mode":"observe"')],
    ["a key twice in a journal entry", text.replace('"closed":true,', '"closed":true,"closed":true,')],
    ["a key twice in a delivery", text.replace('"frame":1,', '"frame":1,"frame":1,')],
  ];
  for (const [what, t] of cases) {
    assert.notEqual(t, text, what);
    const r = await check({ ...b, manifest: enc.encode(t) });
    assert.deepEqual([r.failures, r.cut_hash], [[{ code: "CUT_FORM" }], null], what);
  }
  const bom = await check({ ...b, manifest: new Uint8Array([0xef, 0xbb, 0xbf, ...b.manifest]) });
  assert.deepEqual([bom.failures, bom.cut_hash], [[{ code: "CUT_FORM" }], null]);
  const latin1 = await check({ ...b, manifest: new Uint8Array([...b.manifest.slice(0, -1), 0xe9, 0x7d]) });
  assert.deepEqual(latin1.failures, [{ code: "CUT_FORM" }]);
  // Layout is free: white space and a trailing newline do not matter.
  const spaced = await check({ ...b, manifest: enc.encode(" \n" + JSON.stringify(b.plain, null, "\t") + "\r\n") });
  assert.deepEqual([spaced.verdict, spaced.cut_hash], ["PASS", (await check(b)).cut_hash]);
});

test("B0: previous_cut is checked for its form only", async () => {
  const r = await check(bundle(1, (m) => void (m.previous_cut = "ab".repeat(32))));
  assert.equal(r.verdict, "PASS");
  assert.notEqual(r.cut_hash, (await check(bundle(1))).cut_hash);
});

test("cut_hash = hex(H(\"YUCE-CUT/1\", JCS(manifest))), whatever the bytes of the file", async () => {
  const b = bundle(1);
  const pretty = enc.encode(JSON.stringify(b.plain, null, 2));
  const r = await check({ ...b, manifest: pretty });
  assert.equal(r.cut_hash, JSON.parse(readFileSync(room("inputs/cut/V-CUT-1/expected.json"), "utf8")).cut_hash);
  assert.equal(r.verdict, "PASS");
});

// ---------------------------------------------------------------------------
// B1-B3: variants made from the vectors (section 7, the executable check)
// ---------------------------------------------------------------------------

test("B1: closed false on a closed journal: the close frame is not in the part, and the cut still passes", async () => {
  const r = await check(bundle(1, (m) => void (m.journals[0].closed = false)));
  assert.equal(r.verdict, "PASS", JSON.stringify(r.failures));
});

test("B1: closed true on a journal that goes on after its seal (V-CUT-13) -> CUT_JOURNAL_MISMATCH closed", async () => {
  const r = await check(bundle(13, (m) => void (m.journals.find((j) => j.name === "b").closed = true)));
  assert.deepEqual(r.failures, [{ code: "CUT_JOURNAL_MISMATCH", journal: "b", field: "closed" }]);
});

test("B1: run_id and rules_version of the genesis record", async () => {
  const runId = await check(bundle(1, (m) => void (m.journals[1].run_id = "cut-x")));
  assert.deepEqual(runId.failures, [{ code: "CUT_JOURNAL_MISMATCH", journal: "b", field: "run_id" }]);
  const rules = await check(bundle(1, (m) => void (m.journals[1].rules_version = "r2r-audit-rules/3")));
  assert.deepEqual(rules.failures, [{ code: "CUT_JOURNAL_MISMATCH", journal: "b", field: "rules_version" }]);
});

test("B1.5: a journal that fails its own check -> CUT_JOURNAL_FAILED with its failure code", async () => {
  const b = bundle(1);
  const a = b.journals.get("a");
  const text = new TextDecoder().decode(a.journal).replace("Alpha holds in the northern field.", "Alpha holds in the northern field!");
  const r = await check({ ...b, journals: new Map([...b.journals, ["a", { ...a, journal: enc.encode(text) }]]) });
  assert.deepEqual(r.failures[0], { code: "CUT_JOURNAL_FAILED", journal: "a", failure: "BODY_HASH_MISMATCH" });
});

test("B3.2: a delivery dropped -> CUT_UNDECLARED_DELIVERY at the put", async () => {
  const r = await check(bundle(1, (m) => void (m.deliveries = [])));
  assert.deepEqual(r.failures, [{ code: "CUT_UNDECLARED_DELIVERY", journal: "b", frame: 1, doc_id: "export-e", export: "e1" }]);
  assert.deepEqual(r.across, { paragraphs_fallen: 0, observations_checked: 0 });
});

test("B3.2 (V-CUT-25, V-CUT-26): a batch that brings in an export's exact bytes fails, undeclared or declared", async () => {
  const undeclared = await check(bundle(25));
  assert.deepEqual(undeclared.failures, [{ code: "CUT_UNDECLARED_DELIVERY", journal: "b", frame: 1, doc_id: "export-e", export: "e1" }]);
  const declared = await check(bundle(26));
  assert.deepEqual(declared.failures, [{ code: "DELIVERY_MISSING", export: "e1", journal: "b", doc_id: "export-e", frame: 1 }]);
  assert.deepEqual(declared.deliveries, [{ export: "e1", journal: "b", verdict: "FAIL" }]);
  // The frame of the import is a batch, not a put_document frame of its own.
  const frame1 = JSON.parse(new TextDecoder().decode(bundle(25).journals.get("b").journal).split("\n")[1]);
  assert.equal(frame1.body.command.kind, "batch");
});

test("B3.1: a delivery naming another doc_id at the right frame -> DELIVERY_MISSING only (the import is declared)", async () => {
  const r = await check(bundle(1, (m) => void (m.deliveries[0].doc_id = "other")));
  assert.deepEqual(r.failures, [{ code: "DELIVERY_MISSING", export: "e1", journal: "b", doc_id: "other", frame: 1 }]);
});

test("B2: an export naming a seal that is not in its journal's part -> EXPORT_SEAL_UNKNOWN (and the header mismatch)", async () => {
  const r = await check(bundle(1, (m) => void (m.exports[0].seal_hash = m.journals[1].seal_hash)));
  assert.deepEqual(r.failures, [
    { code: "EXPORT_MISMATCH", export: "e1" },
    { code: "EXPORT_SEAL_UNKNOWN", export: "e1" },
  ]);
});

// ---------------------------------------------------------------------------
// Section 2: the export
// ---------------------------------------------------------------------------

test("2.2: escapes of an export: backslash, line feed, carriage return, nothing else", () => {
  assert.equal(yv.exportEscape('a\\b\nc\rd"e[f]'), 'a\\\\b\\nc\\rd"e[f]');
});

test("2.2: V-CUT-12: a paragraph is read only up to its record id; quote marks, separators and keywords stay inside", () => {
  const e1 = bytes(room("inputs/cut/V-CUT-12/e1.txt"));
  const paragraphs = yv.exportParagraphs(e1);
  assert.equal(paragraphs.length, 2);
  for (const p of paragraphs) assert.match(p.record, /^[0-9a-f]{64}$/);
  const text = new TextDecoder().decode(e1);
  assert.ok(text.includes("Quotes:") && text.includes("Rests on:") && text.includes("\\\\") && text.includes("\\n"));
  // Each range covers exactly one line of the file.
  for (const p of paragraphs) assert.ok(!new TextDecoder().decode(e1.subarray(p.start, p.end)).includes("\n"));
});

test("2.2 (answer to SPEC-DEFECT-26.5): V-CUT-20: a repeated ground is written once, at its first place", async () => {
  const e1 = new TextDecoder().decode(bytes(room("inputs/cut/V-CUT-20/e1.txt")));
  const want = JSON.parse(readFileSync(room("inputs/cut/V-CUT-20/expected.json"), "utf8")).ids;
  assert.equal(e1.split(`[source] "`).length, 2);
  assert.equal(e1.split(`Rests on: ${want.c1}`).length, 2);
  assert.ok(!e1.includes(`${want.c1}, ${want.c1}`));
  const r = await check(bundle(20));
  assert.deepEqual([r.verdict, r.exports], ["PASS", [{ name: "e1", verdict: "PASS", paragraphs: 2, fallen_at_cut: 0 }]]);
});

test("2.1: an export with no paragraph is the header line alone", () => {
  assert.equal(yv.exportText("run\nx", "ab".repeat(32), []), `yuce-export/1 run=run\\nx seal=${"ab".repeat(32)} records=0\n`);
  assert.deepEqual(yv.exportParagraphs(enc.encode(yv.exportText("r", "ab".repeat(32), []))), []);
});

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

const cli = (...args) => {
  const r = spawnSync(process.execPath, [BUNDLE, ...args], { cwd: ROOM, encoding: "utf8" });
  return { code: r.status, out: r.stdout, err: r.stderr };
};

test("CLI: cut <folder> gives a human line and exit 0 or 1; --json gives yuce-cut-report/1", async () => {
  const pass = cli("cut", "inputs/cut/V-CUT-1");
  assert.equal(pass.code, 0);
  assert.equal(pass.out, "Cut PASS. Journals: 2. Exports: 1. Deliveries: 1. Paragraphs fallen: 1; observations checked: 1. Not verified: meaning, undeclared dependencies, signatures.\n");
  const fail = cli("cut", "inputs/cut/V-CUT-4");
  assert.equal(fail.code, 1);
  assert.equal(fail.out, "Cut FAIL: DELIVERY_MISSING (export e1, journal b, doc_id export-e, frame 2) (2 failures). Not verified: meaning, undeclared dependencies, signatures.\n");
  const json = cli("cut", "inputs/cut/V-CUT-4", "--json");
  const report = JSON.parse(json.out);
  assert.equal(yv.jcs(yv.fromPlain(report)) + "\n", json.out);
  assert.deepEqual(report, JSON.parse(yv.jcs(yv.fromPlain(await check(bundle(4))))));
});

test("CLI: V-CUT-21, an export named '.': CUT_FORM, exit 1, and no file is read before B0", () => {
  const r = cli("cut", "inputs/cut/V-CUT-21");
  assert.equal(r.code, 1);
  assert.equal(r.out, "Cut FAIL: CUT_FORM. Not verified: meaning, undeclared dependencies, signatures.\n");
  assert.equal(r.err, "");
});

test("CLI: V-CUT-24, a manifest holding null and nothing else in the folder: CUT_FORM, cut_hash null, exit 1", () => {
  const r = cli("cut", "inputs/cut/V-CUT-24", "--json");
  assert.equal(r.code, 1);
  const report = JSON.parse(r.out);
  assert.deepEqual([report.failures, report.cut_hash, report.journals, report.exports], [[{ code: "CUT_FORM" }], null, [], []]);
  assert.equal(r.err, "");
});

test("CLI: V-CUT-22, a repeated key: CUT_FORM, exit 1, no file of the bundle read", () => {
  const r = cli("cut", "inputs/cut/V-CUT-22", "--json");
  assert.equal(r.code, 1);
  const report = JSON.parse(r.out);
  assert.deepEqual([report.failures, report.cut_hash, report.journals], [[{ code: "CUT_FORM" }], null, []]);
  assert.equal(r.err, "");
});

test("CLI: cut on a folder without cut.json, or with a missing journal file -> exit 2", () => {
  assert.equal(cli("cut", "inputs/cut").code, 2);
  assert.equal(cli("cut", "inputs/cut/V-CUT-1", "--docs", "x").code, 2);
});
