// The observation report yuce-observation-report/1 (SPEC_OBSERVATION_REPORT_v1):
// the vectors V-OBS-1 ... V-OBS-6, byte for byte, the three checks of a given
// report, and the command line.
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
const dec = new TextDecoder();
const enc = new TextEncoder();

function cutBundle(folder) {
  const dir = room(`inputs/${folder}`);
  const m = JSON.parse(readFileSync(join(dir, "cut.json"), "utf8"));
  const journals = new Map(m.journals.map((j) => [j.name, { journal: bytes(join(dir, j.name, "run.wal")), documents: walk(join(dir, j.name, "docs")).map(bytes) }]));
  const exports = new Map(m.exports.map((e) => [e.name, bytes(join(dir, `${e.name}.txt`))]));
  return { manifest: bytes(join(dir, "cut.json")), journals, exports };
}

async function compute(n) {
  const input = JSON.parse(readFileSync(room(`inputs/obs/V-OBS-${n}/input.json`), "utf8"));
  if (input.input === "cut") return yv.observationReportForCut(cutBundle(input.cut), adapter);
  const docs = room(`inputs/${input.journal}`).replace(/\.wal$/, ".docs");
  return yv.observationReportForJournal(bytes(room(`inputs/${input.journal}`)), existsSync(docs) ? walk(docs).map(bytes) : [], input.seal_frame, adapter);
}
const given = (n) => bytes(room(`inputs/obs/V-OBS-${n}/report.json`));
const expected = (n) => JSON.parse(readFileSync(room(`inputs/obs/V-OBS-${n}/expected.json`), "utf8"));

// ---------------------------------------------------------------------------
// The vectors (section 8)
// ---------------------------------------------------------------------------

for (const n of [1, 2, 3, 6, 8, 9]) {
  test(`V-OBS-${n}: the computed report equals report.json byte for byte, and the given report passes the check`, async () => {
    assert.equal(expected(n).verdict, "PASS");
    const out = await compute(n);
    assert.ok(out.ok, out.reason);
    assert.equal(out.text, dec.decode(given(n)));
    assert.ok(!out.text.endsWith("\n"));
    assert.deepEqual(await yv.checkReport(given(n), out.value, adapter), { verdict: "PASS", code: null, path: null });
  });
}

test("V-OBS-4: claims[0].support changed, report_hash kept -> REPORT_HASH_MISMATCH", async () => {
  const want = expected(4);
  const out = await compute(4);
  assert.deepEqual(await yv.checkReport(given(4), out.value, adapter), { verdict: "FAIL", code: want.code, path: null });
});

test("V-OBS-7 (review of PR 74): the report of V-OBS-1 with a UTF-8 byte-order mark before it -> REPORT_FORM", async () => {
  const want = expected(7);
  const bytes7 = given(7);
  assert.deepEqual([...bytes7.slice(0, 3)], [0xef, 0xbb, 0xbf]);
  assert.deepEqual(bytes7.slice(3), given(1));
  const out = await compute(7);
  assert.deepEqual(await yv.checkReport(bytes7, out.value, adapter), { verdict: "FAIL", code: want.code, path: null });
});

test("V-OBS-5: report_hash recomputed over the changed body -> REPORT_MISMATCH at claims[0].support", async () => {
  const want = expected(5);
  const out = await compute(5);
  assert.deepEqual(await yv.checkReport(given(5), out.value, adapter), { verdict: "FAIL", code: want.code, path: want.path });
});

// What each vector must show (section 8), read from the computed report.
const report = async (n) => JSON.parse((await compute(n)).text);

test("V-OBS-1: support, root causes, rests_on_across; all uncontested and current; no key conflict", async () => {
  const r = await report(1);
  assert.equal(r.cut_hash, JSON.parse(readFileSync(room("inputs/cut/V-CUT-1/expected.json"), "utf8")).cut_hash);
  const [a1, a2, b1] = r.claims;
  assert.deepEqual([a1.journal, a1.support, a1.root_causes.map((c) => c.reason)], ["a", "affected", ["withdrawn"]]);
  assert.deepEqual([a2.journal, a2.support, a2.root_causes], ["a", "grounded", []]);
  assert.deepEqual([b1.journal, b1.support, b1.root_causes.map((c) => c.reason)], ["b", "affected", ["withdrawn"]]);
  assert.deepEqual(b1.rests_on_across, [{ journal: "a", record: a1.id }]);
  assert.ok(r.claims.every((c) => c.dispute === "uncontested" && c.time === "current"));
  assert.deepEqual(r.key_conflicts, []);
  assert.equal(r.debt.total.affected, 2);
});

test("V-OBS-8: baicalin-n3-shard1.wal at its last seal: 275 claims, 113 affected, 22 key conflicts, rejected_submissions 10, late_submissions 0", async () => {
  const r = await report(8);
  assert.deepEqual([r.journals[0].log_size, r.claims.length, r.key_conflicts.length], [104, 275, 22]);
  assert.equal(r.claims.filter((c) => c.support === "affected").length, 113);
  assert.ok(r.claims.filter((c) => c.support === "affected").every((c) => c.root_causes.length > 0));
  assert.deepEqual([r.debt.total.affected, r.debt.total.key_conflicts, r.debt.total.rejected_submissions, r.debt.total.late_submissions], [113, 22, 10, 0]);
});

test("V-OBS-9: d9 at its seal of frame 8: 2 claims, rejected_submissions 2, late_submissions 2", async () => {
  const r = await report(9);
  assert.deepEqual([r.journals[0].log_size, r.claims.length], [8, 2]);
  assert.deepEqual([r.debt.total.rejected_submissions, r.debt.total.late_submissions], [2, 2]);
  assert.deepEqual(r.debt.by_journal[r.journals[0].name], r.debt.total);
});

test("6: rejected_submissions and late_submissions count the batch frames with a checkpointed task-repair: or task-conflict: key", async () => {
  const p = (t) => yv.parseJson(t).value;
  const frame = (key, { kind = "batch", outcome = "value", checkpointed = true } = {}) => [
    p(JSON.stringify({ kind, operations: [], checkpoint: { key, from: 0, to: 0, context: {} } })),
    p(JSON.stringify({ kind: outcome, result: { checkpointed, results: [] } })),
  ];
  const cascade = new yv.Cascade(adapter, { bytes: () => undefined, version: async () => undefined });
  for (const [c, o] of [
    frame("task-repair:t1:1"),
    frame("task-repair:t2:1"),
    frame("task-conflict:t1:2"),
    frame("task-repair:t3:1", { checkpointed: false }),
    frame("task-repair:t4:1", { outcome: "error" }),
    frame("task:t5:1"),
    frame("audit-close"),
    frame("task-conflict:t6:1", { kind: "submit" }),
    // late_submissions reads the whole predicate too (section 6, as Codex's review of PR 75 wrote it out)
    frame("task-conflict:t7:1", { checkpointed: false }),
    frame("task-conflict:t8:1", { outcome: "error" }),
  ]) {
    cascade.noteFrame(c, o);
  }
  assert.deepEqual([cascade.rejectedSubmissions, cascade.lateSubmissions], [2, 1]);
  // A report over a journal without such frames counts 0 of each.
  const r = await report(1);
  assert.deepEqual([r.debt.total.rejected_submissions, r.debt.total.late_submissions], [0, 0]);
});

test("V-OBS-2: the replaced claim is stale through the relation record; a question about a record; key A is no conflict", async () => {
  const r = await report(2);
  assert.equal(r.cut_hash, null);
  assert.equal(r.journals.length, 1);
  assert.ok(r.claims.some((c) => c.time === "stale"));
  assert.ok(r.claims.some((c) => c.questions.length > 0));
  assert.ok(!r.key_conflicts.some((k) => k.subject === "A"));
  assert.ok(r.debt.total.questions_about_claims >= 1);
});

test("V-OBS-3: contradicts accepted but not usable, contested; the old claim stale; a key conflict", async () => {
  const r = await report(3);
  const contested = r.claims.filter((c) => c.dispute === "contested");
  assert.ok(contested.length > 0);
  assert.ok(contested.every((c) => c.dispute_links.some((l) => l.rel === "contradicts" && l.status === "accepted" && l.usable === false)));
  assert.ok(r.claims.some((c) => c.time === "stale"));
  assert.ok(r.key_conflicts.length > 0);
});

test("V-OBS-6: after the link is rejected, both claims uncontested, the rejected link still listed; stale stays; the conflict stays", async () => {
  const r = await report(6);
  assert.equal(r.journals[0].log_size, 13);
  const withLink = r.claims.filter((c) => c.dispute_links.length > 0);
  assert.ok(withLink.length >= 2);
  assert.ok(withLink.every((c) => c.dispute === "uncontested" && c.dispute_links.every((l) => l.status === "rejected")));
  assert.ok(r.claims.some((c) => c.time === "stale"));
  assert.ok(r.key_conflicts.length > 0);
});

// ---------------------------------------------------------------------------
// Section 7: the checks of a given report
// ---------------------------------------------------------------------------

test("7: a report that is not canonical JSON -> REPORT_FORM (a trailing newline, other spacing, not JSON)", async () => {
  const out = await compute(1);
  for (const text of [out.text + "\n", JSON.stringify(JSON.parse(out.text), null, 1), "{", "[]"]) {
    assert.deepEqual(await yv.checkReport(enc.encode(text), out.value, adapter), { verdict: "FAIL", code: "REPORT_FORM", path: null }, text.slice(0, 20));
  }
});

test("7, step 1 (answer to SPEC-DEFECT-27.6): a report without its hash, or with a hash not in lowercase hex, is REPORT_FORM", async () => {
  const out = await compute(1);
  const without = new Map([...out.value].filter(([k]) => k !== "report_hash"));
  const upper = new Map([...out.value].map(([k, v]) => [k, k === "report_hash" ? v.toUpperCase() : v]));
  for (const v of [without, upper]) {
    assert.deepEqual(await yv.checkReport(enc.encode(yv.jcs(v)), out.value, adapter), { verdict: "FAIL", code: "REPORT_FORM", path: null });
  }
});

test("7: report_hash = hex(H(\"YUCE-OBS-REPORT/1\", JCS(report without report_hash)))", async () => {
  const out = await compute(2);
  const body = new Map([...out.value].filter(([k]) => k !== "report_hash"));
  const h = yv.toHex(await yv.domainHash(adapter, "YUCE-OBS-REPORT/1", yv.utf8(yv.jcs(body))));
  assert.equal(out.value.get("report_hash"), h);
  assert.equal(await yv.reportHash(adapter, out.value), h);
});

test("7: the first differing path: depth first, keys in canonical order, positions ascending", () => {
  const p = (t) => yv.parseJson(t).value;
  assert.equal(yv.firstDifference(p('{"a":[1,{"b":2,"c":3}],"d":1}'), p('{"a":[1,{"b":2,"c":4}],"d":2}'), ""), "a[1].c");
  assert.equal(yv.firstDifference(p('{"a":[1]}'), p('{"a":[1,2]}'), ""), "a[1]");
  assert.equal(yv.firstDifference(p('{"b":1}'), p('{"a":1,"b":1}'), ""), "a");
  assert.equal(yv.firstDifference(p('{"a":1}'), p('{"a":1}'), ""), null);
});

test("1: a report over a journal needs a seal at the frame given, and a part that passes J0-J4a", async () => {
  const wal = bytes(room("inputs/valid/stream-context-checkpoints.wal"));
  assert.equal((await yv.observationReportForJournal(wal, [], 9, adapter)).ok, false);
  assert.equal((await yv.observationReportForJournal(wal, [], 99, adapter)).ok, false);
  const forged = await yv.observationReportForJournal(bytes(room("inputs/j4a/set-c/forged-cascade.wal")), walk(room("inputs/j4a/set-c/forged-cascade.docs")).map(bytes), 6, adapter);
  assert.deepEqual(forged, { ok: false, reason: "the part fails at J4a, frame 6: PROJECTION_STATUS_MISMATCH" });
  const failingCut = await yv.observationReportForCut(cutBundle("cut/V-CUT-2"), adapter);
  assert.deepEqual(failingCut, { ok: false, reason: "the cut fails: WITHDRAWAL_NOT_DELIVERED" });
});

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

const cli = (...args) => {
  const r = spawnSync(process.execPath, [BUNDLE, ...args], { cwd: ROOM, encoding: "utf8" });
  return { code: r.status, out: r.stdout, err: r.stderr };
};

test("CLI: report <cut folder> and report <journal> --seal-frame print the canonical bytes, without a newline", () => {
  const cut = cli("report", "inputs/cut/V-CUT-1");
  assert.equal(cut.code, 0);
  assert.equal(cut.out, dec.decode(given(1)));
  const journal = cli("report", "inputs/valid/stream-context-checkpoints.wal", "--seal-frame", "10", "--docs", "inputs/valid/stream-context-checkpoints.docs");
  assert.equal(journal.code, 0);
  assert.equal(journal.out, dec.decode(given(2)));
});

test("CLI: report --check: PASS exit 0, a mismatch exit 1 with its path, --json", () => {
  const pass = cli("report", "inputs/cut/V-CUT-1", "--check", "inputs/obs/V-OBS-1/report.json");
  assert.equal(pass.code, 0);
  assert.equal(pass.out, "Report PASS: the given report equals the report recomputed from the journals.\n");
  const mismatch = cli("report", "inputs/cut/V-CUT-1", "--check", "inputs/obs/V-OBS-5/report.json");
  assert.equal(mismatch.code, 1);
  assert.equal(mismatch.out, "Report FAIL: REPORT_MISMATCH at claims[0].support.\n");
  const hash = cli("report", "inputs/cut/V-CUT-1", "--check", "inputs/obs/V-OBS-4/report.json", "--json");
  assert.equal(hash.code, 1);
  assert.deepEqual(JSON.parse(hash.out), { code: "REPORT_HASH_MISMATCH", path: null, verdict: "FAIL" });
  const six = cli("report", "inputs/j4a/set-d/d6-relation-link-lifecycle.wal", "--seal-frame", "13", "--docs", "inputs/j4a/set-d/d6-relation-link-lifecycle.docs", "--check", "inputs/obs/V-OBS-6/report.json");
  assert.equal(six.code, 0);
});

test("CLI: report --check of V-OBS-7 (a byte-order mark): REPORT_FORM, exit 1", () => {
  const r = cli("report", "inputs/cut/V-CUT-1", "--check", "inputs/obs/V-OBS-7/report.json", "--json");
  assert.equal(r.code, 1);
  assert.deepEqual(JSON.parse(r.out), { code: "REPORT_FORM", path: null, verdict: "FAIL" });
});

test("CLI: a report that cannot be computed: exit 1, the reason on stderr, nothing on stdout", () => {
  const r = cli("report", "inputs/cut/V-CUT-2");
  assert.equal(r.code, 1);
  assert.equal(r.out, "");
  assert.equal(r.err, "yuce-verify: cannot compute the report: the cut fails: WITHDRAWAL_NOT_DELIVERED\n");
  assert.equal(cli("report", "inputs/valid/stream-context-checkpoints.wal", "--seal-frame", "x").code, 2);
});
