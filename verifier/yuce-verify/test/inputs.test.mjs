// The inputs against expected.json:
// A2/B2 (valid/ with their documents), A3/B3 (corrupt/), A6a (boundary/),
// B5 (the accept/refuse verdict equals the kernel's) and B6 (without documents).
import { test } from "node:test";
import assert from "node:assert/strict";
import { EXPECTED, docsOf, outcome, readRoom, verify } from "./helpers.mjs";

const J1_CODES = new Set([
  "FRAME_AFTER_CLOSE",
  "KERNEL_COMMAND_NOT_FROM_KERNEL",
  "SEAL_FORM",
  "SEAL_FORMAT",
  "SEAL_LOG_SIZE",
  "SEAL_WAL_HEAD",
  "SEAL_LOG_ROOT",
  "SEAL_ROOT_CONTINUITY",
  "SEAL_HASH_MISMATCH",
  "SEAL_RUN_ID",
  "KERNEL_ID_MISUSE",
  "CLOSE_WITHOUT_SEAL",
  "ANCHOR_NOT_FOUND",
]);
/** the task statement section 8: the level is the field `level`; older entries have none, and their level follows from the code. */
const levelOf = (want) => want.level ?? (J1_CODES.has(want.code) ? "J1" : "J0");

const run = async (section, name, entry) =>
  verify(readRoom(`inputs/${section}/${name}`), entry.docs === undefined ? {} : { documents: docsOf(entry.docs) });

for (const [name, want] of Object.entries(EXPECTED.valid)) {
  test(`B2: valid/${name} with its documents passes J0-J3 with the values of expected.json`, async () => {
    const report = await run("valid", name, want);
    assert.equal(report.verdict, "PASS", JSON.stringify(report.first_failure));
    // J0-J1 as in delivery 1 (A2)
    assert.equal(report.input.journal_sha256, want.sha256);
    assert.equal(report.input.frames, want.frames);
    assert.equal(report.computed.wal_head, want.wal_head);
    assert.deepEqual(report.levels.J1.seals, want.seals);
    assert.deepEqual(report.levels.J1.tail, want.tail);
    assert.equal(report.computed.closed, want.tail.kind === "closed");
    // J2, J3
    assert.deepEqual(report.levels.J2, want.J2);
    assert.deepEqual(report.levels.J3, want.J3);
    assert.deepEqual(report.input.sources, { given: true, files: docsOf(want.docs).length });
    assert.deepEqual(report.not_verified, ["withdrawal_cascade", "signatures"]);
  });

  test(`B6: valid/${name} without documents passes J0-J2, J3 not checked`, async () => {
    const report = await verify(readRoom(`inputs/valid/${name}`));
    assert.equal(report.verdict, "PASS", JSON.stringify(report.first_failure));
    assert.deepEqual(report.levels.J2, want.J2);
    assert.deepEqual(report.levels.J3, { result: "NOT_CHECKED" });
    assert.deepEqual(report.input.sources, { given: false });
    assert.deepEqual(report.not_verified, ["quotes_against_sources", "withdrawal_cascade", "signatures"]);
  });
}

for (const [name, want] of Object.entries(EXPECTED.corrupt)) {
  test(`A3/B3: corrupt/${name} fails at ${levelOf(want)} with ${want.code} at frame ${want.frame}`, async () => {
    const report = await run("corrupt", name, want);
    assert.deepEqual(outcome(report), { verdict: "FAIL", level: levelOf(want), code: want.code, frame: want.frame });
    if (want.sha256 !== undefined) assert.equal(report.input.journal_sha256, want.sha256);
  });
}

for (const [name, want] of Object.entries(EXPECTED.boundary)) {
  test(`A6a: boundary/${name} fails as expected for delivery 2: ${want.delivery2.level} ${want.delivery2.code} at frame ${want.delivery2.frame}`, async () => {
    const report = await run("boundary", name, want);
    assert.equal(report.input.journal_sha256, want.sha256);
    assert.deepEqual(outcome(report), { verdict: "FAIL", ...want.delivery2 });
  });
}

test("B5: on every input, accept or refuse equals the kernel (sbgk audit-verify)", async () => {
  const rows = [];
  for (const section of ["valid", "corrupt", "boundary"]) {
    for (const [name, entry] of Object.entries(EXPECTED[section])) {
      const report = await run(section, name, entry);
      const accepted = report.verdict === "PASS";
      const kernelAccepted = entry.kernel.exit === 0;
      rows.push(`${section}/${name}: verifier ${report.verdict}, kernel ${entry.kernel.status}`);
      assert.equal(accepted, kernelAccepted, rows.at(-1));
    }
  }
  assert.equal(rows.length, 7 + 11 + 2); // the public copy leaves out two inputs of a closed run (expected.json, _note_public)
});

test("B6: a documents folder without one of the documents gives INCOMPLETE, naming the doc_id", async () => {
  const all = docsOf("valid/kinds-batch-put.docs");
  // vector-a.txt is the first file (sorted names) and the first doc_id in JCS order.
  const without = all.slice(1);
  const report = await verify(readRoom("inputs/valid/kinds-batch-put.wal"), { documents: without });
  assert.equal(report.verdict, "INCOMPLETE");
  assert.deepEqual(report.levels.J3, { result: "NOT_CHECKABLE", reason: "document vector-a.txt not supplied" });
  assert.equal(report.first_failure, null);
  assert.equal(report.levels.J2.result, "PASS");
  assert.deepEqual(report.not_verified, ["quotes_against_sources", "withdrawal_cascade", "signatures"]);
  // A failure of an earlier level wins over the missing document.
  const corrupt = await verify(readRoom("inputs/corrupt/genesis-rules-version.wal"), { documents: without });
  assert.equal(corrupt.verdict, "FAIL");
  assert.deepEqual(corrupt.levels.J3, { result: "NOT_CHECKABLE", reason: "J2 failed" });
});

test("B6: extra files in the documents folder do not matter, and names do not matter", async () => {
  const all = docsOf("valid/kinds-batch-put.docs");
  const extra = [new TextEncoder().encode("an unrelated file"), ...all.reverse()];
  const report = await verify(readRoom("inputs/valid/kinds-batch-put.wal"), { documents: extra });
  assert.equal(report.verdict, "PASS");
  assert.deepEqual(report.input.sources, { given: true, files: 4 });
});
