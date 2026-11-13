// A2 (inputs/valid), A3 first half (inputs/corrupt), A6a (inputs/boundary).
import { test } from "node:test";
import assert from "node:assert/strict";
import { EXPECTED, outcome, readRoom, verify } from "./helpers.mjs";

for (const [name, want] of Object.entries(EXPECTED.valid)) {
  test(`A2: valid/${name} passes with the head, seals and tail of expected.json`, async () => {
    const report = await verify(readRoom(`inputs/valid/${name}`));
    assert.equal(report.verdict, "PASS", JSON.stringify(report.first_failure));
    assert.equal(report.levels.J0.result, "PASS");
    assert.equal(report.levels.J1.result, "PASS");
    assert.equal(report.input.journal_sha256, want.sha256);
    assert.equal(report.input.frames, want.frames);
    assert.equal(report.computed.wal_head, want.wal_head);
    assert.deepEqual(report.levels.J1.seals, want.seals);
    assert.deepEqual(report.levels.J1.tail, want.tail);
    assert.equal(report.input.format, "sbgk-session-log/3");
    assert.deepEqual(Object.keys(report.levels.J1).sort(), ["result", "seals", "tail"]);
    assert.deepEqual(report.anchor, { seal: { given: false, matched: null }, head: { given: false, matched: null } });
    assert.equal(report.computed.closed, want.tail.kind === "closed");
  });
}

for (const [name, want] of Object.entries(EXPECTED.corrupt)) {
  test(`A3: corrupt/${name} fails with ${want.code} at frame ${want.frame}`, async () => {
    const report = await verify(readRoom(`inputs/corrupt/${name}`));
    assert.equal(report.verdict, "FAIL");
    assert.equal(report.first_failure.code, want.code);
    assert.equal(report.first_failure.frame, want.frame);
    const level = want.code.startsWith("SEAL_") || want.code === "KERNEL_ID_MISUSE" ? "J1" : "J0";
    assert.equal(report.first_failure.level, level);
  });
}

// A6a: no expectation is given for boundary/; these are the observed results,
// pinned so that BOUNDARY_RESULTS.md stays true.
const BOUNDARY_OBSERVED = {
  "auto-seal-ack.wal": { verdict: "FAIL", level: "J1", code: "KERNEL_ID_MISUSE", frame: 1 },
  "nested-seal.wal": { verdict: "PASS" },
};

for (const [name, want] of Object.entries(BOUNDARY_OBSERVED)) {
  test(`A6a: boundary/${name}: observed J0-J1 outcome`, async () => {
    const bytes = readRoom(`inputs/boundary/${name}`);
    const report = await verify(bytes);
    assert.equal(report.input.journal_sha256, EXPECTED.boundary[name].sha256);
    assert.deepEqual(outcome(report), want);
  });
}

test("A6a: nested-seal.wal passes J0-J1 with one seal and one unsealed frame", async () => {
  const report = await verify(readRoom("inputs/boundary/nested-seal.wal"));
  assert.deepEqual(report.levels.J1.seals.map((s) => s.n), [1]);
  assert.deepEqual(report.levels.J1.tail, { kind: "unsealed", frames_after_last_seal: 1 });
});
