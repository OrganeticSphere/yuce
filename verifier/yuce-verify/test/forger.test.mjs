// A6 and B4: the forger. A journal changed and re-hashed (frames, request
// hashes, seals; with the documents also record ids and records roots) passes
// J0-J2. J3 catches it when a changed quote is not in its source. A quote
// replaced by another phrase that occurs once in the same document, or a change
// outside the records, passes J0-J3. Since delivery 3 the forger also recomputes
// the projections of every seal, and the same journals pass J4a too: only an
// anchor kept outside the file tells. A forger that leaves the projections as
// they were is caught by J4a.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { FORGED, makeForged } from "./make-forged.mjs";
import { forgeWithRecords, readDocs } from "./forge.mjs";
import { EXPECTED, docsOf, fixture, outcome, readRoom, room, textOf, verify } from "./helpers.mjs";

/** What J3 answers on each forged journal, with the documents of its original. */
const WITH_DOCUMENTS = {
  "forged-quote.wal": { verdict: "FAIL", level: "J3", code: "QUOTE_NOT_IN_SOURCE", frame: 1 },
  "forged-revoke.wal": { verdict: "PASS" }, // a revoke accepts no records: invisible to J3
  "forged-checkpoint.wal": { verdict: "PASS" }, // a checkpoint accepts no records: invisible to J3
  "forged-records-quote-not-in-source.wal": { verdict: "FAIL", level: "J3", code: "QUOTE_NOT_IN_SOURCE", frame: 1 },
  "forged-records-same-document.wal": { verdict: "PASS" }, // the honest boundary of J3 (P3-10) and of J4a
};

for (const spec of FORGED) {
  const name = spec.from.split("/").pop();
  const original = EXPECTED.valid[name];
  const bytes = () => readFileSync(fixture(`forged/${spec.file}`));

  test(`A6/B4: ${spec.file} is reproducible from the forger`, async () => {
    const fresh = await makeForged(spec);
    assert.equal(readFileSync(fixture(`forged/${spec.file}`), "utf8"), fresh);
    assert.notEqual(fresh, textOf(readRoom(spec.from)));
  });

  test(`A6/B4: ${spec.file} passes J0-J2 with the same shape as the original`, async () => {
    const report = await verify(bytes());
    assert.equal(report.verdict, "PASS", JSON.stringify(report.first_failure));
    assert.equal(report.levels.J2.result, "PASS");
    assert.equal(report.input.frames, original.frames);
    assert.deepEqual(report.levels.J1.tail, original.tail);
    assert.deepEqual(report.levels.J1.seals.map((s) => s.n), original.seals.map((s) => s.n));
    assert.notEqual(report.computed.wal_head, original.wal_head);
    // Seals after the forged frame change; seals before it do not.
    for (const [k, seal] of report.levels.J1.seals.entries()) {
      if (seal.n > spec.frame) assert.notEqual(seal.seal_hash, original.seals[k].seal_hash);
      else assert.equal(seal.seal_hash, original.seals[k].seal_hash);
    }
  });

  test(`B4: ${spec.file} with the documents of its original -> ${WITH_DOCUMENTS[spec.file].code ?? "PASS"}`, async () => {
    const report = await verify(bytes(), { documents: docsOf(original.docs) });
    assert.deepEqual(outcome(report), WITH_DOCUMENTS[spec.file], JSON.stringify(report.first_failure));
  });

  test(`A6: ${spec.file} is caught by an anchor kept outside the file`, async () => {
    const head = await verify(bytes(), { expectHead: original.wal_head });
    assert.deepEqual(outcome(head), { verdict: "FAIL", level: "J0", code: "HEAD_MISMATCH", frame: null });
    const later = original.seals.filter((s) => s.n > spec.frame).pop();
    if (later !== undefined) {
      const anchored = await verify(bytes(), { expectSeal: later.seal_hash });
      assert.deepEqual(outcome(anchored), { verdict: "FAIL", level: "J1", code: "ANCHOR_NOT_FOUND", frame: null });
    }
    // A seal of a point before the forged frame still matches: it vouches for its prefix only.
    const earlier = original.seals.filter((s) => s.n <= spec.frame).pop();
    if (earlier !== undefined) {
      const anchored = await verify(bytes(), { expectSeal: earlier.seal_hash });
      assert.equal(anchored.verdict, "PASS");
      assert.equal(anchored.anchor.seal.at_n, earlier.n);
    }
  });
}

test("B4: the records forger rewrote record ids, an '@' reference and records roots", async () => {
  const forged = textOf(readFileSync(fixture("forged/forged-records-same-document.wal")));
  const orig = textOf(readRoom("inputs/valid/kinds-batch-put.wal"));
  const f = forged.split("\n");
  const o = orig.split("\n");
  // Frame 1 records root and accepted ids changed.
  assert.notEqual(JSON.parse(f[1]).header.records_root, JSON.parse(o[1]).header.records_root);
  assert.notDeepEqual(JSON.parse(f[1]).body.outcome.result.accepted, JSON.parse(o[1]).body.outcome.result.accepted);
  // Frame 3 named the first observation of frame 1 by "@479c73e57790c6f3": it now names the new id.
  const ref = JSON.parse(f[3]).body.command.lines[1].based_on[0];
  assert.notEqual(ref, "@479c73e57790c6f3");
  assert.equal(ref, "@" + JSON.parse(f[1]).body.outcome.result.accepted[0]);
});

test("B4, amendment 6: the same-document forgery passes J4a only because the forger recomputed the projections", async () => {
  const spec = FORGED.find((s) => s.file === "forged-records-same-document.wal");
  const docs = docsOf(EXPECTED.valid["kinds-batch-put.wal"].docs);
  const full = await verify(readFileSync(fixture(`forged/${spec.file}`)), { documents: docs });
  assert.deepEqual(full.levels.J4a, { result: "PASS" });
  assert.deepEqual(full.cascade, { seals_checked: 1, checked_through_frame: 6, unchecked_frames: 0 });
  // The same forgery with the projections of the seal left as they were: J4a refuses it at the seal.
  const text = readFileSync(room(spec.from), "utf8");
  const partial = await forgeWithRecords(text, readDocs(room(spec.docs)), spec.frame, spec.path, JSON.parse(spec.value), { projections: false });
  const report = await verify(partial, { documents: docs });
  assert.deepEqual(outcome(report), { verdict: "FAIL", level: "J4a", code: "PROJECTION_STATUS_MISMATCH", frame: 6 });
  assert.equal(report.levels.J3.result, "PASS");
});

test("A6: at least one forged journal has a seal before the forged frame and one has none", () => {
  const has = (spec) => EXPECTED.valid[spec.from.split("/").pop()].seals.some((s) => s.n <= spec.frame);
  assert.ok(FORGED.some(has));
  assert.ok(FORGED.some((s) => !has(s)));
});
