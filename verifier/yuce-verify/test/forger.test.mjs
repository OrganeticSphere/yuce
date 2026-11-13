// A6: the forger. A journal changed and fully re-hashed, seals included,
// passes levels J0-J1. Only an external seal or head tells it apart.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { FORGED, makeForged } from "./make-forged.mjs";
import { EXPECTED, fixture, outcome, readRoom, textOf, verify } from "./helpers.mjs";

for (const spec of FORGED) {
  const name = spec.from.split("/").pop();
  const original = EXPECTED.valid[name];

  test(`A6: ${spec.file} is reproducible from the forger`, async () => {
    const fresh = await makeForged(spec);
    assert.equal(readFileSync(fixture(`forged/${spec.file}`), "utf8"), fresh);
    assert.notEqual(fresh, textOf(readRoom(spec.from)));
  });

  test(`A6: ${spec.file} passes J0-J1 with the same shape as the original`, async () => {
    const report = await verify(readFileSync(fixture(`forged/${spec.file}`)));
    assert.equal(report.verdict, "PASS", JSON.stringify(report.first_failure));
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

  test(`A6: ${spec.file} is caught only by an anchor kept outside the file`, async () => {
    const bytes = readFileSync(fixture(`forged/${spec.file}`));
    const head = await verify(bytes, { expectHead: original.wal_head });
    assert.deepEqual(outcome(head), { verdict: "FAIL", level: "J0", code: "HEAD_MISMATCH", frame: null });
    const later = original.seals.filter((s) => s.n > spec.frame).pop();
    if (later !== undefined) {
      const anchored = await verify(bytes, { expectSeal: later.seal_hash });
      assert.deepEqual(outcome(anchored), { verdict: "FAIL", level: "J1", code: "ANCHOR_NOT_FOUND", frame: null });
    }
    // A seal of a point before the forged frame still matches: it vouches for its prefix only.
    const earlier = original.seals.filter((s) => s.n <= spec.frame).pop();
    if (earlier !== undefined) {
      const anchored = await verify(bytes, { expectSeal: earlier.seal_hash });
      assert.equal(anchored.verdict, "PASS");
      assert.equal(anchored.anchor.seal.at_n, earlier.n);
    }
  });
}

test("A6: at least one forged journal has a seal before the forged frame and one has none", () => {
  const has = (spec) => EXPECTED.valid[spec.from.split("/").pop()].seals.some((s) => s.n <= spec.frame);
  assert.ok(FORGED.some(has));
  assert.ok(FORGED.some((s) => !has(s)));
});
