// A4 (substitutions in a seal), A4a (kernel commands: SPEC 6.4, J1-10 ... J1-14),
// the tail kinds (6.5), the anchor (6.5, 8.2) and A5 (the boundary without
// an external anchor).
import { test } from "node:test";
import assert from "node:assert/strict";
import { clone, getPath, loadFrames, rechain, saveFrames, setPath } from "./forge.mjs";
import { OTHER_HASH, SMALL, joinLines, linesOf, outcome, readRoom, textOf, verify } from "./helpers.mjs";

const base = textOf(readRoom(SMALL)); // seals at 2 and 6, close at 7; genesis run_id "reference-small"
const j1 = (code, frame) => ({ verdict: "FAIL", level: "J1", code, frame });

/** Applies edits to the parsed frames, then recomputes hashes per `how`. */
async function mutate(edit, how = {}) {
  const frames = loadFrames(base);
  edit(frames);
  await rechain(frames, how);
  return saveFrames(frames);
}
const both = (frames, k, path, value) => {
  setPath(frames[k], `body.command.seal.${path}`, value);
  setPath(frames[k], `body.outcome.result.seal.${path}`, clone(value));
};

const cases = [
  // A4. Edits of the last seal (frame 6): only the edited check can fail.
  ["log_size + 1", (f) => both(f, 6, "log_size", 7), { resealHash: true }, j1("SEAL_LOG_SIZE", 6)],
  ["log_size - 1", (f) => both(f, 6, "log_size", 5), { resealHash: true }, j1("SEAL_LOG_SIZE", 6)],
  ["submission_id of another size", (f) => setPath(f[6], "body.submission_id", "seal-5"), { resealHash: true }, j1("SEAL_LOG_SIZE", 6)],
  ["submission_id with a leading zero", (f) => setPath(f[6], "body.submission_id", "seal-06"), { resealHash: true }, j1("SEAL_LOG_SIZE", 6)],
  ["log_root", (f) => both(f, 6, "log_root", OTHER_HASH), { resealHash: true }, j1("SEAL_LOG_ROOT", 6)],
  ["wal_head", (f) => both(f, 6, "wal_head", OTHER_HASH), { resealHash: true }, j1("SEAL_WAL_HEAD", 6)],
  ["audit_root", (f) => both(f, 6, "audit_root", OTHER_HASH), { resealHash: true }, j1("SEAL_ROOT_CONTINUITY", 6)],
  ["engine_root", (f) => both(f, 6, "engine_root", OTHER_HASH), { resealHash: true }, j1("SEAL_ROOT_CONTINUITY", 6)],
  ["audit_root of the seal frame's own body instead", (f) => both(f, 6, "audit_root", getPath(f[6], "body.audit_root")), { resealHash: true }, j1("SEAL_ROOT_CONTINUITY", 6)],
  ["the frame before the seal has no audit_root", (f) => getPath(f[5], "body").delete("audit_root"), { reseal: true }, j1("SEAL_ROOT_CONTINUITY", 6)],
  ["run_id of the later seal", (f) => both(f, 6, "run_id", "another-run"), { resealHash: true }, j1("SEAL_RUN_ID", 6)],
  ["run_id of the earlier seal (all resealed)", (f) => both(f, 2, "run_id", "another-run"), { reseal: true }, j1("SEAL_RUN_ID", 2)],
  ["run_id of both seals equal, but not the genesis run_id", (f) => { both(f, 2, "run_id", "another-run"); both(f, 6, "run_id", "another-run"); }, { reseal: true }, j1("SEAL_RUN_ID", 2)],
  ["genesis run_id changed", (f) => setPath(f[0], "body.run_id", "another-run"), { reseal: true }, j1("SEAL_RUN_ID", 2)],
  ["genesis run_id missing", (f) => getPath(f[0], "body").delete("run_id"), { reseal: true }, j1("SEAL_RUN_ID", 2)],
  ["genesis run_id not a string", (f) => setPath(f[0], "body.run_id", 7), { reseal: true }, j1("SEAL_RUN_ID", 2)],
  ["run_id not a string", (f) => both(f, 2, "run_id", 5), { reseal: true }, j1("SEAL_FORM", 2)],
  ["format not a string", (f) => both(f, 6, "format", 2), { resealHash: true }, j1("SEAL_FORM", 6)],
  ["log_size not a number", (f) => both(f, 6, "log_size", "6"), { resealHash: true }, j1("SEAL_FORM", 6)],
  ["format", (f) => both(f, 6, "format", "r2r-seal/3"), { resealHash: true }, j1("SEAL_FORMAT", 6)],
  ["extra key in P", (f) => both(f, 6, "extra", 1), { resealHash: true }, j1("SEAL_FORM", 6)],
  ["missing key in P", (f) => { getPath(f[6], "body.command.seal").delete("run_id"); getPath(f[6], "body.outcome.result.seal").delete("run_id"); }, { resealHash: true }, j1("SEAL_FORM", 6)],
  ["extra key in P.projections", (f) => both(f, 6, "projections.extra", OTHER_HASH), { resealHash: true }, j1("SEAL_FORM", 6)],
  ["P.projections.status not a hash", (f) => both(f, 6, "projections.status", "x"), { resealHash: true }, j1("SEAL_FORM", 6)],
  ["uppercase hash in P", (f) => both(f, 6, "log_root", getPath(f[6], "body.command.seal.log_root").toUpperCase()), { resealHash: true }, j1("SEAL_FORM", 6)],
  ["P in the outcome differs from P in the command", (f) => setPath(f[6], "body.outcome.result.seal.log_size", 5), {}, j1("SEAL_FORM", 6)],
  ["wrong seal_hash", (f) => setPath(f[6], "body.outcome.result.seal_hash", OTHER_HASH), {}, j1("SEAL_HASH_MISMATCH", 6)],
  ["seal_hash not a hash", (f) => setPath(f[6], "body.outcome.result.seal_hash", 1), {}, j1("SEAL_FORM", 6)],
  ["a kernel seal with a refusal outcome", (f) => setPath(f[6], "body.outcome.kind", "error"), {}, j1("SEAL_FORM", 6)],
  ["extra key in outcome.result", (f) => setPath(f[6], "body.outcome.result.extra", 1), {}, j1("SEAL_FORM", 6)],
  ["extra key in the command", (f) => setPath(f[6], "body.command.extra", 1), { resealHash: true }, j1("SEAL_FORM", 6)],
  ["seal is not an object", (f) => setPath(f[6], "body.command.seal", "x"), {}, j1("SEAL_FORM", 6)],
  ["the first seal broken: later seals are not reached", (f) => setPath(f[2], "body.outcome.result.seal_hash", OTHER_HASH), {}, j1("SEAL_HASH_MISMATCH", 2)],
  ["a seal at position 0", (f) => {
    const seal = clone(getPath(f[2], "body"));
    seal.get("command").get("seal").set("log_size", 0);
    seal.get("outcome").get("result").get("seal").set("log_size", 0);
    seal.set("submission_id", "seal-0");
    seal.set("run_id", "reference-small");
    f[0].set("body", seal);
  }, {}, j1("SEAL_LOG_SIZE", 0)],

  // A4a. Kernel commands (SPEC 6.4).
  ["J1-10: a kernel frame named seal-<k> that is not a seal", (f) => { setPath(f[3], "body.actor", "kernel"); setPath(f[3], "body.submission_id", "seal-3"); }, {}, j1("KERNEL_ID_MISUSE", 3)],
  ["J1-10: a kernel frame named seal-<k> for another position", (f) => { setPath(f[3], "body.actor", "kernel"); setPath(f[3], "body.submission_id", "seal-9"); }, {}, j1("KERNEL_ID_MISUSE", 3)],
  ["J1-10: a non-kernel frame named seal-<k> is not checked", (f) => setPath(f[3], "body.submission_id", "seal-3"), { reseal: true }, { verdict: "PASS" }],
  ["J1-10: the close frame named seal-7", (f) => setPath(f[7], "body.submission_id", "seal-7"), {}, j1("KERNEL_ID_MISUSE", 7)],
  ["J1-11: the close frame with an extra key in its command", (f) => setPath(f[7], "body.command.extra", 1), {}, j1("KERNEL_ID_MISUSE", 7)],
  ["J1-11: the close frame with another submission_id", (f) => setPath(f[7], "body.submission_id", "closing"), {}, j1("KERNEL_ID_MISUSE", 7)],
  ["J1-11: audit-close on a kernel frame that is not a close", (f) => { setPath(f[7], "body.command", clone(getPath(f[1], "body.command"))); setPath(f[7], "body.command.kind", "batch"); }, {}, j1("KERNEL_ID_MISUSE", 7)],
  ["J1-12: close without the seal before it", (f) => f.splice(6, 1), { renumber: true }, j1("CLOSE_WITHOUT_SEAL", 6)],
  ["J1-12: close in the middle, after a seal, then frames", (f) => { setPath(f[3], "body", clone(getPath(f[7], "body"))); }, { reseal: true }, j1("FRAME_AFTER_CLOSE", 4)],
  ["J1-13: a seal from another actor", (f) => setPath(f[6], "body.actor", "reader-2"), {}, j1("KERNEL_COMMAND_NOT_FROM_KERNEL", 6)],
  ["J1-13: a seal from another actor is not checked as a seal", (f) => { setPath(f[6], "body.actor", "reader-2"); setPath(f[6], "body.outcome.result.seal_hash", 1); }, {}, j1("KERNEL_COMMAND_NOT_FROM_KERNEL", 6)],
  ["J1-13: a close from another actor", (f) => setPath(f[7], "body.actor", "owner"), {}, j1("KERNEL_COMMAND_NOT_FROM_KERNEL", 7)],
  ["J1-13: a seal command without an actor", (f) => getPath(f[6], "body").delete("actor"), {}, j1("KERNEL_COMMAND_NOT_FROM_KERNEL", 6)],
  ["J1-13: a close command from another actor in the middle", (f) => setPath(f[3], "body.command", parseKind("close")), {}, j1("KERNEL_COMMAND_NOT_FROM_KERNEL", 3)],
  ["J1-13: a command kind that is not a string is no kind", (f) => setPath(f[3], "body.command.kind", ["seal"]), { reseal: true }, { verdict: "PASS" }],
  ["J1-14: a frame after the close frame", (f) => f.push(clone(f[5])), { renumber: true }, j1("FRAME_AFTER_CLOSE", 8)],
  ["J1-14: close twice", (f) => f.push(clone(f[7])), { renumber: true }, j1("FRAME_AFTER_CLOSE", 8)],
  ["J1-14 comes before J1-13", (f) => { f.push(clone(f[7])); setPath(f[8], "body.actor", "owner"); }, { renumber: true }, j1("FRAME_AFTER_CLOSE", 8)],
  ["J1-14 names the first frame after the close", (f) => { f.push(clone(f[5])); f.push(clone(f[5])); }, { renumber: true }, j1("FRAME_AFTER_CLOSE", 8)],
];

function parseKind(kind) {
  return new Map([["kind", kind]]);
}

for (const [name, edit, how, want] of cases) {
  test(`A4/A4a: ${name} -> ${want.code ?? want.verdict}${want.frame !== undefined ? ` @ ${want.frame}` : ""}`, async () => {
    const report = await verify(await mutate(edit, how));
    assert.deepEqual(outcome(report), want, JSON.stringify(report.first_failure));
    if (want.verdict === "FAIL") {
      assert.equal(report.levels.J0.result, "PASS");
      assert.deepEqual(report.levels.J1, { result: "FAIL" });
      assert.equal(report.computed.closed, null);
    }
  });
}

test("6.5: the four tail kinds; the run is closed only with the tail closed", async () => {
  const lines = linesOf(base);
  const run = async (n) => verify(joinLines(lines.slice(0, n)));
  const tails = {};
  for (const n of [8, 7, 6, 2]) {
    const r = await run(n);
    tails[n] = r.levels.J1.tail;
    assert.equal(r.computed.closed, r.levels.J1.tail.kind === "closed");
  }
  assert.deepEqual(tails[8], { kind: "closed", frames_after_last_seal: 1 });
  assert.deepEqual(tails[7], { kind: "sealed", frames_after_last_seal: 0 });
  assert.deepEqual(tails[6], { kind: "unsealed", frames_after_last_seal: 3 });
  assert.deepEqual(tails[2], { kind: "no_seals" });
});

test("8.2: a passing J1 has only result, seals and tail", async () => {
  const report = await verify(base);
  assert.deepEqual(Object.keys(report.levels.J1).sort(), ["result", "seals", "tail"]);
});

const SEAL2 = "3649c1601a583d7ef0d880f8ab89baeb91c1462d530807de76e1421a532d8574";
const SEAL6 = "4c384f513689aafa314ca11505947186bf94a6dce0cffda0275a460c5de7ea1c";
const HEAD = "3431d070a4345a4b9e3b8973ce526621408c2921a5d100c00956c5ceac4d34bc";
const NOT_GIVEN = { given: false, matched: null };

test("8.2 anchor: neither given", async () => {
  const report = await verify(base);
  assert.deepEqual(report.anchor, { seal: NOT_GIVEN, head: NOT_GIVEN });
});

test("8.2 anchor: seal found names the point n and the frames after it", async () => {
  const report = await verify(base, { expectSeal: SEAL6 });
  assert.equal(report.verdict, "PASS");
  assert.deepEqual(report.anchor, { seal: { given: true, matched: true, at_n: 6, frames_after: 1 }, head: NOT_GIVEN });
});

test("8.2 anchor: head matched", async () => {
  const report = await verify(base, { expectHead: HEAD });
  assert.equal(report.verdict, "PASS");
  assert.deepEqual(report.anchor, { seal: NOT_GIVEN, head: { given: true, matched: true } });
});

test("8.2 anchor: both matched", async () => {
  const report = await verify(base, { expectSeal: SEAL2, expectHead: HEAD });
  assert.deepEqual(report.anchor, { seal: { given: true, matched: true, at_n: 2, frames_after: 5 }, head: { given: true, matched: true } });
});

test("8.2 anchor: seal not found is ANCHOR_NOT_FOUND, matched false", async () => {
  const report = await verify(base, { expectSeal: OTHER_HASH, expectHead: HEAD });
  assert.deepEqual(outcome(report), { verdict: "FAIL", level: "J1", code: "ANCHOR_NOT_FOUND", frame: null });
  assert.deepEqual(report.anchor, { seal: { given: true, matched: false }, head: { given: true, matched: true } });
});

test("8.2 anchor: head mismatch is HEAD_MISMATCH, matched false; the seal is not reached", async () => {
  const report = await verify(base, { expectSeal: SEAL6, expectHead: OTHER_HASH });
  assert.deepEqual(outcome(report), { verdict: "FAIL", level: "J0", code: "HEAD_MISMATCH", frame: null });
  assert.deepEqual(report.anchor, { seal: { given: true, matched: null }, head: { given: true, matched: false } });
});

test("8.2 anchor: an earlier failure leaves both unchecked", async () => {
  const report = await verify(base.slice(0, -5), { expectSeal: SEAL6, expectHead: HEAD });
  assert.equal(report.first_failure.code, "TORN_TAIL");
  assert.deepEqual(report.anchor, { seal: { given: true, matched: null }, head: { given: true, matched: null } });
  const j1fail = await verify(await mutate((f) => setPath(f[6], "body.outcome.result.seal_hash", OTHER_HASH)), { expectSeal: SEAL2 });
  assert.equal(j1fail.first_failure.code, "SEAL_HASH_MISMATCH");
  assert.deepEqual(j1fail.anchor.seal, { given: true, matched: null });
});

test("A5: a journal cut after a seal: PASS not anchored; a later seal or the full head refuse it", async () => {
  const cut = joinLines(linesOf(base).slice(0, 3)); // frames 0..2, the seal of n=2 last
  const plain = await verify(cut);
  assert.equal(plain.verdict, "PASS");
  assert.deepEqual(plain.levels.J1.tail, { kind: "sealed", frames_after_last_seal: 0 });
  assert.deepEqual(plain.anchor, { seal: NOT_GIVEN, head: NOT_GIVEN });

  const laterSeal = await verify(cut, { expectSeal: SEAL6 }); // n=6 of the whole journal
  assert.deepEqual(outcome(laterSeal), { verdict: "FAIL", level: "J1", code: "ANCHOR_NOT_FOUND", frame: null });

  const fullHead = await verify(cut, { expectHead: HEAD }); // the head of the whole journal
  assert.deepEqual(outcome(fullHead), { verdict: "FAIL", level: "J0", code: "HEAD_MISMATCH", frame: null });

  const own = await verify(cut, { expectSeal: SEAL2 });
  assert.deepEqual(own.anchor.seal, { given: true, matched: true, at_n: 2, frames_after: 0 });
});

test("9: J0 is checked over the whole file before any J1 failure is reported", async () => {
  // The SPEC 9 example: a wrong seal at frame 6 and a torn tail after frame 7.
  const text = await mutate((f) => setPath(f[6], "body.outcome.result.seal_hash", OTHER_HASH));
  assert.deepEqual(outcome(await verify(text + '{"bo')), { verdict: "FAIL", level: "J0", code: "TORN_TAIL", frame: 8 });
  assert.deepEqual(outcome(await verify(text.slice(0, -10))), { verdict: "FAIL", level: "J0", code: "TORN_TAIL", frame: 7 });
  assert.deepEqual(outcome(await verify(text)), j1("SEAL_HASH_MISMATCH", 6));
  const failed = await verify(text.slice(0, -10));
  assert.deepEqual(failed.levels.J1, { result: "NOT_CHECKABLE", reason: "J0 failed" });
});
