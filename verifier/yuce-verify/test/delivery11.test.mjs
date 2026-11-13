// Delivery 1.1: one test per line of the task statement section 6, and acceptance A9
// (results on valid/, corrupt/ and boundary/ unchanged since delivery 1,
// except the form of `anchor` and the removed fields).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { clone, loadFrames, rechain, saveFrames, setPath } from "./forge.mjs";
import { OTHER_HASH, SMALL, adapter, bytesOf, fixture, joinLines, linesOf, outcome, readRoom, room, textOf, verify, yv } from "./helpers.mjs";

const base = textOf(readRoom(SMALL)); // seals at 2 and 6, close at 7
const j1 = (code, frame) => ({ verdict: "FAIL", level: "J1", code, frame });

async function mutate(edit, how = {}) {
  const frames = loadFrames(base);
  edit(frames);
  await rechain(frames, how);
  return saveFrames(frames);
}

// the task statement 6.1 as changed by amendment 1 (P1-5): 67108863 and 64; see amendment1.test.mjs.
test("6.1 defaults: line limit 67108863 bytes, nesting limit 64 (amendment 1)", async () => {
  assert.equal(yv.DEFAULT_MAX_LINE_BYTES, 67108863);
  assert.equal(yv.DEFAULT_MAX_DEPTH, 64);
  // A one-frame journal with a line of 17 MiB: refused at the old 16 MiB, accepted by default.
  const frames = loadFrames(base).slice(0, 1);
  frames[0].get("body").set("padding", "x".repeat(17 * 1024 * 1024));
  await rechain(frames);
  const big = bytesOf(saveFrames(frames));
  assert.equal((await verify(big)).verdict, "PASS");
  assert.deepEqual(outcome(await verify(big, { maxLineBytes: 16 * 1024 * 1024 })), { verdict: "FAIL", level: "J0", code: "LIMIT_EXCEEDED", frame: 0 });
  // Nesting 64 passes the limit, 65 does not.
  const nest = (m) => joinLines([JSON.stringify({ deep: JSON.parse("[".repeat(m) + "]".repeat(m)) })]);
  assert.notEqual((await verify(nest(63))).first_failure.code, "LIMIT_EXCEEDED");
  assert.equal((await verify(nest(64))).first_failure.code, "LIMIT_EXCEEDED");
});

test("6.2 J1-13: a seal or a close not from the kernel is KERNEL_COMMAND_NOT_FROM_KERNEL; no anomalies field", async () => {
  const seal = await verify(await mutate((f) => setPath(f[6], "body.actor", "reader-2")));
  assert.deepEqual(outcome(seal), j1("KERNEL_COMMAND_NOT_FROM_KERNEL", 6));
  const close = await verify(await mutate((f) => setPath(f[7], "body.actor", "owner")));
  assert.deepEqual(outcome(close), j1("KERNEL_COMMAND_NOT_FROM_KERNEL", 7));
  for (const f of ["inputs/valid/k017-oracle-v3.wal", SMALL]) {
    const r = await verify(readRoom(f));
    assert.equal("anomalies" in r.levels.J1, false);
    assert.equal(yv.reportToJcs(r).includes("anomalies"), false);
  }
});

test("6.3 J1-14: a frame after the close is FRAME_AFTER_CLOSE; no frames_after_close field", async () => {
  const after = await verify(await mutate((f) => f.push(clone(f[5])), { renumber: true }));
  assert.deepEqual(outcome(after), j1("FRAME_AFTER_CLOSE", 8));
  const r = await verify(base);
  assert.equal("frames_after_close" in r.levels.J1, false);
  assert.equal(yv.reportToJcs(r).includes("frames_after_close"), false);
});

test("6.4 J1-1 checks the types of P.format, P.run_id, P.log_size: SEAL_FORM", async () => {
  const both = (f, path, v) => {
    setPath(f[6], `body.command.seal.${path}`, v);
    setPath(f[6], `body.outcome.result.seal.${path}`, clone(v));
  };
  for (const [path, value] of [["format", 2], ["run_id", 5], ["run_id", null], ["log_size", "6"], ["log_size", true]]) {
    const r = await verify(await mutate((f) => both(f, path, value), { resealHash: true }));
    assert.deepEqual(outcome(r), j1("SEAL_FORM", 6), `${path} = ${JSON.stringify(value)}`);
  }
});

test("6.5 J1-9 compares P.run_id with body.run_id of frame 0", async () => {
  assert.equal(loadFrames(base)[0].get("body").get("run_id"), "reference-small");
  const genesis = await verify(await mutate((f) => setPath(f[0], "body.run_id", "other"), { reseal: true }));
  assert.deepEqual(outcome(genesis), j1("SEAL_RUN_ID", 2));
  const seals = await verify(
    await mutate((f) => {
      for (const k of [2, 6]) setPath(f[k], "body.command.seal.run_id", "other");
    }, { reseal: true }),
  );
  assert.deepEqual(outcome(seals), j1("SEAL_RUN_ID", 2));
  const missing = await verify(await mutate((f) => f[0].get("body").delete("run_id"), { reseal: true }));
  assert.deepEqual(outcome(missing), j1("SEAL_RUN_ID", 2));
  // Without seals there is nothing to compare.
  const noSeals = await verify(joinLines(linesOf(await mutate((f) => f[0].get("body").delete("run_id"))).slice(0, 2)));
  assert.equal(noSeals.verdict, "PASS");
});

test("6.6 anchor has two parts, seal and head; three anchor sentences", async () => {
  const SEAL6 = "4c384f513689aafa314ca11505947186bf94a6dce0cffda0275a460c5de7ea1c";
  const HEAD = "3431d070a4345a4b9e3b8973ce526621408c2921a5d100c00956c5ceac4d34bc";
  const sentence = async (o) => yv.humanLine(await verify(base, o)).match(/Anchor: [^.]*\./)[0];
  assert.deepEqual(Object.keys((await verify(base)).anchor).sort(), ["head", "seal"]);
  assert.equal(await sentence({ expectSeal: SEAL6 }), "Anchor: matched seal at n=6.");
  assert.equal(await sentence({ expectHead: HEAD }), "Anchor: matched head at n=8.");
  assert.equal(await sentence({ expectSeal: SEAL6, expectHead: HEAD }), "Anchor: matched seal at n=6 and head at n=8.");
  assert.equal(await sentence({}), "Anchor: not given - journal is internally consistent; authenticity not established.");
});

test('6.7 after a J0 failure, J1 is NOT_CHECKABLE with the reason "J0 failed"', async () => {
  const r = await verify(readRoom("inputs/corrupt/tampered-quote.wal"));
  assert.deepEqual(r.levels.J1, { result: "NOT_CHECKABLE", reason: "J0 failed" });
  assert.equal(r.verdict, "FAIL");
});

test("6.8 lone surrogate: raw bytes give INVALID_UTF8, escaped gives INVALID_JSON", async () => {
  const lines = linesOf(base);
  const enc = new TextEncoder();
  const raw = new Uint8Array([...enc.encode(joinLines(lines.slice(0, 3))), ...enc.encode('{"x":"'), 0xed, 0xa0, 0x80, ...enc.encode('"}\n')]);
  assert.deepEqual(outcome(await verify(raw)), { verdict: "FAIL", level: "J0", code: "INVALID_UTF8", frame: 3 });
  const escaped = joinLines([...lines.slice(0, 3), '{"x":"\\ud800"}']);
  assert.deepEqual(outcome(await verify(escaped)), { verdict: "FAIL", level: "J0", code: "INVALID_JSON", frame: 3 });
});

test("6.9 vectors checks log_root in V9", async () => {
  const parsed = yv.parseJson(readFileSync(room("spec/VECTORS_INDEPENDENT_VERIFIER_20261110.json"), "utf8"));
  const good = await yv.checkVectors(parsed.value, adapter);
  assert.equal(good.find((o) => o.name === "V9_checks").status, "PASS");
  assert.equal(good.some((o) => o.status === "SKIP" && o.name.startsWith("V9")), false);
  // A seal line whose P names another log root (seal hash recomputed): only the log_root check fails.
  const vectors = parsed.value.get("vectors");
  const sealLine = yv.parseJson(vectors.get("V9_line_seal_frame_n")).value;
  const result = sealLine.get("body").get("outcome").get("result");
  for (const p of [sealLine.get("body").get("command").get("seal"), result.get("seal")]) p.set("log_root", OTHER_HASH);
  const P = sealLine.get("body").get("command").get("seal");
  result.set("seal_hash", yv.toHex(await yv.domainHash(adapter, yv.DOMAIN.seal, yv.utf8(yv.jcs(P)))));
  vectors.set("V9_line_seal_frame_n", yv.jcs(sealLine));
  const bad = await yv.checkVectors(parsed.value, adapter);
  const checks = bad.find((o) => o.name === "V9_checks");
  assert.equal(checks.status, "FAIL");
  assert.equal(checks.detail, "fails: P.log_root == RFC 6962 root over the hashes of frames 0..n-1");
});

// the task statement 6.10 as changed by amendments 1 (P1-5) and 2 (P2-3): /4.
test("6.10 the report names SPEC_INDEPENDENT_VERIFIER/4 (amendments 1 and 2)", async () => {
  const r = await verify(base);
  assert.equal(r.verifier.spec, "SPEC_INDEPENDENT_VERIFIER/4");
});

test("6.11 the checks of one frame run in the order of SPEC 6.2", async () => {
  // J1-14 before J1-13: a non-kernel seal after the close.
  const a = await verify(await mutate((f) => { f.push(clone(f[6])); setPath(f[8], "body.actor", "owner"); }, { renumber: true }));
  assert.deepEqual(outcome(a), j1("FRAME_AFTER_CLOSE", 8));
  // J1-13 before J1-10: a non-kernel seal is not a candidate, but J1-10 applies to kernel frames only anyway;
  // J1-13 before J1-1: a broken seal from another actor is refused as not from the kernel.
  const b = await verify(await mutate((f) => { setPath(f[6], "body.actor", "reader-2"); setPath(f[6], "body.command.extra", 1); }));
  assert.deepEqual(outcome(b), j1("KERNEL_COMMAND_NOT_FROM_KERNEL", 6));
  // J1-1 ... J1-9 before J1-10/11/12: a kernel seal with a broken form named audit-close.
  const c = await verify(await mutate((f) => { setPath(f[6], "body.submission_id", "audit-close"); setPath(f[6], "body.command.extra", 1); }));
  assert.deepEqual(outcome(c), j1("SEAL_FORM", 6));
  // J1-10 before J1-11: a kernel close named seal-7.
  const d = await verify(await mutate((f) => setPath(f[7], "body.submission_id", "seal-7")));
  assert.deepEqual(outcome(d), { ...j1("KERNEL_ID_MISUSE", 7) });
  assert.match(d.first_failure.detail, /not a seal/);
  // J1-11 before J1-12: a close with another id and no seal before it.
  const e = await verify(await mutate((f) => { f.splice(6, 1); setPath(f[6], "body.submission_id", "closing"); }, { renumber: true }));
  assert.deepEqual(outcome(e), j1("KERNEL_ID_MISUSE", 6));
});

// ---------------------------------------------------------------------------
// A9: delivery 1 reports, normalized, equal the reports of 1.1.
// ---------------------------------------------------------------------------

/** Drops what 1.1 changes on purpose: anchor, removed fields, spec id, version, the J1 reason, free-text details. */
function normalize(report) {
  const r = structuredClone(report);
  delete r.anchor;
  delete r.verifier.spec;
  delete r.verifier.version;
  delete r.levels.J1.anomalies;
  delete r.levels.J1.frames_after_close;
  delete r.levels.J1.reason;
  if (r.first_failure !== null) delete r.first_failure.detail;
  return r;
}

const SNAPSHOTS = readdirSync(fixture("delivery1-reports")).filter((f) => f.endsWith(".json"));

test("A9: there is a delivery 1 report for every input journal", () => {
  assert.equal(SNAPSHOTS.length, 14);
});

for (const name of SNAPSHOTS) {
  test(`A9: ${name.replace("--", "/").replace(".json", ".wal")} gives the same result as in delivery 1`, async () => {
    const before = JSON.parse(readFileSync(fixture(`delivery1-reports/${name}`), "utf8"));
    const now = await verify(readRoom(`inputs/${name.replace("--", "/").replace(".json", ".wal")}`));
    assert.deepEqual(normalize(now), normalize(before));
    assert.equal(before.verifier.spec, "SPEC_INDEPENDENT_VERIFIER/1");
    // The anchor was not given in these runs: both parts say so now.
    assert.equal(before.anchor.given, false);
    assert.deepEqual(now.anchor, { seal: { given: false, matched: null }, head: { given: false, matched: null } });
  });
}
