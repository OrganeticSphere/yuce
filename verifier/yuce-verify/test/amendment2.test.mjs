// Amendment 2 to SPEC v3, item P2-3: J1-10 by the prefix "seal-", the spec id
// /4, and the tests that P2-2 asks for.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { loadFrames, rechain, saveFrames, setPath } from "./forge.mjs";
import { BUNDLE, ROOM, SMALL, outcome, readRoom, textOf, verify, yv } from "./helpers.mjs";

const base = textOf(readRoom(SMALL)); // frame 3: actor "owner", an ordinary command; seals at 2 and 6; close at 7
const j1 = (code, frame) => ({ verdict: "FAIL", level: "J1", code, frame });

async function mutate(edit, how = { reseal: true }) {
  const frames = loadFrames(base);
  edit(frames);
  await rechain(frames, how);
  return saveFrames(frames);
}

/** Frame 3 written by the kernel, with an ordinary command and the given submission_id. */
const kernelFrame3 = (sid) => (f) => {
  setPath(f[3], "body.actor", "kernel");
  setPath(f[3], "body.submission_id", sid);
};

test("P2-2: frame 3 has an ordinary command (not seal, not close)", () => {
  const kind = loadFrames(base)[3].get("body").get("command").get("kind");
  assert.equal(typeof kind, "string");
  assert.ok(kind !== "seal" && kind !== "close");
});

for (const sid of ["seal-", "seal-x", "seal-٣", "seal-01", "seal-3", "seal-99", "seal-3 ", "seal--1"]) {
  test(`P2-2 / J1-10: a kernel frame that is not a seal, id ${JSON.stringify(sid)} -> KERNEL_ID_MISUSE`, async () => {
    const r = await verify(await mutate(kernelFrame3(sid)));
    assert.deepEqual(outcome(r), j1("KERNEL_ID_MISUSE", 3), JSON.stringify(r.first_failure));
  });
}

for (const sid of ["Seal-1", "sealx-1", "SEAL-3", "seal", "seal_3", " seal-3", "xseal-3"]) {
  test(`P2-2 / J1-10: a kernel frame with id ${JSON.stringify(sid)} is not under the rule`, async () => {
    const r = await verify(await mutate(kernelFrame3(sid)));
    assert.equal(r.verdict, "PASS", JSON.stringify(r.first_failure));
  });
}

test("P2-2 / J1-10: a non-string submission_id is not under the rule (J1 passes; J2 then refuses it)", async () => {
  for (const sid of [5, null, ["seal-3"]]) {
    const r = await verify(await mutate(kernelFrame3(sid)));
    assert.equal(r.levels.J1.result, "PASS", `${JSON.stringify(sid)}: ${JSON.stringify(r.first_failure)}`);
    // Amendment 3, J2-7: submission_id must be an identifier.
    assert.deepEqual(outcome(r), { verdict: "FAIL", level: "J2", code: "BODY_FIELD", frame: 3 });
  }
});

test("P2-2 / J1-10: another actor with id seal-5 and an ordinary command passes", async () => {
  const r = await verify(await mutate((f) => setPath(f[3], "body.submission_id", "seal-5")));
  assert.equal(loadFrames(base)[3].get("body").get("actor"), "owner");
  assert.equal(r.verdict, "PASS", JSON.stringify(r.first_failure));
});

for (const sid of ["seal-x", "seal-٣", "seal-06", "seal-", "seal-6x"]) {
  test(`P2-2 / J1-4: a seal candidate with id ${JSON.stringify(sid)} -> SEAL_LOG_SIZE`, async () => {
    const r = await verify(await mutate((f) => setPath(f[6], "body.submission_id", sid), { resealHash: true }));
    assert.deepEqual(outcome(r), j1("SEAL_LOG_SIZE", 6), JSON.stringify(r.first_failure));
  });
}

test("P2-2: J1-11 is unchanged, audit-close compared exactly, both ways", async () => {
  // The close frame with a near-miss id.
  for (const sid of ["audit-close ", "Audit-close", "audit-close\u0000"]) {
    const r = await verify(await mutate((f) => setPath(f[7], "body.submission_id", sid), {}));
    assert.deepEqual(outcome(r), j1("KERNEL_ID_MISUSE", 7), JSON.stringify(sid));
  }
  // A kernel frame that is not a close: a near-miss id passes, the exact id fails.
  assert.equal((await verify(await mutate(kernelFrame3("Audit-close")))).verdict, "PASS");
  assert.deepEqual(outcome(await verify(await mutate(kernelFrame3("audit-close")))), j1("KERNEL_ID_MISUSE", 3));
});

// P2-3 asked for /4; amendment 3 replaces it with /5.
test("P2-3: the report names the spec id of the latest amendment (/5)", async () => {
  assert.equal(yv.SPEC_ID, "SPEC_INDEPENDENT_VERIFIER/7");
  assert.equal((await verify(base)).verifier.spec, "SPEC_INDEPENDENT_VERIFIER/7");
  const r = spawnSync(process.execPath, [BUNDLE, "journal", SMALL, "--json"], { cwd: ROOM, encoding: "utf8" });
  assert.equal(JSON.parse(r.stdout).verifier.spec, "SPEC_INDEPENDENT_VERIFIER/7");
});

test("P2-3: results on the inputs do not change (boundary/auto-seal-ack.wal still KERNEL_ID_MISUSE at frame 1)", async () => {
  assert.deepEqual(outcome(await verify(readRoom("inputs/boundary/auto-seal-ack.wal"))), j1("KERNEL_ID_MISUSE", 1));
  // J0-J1 still pass nested-seal.wal; J2 now refuses it (amendment 3, J2-11).
  assert.equal((await verify(readRoom("inputs/boundary/nested-seal.wal"))).levels.J1.result, "PASS");
});
