// Amendment 6 to SPEC v3: level J4a, the withdrawal cascade recomputed at every
// seal, and quittances given with the journal. Acceptance: inputs/j4a/expected.json
// (sets A, A', C, D, E and the boundary journal) and the kernel's rows of set B.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { gunzipSync } from "node:zlib";
import { BUNDLE, ROOM, adapter, fixture, outcome, room, verify, yv } from "./helpers.mjs";

const EXPECTED = JSON.parse(readFileSync(room("inputs/j4a/expected.json"), "utf8"));
const SET_E = JSON.parse(readFileSync(room("inputs/j4a/set-e/expected.json"), "utf8"));

const walk = (d) =>
  readdirSync(d)
    .sort()
    .flatMap((n) => {
      const p = join(d, n);
      return statSync(p).isDirectory() ? walk(p) : [p];
    });

/** The documents folder of a journal under inputs/: <name>.docs next to it, or docs/ in a cut's journal folder. */
function docsFolder(path) {
  const full = room(`inputs/${path}`);
  const beside = full.replace(/\.wal$/, ".docs");
  return existsSync(beside) ? beside : join(dirname(full), "docs");
}
const docsOfJournal = (path) => walk(docsFolder(path)).map((p) => new Uint8Array(readFileSync(p)));

async function run(path, options = {}) {
  const points = [];
  const report = await verify(readFileSync(room(`inputs/${path}`)), { documents: docsOfJournal(path), onProjections: (p) => points.push(p), ...options });
  return { report, points };
}

function kernelRows(name) {
  const bytes = readFileSync(room(`inputs/${name}`));
  return JSON.parse((name.endsWith(".gz") ? gunzipSync(bytes) : bytes).toString("utf8"));
}

const projectionsOf = (points) => points.map((p) => ({ frame: p.seal_position, status: p.status_hash, dependencies: p.dependencies_hash }));

// ---------------------------------------------------------------------------
// Sets A and D: every seal recomputed equal to its own projections
// ---------------------------------------------------------------------------

const SET_A = Object.entries(EXPECTED.set_a);
const SET_D = Object.entries(EXPECTED.set_d).map(([k, v]) => [`j4a/${k}`, v]);

test("P6-10: set A has 58 journal paths, 57 of them sealed, 115 seals; set D 9 journals with 23 seals", () => {
  assert.equal(SET_A.length, 58);
  assert.equal(SET_A.filter(([, e]) => e.projections.length > 0).length, 57);
  assert.equal(SET_A.reduce((n, [, e]) => n + e.projections.length, 0), 115);
  assert.equal(SET_D.length, 9);
  assert.equal(SET_D.reduce((n, [, e]) => n + e.projections.length, 0), 23);
});

for (const [path, want] of [...SET_A, ...SET_D]) {
  test(`P6-10 set ${path.startsWith("j4a/") ? "D" : "A"}: ${path} passes J4a; cascade and every seal's projections as expected`, async () => {
    const { report, points } = await run(path);
    assert.equal(report.verdict, "PASS", JSON.stringify(report.first_failure));
    assert.deepEqual(report.levels.J4a, { result: want.J4a });
    assert.deepEqual(report.cascade, want.cascade);
    assert.deepEqual(projectionsOf(points), want.projections);
    assert.ok(points.every((p) => p.equals_seal));
  });
}

// Set B: the kernel's rows and pairs at each seal, for each distinct journal of A and D.
const ROWS = new Map();
for (const [path, want] of [...SET_A, ...SET_D]) if (!ROWS.has(want.rows)) ROWS.set(want.rows, path);
for (const [rows, path] of ROWS) {
  test(`P6-10 set B: ${rows} equals the rows and pairs J4a computes on ${path}, seal by seal`, async () => {
    const kernel = kernelRows(rows);
    assert.equal(kernel.mismatches, 0);
    const { points } = await run(path);
    assert.equal(points.length, kernel.points.length);
    for (const [k, p] of points.entries()) {
      const kp = kernel.points[k];
      assert.equal(p.seal_position, kp.seal_position);
      assert.deepEqual(p.status_rows, kp.status_rows, `rows at the seal of frame ${p.seal_position}`);
      assert.deepEqual(p.dependency_pairs, kp.dependency_pairs, `pairs at the seal of frame ${p.seal_position}`);
      assert.equal(p.status_hash, kp.status_hash);
      assert.equal(p.dependencies_hash, kp.dependencies_hash);
    }
  });
}

// ---------------------------------------------------------------------------
// Sets A', C and the boundary journal
// ---------------------------------------------------------------------------

for (const [path, want] of Object.entries(EXPECTED.set_a_prime)) {
  test(`P6-10 set A': ${path} fails earlier, J4a NOT_RUN`, async () => {
    const { report } = await run(path);
    const level = want.J1 === "FAIL" ? "J1" : "J2";
    assert.deepEqual(outcome(report), { verdict: "FAIL", level, code: want.code, frame: want.frame });
    assert.equal(report.levels.J4a.result, want.J4a);
    assert.equal(report.cascade, null);
    assert.deepEqual(report.not_verified, ["quotes_against_sources", "withdrawal_cascade", "signatures"]);
  });
}

test("P6-10 set C: the forged cascade passes J0-J3 and fails J4a with PROJECTION_STATUS_MISMATCH at frame 6", async () => {
  const want = EXPECTED.set_c["set-c/forged-cascade.wal"];
  const { report, points } = await run("j4a/set-c/forged-cascade.wal");
  for (const l of ["J0", "J1", "J2", "J3"]) assert.equal(report.levels[l].result, want[l]);
  assert.deepEqual(outcome(report), { verdict: "FAIL", level: "J4a", code: want.code, frame: want.frame });
  assert.deepEqual(report.levels.J4a, { result: "FAIL" });
  assert.deepEqual(report.not_verified, ["withdrawal_cascade", "signatures"]);
  // The dependency hash is unchanged: the forger changed only the status row of the fallen claim.
  const seal6 = JSON.parse(readFileSync(room("inputs/j4a/set-c/forged-cascade.wal"), "utf8").split("\n")[6]).body.command.seal.projections;
  const at6 = points.find((p) => p.seal_position === 6);
  assert.equal(at6.dependencies_hash, seal6.dependencies);
  assert.notEqual(at6.status_hash, seal6.status);
  assert.equal(yv.humanLine(report), "FAIL at J4a, frame 6: PROJECTION_STATUS_MISMATCH. Not verified: withdrawal cascade, signatures.");
});

test("P6-1 boundary: open-two-seals.wal gives cascade (2, 6, 0) with and without --expect-seal of frame 3", async () => {
  const want = EXPECTED.boundary["j4a/boundary/open-two-seals.wal"];
  const { report: without, points } = await run("j4a/boundary/open-two-seals.wal");
  assert.deepEqual([without.levels.J4a.result, without.cascade], [want.without_expect_seal.J4a, want.without_expect_seal.cascade]);
  assert.deepEqual(projectionsOf(points), want.projections);
  const kernel = kernelRows(want.rows);
  assert.deepEqual(points.map((p) => p.status_rows), kernel.points.map((p) => p.status_rows));
  const withSeal = (await run("j4a/boundary/open-two-seals.wal", { expectSeal: want.with_expect_seal.expect_seal })).report;
  assert.deepEqual([withSeal.levels.J4a.result, withSeal.cascade], [want.with_expect_seal.J4a, want.with_expect_seal.cascade]);
  assert.deepEqual(withSeal.anchor.seal, want.with_expect_seal.anchor_seal);
});

// ---------------------------------------------------------------------------
// Set E: quittances
// ---------------------------------------------------------------------------

const quittance = (name) => ({ file: name, bytes: new Uint8Array(readFileSync(room(`inputs/j4a/set-e/${name}`))) });
const SET_E_FILES = Object.keys(SET_E).filter((k) => k.endsWith(".proof.json"));

for (const name of SET_E_FILES) {
  const want = SET_E[name];
  test(`P6-11 set E: ${name} -> ${want.code ?? "PASS"}`, async () => {
    const { report } = await run(SET_E.journal, { quittances: [quittance(name)] });
    assert.deepEqual(report.quittances, [{ file: name, verdict: want.J4a, code: want.code }]);
    assert.equal(report.levels.J4a.result, want.J4a);
    if (want.code === null) {
      assert.equal(report.verdict, "PASS");
      assert.deepEqual(report.not_verified, ["quittance_inclusion", "signatures"]);
    } else {
      assert.deepEqual(outcome(report), { verdict: "FAIL", level: "J4a", code: want.code, frame: null });
      assert.deepEqual(report.not_verified, ["withdrawal_cascade", "quittance_inclusion", "signatures"]);
      if (want.record !== undefined) assert.ok(report.first_failure.detail.includes(want.record), report.first_failure.detail);
    }
    // The cascade check itself is unchanged by a quittance.
    assert.deepEqual(report.cascade, { seals_checked: 2, checked_through_frame: SET_E.seal_frame, unchecked_frames: 0 });
  });
}

test("P6-11: several quittances are checked in the order given; the first failing one is the failure", async () => {
  const both = (await run(SET_E.journal, { quittances: [quittance("E1-with-status.proof.json"), quittance("E2-without-status.proof.json")] })).report;
  assert.equal(both.verdict, "PASS");
  assert.deepEqual(both.quittances.map((q) => q.verdict), ["PASS", "PASS"]);
  const mixed = (
    await run(SET_E.journal, {
      quittances: [quittance("E1-with-status.proof.json"), quittance("E4-other-journal.proof.json"), quittance("E3-status-altered.proof.json")],
    })
  ).report;
  assert.deepEqual(mixed.quittances.map((q) => q.code), [null, "QUITTANCE_SEAL_UNKNOWN", "QUITTANCE_STATUS_MISMATCH"]);
  assert.equal(mixed.first_failure.code, "QUITTANCE_SEAL_UNKNOWN");
});

test("P6-11: the form of a quittance (QUITTANCE_FORM)", async () => {
  const e1 = JSON.parse(readFileSync(room("inputs/j4a/set-e/E1-with-status.proof.json"), "utf8"));
  const bad = async (value) => (await run(SET_E.journal, { quittances: [{ file: "q", bytes: new TextEncoder().encode(typeof value === "string" ? value : JSON.stringify(value)) }] })).report;
  for (const [what, value] of [
    ["not JSON", "{"],
    ["another format", { ...e1, format: "yuce-proof/2" }],
    ["a target that is not an id", { ...e1, target: "abc" }],
    ["no records", { ...e1, records: [] }],
    ["a target not among the records", { ...e1, target: "ab".repeat(32) }],
    ["a seal header with another key set", { ...e1, seal: { ...e1.seal, header: { ...e1.seal.header, extra: 1 } } }],
    ["a seal body that is not a seal", { ...e1, seal: { ...e1.seal, body: { ...e1.seal.body, command: { kind: "close" } } } }],
  ]) {
    const r = await bad(value);
    assert.deepEqual(r.quittances, [{ file: "q", verdict: "FAIL", code: "QUITTANCE_FORM" }], what);
  }
  // Step 1 (review of PR 74): the seal body passes the form and types of J1-1 before the journal is looked at.
  const body = e1.seal.body;
  const result = body.outcome.result;
  for (const [what, b] of [
    ["no outcome.result (E5)", { ...body, outcome: { kind: "value" } }],
    ["an extra key in outcome.result", { ...body, outcome: { ...body.outcome, result: { ...result, extra: 1 } } }],
    ["seal_hash not a hash", { ...body, outcome: { ...body.outcome, result: { ...result, seal_hash: "x" } } }],
    ["outcome.kind error", { ...body, outcome: { ...body.outcome, kind: "error" } }],
    ["no projections in the seal", { ...body, command: { ...body.command, seal: { ...body.command.seal, projections: undefined } } }],
    ["log_size not a number", { ...body, command: { ...body.command, seal: { ...body.command.seal, log_size: "6" } } }],
    ["an extra key in the command", { ...body, command: { ...body.command, extra: 1 } }],
    ["another actor", { ...body, actor: "owner" }],
  ]) {
    const r = await bad({ ...e1, seal: { ...e1.seal, body: b } });
    assert.deepEqual(r.quittances, [{ file: "q", verdict: "FAIL", code: "QUITTANCE_FORM" }], what);
  }
  // A quittance of a record that does not stand there: QUITTANCE_STATUS_MISMATCH at step 3.
  const fallen = e1.status.find((row) => row[2] === false)[0];
  const r = await bad({ ...e1, records: [...e1.records, { value: { id: fallen } }] });
  assert.equal(r.quittances[0].code, "QUITTANCE_STATUS_MISMATCH");
  assert.ok(r.first_failure.detail.includes(fallen));
});

test("P6-11: without documents J4a does not run, and the quittance is not checked", async () => {
  const report = await verify(readFileSync(room(`inputs/${SET_E.journal}`)), { quittances: [quittance("E1-with-status.proof.json")] });
  assert.deepEqual(report.levels.J4a, { result: "NOT_RUN", reason: "J3 not run" });
  assert.deepEqual(report.quittances, [{ file: "E1-with-status.proof.json", verdict: "NOT_RUN", code: null }]);
  assert.deepEqual(report.not_verified, ["quotes_against_sources", "withdrawal_cascade", "quittance_inclusion", "signatures"]);
});

// ---------------------------------------------------------------------------
// Report fields, human lines, formulas
// ---------------------------------------------------------------------------

test("P6-1: the three human lines of a J4a PASS", async () => {
  const line = async (path) => yv.humanLine((await run(path)).report);
  assert.match(await line("valid/withdrawal-version-close.wal"), / Cascade: checked at 2 seals\. Not verified: signatures\.$/);
  assert.match(await line("valid/live-server-unsealed-tail.wal"), / Cascade: checked at 1 seals through frame 3; 5 later frames not checked\. Not verified: withdrawal cascade after last seal, signatures\.$/);
  assert.match(await line("valid/gap-primary-exhausted.wal"), / Cascade: no seal to check\. Not verified: withdrawal cascade, signatures\.$/);
});

test("P6-1: J4a NOT_RUN when J3 failed or could not be checked", async () => {
  const failed = await verify(readFileSync(room("inputs/corrupt/quote-not-in-source.wal")), { documents: docsOfJournal("valid/kinds-batch-put.wal") });
  assert.deepEqual([failed.levels.J3.result, failed.levels.J4a], ["FAIL", { result: "NOT_RUN", reason: "J3 failed" }]);
  const missing = await verify(readFileSync(room("inputs/valid/kinds-batch-put.wal")), { documents: walk(fixture("docs-without-vector-a")).map((p) => new Uint8Array(readFileSync(p))) });
  assert.deepEqual([missing.verdict, missing.levels.J4a], ["INCOMPLETE", { result: "NOT_RUN", reason: "J3 not checkable" }]);
  assert.equal(missing.cascade, null);
});

test("P6-8: the projections of a run with no record", async () => {
  assert.deepEqual(await yv.projectionHashes(adapter, [], []), yv.EMPTY_PROJECTIONS);
  // live-server-unsealed-tail.wal has no record at its seal (frame 3)
  const { points } = await run("valid/live-server-unsealed-tail.wal");
  assert.deepEqual([points[0].status_hash, points[0].dependencies_hash], [yv.EMPTY_PROJECTIONS.status, yv.EMPTY_PROJECTIONS.dependencies]);
});

test("P6-3, P6-10 (first code round): d8, a batch whose put_document after the accepted prefix has no result, changes no document", async () => {
  const path = "j4a/set-d/d8-batch-prefix-put-not-applied.wal";
  const lines = readFileSync(room(`inputs/${path}`), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  // The batch: a submit with a result, then a put_document without one.
  const batch = lines.find((f) => f.body.command?.kind === "batch" && f.body.command.operations.some((o) => o.kind === "put_document"));
  const ops = batch.body.command.operations.map((o) => o.kind);
  const results = batch.body.outcome.result.results.length;
  assert.ok(ops.indexOf("put_document") >= results, JSON.stringify({ ops, results }));
  const { report, points } = await run(path);
  assert.equal(report.verdict, "PASS", JSON.stringify(report.first_failure));
  // Both seals say the quote and the claim on it stand: no row falls.
  for (const p of points) assert.ok(p.status_rows.every((row) => row[2] === true), `seal ${p.seal_position}`);
});

test("P6-3 (answer to SPEC-DEFECT-25): revoke.record is a full 64-digit id in any case; the @ form revokes nothing", async () => {
  const { forge } = await import("./forge.mjs");
  const path = "cut/V-CUT-1/a/run.wal";
  const text = readFileSync(room(`inputs/${path}`), "utf8");
  const record = JSON.parse(text.split("\n")[5]).body.command.record;
  const docs = docsOfJournal(path);
  // Upper case: the same revocation; the seal at frame 6 still agrees.
  const upper = await verify(await forge(text, 5, "body.command.record", record.toUpperCase()), { documents: docs });
  assert.equal(upper.verdict, "PASS", JSON.stringify(upper.first_failure));
  assert.deepEqual(upper.cascade, { seals_checked: 2, checked_through_frame: 6, unchecked_frames: 0 });
  // The @ form of the same id: the command changes nothing, and the next seal no longer agrees.
  const at = await verify(await forge(text, 5, "body.command.record", "@" + record.slice(0, 16)), { documents: docs });
  assert.deepEqual(outcome(at), { verdict: "FAIL", level: "J4a", code: "PROJECTION_STATUS_MISMATCH", frame: 6 });
});

test("P6-6: the link id has no zero byte after its domain", async () => {
  // d6, frame 7: the kernel's set_link_status names the link and its triple.
  const result = JSON.parse(readFileSync(room("inputs/j4a/set-d/d6-relation-link-lifecycle.wal"), "utf8").split("\n")[7]).body.outcome.result;
  assert.equal(await yv.linkId(adapter, result.from, result.rel, result.to), result.id);
  const withZero = yv.toHex(await yv.domainHash(adapter, yv.LINK_DOMAIN, yv.utf8(yv.jcs([result.from, result.rel, result.to]))));
  assert.notEqual(withZero, result.id);
});

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

const cli = (...args) => {
  const r = spawnSync(process.execPath, [BUNDLE, ...args], { cwd: ROOM, encoding: "utf8" });
  return { code: r.status, out: r.stdout, err: r.stderr };
};
const A = "inputs/cut/V-CUT-1/a/run.wal";
const A_DOCS = "inputs/cut/V-CUT-1/a/docs";

test("CLI: journal --docs gives the cascade sentence and the J4a fields", () => {
  const r = cli("journal", A, "--docs", A_DOCS);
  assert.equal(r.code, 0);
  assert.match(r.out, /^J0-J3 PASS\. Frames: 8\. Seals: 2\. Records: 4\. Quotes: 2\. Tail: closed\. .* Cascade: checked at 2 seals\. Not verified: signatures\.\n$/);
  const json = JSON.parse(cli("journal", A, "--docs", A_DOCS, "--json").out);
  assert.deepEqual([json.levels.J4a, json.cascade, json.quittances], [{ result: "PASS" }, { seals_checked: 2, checked_through_frame: 6, unchecked_frames: 0 }, []]);
});

test("CLI: --quittance, repeatable; a failing quittance gives exit 1", () => {
  const ok = cli("journal", A, "--docs", A_DOCS, "--quittance", "inputs/j4a/set-e/E1-with-status.proof.json", "--quittance", "inputs/j4a/set-e/E2-without-status.proof.json", "--json");
  assert.equal(ok.code, 0);
  assert.deepEqual(JSON.parse(ok.out).quittances.map((q) => q.verdict), ["PASS", "PASS"]);
  const bad = cli("journal", A, "--docs", A_DOCS, "--quittance", "inputs/j4a/set-e/E3-status-altered.proof.json");
  assert.equal(bad.code, 1);
  assert.equal(bad.out, "FAIL at J4a: QUITTANCE_STATUS_MISMATCH. Not verified: withdrawal cascade, quittance inclusion, signatures.\n");
  const missing = cli("journal", A, "--docs", A_DOCS, "--quittance", "inputs/j4a/set-e/none.json");
  assert.equal(missing.code, 2);
});

test("CLI: --dump-projections writes the rows and pairs of every seal in the form of the kernel's rows", () => {
  const dir = mkdtempSync(join(tmpdir(), "yv-dump-"));
  try {
    const out = join(dir, "rows.json");
    const r = cli("journal", A, "--docs", A_DOCS, "--dump-projections", out);
    assert.equal(r.code, 0);
    const mine = JSON.parse(readFileSync(out, "utf8"));
    const kernel = kernelRows("j4a/rows/V-CUT-1-a.rows.json");
    assert.deepEqual(Object.keys(mine).sort(), Object.keys(kernel).sort());
    assert.deepEqual(mine, kernel);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
