// The command line (the task statement section 4): commands, output forms, exit codes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { BUNDLE, ROOM, SMALL, yv } from "./helpers.mjs";

const run = (...args) => {
  const r = spawnSync(process.execPath, [BUNDLE, ...args], { cwd: ROOM, encoding: "utf8" });
  return { code: r.status, out: r.stdout, err: r.stderr };
};

const NOT_VERIFIED = "Not verified: quotes against sources, withdrawal cascade, signatures.";
const NOT_ANCHORED = "Anchor: not given - journal is internally consistent; authenticity not established.";
const SEAL6 = "4c384f513689aafa314ca11505947186bf94a6dce0cffda0275a460c5de7ea1c";
const HEAD = "3431d070a4345a4b9e3b8973ce526621408c2921a5d100c00956c5ceac4d34bc";

test("journal: the human line for a pass, exit 0", () => {
  const r = run("journal", SMALL);
  assert.equal(r.code, 0);
  assert.equal(r.out, `J0-J2 PASS. Frames: 8. Seals: 2. Tail: closed. ${NOT_ANCHORED} ${NOT_VERIFIED}\n`);
  assert.equal(r.err, "");
});

test("journal: the human line for each tail kind", () => {
  assert.match(run("journal", "inputs/valid/live-server-unsealed-tail.wal").out, / Tail: 5 unsealed frames\. /);
  assert.match(run("journal", "inputs/valid/gap-primary-exhausted.wal").out, / Tail: no seals\. /);
});

test("journal: the human line for a failure, exit 1", () => {
  const r = run("journal", "inputs/corrupt/tampered-prev-hash.wal");
  assert.equal(r.code, 1);
  assert.equal(r.out, `FAIL at J0, frame 3: PREVIOUS_MISMATCH. ${NOT_VERIFIED}\n`);
  const s = run("journal", "inputs/corrupt/tampered-seal.wal");
  assert.equal(s.code, 1);
  assert.equal(s.out, `FAIL at J1, frame 2: SEAL_LOG_ROOT. ${NOT_VERIFIED}\n`);
});

test("journal: the word 'verified' never stands without the list of levels", () => {
  for (const f of [SMALL, "inputs/corrupt/tampered-quote.wal"]) {
    const line = run("journal", f).out;
    assert.equal(line.match(/verified/gi).length, 1);
    assert.ok(line.includes("Not verified: quotes against sources, withdrawal cascade, signatures."));
  }
});

test("journal --json: the report is JCS, deterministic, without paths", () => {
  const a = run("journal", SMALL, "--json");
  const b = run("journal", SMALL, "--json");
  assert.equal(a.code, 0);
  assert.equal(a.out, b.out);
  assert.ok(a.out.endsWith("\n"));
  const text = a.out.slice(0, -1);
  const parsed = yv.parseJson(text);
  assert.ok(parsed.ok);
  assert.equal(yv.jcs(parsed.value), text);
  assert.ok(!text.includes(".wal") && !text.includes("inputs") && !text.includes("\\"));
  const report = JSON.parse(text);
  assert.deepEqual(Object.keys(report).sort(), ["anchor", "computed", "first_failure", "input", "levels", "not_verified", "verdict", "verifier"]);
  assert.deepEqual(report.verifier, { name: "yuce-verify", spec: "SPEC_INDEPENDENT_VERIFIER/7", version: "0.3.0" });
  assert.deepEqual(report.anchor, { head: { given: false, matched: null }, seal: { given: false, matched: null } });
  assert.deepEqual(report.not_verified, ["quotes_against_sources", "withdrawal_cascade", "signatures"]);
  assert.deepEqual(report.levels.J2, { result: "PASS", documents: 2, settings_hash: "a13963df2e41d383b808f40f7405e012cfd2568ec7154b7b992dc1cd4e081a8b" });
  assert.deepEqual(report.levels.J3, { result: "NOT_CHECKED" });
  assert.deepEqual(report.input.sources, { given: false });
});

test("journal --json for a failure carries first_failure with level, frame, code, detail", () => {
  const r = run("journal", "inputs/corrupt/uppercase-hash.wal", "--json");
  assert.equal(r.code, 1);
  const report = JSON.parse(r.out);
  assert.equal(report.verdict, "FAIL");
  assert.deepEqual(Object.keys(report.first_failure).sort(), ["code", "detail", "frame", "level"]);
  assert.equal(report.first_failure.code, "BAD_TYPE");
  assert.equal(report.first_failure.frame, 7);
});

test("journal --quiet: only the exit code", () => {
  for (const [args, code] of [
    [["journal", SMALL], 0],
    [["journal", "inputs/corrupt/tampered-quote.wal"], 1],
    [["journal", "missing.wal"], 2],
    [["journal", SMALL, "--json"], 0],
  ]) {
    const r = run(...args, "--quiet");
    assert.equal(r.code, code);
    assert.equal(r.out, "");
    assert.equal(r.err, "");
  }
});

test("journal --expect-seal: lowercased, matched, named in the line", () => {
  const r = run("journal", SMALL, "--expect-seal", SEAL6.toUpperCase());
  assert.equal(r.code, 0);
  assert.match(r.out, / Anchor: matched seal at n=6\. /);
  const eq = run("journal", SMALL, `--expect-seal=${SEAL6}`);
  assert.equal(eq.out, r.out);
});

test("journal --expect-seal not found: exit 1, ANCHOR_NOT_FOUND", () => {
  const r = run("journal", SMALL, "--expect-seal", "ab".repeat(32));
  assert.equal(r.code, 1);
  assert.equal(r.out, `FAIL at J1: ANCHOR_NOT_FOUND. ${NOT_VERIFIED}\n`);
});

test("journal: the anchor sentence when both a seal and the head are given", () => {
  const r = run("journal", SMALL, "--expect-seal", SEAL6, "--expect-head", HEAD);
  assert.equal(r.code, 0);
  assert.equal(r.out, `J0-J2 PASS. Frames: 8. Seals: 2. Tail: closed. Anchor: matched seal at n=6 and head at n=8. ${NOT_VERIFIED}\n`);
});

test("journal --json prints only the report, without the human line", () => {
  const r = run("journal", SMALL, "--json", "--expect-head", HEAD);
  assert.equal(r.out.split("\n").length, 2);
  assert.ok(!r.out.includes("J0-J2 PASS"));
  assert.deepEqual(JSON.parse(r.out).anchor.head, { given: true, matched: true });
});

test("journal --expect-head: matched, or HEAD_MISMATCH", () => {
  const ok = run("journal", SMALL, "--expect-head", HEAD);
  assert.equal(ok.code, 0);
  assert.match(ok.out, / Anchor: matched head at n=8\. /);
  const bad = run("journal", SMALL, "--expect-head", "ab".repeat(32));
  assert.equal(bad.code, 1);
  assert.equal(bad.out, `FAIL at J0: HEAD_MISMATCH. ${NOT_VERIFIED}\n`);
});

test("journal --max-line-bytes and --max-depth", () => {
  assert.equal(run("journal", SMALL, "--max-line-bytes", "100").code, 1);
  assert.match(run("journal", SMALL, "--max-line-bytes", "100").out, /FAIL at J0, frame 0: LIMIT_EXCEEDED\./);
  assert.equal(run("journal", SMALL, "--max-depth", "4").code, 1);
  assert.equal(run("journal", SMALL, "--max-depth", "64", "--max-line-bytes", "67108863").code, 0);
});

test("call errors: exit 2 with a message on stderr", () => {
  const cases = [
    [],
    ["check", SMALL],
    ["journal"],
    ["journal", SMALL, SMALL],
    ["journal", SMALL, "--expect-seal", "abc"],
    ["journal", SMALL, "--expect-seal", "g".repeat(64)],
    ["journal", SMALL, "--expect-head"],
    ["journal", SMALL, "--expect-seal", SEAL6, "--expect-seal", SEAL6],
    ["journal", SMALL, "--max-depth", "0"],
    ["journal", SMALL, "--max-line-bytes", "1.5"],
    ["journal", SMALL, "--unknown"],
    ["journal", "missing.wal"],
    ["journal", "inputs"],
    ["vectors", "missing.json"],
    ["vectors", SMALL],
    ["vectors", "spec/VECTORS_INDEPENDENT_VERIFIER_20261119_v2.json", "--expect-seal", SEAL6],
  ];
  for (const args of cases) {
    const r = run(...args);
    assert.equal(r.code, 2, `${args.join(" ")}: ${r.out}`);
    assert.equal(r.out, "");
    assert.match(r.err, /^yuce-verify: /);
  }
});

test("vectors: checks, names the skipped ones, exit 0", () => {
  const r = run("vectors", "spec/VECTORS_INDEPENDENT_VERIFIER_20261119_v2.json");
  assert.equal(r.code, 0);
  const lines = r.out.trim().split("\n");
  assert.equal(lines.at(-1), "Vectors: 39 passed, 0 failed, 14 skipped.");
  for (const v of ["PASS V7_seal_hash", "PASS V9_frame_hash_n_minus_1", "PASS V9_frame_hash_n", "PASS V9_seal_hash", "PASS V9_checks"]) {
    assert.ok(lines.includes(v), v);
  }
  assert.ok(!lines.some((l) => l.startsWith("SKIP V9")));
  assert.ok(lines.some((l) => l.startsWith("SKIP V5_root_empty_state: ")));
  const j = JSON.parse(run("vectors", "spec/VECTORS_INDEPENDENT_VERIFIER_20261119_v2.json", "--json").out);
  assert.equal(j.failed, 0);
});

test("--help prints the usage", () => {
  const r = run("--help");
  assert.equal(r.code, 0);
  assert.match(r.out, /yuce-verify journal <file>/);
});

// ---------------------------------------------------------------------------
// --docs (the task statement, section 4; amendment 3, P3-2 and P3-10)
// ---------------------------------------------------------------------------
const KBP = "inputs/valid/kinds-batch-put.wal";
const KBP_DOCS = "inputs/valid/kinds-batch-put.docs";
const NOT_VERIFIED_J3 = "Not verified: withdrawal cascade, signatures.";

test("journal --docs: J0-J3 PASS line, exit 0", () => {
  const r = run("journal", KBP, "--docs", KBP_DOCS);
  assert.equal(r.code, 0);
  assert.equal(r.out, `J0-J3 PASS. Frames: 8. Seals: 1. Records: 13. Quotes: 5. Tail: closed. ${NOT_ANCHORED} ${NOT_VERIFIED_J3}\n`);
});

test("journal --docs --json: sources, J2, J3, not_verified", () => {
  const r = run("journal", KBP, "--docs", KBP_DOCS, "--json");
  assert.equal(r.code, 0);
  const report = JSON.parse(r.out);
  assert.deepEqual(report.input.sources, { given: true, files: 3 });
  assert.deepEqual(report.levels.J2, { result: "PASS", documents: 3, settings_hash: "c3fd19b720d1418ca1e016ad97046c973a7d0994e9eab46b9de48fefd44bfa46" });
  assert.deepEqual(report.levels.J3, { result: "PASS", records: 13, quotes: 5 });
  assert.deepEqual(report.not_verified, ["withdrawal_cascade", "signatures"]);
  assert.equal(report.verifier.spec, "SPEC_INDEPENDENT_VERIFIER/7");
});

test("journal --docs with a document missing: INCOMPLETE, exit 3, the doc_id named", () => {
  const r = run("journal", KBP, "--docs", "yuce-verify/test/fixtures/docs-without-vector-a");
  assert.equal(r.code, 3);
  assert.equal(
    r.out,
    `J0-J2 PASS. Frames: 8. Seals: 1. J3 not checkable: document vector-a.txt not supplied. Tail: closed. ${NOT_ANCHORED} ${NOT_VERIFIED}\n`,
  );
  const report = JSON.parse(run("journal", KBP, "--docs", "yuce-verify/test/fixtures/docs-without-vector-a", "--json").out);
  assert.equal(report.verdict, "INCOMPLETE");
  assert.deepEqual(report.levels.J3, { result: "NOT_CHECKABLE", reason: "document vector-a.txt not supplied" });
  assert.deepEqual(report.input.sources, { given: true, files: 2 });
  assert.equal(run("journal", KBP, "--docs", "yuce-verify/test/fixtures/docs-without-vector-a", "--quiet").code, 3);
});

test("journal --docs: a J3 failure, exit 1", () => {
  const r = run("journal", "inputs/corrupt/quote-not-in-source.wal", "--docs", KBP_DOCS);
  assert.equal(r.code, 1);
  assert.equal(r.out, `FAIL at J3, frame 1: QUOTE_NOT_IN_SOURCE. ${NOT_VERIFIED}\n`);
});

test("journal: a J2 failure without --docs, exit 1", () => {
  const r = run("journal", "inputs/boundary/nested-seal.wal");
  assert.equal(r.code, 1);
  assert.equal(r.out, `FAIL at J2, frame 2: KERNEL_OP_IN_BATCH. ${NOT_VERIFIED}\n`);
});

test("journal --docs: a folder that cannot be read is exit 2", () => {
  for (const args of [
    ["journal", KBP, "--docs", "no-such-folder"],
    ["journal", KBP, "--docs", KBP],
    ["journal", KBP, "--docs"],
    ["journal", KBP, "--docs", KBP_DOCS, "--docs", KBP_DOCS],
  ]) {
    const r = run(...args);
    assert.equal(r.code, 2, args.join(" "));
    assert.equal(r.out, "");
    assert.match(r.err, /^yuce-verify: /);
  }
});
