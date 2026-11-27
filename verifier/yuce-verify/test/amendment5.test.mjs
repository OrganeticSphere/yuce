// Amendment 5 to SPEC v3: the rules r2r-audit-rules/4 of release 0.3.0. The
// genesis record names the rules 3 or 4 (P5-1); under the rules 4 a question
// may name the record it is about (P5-2); the other additions of the rules 4
// change no check of J0-J3 (P5-3); valid/stream-context-checkpoints.wal (P5-4).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { getPath, loadFrames, rechain, saveFrames, setPath } from "./forge.mjs";
import { BUNDLE, ROOM, SMALL, docsOf, outcome, readRoom, textOf, verify, yv } from "./helpers.mjs";

const STREAM = textOf(readRoom("inputs/valid/stream-context-checkpoints.wal"));
const DOCS = docsOf("valid/stream-context-checkpoints.docs");
const FRAMES = loadFrames(STREAM);
const fail = (level, code, frame) => ({ verdict: "FAIL", level, code, frame });

async function mutate(edit, base = STREAM) {
  const frames = loadFrames(base);
  edit(frames);
  await rechain(frames, { reseal: true });
  return saveFrames(frames);
}

/** The frame and the line of the question that names a record. */
function questionLine() {
  for (let fr = 1; fr < FRAMES.length; fr++) {
    const lines = getPath(FRAMES[fr], "body.command").get("lines");
    if (!Array.isArray(lines)) continue;
    const j = lines.findIndex((l) => l.get("kind") === "question" && l.has("about_record"));
    if (j >= 0) return { fr, j, path: `${fr}.body.command.lines.${j}.about_record` };
  }
  throw new Error("the input has no question with about_record");
}

// Amendment 5 asked for /7 (0.3.0); amendment 6 replaces it with /8 (0.3.1).
test("P5: the report names the spec id of the latest amendment (/8) and the version 0.3.1", async () => {
  assert.equal(yv.SPEC_ID, "SPEC_INDEPENDENT_VERIFIER/8");
  assert.equal(yv.VERIFIER_VERSION, "0.3.1");
  const r = spawnSync(process.execPath, [BUNDLE, "journal", SMALL, "--json"], { cwd: ROOM, encoding: "utf8" });
  assert.deepEqual(JSON.parse(r.stdout).verifier, { name: "yuce-verify", spec: "SPEC_INDEPENDENT_VERIFIER/8", version: "0.3.1" });
});

// The release 0.3.1: package.json, its lock file, the report and the banner of the
// built file name one version, the lock file names the license of package.json,
// and the banner names the delivery of today.
test("release: package.json, package-lock.json, VERIFIER_VERSION and the banner of dist/yuce-verify.mjs agree", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
  assert.equal(pkg.version, yv.VERIFIER_VERSION);
  assert.deepEqual([lock.version, lock.packages[""].version], [pkg.version, pkg.version]);
  assert.equal(pkg.license, "Apache-2.0");
  assert.equal(lock.packages[""].license, pkg.license);
  const banner = readFileSync(BUNDLE, "utf8").split("\n")[1];
  assert.equal(banner, `// yuce-verify ${yv.VERIFIER_VERSION}: independent verifier of YuCe journals, delivery 3: levels J0-J3 and J4a, the cut check, the observation report.`);
  assert.ok(pkg.description.endsWith("delivery 3: levels J0-J3 and J4a, the cut check, the observation report."), pkg.description);
});

test("P5-1: a genesis record names the rules 3 or 4, and no other", async () => {
  assert.deepEqual([...yv.RULES_VERSIONS], ["r2r-audit-rules/3", "r2r-audit-rules/4"]);
  assert.equal(FRAMES[0].get("body").get("rules_version"), "r2r-audit-rules/4");
  assert.equal(loadFrames(textOf(readRoom(SMALL)))[0].get("body").get("rules_version"), "r2r-audit-rules/3");
  for (const rules of ["r2r-audit-rules/5", "r2r-audit-rules/2", "r2r-audit-rules/40", "R2R-AUDIT-RULES/4", "", 4, null, ["r2r-audit-rules/4"]]) {
    const r = await verify(await mutate((f) => setPath(f, "0.body.rules_version", rules)), { documents: DOCS });
    assert.deepEqual(outcome(r), fail("J2", "GENESIS_FORMAT", 0), JSON.stringify(rules));
  }
  // the order of the checks: format, rules_version, state_root_format, seal_format
  const two = await verify(await mutate((f) => (setPath(f, "0.body.rules_version", "x"), setPath(f, "0.body.seal_format", "y"))));
  assert.match(two.first_failure.detail, /^rules_version is not one of/);
});

test("P5-4: the journal that starts without a document passes J0-J3", async () => {
  const genesis = FRAMES[0].get("body");
  assert.equal(genesis.get("source_mode"), "opaque");
  assert.equal(genesis.get("source_documents").size, 0);
  const withDocs = await verify(STREAM, { documents: DOCS });
  assert.equal(withDocs.verdict, "PASS", JSON.stringify(withDocs.first_failure));
  assert.equal(withDocs.levels.J2.documents, 0);
  assert.equal(withDocs.levels.J3.result, "PASS");
  // amendment 6: J4a checked the cascade at its seal (frame 10); the close frame after it is not counted
  assert.deepEqual(withDocs.not_verified, ["signatures"]);
  assert.deepEqual(withDocs.cascade, { seals_checked: 1, checked_through_frame: 10, unchecked_frames: 0 });
  // and with no file at all: every version of every document comes from a put_document command
  const noFiles = await verify(STREAM, { documents: [] });
  assert.deepEqual([noFiles.verdict, noFiles.levels.J3], ["PASS", withDocs.levels.J3]);
  assert.equal((await verify(STREAM)).levels.J3.result, "NOT_CHECKED");
});

test("P5-2: under the rules 4 a question names the record it is about, resolved as a reference", async () => {
  const q = questionLine();
  // a local name of the same task resolves; so does the whole id, and its short form
  const lines = getPath(FRAMES[q.fr], "body.command").get("lines");
  const named = lines.findIndex((l) => l.get("local_id") === lines[q.j].get("about_record"));
  assert.ok(named >= 0 && named < q.j, "the question names an earlier line of its own task");
  for (const [what, value, want] of [
    ["an unknown reference", "@" + "0".repeat(16), "UNRESOLVED_REFERENCE"],
    ["a name of no record", "no-such-line", "UNRESOLVED_REFERENCE"],
    ["a number", 5, "RECORD_FORM"],
    ["an array", ["a"], "RECORD_FORM"],
  ]) {
    const r = await verify(await mutate((f) => setPath(f, q.path, value)), { documents: DOCS });
    assert.deepEqual(outcome(r), fail("J3", want, q.fr), what);
  }
  // another record that exists: the body of the question changes, and with it the record id
  const other = lines.findIndex((l, k) => k < q.j && k !== named && typeof l.get("local_id") === "string");
  const r = await verify(await mutate((f) => setPath(f, q.path, lines[other].get("local_id"))), { documents: DOCS });
  assert.deepEqual(outcome(r), fail("J3", "RECORD_ID_MISMATCH", q.fr));
});

test("P5-2: under the rules 3 the key about_record is not allowed for a question", async () => {
  const q = questionLine();
  const r = await verify(await mutate((f) => setPath(f, "0.body.rules_version", "r2r-audit-rules/3")), { documents: DOCS });
  assert.deepEqual(outcome(r), fail("J3", "RECORD_FORM", q.fr));
  assert.match(r.first_failure.detail, /key "about_record" is not allowed for question/);
  assert.equal(yv.lineFormProblem(getPath(FRAMES[q.fr], "body.command").get("lines")[q.j]), 'key "about_record" is not allowed for question');
  assert.equal(yv.lineFormProblem(getPath(FRAMES[q.fr], "body.command").get("lines")[q.j], true), null);
  assert.deepEqual(yv.QUESTION_KEYS_RULES_4, [...yv.LINE_KEYS.question, "about_record"]);
  // the other kinds have the keys they had
  const claim = new Map([["kind", "claim"], ["local_id", "c"], ["text", "t"], ["subject", "s"], ["stance", "reported"], ["based_on", ["o"]], ["about_record", "o"]]);
  assert.equal(yv.lineFormProblem(claim, true), 'key "about_record" is not allowed for claim');
});

test("P5-3: a context checkpoint is a frame of its own with the empty records root", async () => {
  const checkpoints = FRAMES.filter((f) => {
    const c = f.get("body").get("command");
    return c instanceof Map && c.get("kind") === "checkpoint" && String(c.get("key")).startsWith("vsc:checkpoint:");
  });
  assert.deepEqual(checkpoints.map((f) => f.get("body").get("command").get("key")), ["vsc:checkpoint:1", "vsc:checkpoint:2", "vsc:checkpoint:3"]);
  for (const f of checkpoints) {
    assert.equal(f.get("header").get("records_root"), yv.EMPTY_RECORDS_ROOT);
    assert.equal(f.get("body").get("outcome").get("kind"), "value");
  }
});

test("P5-3: a claim rests on a claim, a withdrawal names its reason, and neither changes a check", async () => {
  const records = new Map();
  let withdrawals = 0;
  for (const f of FRAMES.slice(1)) {
    const command = f.get("body").get("command");
    if (command.get("kind") === "revoke_text" || command.get("kind") === "revoke") withdrawals += command.has("reason_source_id") ? 1 : 0;
    const accepted = f.get("body").get("outcome").get("result")?.get?.("accepted");
    if (!Array.isArray(accepted)) continue;
    accepted.forEach((id, k) => records.set(command.get("lines")[k].get("local_id") + "@" + command.get("directive"), command.get("lines")[k]));
  }
  const onClaims = [...records.entries()].filter(([name, line]) => {
    const task = name.slice(name.indexOf("@") + 1);
    return line.get("kind") === "claim" && line.get("based_on").some((b) => records.get(b + "@" + task)?.get("kind") === "claim");
  });
  assert.ok(onClaims.length >= 1, "the input has a claim that rests on a claim");
  assert.equal(withdrawals, 1);
});
