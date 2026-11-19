// A1 and B1: control vectors (file of 19.11.2026: V1-V9 unchanged, V10-V16 new).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { adapter, room, yv } from "./helpers.mjs";

export const VECTORS = "spec/VECTORS_INDEPENDENT_VERIFIER_20261119_v2.json";
const load = () => {
  const parsed = yv.parseJson(readFileSync(room(VECTORS), "utf8"));
  assert.ok(parsed.ok);
  return parsed.value;
};

test("the vectors file has the size and SHA-256 that amendment 4, P4-9, names", () => {
  const spec = readFileSync(room("spec/SPEC_INDEPENDENT_VERIFIER_v3_AMENDMENT4.md"), "utf8");
  const named = spec.match(/Current version: ([\d,]+) bytes, SHA-256 `([0-9a-f]{64})`/);
  assert.ok(named, "P4-9 names the size and SHA-256 of the vectors file");
  const bytes = readFileSync(room(VECTORS));
  assert.equal(bytes.length, Number(named[1].replaceAll(",", "")));
  assert.equal(createHash("sha256").update(bytes).digest("hex"), named[2]);
});

test("A1/B1: every vector the delivery can compute passes; V5, V6, V8 (but the settings hash) are named as skipped", async () => {
  const outcomes = await yv.checkVectors(load(), adapter);
  const by = Object.fromEntries(outcomes.map((o) => [o.name, o]));

  const delivery1 = ["V3_body_hash", "V3_h", "V3_line", "V3_line_sha256", "V3_line_len", "V4_log_root_n1", "V4_log_root_n2", "V4_log_root_n3", "V7_seal_hash"];
  const v9 = ["V9_frame_hash_n_minus_1", "V9_frame_hash_n", "V9_seal_hash", "V9_checks"];
  const desirable = ["V1_rec_empty", "V2_leaf", "V2_root_n1", "V2_root_n2", "V2_root_n3", "V2_real_leaf", "V2_real_records_root"];
  const delivery2 = [
    "V10_request_hash",
    "V11_gear_hex",
    "V11_cdc",
    "V11_documents[vector-a.txt]",
    "V11_documents[vector-b.txt]",
    "V11_documents[vector-c.txt]",
    "V11_version_empty_document",
    "V11_short_documents[0]",
    "V11_short_documents[1]",
    "V12_evidence[0]",
    "V12_evidence[1]",
    "V13_record_id",
    "V14_records",
    "V14_records_roots",
    "V16_git_document_id",
  ];
  const v15 = ["V15_settings_hash", "V15_settings_hash_empty", "V8_settings_hash_empty"];
  for (const name of [...delivery1, ...v9, ...desirable, ...delivery2, ...v15]) {
    assert.equal(by[name]?.status, "PASS", `${name}: ${by[name]?.detail}`);
  }
  assert.deepEqual(outcomes.filter((o) => o.status === "FAIL"), []);
  const skipped = outcomes.filter((o) => o.status === "SKIP").map((o) => o.name);
  for (const name of skipped) assert.match(name, /^(V5_|V6_|V8_)/);
  assert.ok(!skipped.includes("V8_settings_hash_empty"));
  assert.equal(skipped.length, 14);
});

test("A1/B1: a wrong vector value is reported as FAIL", async () => {
  const file = load();
  const v = file.get("vectors");
  v.set("V7_seal_hash", "00".repeat(32));
  v.set("V4_log_root_n2", "11".repeat(32));
  v.set("V10_request_hash", "22".repeat(32));
  v.set("V13_record_id", "33".repeat(32));
  v.get("V11_documents")[1].set("version", "44".repeat(32));
  v.get("V14_records")[3].set("leaf", "55".repeat(32));
  v.set("V16_git_document_id", "d_" + "66".repeat(32));
  const outcomes = await yv.checkVectors(file, adapter);
  const failed = outcomes.filter((o) => o.status === "FAIL").map((o) => o.name).sort();
  assert.deepEqual(failed, ["V10_request_hash", "V11_documents[vector-b.txt]", "V13_record_id", "V14_records", "V14_records_roots", "V16_git_document_id", "V4_log_root_n2", "V7_seal_hash"]);
});

test("B1: the V12 anchor of a quote across two chunks has two segments", async () => {
  const e = load().get("vectors").get("V12_evidence");
  assert.equal(e[1].get("segments").length, 2);
});
