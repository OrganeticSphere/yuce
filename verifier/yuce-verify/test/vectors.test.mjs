// A1: control vectors.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { adapter, room, yv } from "./helpers.mjs";

const VECTORS = "spec/VECTORS_INDEPENDENT_VERIFIER_20261110.json";

test("A1: every vector delivery 1 can compute passes; V5, V6, V8 are named as skipped", async () => {
  const parsed = yv.parseJson(readFileSync(room(VECTORS), "utf8"));
  assert.ok(parsed.ok);
  const outcomes = await yv.checkVectors(parsed.value, adapter);
  const by = Object.fromEntries(outcomes.map((o) => [o.name, o]));

  const required = ["V3_body_hash", "V3_h", "V3_line", "V3_line_sha256", "V3_line_len", "V4_log_root_n1", "V4_log_root_n2", "V4_log_root_n3", "V7_seal_hash"];
  const desirable = ["V1_rec_empty", "V2_leaf", "V2_root_n1", "V2_root_n2", "V2_root_n3", "V2_real_leaf", "V2_real_records_root"];
  for (const name of [...required, ...desirable, "V9_seal_hash"]) {
    assert.equal(by[name]?.status, "PASS", `${name}: ${by[name]?.detail}`);
  }
  assert.deepEqual(outcomes.filter((o) => o.status === "FAIL"), []);
  const skipped = outcomes.filter((o) => o.status === "SKIP").map((o) => o.name);
  for (const name of skipped) assert.match(name, /^(V5_|V6_|V8_|V9_checks\[P\.log_root\])/);
  assert.ok(skipped.some((n) => n.startsWith("V5_")) && skipped.some((n) => n.startsWith("V6_")) && skipped.some((n) => n.startsWith("V8_")));
});

test("A1: a wrong vector value is reported as FAIL", async () => {
  const parsed = yv.parseJson(readFileSync(room(VECTORS), "utf8"));
  parsed.value.get("vectors").set("V7_seal_hash", "00".repeat(32));
  parsed.value.get("vectors").set("V4_log_root_n2", "11".repeat(32));
  const outcomes = await yv.checkVectors(parsed.value, adapter);
  const failed = outcomes.filter((o) => o.status === "FAIL").map((o) => o.name).sort();
  assert.deepEqual(failed, ["V4_log_root_n2", "V7_seal_hash"]);
});
