// A3, second half: the substitution matrix on a small journal, built by the
// executor. Every case names the refusal code and frame the specification
// gives for it (SPEC sections 5 and 9).
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseLine } from "./forge.mjs";
import { OTHER_HASH, SMALL, bytesOf, joinLines, linesOf, outcome, readRoom, textOf, verify, yv } from "./helpers.mjs";

const base = textOf(readRoom(SMALL));
const lines = linesOf(base);
const N = lines.length; // 8
const enc = new TextEncoder();

const cases = [];
const add = (name, input, want, options = {}) => cases.push({ name, input, want, options });
const j0 = (code, frame) => ({ verdict: "FAIL", level: "J0", code, frame });

/** The journal with line k replaced. */
const withLine = (k, line) => joinLines(lines.map((l, i) => (i === k ? line : l)));
/** Line k re-serialized canonically after an edit of its parsed frame. */
const editLine = (k, edit) => {
  const f = parseLine(lines[k]);
  edit(f);
  return yv.jcs(f);
};

/** Changes one ASCII letter inside the first string value of the body that has one. */
function oneByteOfBody(k) {
  const f = parseLine(lines[k]);
  const stack = [f.get("body")];
  while (stack.length > 0) {
    const v = stack.pop();
    if (typeof v === "string") continue;
    const children = v instanceof Map ? [...v.entries()] : v.map((x, i) => [i, x]);
    for (const [key, x] of children) {
      if (typeof x === "string" && /[a-z]/.test(x)) {
        const at = x.search(/[a-z]/);
        const changed = x.slice(0, at) + (x[at] === "a" ? "b" : "a") + x.slice(at + 1);
        if (v instanceof Map) v.set(key, changed);
        else v[key] = changed;
        return yv.jcs(f);
      }
      if (x !== null && typeof x === "object") stack.unshift(x);
    }
  }
  throw new Error(`no string to change in the body of frame ${k}`);
}

function byteDiff(a, b) {
  const x = enc.encode(a);
  const y = enc.encode(b);
  if (x.length !== y.length) return -1;
  let d = 0;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) d++;
  return d;
}

/** Replaces the last occurrence of `from` in line k (the header is the last key of a frame). */
const replaceLast = (k, from, to) => {
  const l = lines[k];
  const at = l.lastIndexOf(from);
  if (at < 0) throw new Error(`${from} not in line ${k}`);
  return l.slice(0, at) + to + l.slice(at + from.length);
};

// --- every header field, every outer field, one byte of every body ----------
for (let k = 0; k < N; k++) {
  add(`frame ${k}: header.body_hash replaced`, withLine(k, editLine(k, (f) => f.get("header").set("body_hash", OTHER_HASH))), j0("BODY_HASH_MISMATCH", k));
  add(
    `frame ${k}: header.format replaced`,
    withLine(k, editLine(k, (f) => f.get("header").set("format", "sbgk-session-log/4"))),
    j0(k === 0 ? "UNSUPPORTED_FORMAT" : "MIXED_FORMAT", k),
  );
  add(`frame ${k}: header.previous replaced`, withLine(k, editLine(k, (f) => f.get("header").set("previous", OTHER_HASH))), j0("PREVIOUS_MISMATCH", k));
  add(`frame ${k}: header.records_root replaced`, withLine(k, editLine(k, (f) => f.get("header").set("records_root", OTHER_HASH))), j0("FRAME_HASH_MISMATCH", k));
  add(`frame ${k}: header.seq replaced`, withLine(k, editLine(k, (f) => f.get("header").set("seq", k + 1))), j0("SEQ_MISMATCH", k));
  add(
    `frame ${k}: header.wal_op replaced`,
    withLine(k, editLine(k, (f) => f.get("header").set("wal_op", k === 0 ? "audit" : "genesis"))),
    j0("WAL_OP_MISMATCH", k),
  );
  add(`frame ${k}: hash replaced`, withLine(k, editLine(k, (f) => f.set("hash", OTHER_HASH))), j0("FRAME_HASH_MISMATCH", k));
  const changed = oneByteOfBody(k);
  assert.equal(byteDiff(changed, lines[k]), 1, `frame ${k}: exactly one byte differs`);
  add(`frame ${k}: one byte of the body changed`, withLine(k, changed), j0("BODY_HASH_MISMATCH", k));
  add(`frame ${k}: CR before LF`, withLine(k, lines[k] + "\r"), j0("NOT_CANONICAL", k));
  add(`frame ${k}: extra space`, withLine(k, lines[k].replace('{"body":', '{"body": ')), j0("NOT_CANONICAL", k));
  add(`frame ${k}: uppercase letter in hash`, withLine(k, replaceLast(k, `"hash":"${parseLine(lines[k]).get("hash")}"`, `"hash":"${parseLine(lines[k]).get("hash").toUpperCase()}"`)), j0("BAD_TYPE", k));
  add(`frame ${k}: number 1.0 (seq)`, withLine(k, replaceLast(k, `"seq":${k},`, `"seq":${k}.0,`)), {
    verdict: "FAIL",
    level: "J0",
    code: "BAD_NUMBER",
    frame: k,
  });
  add(`frame ${k}: number 2^53 (seq)`, withLine(k, replaceLast(k, `"seq":${k},`, `"seq":9007199254740992,`)), j0("BAD_NUMBER", k));
  add(`frame ${k}: number 2^53-1 (seq) is in range`, withLine(k, replaceLast(k, `"seq":${k},`, `"seq":9007199254740991,`)), j0("SEQ_MISMATCH", k));
  // Keys of the body in reverse order.
  {
    const f = parseLine(lines[k]);
    const body = f.get("body");
    const reversed = "{" + [...body.keys()].sort().reverse().map((key) => yv.jcsString(key) + ":" + yv.jcs(body.get(key))).join(",") + "}";
    const line = `{"body":${reversed},"hash":"${f.get("hash")}","header":${yv.jcs(f.get("header"))}}`;
    add(`frame ${k}: keys of the body in another order`, withLine(k, line), j0("NOT_CANONICAL", k));
  }
}

// --- uppercase in the other hash fields, other numbers ----------------------
for (const field of ["body_hash", "previous", "records_root"]) {
  const k = 3;
  const value = parseLine(lines[k]).get("header").get(field);
  add(`frame ${k}: uppercase letter in header.${field}`, withLine(k, replaceLast(k, `"${field}":"${value}"`, `"${field}":"${value.toUpperCase()}"`)), j0("BAD_TYPE", k));
}
add("number -3 (seq)", withLine(3, replaceLast(3, '"seq":3,', '"seq":-3,')), j0("BAD_NUMBER", 3));
add("number -0 (seq)", withLine(0, replaceLast(0, '"seq":0,', '"seq":-0,')), j0("BAD_NUMBER", 0));
add("number 3e0 (seq)", withLine(3, replaceLast(3, '"seq":3,', '"seq":3e0,')), j0("BAD_NUMBER", 3));
add("number 03 is not JSON", withLine(3, replaceLast(3, '"seq":3,', '"seq":03,')), j0("INVALID_JSON", 3));
add("number 1e400 is out of range, not a parse error", withLine(3, replaceLast(3, '"seq":3,', '"seq":1e400,')), j0("BAD_NUMBER", 3));
add("a bad number in the body comes after a JSON error later in the line", withLine(3, replaceLast(3, '"seq":3,', '"seq":3.5,') + ","), j0("INVALID_JSON", 3));
add("seq as a string", withLine(3, editLine(3, (f) => f.get("header").set("seq", "3"))), j0("BAD_TYPE", 3));
add("seq as true", withLine(3, editLine(3, (f) => f.get("header").set("seq", true))), j0("BAD_TYPE", 3));
add("wal_op as a number", withLine(3, editLine(3, (f) => f.get("header").set("wal_op", 1))), j0("BAD_TYPE", 3));
add("format as null skips J0-7 and is a type error", withLine(3, editLine(3, (f) => f.get("header").set("format", null))), j0("BAD_TYPE", 3));
add("body as a string", withLine(3, editLine(3, (f) => f.set("body", "x"))), j0("BAD_TYPE", 3));
add("hash as a number", withLine(3, editLine(3, (f) => f.set("hash", 7))), j0("BAD_TYPE", 3));
add("frame 0: previous not zeros", withLine(0, editLine(0, (f) => f.get("header").set("previous", OTHER_HASH))), j0("PREVIOUS_MISMATCH", 0));

// --- keys ------------------------------------------------------------------
add("extra outer key", withLine(3, editLine(3, (f) => f.set("extra", 1))), j0("OUTER_KEYS", 3));
add("missing outer key", withLine(3, editLine(3, (f) => f.delete("hash"))), j0("OUTER_KEYS", 3));
add("extra header key", withLine(3, editLine(3, (f) => f.get("header").set("extra", 1))), j0("HEADER_KEYS", 3));
add("missing header key", withLine(3, editLine(3, (f) => f.get("header").delete("records_root"))), j0("HEADER_KEYS", 3));
add("header not an object", withLine(3, editLine(3, (f) => f.set("header", 1))), j0("HEADER_KEYS", 3));
add("format is checked before the outer keys", withLine(3, editLine(3, (f) => { f.set("extra", 1); f.get("header").set("format", "other/1"); })), j0("MIXED_FORMAT", 3));
add("repeated key", withLine(3, lines[3].replace(/("hash":"[0-9a-f]{64}"),/, "$1,$1,")), j0("NOT_CANONICAL", 3));

// --- strings and bytes ------------------------------------------------------
const bytesWith = (k, mutate) => {
  const all = lines.map((l) => enc.encode(l + "\n"));
  all[k] = mutate(enc.encode(lines[k]), "\n");
  const out = new Uint8Array(all.reduce((s, b) => s + b.length, 0));
  let off = 0;
  for (const b of all) {
    out.set(b, off);
    off += b.length;
  }
  return out;
};
const spliceBytes = (insert) => (line) => {
  const at = new TextDecoder().decode(line).indexOf('"actor":"') + 9;
  const out = new Uint8Array(line.length + insert.length + 1);
  out.set(line.subarray(0, at), 0);
  out.set(insert, at);
  out.set(line.subarray(at), at + insert.length);
  out[out.length - 1] = 0x0a;
  return out;
};
add("byte 0xFF in a string", bytesWith(3, spliceBytes([0xff])), j0("INVALID_UTF8", 3));
add("overlong UTF-8", bytesWith(3, spliceBytes([0xc0, 0xaf])), j0("INVALID_UTF8", 3));
add("lone surrogate, raw bytes (high, ED A0 80)", bytesWith(3, spliceBytes([0xed, 0xa0, 0x80])), j0("INVALID_UTF8", 3));
add("lone surrogate, raw bytes (low, ED B0 80)", bytesWith(3, spliceBytes([0xed, 0xb0, 0x80])), j0("INVALID_UTF8", 3));
add("surrogate pair, raw bytes (CESU-8), is not UTF-8", bytesWith(3, spliceBytes([0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80])), j0("INVALID_UTF8", 3));
add("truncated UTF-8 sequence", bytesWith(3, spliceBytes([0xe2, 0x82])), j0("INVALID_UTF8", 3));
add("lone surrogate, escaped (high)", withLine(3, lines[3].replace('"actor":"', '"actor":"\\ud800')), j0("INVALID_JSON", 3));
add("lone surrogate, escaped (low)", withLine(3, lines[3].replace('"actor":"', '"actor":"\\uDC00')), j0("INVALID_JSON", 3));
add("lone surrogate, escaped high then a letter", withLine(3, lines[3].replace('"actor":"', '"actor":"\\ud800\\u0041')), j0("INVALID_JSON", 3));
add("surrogate pair, escaped, is valid JSON but not canonical", withLine(3, lines[3].replace('"actor":"', '"actor":"\\ud83d\\ude00')), j0("NOT_CANONICAL", 3));
add("escaped letter", withLine(3, lines[3].replace('"actor":"o', '"actor":"\\u006f')), j0("NOT_CANONICAL", 3));
add("escaped slash", withLine(3, lines[3].replace('"actor":"', '"actor":"\\/')), j0("NOT_CANONICAL", 3));
add("raw tab in a string", withLine(3, lines[3].replace('"actor":"', '"actor":"\t')), j0("INVALID_JSON", 3));
add("BOM at the start of the file", "﻿" + base, j0("INVALID_JSON", 0));
add("BOM at the start of a line", withLine(4, "﻿" + lines[4]), j0("INVALID_JSON", 4));
add("trailing comma", withLine(3, lines[3].slice(0, -1) + ",}"), j0("INVALID_JSON", 3));
add("a line that is an array", withLine(3, "[]"), j0("INVALID_JSON", 3));
add("empty line in the middle", joinLines([...lines.slice(0, 4), "", ...lines.slice(4)]), j0("INVALID_JSON", 4));

// --- lines removed, added, moved; ends of file -----------------------------
for (let k = 0; k < N - 1; k++) {
  add(`line ${k} removed`, joinLines(lines.filter((_, i) => i !== k)), j0("SEQ_MISMATCH", k));
  add(`lines ${k} and ${k + 1} swapped`, joinLines([...lines.slice(0, k), lines[k + 1], lines[k], ...lines.slice(k + 2)]), j0("SEQ_MISMATCH", k));
}
for (let k = 0; k < N; k++) {
  add(`line ${k} repeated`, joinLines([...lines.slice(0, k + 1), lines[k], ...lines.slice(k + 1)]), j0("SEQ_MISMATCH", k + 1));
}
add("last line cut in its middle", base.slice(0, base.length - 1 - Math.floor(lines[N - 1].length / 2)), j0("TORN_TAIL", N - 1));
add("last LF removed", base.slice(0, -1), j0("TORN_TAIL", N - 1));
add("an LF in the middle removed", joinLines([...lines.slice(0, 3), lines[3] + lines[4], ...lines.slice(5)]), j0("INVALID_JSON", 3));
add("garbage at the end, no LF", base + "garbage", j0("TORN_TAIL", N));
add("garbage line at the end", base + "garbage\n", j0("INVALID_JSON", N));
add("empty line at the end", base + "\n", j0("INVALID_JSON", N));
add("empty object at the end", base + "{}\n", j0("OUTER_KEYS", N));
add("empty file", "", { verdict: "FAIL", level: "J0", code: "EMPTY_JOURNAL", frame: null });
add("a single LF", "\n", j0("INVALID_JSON", 0));
add("a torn first line", lines[0].slice(0, 100), j0("TORN_TAIL", 0));

// --- limits (J0-1) ----------------------------------------------------------
const longest = Math.max(...lines.map((l) => enc.encode(l).length));
add("line exactly at --max-line-bytes", base, { verdict: "PASS" }, { maxLineBytes: longest });
add("line one byte over --max-line-bytes", base, j0("LIMIT_EXCEEDED", 0), { maxLineBytes: longest - 1 });
add("a torn tail over --max-line-bytes", base + "x".repeat(longest + 1), j0("LIMIT_EXCEEDED", N), { maxLineBytes: longest });
const deep = (m) => withLine(3, editLine(3, (f) => f.get("body").set("deep", JSON.parse("[".repeat(m) + "]".repeat(m)))));
// The outer object is depth 1, the body 2, so m nested arrays reach depth 2 + m.
add("depth 64 is allowed by default (then the body hash fails)", deep(62), j0("BODY_HASH_MISMATCH", 3));
add("depth 65 exceeds the default 64", deep(63), j0("LIMIT_EXCEEDED", 3));
add("--max-depth raises the limit", deep(63), j0("BODY_HASH_MISMATCH", 3), { maxDepth: 65 });
add("--max-depth lowers the limit", deep(62), j0("LIMIT_EXCEEDED", 3), { maxDepth: 63 });
add("brackets inside strings do not count toward depth", withLine(3, editLine(3, (f) => f.get("body").set("deep", "[{".repeat(100)))), j0("BODY_HASH_MISMATCH", 3));
add("--max-depth 4 stops at the first frame deeper than 4", base, j0("LIMIT_EXCEEDED", 0), { maxDepth: 4 });
add("a deep string is not nesting", withLine(3, editLine(3, (f) => f.get("body").set("deep", "[".repeat(100)))), j0("BODY_HASH_MISMATCH", 3));

// --- head (5.3) --------------------------------------------------------------
add("--expect-head differs", base, { verdict: "FAIL", level: "J0", code: "HEAD_MISMATCH", frame: null }, { expectHead: OTHER_HASH });

test("A3 matrix is built as described", () => {
  assert.equal(N, 8);
  assert.ok(cases.length > 150, `${cases.length} cases`);
});

for (const c of cases) {
  test(`A3 matrix: ${c.name} -> ${c.want.code ?? c.want.verdict}${c.want.frame !== undefined ? ` @ ${c.want.frame}` : ""}`, async () => {
    const report = await verify(bytesOf(c.input), c.options);
    assert.deepEqual(outcome(report), c.want, JSON.stringify(report.first_failure));
    if (report.levels.J0.result === "FAIL") {
      assert.equal(report.levels.J1.result, "NOT_CHECKABLE");
      assert.equal(report.computed.wal_head, null);
    }
  });
}
