// Strict parsing and canonical form (SPEC section 2), and the log tree (6.5).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { adapter, yv } from "./helpers.mjs";

const canon = (text) => {
  const r = yv.parseJson(text);
  assert.ok(r.ok, `${text}: ${r.error}`);
  return yv.jcs(r.value);
};

test("JCS: keys sorted by UTF-16 code units, no whitespace", () => {
  assert.equal(canon('{ "b" : 1, "a" : [ true, false, null ] }'), '{"a":[true,false,null],"b":1}');
  // U+1F600 is the surrogate pair D83D DE00, which sorts before U+FFFF in UTF-16.
  assert.equal(canon('{"￿":1,"😀":2,"a":3,"B":4}'), '{"B":4,"a":3,"😀":2,"￿":1}');
  assert.equal(canon('{"aa":1,"a":2,"":3}'), '{"":3,"a":2,"aa":1}');
});

test("JCS: string escapes are minimal, control characters as lowercase \\u00xx", () => {
  assert.equal(canon('"\\u0041\\/\\u00e9\\u20ac"'), '"A/é€"');
  assert.equal(canon('"\\b\\f\\n\\r\\t\\"\\\\"'), '"\\b\\f\\n\\r\\t\\"\\\\"');
  assert.equal(canon('"\\u0000\\u001f\\u001F\\u000b"'), '"\\u0000\\u001f\\u001f\\u000b"');
  assert.equal(canon('"\\u007f\\u2028"'), '"\u007f "');
  assert.equal(canon('"\\ud83d\\ude00"'), '"😀"');
});

test("JCS: integers as plain digits", () => {
  assert.equal(canon("[0, 7, 9007199254740991]"), "[0,7,9007199254740991]");
});

test("parser: strict RFC 8259", () => {
  const bad = [
    "", " ", "{", "}", "[1,]", '{"a":1,}', "{'a':1}", '{"a" 1}', "[01]", "[1.]", "[.5]", "[1e]", "[+1]", "[-]",
    "tru", "nul", "[NaN]", "[Infinity]", '"abc', '"\\x"', '"\\u12"', '"\\u12G4"', '"a\tb"', '"a\nb"',
    "/* c */ {}", "{} //", "﻿{}", "{}{}", "[1 2]", '"\\ud800"', '"\\udc00"', '"\\ud800\\u0041"',
    " {}", "{\u000b}",
  ];
  for (const text of bad) assert.equal(yv.parseJson(text).ok, false, JSON.stringify(text));
  const good = ["{}", "[]", " \t\r\n{} \t\r\n", '{"a":{"b":[[],{}]}}', '"\\ud83d\\ude00"', "0", "true", "null"];
  for (const text of good) assert.equal(yv.parseJson(text).ok, true, JSON.stringify(text));
});

test("parser: numbers outside 0..2^53-1 in plain digits are flagged, not rejected", () => {
  const flagged = ["-1", "-0", "1.0", "1e2", "1E+2", "0.5", "9007199254740992", "18446744073709551616", "1e400"];
  for (const t of flagged) {
    const r = yv.parseJson(`[${t}]`);
    assert.ok(r.ok, t);
    assert.equal(r.badNumber, true, t);
  }
  for (const t of ["0", "1", "9007199254740991", "123456789"]) {
    const r = yv.parseJson(`[${t}]`);
    assert.ok(r.ok && !r.badNumber, t);
  }
});

test("parser: a repeated key keeps one member, so the canonical form differs", () => {
  const text = '{"a":1,"a":1}';
  assert.notEqual(canon(text), text);
  assert.equal(canon(text), '{"a":1}');
});

test("parser: deep nesting does not overflow the stack", () => {
  const depth = 200000;
  const text = "[".repeat(depth) + "]".repeat(depth);
  const r = yv.parseJson(text);
  assert.ok(r.ok);
  assert.equal(yv.jcs(r.value), text);
  assert.equal(yv.depthExceeds(new TextEncoder().encode(text), depth), false);
  assert.equal(yv.depthExceeds(new TextEncoder().encode(text), depth - 1), true);
});

test("depth: counted outside strings only, outermost container is depth 1", () => {
  const e = (s) => new TextEncoder().encode(s);
  assert.equal(yv.depthExceeds(e('{"a":[1]}'), 2), false);
  assert.equal(yv.depthExceeds(e('{"a":[1]}'), 1), true);
  assert.equal(yv.depthExceeds(e('{"a":"[[[[\\"[[["}'), 1), false);
});

test("hash: H(d, x) puts one zero byte after the domain", async () => {
  const got = yv.toHex(await yv.domainHash(adapter, "D", new Uint8Array([1, 2])));
  const want = createHash("sha256").update(Buffer.from([0x44, 0x00, 1, 2])).digest("hex");
  assert.equal(got, want);
});

test("log tree: the running root equals the recursive RFC 6962 root for 1..70 leaves", async () => {
  const leaves = [];
  const tree = new yv.LogTree(adapter);
  for (let n = 1; n <= 70; n++) {
    const h = createHash("sha256").update(`leaf ${n}`).digest();
    leaves.push(new Uint8Array(h));
    await tree.push(new Uint8Array(h));
    assert.equal(yv.toHex(await tree.root()), yv.toHex(await yv.logRootRecursive(adapter, leaves)), `n=${n}`);
  }
});

test("log tree: hand-computed roots for 1, 2 and 3 leaves (RFC 6962, last node not doubled)", async () => {
  const sha = (...parts) => createHash("sha256").update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
  const h = [1, 2, 3].map((k) => sha([k]));
  const leaf = (x) => sha([0], x);
  const node = (l, r) => sha([1], l, r);
  const tree = new yv.LogTree(adapter);
  await tree.push(new Uint8Array(h[0]));
  assert.equal(yv.toHex(await tree.root()), leaf(h[0]).toString("hex"));
  await tree.push(new Uint8Array(h[1]));
  assert.equal(yv.toHex(await tree.root()), node(leaf(h[0]), leaf(h[1])).toString("hex"));
  await tree.push(new Uint8Array(h[2]));
  assert.equal(yv.toHex(await tree.root()), node(node(leaf(h[0]), leaf(h[1])), leaf(h[2])).toString("hex"));
});
