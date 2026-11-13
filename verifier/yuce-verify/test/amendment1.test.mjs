// Amendment 1 to SPEC v3, item P1-6: one test per line, with the tests that
// P1-1 and P1-2 ask for.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { BUNDLE, ROOM, SMALL, fixture, joinLines, linesOf, outcome, readRoom, textOf, verify, yv } from "./helpers.mjs";

const base = textOf(readRoom(SMALL));
const j0 = (code, frame) => ({ verdict: "FAIL", level: "J0", code, frame });
const enc = new TextEncoder();

test("P1-6.1 / P1-1: the default --max-line-bytes is 67108863 (64 MiB with the LF)", async () => {
  assert.equal(yv.DEFAULT_MAX_LINE_BYTES, 67108863);
  assert.equal(yv.DEFAULT_MAX_LINE_BYTES + 1, 64 * 1024 * 1024);
  // At the default, a line of exactly 67108863 bytes passes the length check (it then fails as JSON),
  // a line of 67108864 bytes is LIMIT_EXCEEDED.
  const line = (n) => {
    const b = new Uint8Array(n + 1).fill(0x78);
    b[n] = 0x0a;
    return b;
  };
  assert.deepEqual(outcome(await verify(line(67108863))), j0("INVALID_JSON", 0));
  assert.deepEqual(outcome(await verify(line(67108864))), j0("LIMIT_EXCEEDED", 0));
});

test("P1-1: at --max-line-bytes N, a line of N bytes without LF passes, N + 1 is LIMIT_EXCEEDED", async () => {
  // A JSON line of exactly len bytes: {"x":"aaa…"} ({"x":""} is 8 bytes).
  const short = (len) => joinLines([`{"x":"${"a".repeat(len - 8)}"}`]);
  assert.equal(enc.encode(linesOf(short(50))[0]).length, 50);
  assert.deepEqual(outcome(await verify(short(50), { maxLineBytes: 50 })), j0("OUTER_KEYS", 0)); // past the length check
  assert.deepEqual(outcome(await verify(short(51), { maxLineBytes: 50 })), j0("LIMIT_EXCEEDED", 0));
  // On a real journal: the longest line exactly at N passes; N - 1 refuses that line.
  const longest = Math.max(...linesOf(base).map((l) => enc.encode(l).length));
  assert.equal((await verify(base, { maxLineBytes: longest })).verdict, "PASS");
  assert.deepEqual(outcome(await verify(base, { maxLineBytes: longest - 1 })), j0("LIMIT_EXCEEDED", 0));
  // The same bound on a torn tail: N bytes after the last LF are TORN_TAIL, N + 1 are LIMIT_EXCEEDED.
  assert.deepEqual(outcome(await verify(base + "y".repeat(longest), { maxLineBytes: longest })), j0("TORN_TAIL", 8));
  assert.deepEqual(outcome(await verify(base + "y".repeat(longest + 1), { maxLineBytes: longest })), j0("LIMIT_EXCEEDED", 8));
});

test("P1-6.2 / P1-2: the default --max-depth is 64; depth 64 passes, 65 is LIMIT_EXCEEDED", async () => {
  assert.equal(yv.DEFAULT_MAX_DEPTH, 64);
  // Depth: a scalar 0, a container one more than its deepest member, an empty container 1.
  // {"x":[[...]]} with m arrays has depth 1 + m.
  const nested = (m) => joinLines([`{"x":${"[".repeat(m)}${"]".repeat(m)}}`]);
  assert.deepEqual(outcome(await verify(nested(63))), j0("OUTER_KEYS", 0)); // depth 64: past the depth check
  assert.deepEqual(outcome(await verify(nested(64))), j0("LIMIT_EXCEEDED", 0)); // depth 65
  // Empty containers count 1; a scalar member adds nothing.
  assert.equal(yv.depthExceeds(enc.encode("{}"), 1), false);
  assert.equal(yv.depthExceeds(enc.encode('{"a":1}'), 1), false);
  assert.equal(yv.depthExceeds(enc.encode('{"a":{}}'), 1), true);
  // The deepest member counts, not the number of members.
  assert.equal(yv.depthExceeds(enc.encode('{"a":[1],"b":[2],"c":[3]}'), 2), false);
});

test("P1-2: brackets inside string values do not count toward depth", async () => {
  const inString = joinLines([`{"x":"${"[{".repeat(200)}"}`]);
  assert.deepEqual(outcome(await verify(inString)), j0("OUTER_KEYS", 0));
  const escapedQuote = joinLines([`{"x":"\\"${"[".repeat(200)}"}`]); // an escaped quote does not end the string
  assert.deepEqual(outcome(await verify(escapedQuote)), j0("OUTER_KEYS", 0));
});

test("P1-2: every real journal in inputs/ is within the default depth and length", async () => {
  for (const f of ["valid/k017-oracle-v3.wal", "valid/withdrawal-version-close.wal", "valid/live-server-unsealed-tail.wal", "valid/gap-primary-exhausted.wal", "valid/gap-second-exhausted.wal", "boundary/nested-seal.wal"]) {
    assert.equal((await verify(readRoom(`inputs/${f}`))).verdict, "PASS", f);
  }
});

// P1-6.3 asked for /3; amendment 2 (P2-3) replaces it with /4, tested in amendment2.test.mjs.
test("P1-6.3: the spec id is the one of the latest amendment (/4 since amendment 2)", async () => {
  assert.equal(yv.SPEC_ID, "SPEC_INDEPENDENT_VERIFIER/4");
  assert.equal((await verify(base)).verifier.spec, yv.SPEC_ID);
  const r = spawnSync(process.execPath, [BUNDLE, "journal", SMALL, "--json"], { cwd: ROOM, encoding: "utf8" });
  assert.equal(JSON.parse(r.stdout).verifier.spec, yv.SPEC_ID);
});

test("P1-6.5 / P1-3: README warns that raising a limit above its default can accept impossible lines", () => {
  const readme = readFileSync(fixture("../../README.md"), "utf8");
  assert.match(readme, /If you raise `--max-line-bytes` or `--max-depth` above its default, the verifier may accept a line that cannot occur in a correct journal\./);
  assert.match(readme, /--max-line-bytes 67108863/);
  assert.match(readme, /--max-depth 64/);
});
