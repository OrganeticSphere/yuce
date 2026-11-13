// Streaming, determinism, speed, the browser hash adapter, and loading the
// bundle without Node.js globals (task statement, section 5).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { BUNDLE, SMALL, adapter, readRoom, room, yv } from "./helpers.mjs";

function* chunks(bytes, size) {
  for (let i = 0; i < bytes.length; i += size) yield bytes.subarray(i, i + size);
}

const FILES = [
  SMALL,
  "inputs/corrupt/truncated-tail.wal",
  "inputs/corrupt/tampered-seal.wal",
  "inputs/corrupt/float-in-body.wal",
  "inputs/boundary/auto-seal-ack.wal",
];

test("the report does not depend on how the input is cut into chunks", async () => {
  for (const f of FILES) {
    const bytes = readRoom(f);
    const whole = yv.reportToJcs(await yv.verifyJournal([bytes], {}, adapter));
    for (const size of [1, 2, 3, 7, 64, 4096, 65536]) {
      const cut = yv.reportToJcs(await yv.verifyJournal(chunks(bytes, size), {}, adapter));
      assert.equal(cut, whole, `${f} in chunks of ${size}`);
    }
  }
});

test("an async source works the same as a sync one", async () => {
  const bytes = readRoom(SMALL);
  async function* slow() {
    for (const c of chunks(bytes, 1000)) {
      await new Promise((r) => setImmediate(r));
      yield c;
    }
  }
  const a = yv.reportToJcs(await yv.verifyJournal([bytes], {}, adapter));
  const b = yv.reportToJcs(await yv.verifyJournal(slow(), {}, adapter));
  assert.equal(a, b);
});

test("a ReadableStream source, async-iterable or reader-only, gives the same report", async () => {
  const bytes = readRoom(SMALL);
  const a = yv.reportToJcs(await yv.verifyJournal([bytes], {}, adapter));
  const stream = () =>
    new ReadableStream({
      start(c) {
        for (const ch of chunks(bytes, 777)) c.enqueue(ch);
        c.close();
      },
    });
  assert.equal(yv.reportToJcs(await yv.verifyJournal(stream(), {}, adapter)), a);
  const s = stream();
  const readerOnly = { getReader: () => s.getReader() };
  assert.equal(yv.reportToJcs(await yv.verifyJournal(readerOnly, {}, adapter)), a);
});

test("a read error of the source is a ReadError (exit code 2 in the CLI)", async () => {
  async function* broken() {
    yield new TextEncoder().encode("{");
    throw new Error("disk gone");
  }
  await assert.rejects(yv.verifyJournal(broken(), {}, adapter), yv.ReadError);
});

test("the crypto.subtle adapter gives the same reports as node:crypto", async () => {
  const subtle = yv.subtleHashAdapter(globalThis.crypto.subtle);
  for (const f of [...FILES, "inputs/valid/k017-oracle-v3.wal"]) {
    const bytes = readRoom(f);
    const a = yv.reportToJcs(await yv.verifyJournal(chunks(bytes, 65536), {}, adapter));
    const b = yv.reportToJcs(await yv.verifyJournal(chunks(bytes, 65536), {}, subtle));
    assert.equal(b, a, f);
  }
});

test("speed: the 3 MB journal of 695 frames in under 2 s", async () => {
  const bytes = readRoom("inputs/valid/k017-oracle-v3.wal");
  assert.ok(bytes.length > 3_000_000);
  const t0 = performance.now();
  const report = await yv.verifyJournal(chunks(bytes, 65536), {}, adapter);
  const ms = performance.now() - t0;
  assert.equal(report.verdict, "PASS");
  assert.ok(ms < 2000, `${ms.toFixed(0)} ms`);
});

test("the bundle loads and verifies without Node.js globals, with crypto.subtle only", () => {
  // A browser has no `process`; the bundle must not touch node:* then.
  const script = `
    const { readFileSync } = await import("node:fs");
    const bytes = new Uint8Array(readFileSync(${JSON.stringify(room(SMALL))}));
    delete globalThis.process;
    const yv = await import(${JSON.stringify(pathToFileURL(BUNDLE).href)});
    const adapter = await yv.defaultHashAdapter();
    const report = await yv.verifyJournal([bytes], {}, adapter);
    console.log(yv.humanLine(report));
  `;
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^J0-J1 PASS\. Frames: 8\. Seals: 2\. Tail: closed\./);
});

test("the delivery file has no static imports at all", async () => {
  const { readFileSync } = await import("node:fs");
  const text = readFileSync(BUNDLE, "utf8");
  assert.doesNotMatch(text, /^\s*import\s[^(]/m);
  assert.doesNotMatch(text, /\brequire\(/);
});
