// Document version and evidence anchor (amendment 3, P3-8): content-defined
// chunking with a GEAR rolling score, a local-maximum boundary rule, a
// maximum chunk length, and plain SHA-256 over the chunk hashes.

import type { HashAdapter } from "./hash.ts";
import { concatBytes, utf8 } from "./hash.ts";

/** P3-8: window half-width w and the largest chunk. */
export const CDC_WINDOW = 512;
export const CDC_MAX_CHUNK = 2048;

const MASK64 = (1n << 64n) - 1n;

/** GEAR[i] as 64-bit values, split into high and low 32-bit halves for fast arithmetic. */
export const GEAR_HI = new Uint32Array(256);
export const GEAR_LO = new Uint32Array(256);
(() => {
  let st = 0x5342474b43444301n;
  for (let i = 0; i < 256; i++) {
    st = (st + 0x9e3779b97f4a7c15n) & MASK64;
    let z = st;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
    z = z ^ (z >> 31n);
    GEAR_HI[i] = Number(z >> 32n);
    GEAR_LO[i] = Number(z & 0xffffffffn);
  }
})();

/** GEAR[i] as 16 lowercase hex digits (for the vectors). */
export function gearHex(i: number): string {
  return GEAR_HI[i]!.toString(16).padStart(8, "0") + GEAR_LO[i]!.toString(16).padStart(8, "0");
}

export interface Chunk {
  start: number;
  end: number;
}

/**
 * Cut points of a document, ascending, ending with n (P3-8, steps 2 and 3).
 * score[p] = 2*score[p-1] + GEAR[b[p]] mod 2^64. Position c is a boundary when
 * it is the best of its window [c-w, c+w]: strictly higher than every earlier
 * position, at least as high as every later one. A sliding-window queue gives
 * this in O(n): a new position drops from the back every position it beats.
 */
export function cutPoints(bytes: Uint8Array, w: number = CDC_WINDOW): number[] {
  const n = bytes.length;
  if (n === 0) return [];
  const hi = new Uint32Array(n);
  const lo = new Uint32Array(n);
  let fh = 0;
  let fl = 0;
  for (let p = 0; p < n; p++) {
    const b = bytes[p]!;
    let l = fl * 2 + GEAR_LO[b]!; // < 3 * 2^32, exact in a double
    const carry = l >= 0x100000000 ? (l >= 0x200000000 ? 2 : 1) : 0;
    l -= carry * 0x100000000;
    const h = (((fh << 1) >>> 0) + GEAR_HI[b]! + carry) >>> 0;
    fh = h;
    fl = l;
    hi[p] = h;
    lo[p] = l;
  }
  // a beats b (a later than b) when score[a] > score[b]
  const greater = (a: number, b: number): boolean => hi[a]! > hi[b]! || (hi[a] === hi[b] && lo[a]! > lo[b]!);

  const queue = new Int32Array(n);
  let head = 0;
  let tail = 0;
  let next = 0;
  const cuts: number[] = [];
  for (let c = 0; c < n; c++) {
    const right = Math.min(n - 1, c + w);
    while (next <= right) {
      while (tail > head && greater(next, queue[tail - 1]!)) tail--;
      queue[tail++] = next;
      next++;
    }
    const left = c - w;
    while (queue[head]! < left) head++;
    if (queue[head] === c) cuts.push(c + 1);
  }
  if (cuts[cuts.length - 1] !== n) cuts.push(n);
  return cuts;
}

/** Chunks of a document (P3-8, step 4): cut points, and no chunk longer than the maximum. */
export function chunksOf(bytes: Uint8Array, w: number = CDC_WINDOW, max: number = CDC_MAX_CHUNK): Chunk[] {
  const out: Chunk[] = [];
  let start = 0;
  for (const t of cutPoints(bytes, w)) {
    while (t - start > max) {
      out.push({ start, end: start + max });
      start += max;
    }
    if (t > start) {
      out.push({ start, end: t });
      start = t;
    }
  }
  return out;
}

const VERSION_PREFIX = utf8("SBGK-DOCVER-v1");

export interface DocumentChunks {
  chunks: Chunk[];
  /** SHA-256 of each chunk, raw 32 bytes. */
  hashes: Uint8Array[];
  /** version = SHA256("SBGK-DOCVER-v1" || chunk hashes), raw 32 bytes. */
  version: Uint8Array;
}

/** Chunks, chunk hashes and version of a document's bytes (P3-8, step 5). */
export async function documentChunks(adapter: HashAdapter, bytes: Uint8Array): Promise<DocumentChunks> {
  const chunks = chunksOf(bytes);
  const hashes: Uint8Array[] = [];
  for (const c of chunks) hashes.push(await adapter.sha256(bytes.subarray(c.start, c.end)));
  const version = await adapter.sha256(concatBytes([VERSION_PREFIX, ...hashes]));
  return { chunks, hashes, version };
}

export interface Segment {
  hash: Uint8Array;
  from: number;
  to: number;
}

/** Segments of a quote [start, end): the chunks it crosses, with offsets inside each (P3-8). */
export function segmentsOf(doc: DocumentChunks, start: number, end: number): Segment[] {
  const out: Segment[] = [];
  doc.chunks.forEach((c, k) => {
    if (c.start < end && c.end > start) {
      out.push({ hash: doc.hashes[k]!, from: Math.max(start, c.start) - c.start, to: Math.min(end, c.end) - c.start });
    }
  });
  return out;
}

function u16le(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff]);
}

function u32le(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

/** The anchor cannot be written: P3-8 gives it no form (SPEC-DEFECT-19). */
export class AnchorEncodingError extends Error {}

/**
 * Bytes of the evidence anchor (P3-8):
 * 0x01 || u16le(len doc_id) || doc_id || SHA256(q) || u32le(len q) || count || (h || u32le(from) || u32le(to))*
 */
export async function anchorBytes(adapter: HashAdapter, docId: string, quote: Uint8Array, segments: readonly Segment[]): Promise<Uint8Array> {
  const id = utf8(docId);
  if (id.length > 0xffff) throw new AnchorEncodingError("doc_id longer than 65535 bytes");
  if (segments.length > 0xff) throw new AnchorEncodingError("quote crosses more than 255 chunks");
  if (quote.length > 0xffffffff) throw new AnchorEncodingError("quote longer than 2^32 - 1 bytes");
  const parts: Uint8Array[] = [new Uint8Array([0x01]), u16le(id.length), id, await adapter.sha256(quote), u32le(quote.length), new Uint8Array([segments.length])];
  for (const s of segments) parts.push(s.hash, u32le(s.from), u32le(s.to));
  return concatBytes(parts);
}

/** Starts of every occurrence of q in bytes, overlapping ones included, stopping after `limit`. */
export function occurrences(bytes: Uint8Array, q: Uint8Array, limit: number): number[] {
  const out: number[] = [];
  if (q.length === 0 || q.length > bytes.length) return out;
  const first = q[0]!;
  let p = bytes.indexOf(first, 0);
  while (p >= 0 && p + q.length <= bytes.length) {
    let k = 1;
    while (k < q.length && bytes[p + k] === q[k]) k++;
    if (k === q.length) {
      out.push(p);
      if (out.length >= limit) break;
    }
    p = bytes.indexOf(first, p + 1);
  }
  return out;
}
