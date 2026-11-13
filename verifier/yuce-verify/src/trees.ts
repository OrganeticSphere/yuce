// Domain-separated hashes and the two RFC 6962 tree shapes (SPEC sections 1, 6.5, 7).

import type { HashAdapter } from "./hash.ts";
import { concatBytes } from "./hash.ts";

/** Domain strings used by levels J0 and J1, and by the J3 vectors. */
export const DOMAIN = {
  frameBody: "R2R-FRAME-BODY/2",
  frameHeader: "R2R-FRAME-HDR/2",
  seal: "R2R-SEAL/2",
  recordLeaf: "R2R-REC-LEAF/2",
  recordNode: "R2R-REC-NODE/2",
  recordEmpty: "R2R-REC-EMPTY/2",
} as const;

/** H(d, x1, x2, ...) = SHA-256(ASCII(d) || 0x00 || x1 || x2 || ...). */
export async function domainHash(
  adapter: HashAdapter,
  domain: string,
  ...parts: Uint8Array[]
): Promise<Uint8Array> {
  const d = new Uint8Array(domain.length + 1);
  for (let i = 0; i < domain.length; i++) {
    const c = domain.charCodeAt(i);
    if (c > 0x7f) throw new Error("domain must be ASCII");
    d[i] = c;
  }
  d[domain.length] = 0x00;
  return adapter.sha256(concatBytes([d, ...parts]));
}

/** Largest power of two strictly less than n (n > 1). */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

// ---------------------------------------------------------------------------
// Log tree over frame hashes (SPEC 6.5): bare RFC 6962 prefixes, no domain string.
// ---------------------------------------------------------------------------

export async function logLeaf(adapter: HashAdapter, frameHash: Uint8Array): Promise<Uint8Array> {
  return adapter.sha256(concatBytes([new Uint8Array([0x00]), frameHash]));
}

export async function logNode(adapter: HashAdapter, l: Uint8Array, r: Uint8Array): Promise<Uint8Array> {
  return adapter.sha256(concatBytes([new Uint8Array([0x01]), l, r]));
}

/**
 * Running log root: a stack of (hash, size) pairs of perfect subtrees, as in
 * SPEC 6.5. Memory is O(log n), each root costs O(log n) hashes.
 */
export class LogTree {
  private readonly stack: { hash: Uint8Array; size: number }[] = [];
  private count = 0;

  constructor(private readonly adapter: HashAdapter) {}

  get size(): number {
    return this.count;
  }

  async push(frameHash: Uint8Array): Promise<void> {
    let top = { hash: await logLeaf(this.adapter, frameHash), size: 1 };
    for (;;) {
      const below = this.stack[this.stack.length - 1];
      if (below === undefined || below.size !== top.size) break;
      this.stack.pop();
      top = { hash: await logNode(this.adapter, below.hash, top.hash), size: below.size + top.size };
    }
    this.stack.push(top);
    this.count++;
  }

  /** Root over all leaves pushed so far; null for an empty tree. */
  async root(): Promise<Uint8Array | null> {
    let i = this.stack.length - 1;
    const top = this.stack[i];
    if (top === undefined) return null;
    let result = top.hash;
    for (i--; i >= 0; i--) result = await logNode(this.adapter, this.stack[i]!.hash, result);
    return result;
  }
}

/** Log root by the recursive RFC 6962 definition; used by tests as a second opinion. */
export async function logRootRecursive(adapter: HashAdapter, frameHashes: readonly Uint8Array[]): Promise<Uint8Array> {
  if (frameHashes.length === 0) throw new Error("empty log tree");
  if (frameHashes.length === 1) return logLeaf(adapter, frameHashes[0]!);
  const k = splitPoint(frameHashes.length);
  return logNode(
    adapter,
    await logRootRecursive(adapter, frameHashes.slice(0, k)),
    await logRootRecursive(adapter, frameHashes.slice(k)),
  );
}

// ---------------------------------------------------------------------------
// Records tree of one frame (SPEC section 7, level J3). Not used by J0-J1;
// the vectors command checks V1, V2_* and V2_real_* with it.
// ---------------------------------------------------------------------------

export async function recordLeaf(adapter: HashAdapter, leafJcsBytes: Uint8Array): Promise<Uint8Array> {
  return domainHash(adapter, DOMAIN.recordLeaf, leafJcsBytes);
}

export async function recordsRoot(adapter: HashAdapter, leaves: readonly Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return domainHash(adapter, DOMAIN.recordEmpty);
  if (leaves.length === 1) return leaves[0]!;
  const k = splitPoint(leaves.length);
  return domainHash(
    adapter,
    DOMAIN.recordNode,
    await recordsRoot(adapter, leaves.slice(0, k)),
    await recordsRoot(adapter, leaves.slice(k)),
  );
}
