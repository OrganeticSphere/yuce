// SHA-256 through an adapter: node:crypto under Node.js, crypto.subtle in a
// browser (task statement, section 2.4). The verifier core only sees HashAdapter.

export interface Sha256Stream {
  update(data: Uint8Array): void;
  digest(): Promise<Uint8Array>;
}

export interface HashAdapter {
  /** SHA-256 of one byte string. */
  sha256(data: Uint8Array): Promise<Uint8Array>;
  /** Incremental SHA-256, used for the hash of the whole journal file. */
  createSha256(): Sha256Stream;
}

interface NodeHash {
  update(data: Uint8Array): NodeHash;
  digest(): Uint8Array;
}
interface NodeCrypto {
  createHash(algorithm: string): NodeHash;
}

/** Adapter over node:crypto. Imported lazily so the bundle also loads in a browser. */
export async function nodeHashAdapter(): Promise<HashAdapter> {
  const crypto = (await import("node:crypto")) as unknown as NodeCrypto;
  return {
    async sha256(data) {
      return new Uint8Array(crypto.createHash("sha256").update(data).digest());
    },
    createSha256() {
      const h = crypto.createHash("sha256");
      return {
        update(data) {
          h.update(data);
        },
        async digest() {
          return new Uint8Array(h.digest());
        },
      };
    },
  };
}

/**
 * Adapter over WebCrypto (crypto.subtle). WebCrypto has no incremental digest,
 * so createSha256() keeps the chunks until digest(); in a browser the file is
 * already in memory, so this costs no more than the file itself.
 */
export function subtleHashAdapter(subtle?: SubtleCrypto): HashAdapter {
  const s = subtle ?? globalThis.crypto.subtle;
  const digest = async (data: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array(await s.digest("SHA-256", data as Uint8Array<ArrayBuffer>));
  return {
    sha256: digest,
    createSha256() {
      const chunks: Uint8Array[] = [];
      let total = 0;
      return {
        update(data) {
          chunks.push(data.slice());
          total += data.length;
        },
        async digest() {
          const all = new Uint8Array(total);
          let off = 0;
          for (const c of chunks) {
            all.set(c, off);
            off += c.length;
          }
          return digest(all);
        },
      };
    },
  };
}

/** Picks node:crypto when running under Node.js, crypto.subtle otherwise. */
export async function defaultHashAdapter(): Promise<HashAdapter> {
  const g = globalThis as { process?: { versions?: { node?: string } } };
  if (g.process?.versions?.node !== undefined) return nodeHashAdapter();
  return subtleHashAdapter();
}

// ---------------------------------------------------------------------------
// Bytes and hex
// ---------------------------------------------------------------------------

const HEX = "0123456789abcdef";

/** Lowercase hex, as hashes are written in the journal. */
export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    s += HEX[b >> 4]! + HEX[b & 15]!;
  }
  return s;
}

/** Decodes a string already known to match [0-9a-f]*, of even length. */
export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const encoder = new TextEncoder();

export function utf8(s: string): Uint8Array {
  return encoder.encode(s);
}
