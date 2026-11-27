#!/usr/bin/env node
// yuce-verify 0.3.1: independent verifier of YuCe journals, delivery 3: levels J0-J3 and J4a, the cut check, the observation report.
// Built from src/ by scripts/build.mjs. No runtime dependencies.

// src/hash.ts
async function nodeHashAdapter() {
  const crypto = await import("node:crypto");
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
        }
      };
    }
  };
}
function subtleHashAdapter(subtle) {
  const s = subtle ?? globalThis.crypto.subtle;
  const digest = async (data) => new Uint8Array(await s.digest("SHA-256", data));
  return {
    sha256: digest,
    createSha256() {
      const chunks = [];
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
        }
      };
    }
  };
}
async function defaultHashAdapter() {
  const g = globalThis;
  if (g.process?.versions?.node !== void 0) return nodeHashAdapter();
  return subtleHashAdapter();
}
var HEX = "0123456789abcdef";
function toHex(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    s += HEX[b >> 4] + HEX[b & 15];
  }
  return s;
}
function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}
function concatBytes(parts) {
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
var encoder = new TextEncoder();
function utf8(s) {
  return encoder.encode(s);
}

// src/cdc.ts
var CDC_WINDOW = 512;
var CDC_MAX_CHUNK = 2048;
var MASK64 = (1n << 64n) - 1n;
var GEAR_HI = new Uint32Array(256);
var GEAR_LO = new Uint32Array(256);
(() => {
  let st = 0x5342474b43444301n;
  for (let i = 0; i < 256; i++) {
    st = st + 0x9e3779b97f4a7c15n & MASK64;
    let z = st;
    z = (z ^ z >> 30n) * 0xbf58476d1ce4e5b9n & MASK64;
    z = (z ^ z >> 27n) * 0x94d049bb133111ebn & MASK64;
    z = z ^ z >> 31n;
    GEAR_HI[i] = Number(z >> 32n);
    GEAR_LO[i] = Number(z & 0xffffffffn);
  }
})();
function gearHex(i) {
  return GEAR_HI[i].toString(16).padStart(8, "0") + GEAR_LO[i].toString(16).padStart(8, "0");
}
function cutPoints(bytes, w = CDC_WINDOW) {
  const n = bytes.length;
  if (n === 0) return [];
  const hi = new Uint32Array(n);
  const lo = new Uint32Array(n);
  let fh = 0;
  let fl = 0;
  for (let p = 0; p < n; p++) {
    const b = bytes[p];
    let l = fl * 2 + GEAR_LO[b];
    const carry = l >= 4294967296 ? l >= 8589934592 ? 2 : 1 : 0;
    l -= carry * 4294967296;
    const h = (fh << 1 >>> 0) + GEAR_HI[b] + carry >>> 0;
    fh = h;
    fl = l;
    hi[p] = h;
    lo[p] = l;
  }
  const greater = (a, b) => hi[a] > hi[b] || hi[a] === hi[b] && lo[a] > lo[b];
  const queue = new Int32Array(n);
  let head = 0;
  let tail = 0;
  let next = 0;
  const cuts = [];
  for (let c = 0; c < n; c++) {
    const right = Math.min(n - 1, c + w);
    while (next <= right) {
      while (tail > head && greater(next, queue[tail - 1])) tail--;
      queue[tail++] = next;
      next++;
    }
    const left = c - w;
    while (queue[head] < left) head++;
    if (queue[head] === c) cuts.push(c + 1);
  }
  if (cuts[cuts.length - 1] !== n) cuts.push(n);
  return cuts;
}
function chunksOf(bytes, w = CDC_WINDOW, max = CDC_MAX_CHUNK) {
  const out = [];
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
var VERSION_PREFIX = utf8("SBGK-DOCVER-v1");
async function documentChunks(adapter, bytes) {
  const chunks = chunksOf(bytes);
  const hashes = [];
  for (const c of chunks) hashes.push(await adapter.sha256(bytes.subarray(c.start, c.end)));
  const version = await adapter.sha256(concatBytes([VERSION_PREFIX, ...hashes]));
  return { chunks, hashes, version };
}
function segmentsOf(doc, start, end) {
  const out = [];
  doc.chunks.forEach((c, k) => {
    if (c.start < end && c.end > start) {
      out.push({ hash: doc.hashes[k], from: Math.max(start, c.start) - c.start, to: Math.min(end, c.end) - c.start });
    }
  });
  return out;
}
function u16le(n) {
  return new Uint8Array([n & 255, n >>> 8 & 255]);
}
function u32le(n) {
  return new Uint8Array([n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255]);
}
var AnchorEncodingError = class extends Error {
};
async function anchorBytes(adapter, docId, quote, segments) {
  const id = utf8(docId);
  if (id.length > 65535) throw new AnchorEncodingError("doc_id longer than 65535 bytes");
  if (segments.length > 255) throw new AnchorEncodingError("quote crosses more than 255 chunks");
  if (quote.length > 4294967295) throw new AnchorEncodingError("quote longer than 2^32 - 1 bytes");
  const parts = [new Uint8Array([1]), u16le(id.length), id, await adapter.sha256(quote), u32le(quote.length), new Uint8Array([segments.length])];
  for (const s of segments) parts.push(s.hash, u32le(s.from), u32le(s.to));
  return concatBytes(parts);
}
function occurrences(bytes, q, limit) {
  const out = [];
  if (q.length === 0 || q.length > bytes.length) return out;
  const first = q[0];
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

// src/json.ts
var MAX_JOURNAL_INTEGER_TEXT = "9007199254740991";
function isObject(v) {
  return v instanceof Map;
}
function isHashText(v) {
  return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
}
function hasExactKeys(obj, keys) {
  if (obj.size !== keys.length) return false;
  for (const k of keys) if (!obj.has(k)) return false;
  return true;
}
function depthExceeds(bytes, maxDepth) {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (b === 92) escaped = true;
      else if (b === 34) inString = false;
      continue;
    }
    if (b === 34) inString = true;
    else if (b === 123 || b === 91) {
      depth++;
      if (depth > maxDepth) return true;
    } else if ((b === 125 || b === 93) && depth > 0) depth--;
  }
  return false;
}
var ParseError = class extends Error {
};
function parseJson(text) {
  const n = text.length;
  let pos = 0;
  let badNumber = false;
  let duplicateKey = false;
  const fail = (msg) => {
    throw new ParseError(`${msg} at character ${pos}`);
  };
  const skipWs = () => {
    while (pos < n) {
      const c = text.charCodeAt(pos);
      if (c === 32 || c === 9 || c === 10 || c === 13) pos++;
      else break;
    }
  };
  const hex4 = () => {
    if (pos + 4 > n) fail("truncated \\u escape");
    let v = 0;
    for (let k = 0; k < 4; k++) {
      const c = text.charCodeAt(pos + k);
      let d;
      if (c >= 48 && c <= 57) d = c - 48;
      else if (c >= 97 && c <= 102) d = c - 97 + 10;
      else if (c >= 65 && c <= 70) d = c - 65 + 10;
      else return fail("bad hex digit in \\u escape");
      v = v * 16 + d;
    }
    pos += 4;
    return v;
  };
  const parseString = () => {
    if (text.charCodeAt(pos) !== 34) fail("expected string");
    pos++;
    let out = "";
    let runStart = pos;
    for (; ; ) {
      if (pos >= n) fail("unterminated string");
      const c = text.charCodeAt(pos);
      if (c === 34) {
        out += text.slice(runStart, pos);
        pos++;
        return out;
      }
      if (c < 32) fail("unescaped control character in string");
      if (c >= 55296 && c <= 57343) {
        const next = pos + 1 < n ? text.charCodeAt(pos + 1) : -1;
        if (c <= 56319 && next >= 56320 && next <= 57343) {
          pos += 2;
          continue;
        }
        fail("lone surrogate in string");
      }
      if (c !== 92) {
        pos++;
        continue;
      }
      out += text.slice(runStart, pos);
      pos++;
      if (pos >= n) fail("unterminated escape");
      const e = text.charCodeAt(pos);
      pos++;
      switch (e) {
        case 34:
          out += '"';
          break;
        case 92:
          out += "\\";
          break;
        case 47:
          out += "/";
          break;
        case 98:
          out += "\b";
          break;
        case 102:
          out += "\f";
          break;
        case 110:
          out += "\n";
          break;
        case 114:
          out += "\r";
          break;
        case 116:
          out += "	";
          break;
        case 117: {
          const u = hex4();
          if (u >= 55296 && u <= 56319) {
            if (text.charCodeAt(pos) === 92 && text.charCodeAt(pos + 1) === 117) {
              pos += 2;
              const low = hex4();
              if (low >= 56320 && low <= 57343) {
                out += String.fromCharCode(u, low);
                break;
              }
            }
            fail("lone surrogate escape in string");
          }
          if (u >= 56320 && u <= 57343) fail("lone surrogate escape in string");
          out += String.fromCharCode(u);
          break;
        }
        default:
          pos--;
          fail("invalid escape");
      }
      runStart = pos;
    }
  };
  const parseNumber = () => {
    const start = pos;
    let negative = false;
    if (text.charCodeAt(pos) === 45) {
      negative = true;
      pos++;
    }
    const intStart = pos;
    const c0 = text.charCodeAt(pos);
    if (c0 === 48) pos++;
    else if (c0 >= 49 && c0 <= 57) {
      while (pos < n && isDigit(text.charCodeAt(pos))) pos++;
    } else fail("bad number");
    const intEnd = pos;
    let fraction = false;
    let exponent = false;
    if (text.charCodeAt(pos) === 46) {
      fraction = true;
      pos++;
      if (!isDigit(text.charCodeAt(pos))) fail("bad number fraction");
      while (pos < n && isDigit(text.charCodeAt(pos))) pos++;
    }
    const ce = text.charCodeAt(pos);
    if (ce === 101 || ce === 69) {
      exponent = true;
      pos++;
      const cs = text.charCodeAt(pos);
      if (cs === 43 || cs === 45) pos++;
      if (!isDigit(text.charCodeAt(pos))) fail("bad number exponent");
      while (pos < n && isDigit(text.charCodeAt(pos))) pos++;
    }
    const digits = text.slice(intStart, intEnd);
    if (negative || fraction || exponent || !integerInRange(digits)) {
      badNumber = true;
      return Number(text.slice(start, pos));
    }
    return Number(digits);
  };
  const parseLiteral = () => {
    if (text.startsWith("true", pos)) {
      pos += 4;
      return true;
    }
    if (text.startsWith("false", pos)) {
      pos += 5;
      return false;
    }
    if (text.startsWith("null", pos)) {
      pos += 4;
      return null;
    }
    return fail("unexpected character");
  };
  const parseKeyAndColon = () => {
    skipWs();
    const key = parseString();
    skipWs();
    if (text.charCodeAt(pos) !== 58) fail("expected ':'");
    pos++;
    return key;
  };
  try {
    const stack = [];
    let result = null;
    let done = false;
    while (!done) {
      skipWs();
      if (pos >= n) fail("unexpected end of input");
      const c = text.charCodeAt(pos);
      let value;
      if (c === 123) {
        pos++;
        skipWs();
        if (text.charCodeAt(pos) === 125) {
          pos++;
          value = /* @__PURE__ */ new Map();
        } else {
          stack.push({ kind: "object", members: /* @__PURE__ */ new Map(), key: parseKeyAndColon() });
          continue;
        }
      } else if (c === 91) {
        pos++;
        skipWs();
        if (text.charCodeAt(pos) === 93) {
          pos++;
          value = [];
        } else {
          stack.push({ kind: "array", items: [] });
          continue;
        }
      } else if (c === 34) value = parseString();
      else if (c === 45 || isDigit(c)) value = parseNumber();
      else value = parseLiteral();
      for (; ; ) {
        const top = stack[stack.length - 1];
        if (top === void 0) {
          result = value;
          done = true;
          break;
        }
        skipWs();
        const d = text.charCodeAt(pos);
        if (top.kind === "array") {
          top.items.push(value);
          if (d === 44) {
            pos++;
            break;
          }
          if (d === 93) {
            pos++;
            stack.pop();
            value = top.items;
            continue;
          }
          fail("expected ',' or ']'");
        } else {
          if (top.members.has(top.key)) duplicateKey = true;
          top.members.set(top.key, value);
          if (d === 44) {
            pos++;
            top.key = parseKeyAndColon();
            break;
          }
          if (d === 125) {
            pos++;
            stack.pop();
            value = top.members;
            continue;
          }
          fail("expected ',' or '}'");
        }
      }
    }
    skipWs();
    if (pos !== n) fail("unexpected data after the JSON value");
    return { ok: true, value: result, badNumber, duplicateKey };
  } catch (e) {
    if (e instanceof ParseError) return { ok: false, error: e.message };
    throw e;
  }
}
function isDigit(c) {
  return c >= 48 && c <= 57;
}
function integerInRange(digits) {
  if (digits.length < MAX_JOURNAL_INTEGER_TEXT.length) return true;
  if (digits.length > MAX_JOURNAL_INTEGER_TEXT.length) return false;
  return digits <= MAX_JOURNAL_INTEGER_TEXT;
}
var Literal = class {
  constructor(text) {
    this.text = text;
  }
  text;
};
function jcs(value) {
  const out = [];
  const stack = [value];
  while (stack.length > 0) {
    const t = stack.pop();
    if (t instanceof Literal) out.push(t.text);
    else if (t === null) out.push("null");
    else if (t === true) out.push("true");
    else if (t === false) out.push("false");
    else if (typeof t === "number") out.push(jcsNumber(t));
    else if (typeof t === "string") out.push(jcsString(t));
    else if (Array.isArray(t)) {
      out.push("[");
      stack.push(new Literal("]"));
      for (let i = t.length - 1; i >= 0; i--) {
        stack.push(t[i]);
        if (i > 0) stack.push(new Literal(","));
      }
    } else {
      const keys = [...t.keys()].sort();
      out.push("{");
      stack.push(new Literal("}"));
      for (let i = keys.length - 1; i >= 0; i--) {
        const k = keys[i];
        stack.push(t.get(k));
        stack.push(new Literal(jcsString(k) + ":"));
        if (i > 0) stack.push(new Literal(","));
      }
    }
  }
  return out.join("");
}
function jcsNumber(v) {
  if (!Number.isSafeInteger(v)) {
    throw new Error("JCS: only safe integers occur in this format");
  }
  return String(v);
}
var SHORT_ESCAPES = {
  8: "\\b",
  9: "\\t",
  10: "\\n",
  12: "\\f",
  13: "\\r",
  34: '\\"',
  92: "\\\\"
};
function jcsString(s) {
  let out = '"';
  let runStart = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 32 || c === 34 || c === 92) {
      out += s.slice(runStart, i);
      out += SHORT_ESCAPES[c] ?? "\\u00" + c.toString(16).padStart(2, "0");
      runStart = i + 1;
    } else if (c >= 55296 && c <= 57343) {
      const next = s.charCodeAt(i + 1);
      if (c <= 56319 && next >= 56320 && next <= 57343) i++;
      else throw new Error("JCS: lone surrogate");
    }
  }
  return out + s.slice(runStart) + '"';
}
function fromPlain(v) {
  if (v === null || typeof v === "boolean" || typeof v === "number" || typeof v === "string") return v;
  if (Array.isArray(v)) return v.map((x) => fromPlain(x));
  const m = /* @__PURE__ */ new Map();
  for (const [k, x] of Object.entries(v)) m.set(k, fromPlain(x));
  return m;
}

// src/trees.ts
var DOMAIN = {
  frameBody: "R2R-FRAME-BODY/2",
  frameHeader: "R2R-FRAME-HDR/2",
  seal: "R2R-SEAL/2",
  recordLeaf: "R2R-REC-LEAF/2",
  recordNode: "R2R-REC-NODE/2",
  recordEmpty: "R2R-REC-EMPTY/2"
};
async function domainHash(adapter, domain, ...parts) {
  const d = new Uint8Array(domain.length + 1);
  for (let i = 0; i < domain.length; i++) {
    const c = domain.charCodeAt(i);
    if (c > 127) throw new Error("domain must be ASCII");
    d[i] = c;
  }
  d[domain.length] = 0;
  return adapter.sha256(concatBytes([d, ...parts]));
}
function splitPoint(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
async function logLeaf(adapter, frameHash) {
  return adapter.sha256(concatBytes([new Uint8Array([0]), frameHash]));
}
async function logNode(adapter, l, r) {
  return adapter.sha256(concatBytes([new Uint8Array([1]), l, r]));
}
var LogTree = class {
  constructor(adapter) {
    this.adapter = adapter;
  }
  adapter;
  stack = [];
  count = 0;
  get size() {
    return this.count;
  }
  async push(frameHash) {
    let top = { hash: await logLeaf(this.adapter, frameHash), size: 1 };
    for (; ; ) {
      const below = this.stack[this.stack.length - 1];
      if (below === void 0 || below.size !== top.size) break;
      this.stack.pop();
      top = { hash: await logNode(this.adapter, below.hash, top.hash), size: below.size + top.size };
    }
    this.stack.push(top);
    this.count++;
  }
  /** Root over all leaves pushed so far; null for an empty tree. */
  async root() {
    let i = this.stack.length - 1;
    const top = this.stack[i];
    if (top === void 0) return null;
    let result = top.hash;
    for (i--; i >= 0; i--) result = await logNode(this.adapter, this.stack[i].hash, result);
    return result;
  }
};
async function logRootRecursive(adapter, frameHashes) {
  if (frameHashes.length === 0) throw new Error("empty log tree");
  if (frameHashes.length === 1) return logLeaf(adapter, frameHashes[0]);
  const k = splitPoint(frameHashes.length);
  return logNode(
    adapter,
    await logRootRecursive(adapter, frameHashes.slice(0, k)),
    await logRootRecursive(adapter, frameHashes.slice(k))
  );
}
async function recordLeaf(adapter, leafJcsBytes) {
  return domainHash(adapter, DOMAIN.recordLeaf, leafJcsBytes);
}
async function recordsRoot(adapter, leaves) {
  if (leaves.length === 0) return domainHash(adapter, DOMAIN.recordEmpty);
  if (leaves.length === 1) return leaves[0];
  const k = splitPoint(leaves.length);
  return domainHash(
    adapter,
    DOMAIN.recordNode,
    await recordsRoot(adapter, leaves.slice(0, k)),
    await recordsRoot(adapter, leaves.slice(k))
  );
}

// src/j4a.ts
var PROJECTION_DOMAIN = { status: "R2R-PROJ-STATUS/2", dependencies: "R2R-PROJ-DEPS/2" };
var LINK_DOMAIN = "R2R-AUDIT-LINK/1";
var EMPTY_PROJECTIONS = {
  status: "88f19ee44d285b626e63507ebd361e8ce71ccc967e93d303dad85d908ac5a875",
  dependencies: "65ec2af34b368787092fa5d7b6e498b243c7b7eaedf11eb45f3033fd5ba49133"
};
async function linkId(adapter, from, rel, to) {
  const domain = utf8(LINK_DOMAIN);
  return toHex(await adapter.sha256(concatBytes([domain, utf8(jcs([from, rel, to]))])));
}
async function projectionHashes(adapter, rows, pairs) {
  return {
    status: toHex(await domainHash(adapter, PROJECTION_DOMAIN.status, utf8(jcs(rows)))),
    dependencies: toHex(await domainHash(adapter, PROJECTION_DOMAIN.dependencies, utf8(jcs(pairs))))
  };
}
var tripleKey = (from, rel, to) => jcs([from, rel, to]);
var HEX64 = /^[0-9a-fA-F]{64}$/;
var Cascade = class {
  constructor(adapter, docs) {
    this.adapter = adapter;
    this.docs = docs;
  }
  adapter;
  docs;
  records = [];
  byId = /* @__PURE__ */ new Map();
  byDoc = /* @__PURE__ */ new Map();
  /** P6-2: the revoked anchor ids, with the reason of the first revocation. */
  revoked = /* @__PURE__ */ new Map();
  /** P6-2: per document name, the texts withdrawn from it (key: the text, value: its bytes). */
  withdrawn = /* @__PURE__ */ new Map();
  /** P6-2: the links, keyed by the triple. */
  links = /* @__PURE__ */ new Map();
  linkIds = /* @__PURE__ */ new Map();
  /**
   * Observation report, section 6: frames that record a refused answer (`task-repair:`) or a late one
   * (`task-conflict:`). Not part of the projections.
   */
  rejectedSubmissions = 0;
  lateSubmissions = 0;
  get accepted() {
    return this.records;
  }
  record(id) {
    return this.byId.get(id);
  }
  get allLinks() {
    return [...this.links.values()];
  }
  /** P6-2, P6-3: a record accepted by J3; an accepted relation creates its link right away (P6-6). */
  async addRecord(r) {
    const rec = { ...r, index: this.records.length };
    this.records.push(rec);
    this.byId.set(rec.id, rec);
    if (rec.obs !== null) {
      const list = this.byDoc.get(rec.obs.docId);
      if (list === void 0) this.byDoc.set(rec.obs.docId, [rec]);
      else list.push(rec);
    }
    if (rec.kind === "relation" && rec.ends !== null) await this.createLink(rec.ends.from, rec.ends.rel, rec.ends.to, rec.grounds);
  }
  /** P6-3: a command other than submit and put_document that ran (as a frame, or as a batch operation with a result). */
  async command(command) {
    if (!isObject(command)) return;
    switch (command.get("kind")) {
      case "revoke":
        return this.revoke(command);
      case "revoke_text":
        return this.revokeText(command);
      case "add_link":
        return this.addLink(command);
      case "set_link_status":
        return this.setLinkStatus(command);
      default:
        return;
    }
  }
  /**
   * Observation report, section 6: a `batch` frame with outcome `value` whose `command.checkpoint.key`
   * starts with `task-repair:` (a refused answer) or `task-conflict:` (a late one), and whose
   * `outcome.result.checkpointed` is `true`.
   */
  noteFrame(command, outcome) {
    if (!isObject(command) || command.get("kind") !== "batch" || !isObject(outcome) || outcome.get("kind") !== "value") return;
    const checkpoint = command.get("checkpoint");
    const key = isObject(checkpoint) ? checkpoint.get("key") : void 0;
    const result = outcome.get("result");
    if (typeof key !== "string" || !isObject(result) || result.get("checkpointed") !== true) return;
    if (key.startsWith("task-repair:")) this.rejectedSubmissions++;
    else if (key.startsWith("task-conflict:")) this.lateSubmissions++;
  }
  /** P6-5: the re-close step of a put_document, after the new bytes and version are in place. */
  async reclose(docId) {
    const texts = this.withdrawn.get(docId);
    if (texts === void 0) return;
    for (const t of [...texts.values()]) this.close(docId, t, await this.hits(docId, t));
  }
  // -------------------------------------------------------------------------
  // P6-5: withdrawals
  // -------------------------------------------------------------------------
  /** hits(D, T): live observations bound to the current version of D whose span overlaps an occurrence of T. */
  async hits(docId, t) {
    if (t.length === 0) return [];
    const bytes = this.docs.bytes(docId);
    const candidates = this.byDoc.get(docId);
    if (bytes === void 0 || candidates === void 0) return [];
    const found = occurrences(bytes, t, Number.MAX_SAFE_INTEGER);
    if (found.length === 0) return [];
    const version = await this.docs.version(docId);
    const out = [];
    for (const r of candidates) {
      const o = r.obs;
      if (o.version !== version || this.revoked.has(o.anchor)) continue;
      if (found.some((p) => o.start < p + t.length && p < o.end)) out.push(r);
    }
    return out;
  }
  revokeAnchor(anchor, reason) {
    if (!this.revoked.has(anchor)) this.revoked.set(anchor, reason);
  }
  /** close(D, T, H). */
  close(docId, t, hits) {
    for (const h of hits) this.revokeAnchor(h.obs.anchor, "withdrawn");
    let texts = this.withdrawn.get(docId);
    if (texts === void 0) this.withdrawn.set(docId, texts = /* @__PURE__ */ new Map());
    const key = toHex(t);
    if (!texts.has(key)) texts.set(key, t);
  }
  isWithdrawn(docId, t) {
    return this.withdrawn.get(docId)?.has(toHex(t)) === true;
  }
  async revokeText(command) {
    const docId = command.get("doc_id");
    const quote = command.get("exact_quote");
    if (typeof docId !== "string" || typeof quote !== "string") return;
    const t = utf8(quote);
    this.close(docId, t, await this.hits(docId, t));
  }
  async revoke(command) {
    const ref = command.get("record");
    if (typeof ref !== "string") return;
    const r = HEX64.test(ref) ? this.byId.get(ref.toLowerCase()) : void 0;
    if (r === void 0 || r.obs === null) return;
    const { docId, quoteBytes: t, anchor } = r.obs;
    const already = this.isWithdrawn(docId, t);
    const hits = already ? [] : await this.hits(docId, t);
    this.revokeAnchor(anchor, already ? "revoked" : "withdrawn");
    if (!already) this.close(docId, t, hits);
  }
  // -------------------------------------------------------------------------
  // P6-6: links
  // -------------------------------------------------------------------------
  /** P6-6: a 64-digit hex string names a record id; otherwise "@" and 16 to 64 hex digits of exactly one record. */
  resolve(ref) {
    if (HEX64.test(ref)) return ref.toLowerCase();
    if (!/^@[0-9a-fA-F]{16,64}$/.test(ref)) return null;
    const prefix = ref.slice(1).toLowerCase();
    let found = null;
    for (const r of this.records) {
      if (r.id.startsWith(prefix)) {
        if (found !== null) return null;
        found = r.id;
      }
    }
    return found;
  }
  resolveList(v) {
    if (!Array.isArray(v)) return null;
    return v.map((x) => typeof x === "string" ? this.resolve(x) : null);
  }
  async createLink(from, rel, to, basis) {
    const key = tripleKey(from, rel, to);
    if (this.links.has(key)) return;
    const id = await linkId(this.adapter, from, rel, to);
    this.links.set(key, { id, from, rel, to, status: "proposed", basis: [...basis], acceptanceBasis: null });
    this.linkIds.set(id, key);
  }
  async addLink(command) {
    const from = command.get("from");
    const rel = command.get("rel");
    const to = command.get("to");
    const basis = this.resolveList(command.get("basis"));
    if (typeof from !== "string" || typeof rel !== "string" || typeof to !== "string" || basis === null) return;
    const f = this.resolve(from);
    const t = this.resolve(to);
    if (f === null || t === null) return;
    await this.createLink(f, rel, t, basis);
  }
  async setLinkStatus(command) {
    const link = command.get("link");
    const status = command.get("status");
    if (typeof link !== "string" || typeof status !== "string") return;
    const key = this.linkIds.get(link.toLowerCase());
    if (key === void 0) return;
    const l = this.links.get(key);
    l.status = status;
    if (status === "accepted") l.acceptanceBasis = this.resolveList(command.get("basis")) ?? [];
  }
  // -------------------------------------------------------------------------
  // P6-4, P6-7, P6-8: support and projections
  // -------------------------------------------------------------------------
  /** P6-4 for every observation; null for other records. */
  async observationsGrounded() {
    const versions = /* @__PURE__ */ new Map();
    const out = [];
    for (const r of this.records) {
      if (r.obs === null) {
        out.push(null);
        continue;
      }
      if (this.revoked.has(r.obs.anchor)) {
        out.push(false);
        continue;
      }
      if (!versions.has(r.obs.docId)) versions.set(r.obs.docId, await this.docs.version(r.obs.docId));
      out.push(versions.get(r.obs.docId) === r.obs.version);
    }
    return out;
  }
  /** P6-7, P6-8: the support values and the two projections over the current state. */
  async status() {
    const n = this.records.length;
    const og = await this.observationsGrounded();
    const at = (id) => id === null ? -1 : this.byId.get(id)?.index ?? -1;
    let proof = null;
    if (this.allLinks.some((l) => l.status === "accepted")) {
      const structural = new Array(n);
      proof = new Array(n);
      for (const r of this.records) {
        const k = r.index;
        if (r.kind === "observe") {
          structural[k] = og[k] === true;
          proof[k] = structural[k];
          continue;
        }
        const g = r.grounds.map(at);
        const ends = r.ends !== null ? [at(r.ends.from), at(r.ends.to)] : [];
        structural[k] = r.kind !== "done" && g.length > 0 && g.every((x) => x >= 0 && structural[x]) && ends.every((x) => x >= 0 && structural[x]);
        proof[k] = structural[k] && !["hypothesis", "question", "done"].includes(r.kind) && g.every((x) => proof[x]) && ends.every((x) => proof[x]);
      }
    }
    const effective = (from, rel, to) => {
      const l = this.links.get(tripleKey(from, rel, to));
      return l !== void 0 && this.effectiveWith(l, proof);
    };
    const grounded = new Array(n);
    const established = new Array(n);
    const isG = (x) => x >= 0 && grounded[x];
    const isE = (x) => x >= 0 && established[x];
    for (const r of this.records) {
      const k = r.index;
      const g = r.grounds.map(at);
      switch (r.kind) {
        case "observe":
          grounded[k] = og[k] === true;
          established[k] = grounded[k];
          break;
        case "claim":
          grounded[k] = g.length > 0 && g.every(isG);
          established[k] = grounded[k];
          break;
        case "hypothesis":
          grounded[k] = g.length > 0 && g.every(isG);
          established[k] = false;
          break;
        case "relation": {
          const f = at(r.ends.from);
          const t = at(r.ends.to);
          grounded[k] = g.length > 0 && g.every(isG) && isG(f) && isG(t);
          established[k] = grounded[k] && effective(r.ends.from, r.ends.rel, r.ends.to) && isE(f) && isE(t);
          break;
        }
        case "done":
          grounded[k] = g.length > 0 && g.every((x) => isG(x) && isE(x));
          established[k] = false;
          break;
        default:
          grounded[k] = false;
          established[k] = false;
      }
    }
    const rows = [];
    const pairs = [];
    for (const r of this.records) {
      const direct = this.directGrounds(r);
      const fallen = [...new Set(direct.filter((id) => !isG(at(id))))].sort();
      rows.push([r.id, r.kind, grounded[r.index], established[r.index], r.kind === "observe" || r.kind === "question" ? [] : fallen]);
      for (const d of direct) pairs.push([r.id, d]);
    }
    pairs.sort((a, b) => cmp(a[0] + a[1], b[0] + b[1]));
    const unique = pairs.filter((p, k) => k === 0 || p[0] !== pairs[k - 1][0] || p[1] !== pairs[k - 1][1]);
    const hashes = await projectionHashes(this.adapter, rows, unique);
    return { grounded, established, proof, rows, pairs: unique, ...hashes };
  }
  /** P6-7: a link is effective (the observation report calls it usable). */
  linkEffective(l, st) {
    return this.effectiveWith(l, st.proof);
  }
  effectiveWith(l, proof) {
    if (l.status !== "accepted" || proof === null) return false;
    const proofOf = (id) => {
      const k = id === null ? -1 : this.byId.get(id)?.index ?? -1;
      return k >= 0 && proof[k];
    };
    if (!proofOf(l.from) || !proofOf(l.to)) return false;
    if (l.basis.length === 0 || !l.basis.every(proofOf)) return false;
    return l.acceptanceBasis !== null && l.acceptanceBasis.length > 0 && l.acceptanceBasis.every(proofOf);
  }
  /** P6-8: a record's direct grounds are its based_on, then, for a relation, from and to. */
  directGrounds(r) {
    return r.ends !== null ? [...r.grounds, r.ends.from, r.ends.to] : [...r.grounds];
  }
};
function cmp(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// src/report.ts
var VERIFIER_NAME = "yuce-verify";
var VERIFIER_VERSION = "0.3.1";
var SPEC_ID = "SPEC_INDEPENDENT_VERIFIER/8";
var NOT_VERIFIED = ["quotes_against_sources", "withdrawal_cascade", "signatures"];
var NOT_VERIFIED_AFTER_J3 = ["withdrawal_cascade", "signatures"];
function reportToJcs(report) {
  return jcs(fromPlain(report));
}
function notVerifiedSentence(items) {
  return `Not verified: ${items.map((s) => s.replaceAll("_", " ")).join(", ")}.`;
}
function cascadeSentence(c) {
  if (c.checked_through_frame === null) return "Cascade: no seal to check.";
  if (c.unchecked_frames === 0) return `Cascade: checked at ${c.seals_checked} seals.`;
  return `Cascade: checked at ${c.seals_checked} seals through frame ${c.checked_through_frame}; ${c.unchecked_frames} later frames not checked.`;
}
function humanLine(report) {
  const parts = [];
  const f = report.first_failure;
  const { J1: j1, J3: j3 } = report.levels;
  if (report.verdict === "FAIL" && f !== null) {
    parts.push(f.frame === null ? `FAIL at ${f.level}: ${f.code}.` : `FAIL at ${f.level}, frame ${f.frame}: ${f.code}.`);
  } else if (j1.result === "PASS") {
    const head = `Frames: ${report.input.frames}. Seals: ${j1.seals.length}.`;
    if (j3.result === "PASS") parts.push(`J0-J3 PASS. ${head} Records: ${j3.records}. Quotes: ${j3.quotes}.`);
    else if (j3.result === "NOT_CHECKABLE") parts.push(`J0-J2 PASS. ${head} J3 not checkable: ${j3.reason}.`);
    else parts.push(`J0-J2 PASS. ${head}`);
    parts.push(tailSentence(j1.tail));
    parts.push(anchorSentence(report.anchor, report.input.frames));
    if (report.levels.J4a.result === "PASS" && report.cascade !== null) parts.push(cascadeSentence(report.cascade));
  } else {
    parts.push(`${report.verdict}.`);
  }
  parts.push(notVerifiedSentence(report.not_verified));
  return parts.join(" ");
}
function tailSentence(tail) {
  switch (tail.kind) {
    case "closed":
      return "Tail: closed.";
    case "sealed":
      return "Tail: sealed, run not closed.";
    case "unsealed":
      return `Tail: ${tail.frames_after_last_seal} unsealed frames.`;
    case "no_seals":
      return "Tail: no seals.";
  }
}
function anchorSentence(anchor, frames) {
  const seal = anchor.seal.matched === true ? anchor.seal : null;
  const head = anchor.head.matched === true;
  if (seal !== null && head) return `Anchor: matched seal at n=${seal.at_n} and head at n=${frames}.`;
  if (seal !== null) return `Anchor: matched seal at n=${seal.at_n}.`;
  if (head) return `Anchor: matched head at n=${frames}.`;
  return "Anchor: not given - journal is internally consistent; authenticity not established.";
}
var EXIT = { pass: 0, fail: 1, usage: 2, incomplete: 3 };
function exitCodeFor(verdict) {
  if (verdict === "PASS") return EXIT.pass;
  if (verdict === "FAIL") return EXIT.fail;
  return EXIT.incomplete;
}

// src/seal.ts
var SEAL_KEYS = ["audit_root", "engine_root", "format", "log_root", "log_size", "projections", "run_id", "wal_head"];
var SEAL_HASH_FIELDS = ["log_root", "wal_head", "audit_root", "engine_root"];
var PROJECTION_KEYS = ["dependencies", "status"];
function sealFormProblem(command, outcome) {
  if (!isObject(command) || !hasExactKeys(command, ["kind", "seal"])) return "command must have exactly the keys kind, seal";
  if (!isObject(outcome) || !hasExactKeys(outcome, ["kind", "result"])) return "outcome must have exactly the keys kind, result";
  if (outcome.get("kind") !== "value") return 'outcome.kind is not "value"';
  const result = outcome.get("result");
  if (!isObject(result) || !hasExactKeys(result, ["seal", "seal_hash"])) return "outcome.result must have exactly the keys seal, seal_hash";
  const seal = command.get("seal");
  if (!isObject(seal) || !hasExactKeys(seal, SEAL_KEYS)) return "the seal must have exactly its eight keys";
  const projections = seal.get("projections");
  if (!isObject(projections) || !hasExactKeys(projections, PROJECTION_KEYS)) return "seal.projections must have exactly the keys dependencies, status";
  if (typeof seal.get("format") !== "string") return "seal.format is not a string";
  if (typeof seal.get("run_id") !== "string") return "seal.run_id is not a string";
  if (typeof seal.get("log_size") !== "number") return "seal.log_size is not a number";
  for (const k of SEAL_HASH_FIELDS) if (!isHashText(seal.get(k))) return `seal.${k} is not a hash`;
  for (const k of PROJECTION_KEYS) if (!isHashText(projections.get(k))) return `seal.projections.${k} is not a hash`;
  if (!isHashText(result.get("seal_hash"))) return "outcome.result.seal_hash is not a hash";
  return null;
}

// src/quittance.ts
var QUITTANCE_FORMAT = "yuce-proof/1";
var SEAL_HEADER_KEYS = ["body_hash", "format", "previous", "records_root", "seq", "wal_op"];
function parseQuittance(file, bytes) {
  const q = { file, problem: null, n: null, target: null, ids: [], header: null, body: null, status: void 0 };
  const bad = (problem2) => ({ ...q, problem: problem2 });
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return bad("the file is not UTF-8");
  }
  const parsed = parseJson(text);
  if (!parsed.ok) return bad(`the file is not JSON: ${parsed.error}`);
  if (parsed.badNumber) return bad("a number that is not an integer from 0 to 2^53-1");
  const v = parsed.value;
  if (!isObject(v)) return bad("the quittance is not an object");
  if (v.get("format") !== QUITTANCE_FORMAT) return bad(`format is not "${QUITTANCE_FORMAT}"`);
  const target = v.get("target");
  if (!isHashText(target)) return bad("target is not a 64-digit id");
  const records = v.get("records");
  if (!Array.isArray(records) || records.length === 0) return bad("records is not a non-empty list");
  const ids = [];
  for (const r of records) {
    const value = isObject(r) ? r.get("value") : void 0;
    const id = isObject(value) ? value.get("id") : void 0;
    if (!isHashText(id)) return bad("an element of records has no object value with a 64-digit id");
    ids.push(id);
  }
  if (!ids.includes(target)) return bad("the target is not among the ids of records");
  const seal = v.get("seal");
  if (!isObject(seal)) return bad("seal is not an object");
  const header = seal.get("header");
  if (!isObject(header) || !hasExactKeys(header, SEAL_HEADER_KEYS)) return bad("seal.header is not an object with exactly the six keys of a header");
  const body = seal.get("body");
  const problem = sealBodyProblem(body);
  if (problem !== null) return bad(`seal.body is not a seal body: ${problem}`);
  const n = body.get("command").get("seal");
  return { file, problem: null, n: n.get("log_size"), target, ids, header, body, status: v.get("status") };
}
function sealBodyProblem(body) {
  if (!isObject(body)) return "not an object";
  if (body.get("actor") !== "kernel") return 'actor is not "kernel"';
  const command = body.get("command");
  if (!isObject(command) || command.get("kind") !== "seal") return 'command.kind is not "seal"';
  return sealFormProblem(command, body.get("outcome"));
}
function checkQuittance(q, seal) {
  if (q.problem !== null || q.n === null) return { code: "QUITTANCE_FORM", detail: q.problem ?? "no seal position" };
  if (seal === void 0 || seal.header !== jcs(q.header) || seal.body !== jcs(q.body)) {
    return { code: "QUITTANCE_SEAL_UNKNOWN", detail: `the journal has no seal frame at position ${q.n} equal to the quittance's seal` };
  }
  const wanted = new Set(q.ids);
  const known = /* @__PURE__ */ new Set();
  for (const row of seal.rows) {
    if (!wanted.has(row[0])) continue;
    known.add(row[0]);
    if (row[2] !== true) return { code: "QUITTANCE_STATUS_MISMATCH", detail: `record ${row[0]} does not stand at the seal of frame ${q.n}` };
  }
  const missing = q.ids.find((id) => !known.has(id));
  if (missing !== void 0) return { code: "QUITTANCE_STATUS_MISMATCH", detail: `record ${missing} is not a record of the journal at the seal of frame ${q.n}` };
  if (q.status !== void 0) {
    const given = Array.isArray(q.status) ? q.status : [];
    const count = Math.max(given.length, seal.rows.length);
    for (let k = 0; k < count; k++) {
      const mine = seal.rows[k];
      const theirs = given[k];
      if (mine !== void 0 && theirs !== void 0 && jcs(mine) === jcs(theirs)) continue;
      const id = mine !== void 0 ? mine[0] : Array.isArray(theirs) && typeof theirs[0] === "string" ? theirs[0] : `#${k}`;
      return { code: "QUITTANCE_STATUS_MISMATCH", detail: `status row ${k} (record ${id}) differs from the rows computed at the seal of frame ${q.n}` };
    }
  }
  return null;
}

// src/j2.ts
var EMPTY_RECORDS_ROOT = "fe7c90ca2214e168f5ffe6cccb15729c3b8a03c403e48c406441cd589fdd8c41";
var GENESIS_FORMATS = {
  format: "r2r-audit-genesis/3",
  state_root_format: "r2r-state-root/2",
  seal_format: "r2r-seal/2"
};
var RULES_VERSIONS = ["r2r-audit-rules/3", "r2r-audit-rules/4"];
var RULES_VERSION_4 = "r2r-audit-rules/4";
var GENESIS_KEYS = [
  "format",
  "rules_version",
  "state_root_format",
  "seal_format",
  "run_id",
  "source_mode",
  "source_documents",
  "questions",
  "operator_meta",
  "settings_hash",
  "manifest_hash",
  "engine_root",
  "audit_root",
  "engine_container_hex",
  "base_ontology"
];
var BODY_KEYS = ["actor", "submission_id", "command", "request_hash", "outcome", "engine_root", "audit_root"];
var OPAQUE_KEYS = ["doc_id", "kind", "raw_sha256"];
var GIT_KEYS = ["commit", "kind", "path", "raw_sha256", "repo", "size_bytes", "revision_refs"];
var GIT_OPTIONAL_KEYS = ["date"];
var OPERATOR_META_MAX_BYTES = 4096;
var BATCH_MAX_OPERATIONS = 256;
var WHITESPACE = /* @__PURE__ */ new Set([
  9,
  10,
  11,
  12,
  13,
  32,
  133,
  160,
  5760,
  8192,
  8193,
  8194,
  8195,
  8196,
  8197,
  8198,
  8199,
  8200,
  8201,
  8202,
  8232,
  8233,
  8239,
  8287,
  12288
]);
function isIdentifier(v) {
  if (typeof v !== "string") return false;
  const n = utf8(v).length;
  if (n < 1 || n > 1024) return false;
  let visible = false;
  for (const ch of v) {
    const c = ch.codePointAt(0);
    if (c <= 31 || c >= 127 && c <= 159) return false;
    if (!WHITESPACE.has(c)) visible = true;
  }
  return visible;
}
function commandKind(command) {
  if (!isObject(command)) return void 0;
  const k = command.get("kind");
  return typeof k === "string" ? k : void 0;
}
function isSubmitResult(r) {
  if (!isObject(r) || !hasExactKeys(r, ["accepted", "error", "failed_index"])) return false;
  const accepted = r.get("accepted");
  const error = r.get("error");
  const failed = r.get("failed_index");
  return Array.isArray(accepted) && accepted.every((x) => isHashText(x)) && (error === null || isObject(error)) && (failed === null || typeof failed === "number");
}
function isOutcomeForm(o) {
  if (!isObject(o)) return false;
  switch (o.get("kind")) {
    case "records":
      return hasExactKeys(o, ["kind", "result"]) && isSubmitResult(o.get("result"));
    case "value":
      return hasExactKeys(o, ["kind", "result"]);
    case "error":
      return hasExactKeys(o, ["kind", "error"]);
    default:
      return false;
  }
}
async function gitDocumentId(adapter, repo, commit, path, rawSha256) {
  const preimage = jcs(["R2R-AUDIT-GIT-DOCUMENT/1", repo, commit, path, rawSha256]);
  return "d_" + toHex(await adapter.sha256(utf8(preimage)));
}
async function requestHash(adapter, actor, command) {
  return toHex(await adapter.sha256(utf8(jcs(["r2r-audit-request/1", actor, command]))));
}
var J2Checker = class {
  constructor(adapter) {
    this.adapter = adapter;
  }
  adapter;
  pairs = /* @__PURE__ */ new Set();
  genesis = null;
  /** J2-1 ... J2-5 on frame 0. */
  async frame0(header, body) {
    const fail = (code, detail) => ({ code, detail });
    if (header.get("records_root") !== EMPTY_RECORDS_ROOT) return fail("GENESIS_RECORDS_ROOT", "header.records_root of frame 0 is not the empty records root");
    if (!hasExactKeys(body, GENESIS_KEYS)) return fail("GENESIS_KEYS", "the genesis record must have exactly its 15 keys");
    if (body.get("format") !== GENESIS_FORMATS.format) return fail("GENESIS_FORMAT", `format is not "${GENESIS_FORMATS.format}"`);
    const rules = body.get("rules_version");
    if (typeof rules !== "string" || !RULES_VERSIONS.includes(rules)) {
      return fail("GENESIS_FORMAT", `rules_version is not one of ${RULES_VERSIONS.map((r) => `"${r}"`).join(", ")}`);
    }
    for (const k of ["state_root_format", "seal_format"]) {
      if (body.get(k) !== GENESIS_FORMATS[k]) return fail("GENESIS_FORMAT", `${k} is not "${GENESIS_FORMATS[k]}"`);
    }
    const field = (k, ok, what) => ok ? null : fail("GENESIS_FIELD", `${k} is not ${what}`);
    const mode = body.get("source_mode");
    const docs = body.get("source_documents");
    const meta = body.get("operator_meta");
    const container = body.get("engine_container_hex");
    const problem = field("run_id", isIdentifier(body.get("run_id")), "an identifier") ?? field("source_mode", mode === "opaque" || mode === "git_manifest", '"opaque" or "git_manifest"') ?? field("source_documents", isObject(docs), "an object") ?? field("questions", Array.isArray(body.get("questions")), "an array") ?? field("operator_meta", meta === null || isObject(meta) && utf8(jcs(meta)).length <= OPERATOR_META_MAX_BYTES, `null or an object of at most ${OPERATOR_META_MAX_BYTES} bytes in JCS`) ?? field("settings_hash", isHashText(body.get("settings_hash")), "a hash") ?? field("manifest_hash", isHashText(body.get("manifest_hash")), "a hash") ?? field("engine_root", isHashText(body.get("engine_root")), "a hash") ?? field("audit_root", isHashText(body.get("audit_root")), "a hash") ?? field("engine_container_hex", typeof container === "string" && /^(?:[0-9a-fA-F]{2})*$/.test(container), "an even number of hex digits") ?? field("base_ontology", isObject(body.get("base_ontology")), "an object");
    if (problem !== null) return problem;
    const sources = docs;
    for (const key of [...sources.keys()].sort()) {
      const desc = sources.get(key);
      const formProblem = this.descriptionForm(mode, key, desc);
      if (formProblem !== null) return fail("GENESIS_FIELD", `source_documents[${JSON.stringify(key)}]: ${formProblem}`);
      const d = desc;
      const id = mode === "opaque" ? d.get("doc_id") : await gitDocumentId(this.adapter, d.get("repo"), d.get("commit"), d.get("path"), d.get("raw_sha256"));
      if (id !== key) return fail("SOURCE_ID_MISMATCH", `source_documents[${JSON.stringify(key)}] describes the document ${JSON.stringify(id)}`);
    }
    this.genesis = { documents: sources.size, settingsHash: body.get("settings_hash") };
    return null;
  }
  /** P3-6 and amendment 4, P4-3: the form of one description and its key; null when it is right. */
  descriptionForm(mode, key, desc) {
    if (!isIdentifier(key)) return "the key is not an identifier";
    if (!isObject(desc)) return "not an object";
    if (desc.get("kind") !== mode) return "its kind is not the source_mode";
    if (mode === "opaque") {
      if (!hasExactKeys(desc, OPAQUE_KEYS)) return "an opaque description has exactly the keys doc_id, kind, raw_sha256";
      if (typeof desc.get("doc_id") !== "string") return "doc_id is not a string";
      if (!isHashText(desc.get("raw_sha256"))) return "raw_sha256 is not a hash";
      return null;
    }
    for (const k of desc.keys()) {
      if (!GIT_KEYS.includes(k) && !GIT_OPTIONAL_KEYS.includes(k)) return `unknown key ${JSON.stringify(k)}`;
    }
    for (const k of GIT_KEYS) if (!desc.has(k)) return `missing key ${k}`;
    const commit = desc.get("commit");
    if (typeof commit !== "string" || !/^[0-9a-f]{40}$/.test(commit)) return "commit is not 40 characters [0-9a-f]";
    if (typeof desc.get("path") !== "string") return "path is not a string";
    if (!isHashText(desc.get("raw_sha256"))) return "raw_sha256 is not a hash";
    if (typeof desc.get("repo") !== "string") return "repo is not a string";
    if (typeof desc.get("size_bytes") !== "number") return "size_bytes is not a number";
    if (!isObject(desc.get("revision_refs"))) return "revision_refs is not an object";
    return null;
  }
  /** J2-6 ... J2-11 on a frame at position i >= 1. */
  async frame(body) {
    const fail = (code, detail) => ({ code, detail });
    if (!hasExactKeys(body, BODY_KEYS)) return fail("BODY_KEYS", "the body must have exactly the keys actor, submission_id, command, request_hash, outcome, engine_root, audit_root");
    const actor = body.get("actor");
    const sid = body.get("submission_id");
    const command = body.get("command");
    const outcome = body.get("outcome");
    if (!isIdentifier(actor)) return fail("BODY_FIELD", "actor is not an identifier");
    if (!isIdentifier(sid)) return fail("BODY_FIELD", "submission_id is not an identifier");
    for (const k of ["request_hash", "engine_root", "audit_root"]) {
      if (!isHashText(body.get(k))) return fail("BODY_FIELD", `${k} is not a hash`);
    }
    if (!isOutcomeForm(outcome)) return fail("BODY_FIELD", "outcome is not one of the three forms");
    const kind = commandKind(command);
    if (outcome.get("kind") === "records" && kind !== "submit") return fail("BODY_FIELD", 'an outcome "records" on a command that is not submit');
    if (kind === "submit" && outcome.get("kind") === "value") return fail("BODY_FIELD", 'an outcome "value" on a submit');
    if (body.get("request_hash") !== await requestHash(this.adapter, actor, command)) {
      return fail("REQUEST_HASH_MISMATCH", 'request_hash is not hex(SHA256(JCS(["r2r-audit-request/1", actor, command])))');
    }
    const pair = jcs([actor, sid]);
    if (this.pairs.has(pair)) return fail("DUPLICATE_SUBMISSION", "the pair (actor, submission_id) is used by an earlier frame");
    this.pairs.add(pair);
    if (kind === "batch" && outcome.get("kind") === "value") return batchProblem(command, outcome.get("result"));
    return null;
  }
};
function batchProblem(command, result) {
  const form = (detail) => ({ code: "BATCH_FORM", detail });
  for (const k of command.keys()) if (k !== "kind" && k !== "operations" && k !== "checkpoint") return form(`unknown key ${JSON.stringify(k)} in the batch`);
  const ops = command.get("operations");
  if (!Array.isArray(ops)) return form("operations is not an array");
  if (ops.length > BATCH_MAX_OPERATIONS) return form(`more than ${BATCH_MAX_OPERATIONS} operations`);
  if (!isObject(result)) return form("outcome.result is not an object");
  const results = result.get("results");
  if (!Array.isArray(results)) return form("outcome.result.results is not an array");
  if (result.get("accepted_operations") !== results.length) return form("accepted_operations is not the length of results");
  if (results.length > ops.length) return form("more results than operations");
  for (let k = 0; k < results.length; k++) {
    if (commandKind(ops[k]) === "submit" && !isSubmitResult(results[k])) return form(`results[${k}] is not the result of a submit`);
  }
  for (let k = 0; k < results.length; k++) {
    const kind = commandKind(ops[k]);
    if (kind === "batch" || kind === "seal" || kind === "close") {
      return { code: "KERNEL_OP_IN_BATCH", detail: `operation ${k} (${kind}) was executed inside a batch` };
    }
  }
  return null;
}

// src/j3.ts
var LINE_KEYS = {
  observe: ["kind", "local_id", "doc_id", "exact_quote", "terms"],
  claim: ["kind", "local_id", "text", "subject", "predicate", "object", "stance", "as_of", "based_on"],
  relation: ["kind", "local_id", "from", "rel", "to", "based_on"],
  hypothesis: ["kind", "local_id", "text", "falsifier", "subject", "stance", "based_on"],
  question: ["kind", "local_id", "text", "about", "needed"],
  done: ["kind", "local_id", "rq_id", "directive_id", "answer_ids", "outcome", "text"]
};
var QUESTION_KEYS_RULES_4 = [...LINE_KEYS["question"], "about_record"];
var LINE_REQUIRED = {
  observe: ["doc_id", "exact_quote"],
  claim: ["text", "subject", "stance", "based_on"],
  relation: ["from", "rel", "to", "based_on"],
  hypothesis: ["text", "based_on"],
  question: ["text", "about"],
  done: ["answer_ids"]
};
var STRING_FIELDS = ["doc_id", "exact_quote", "text", "subject", "object", "stance", "from", "rel", "to", "about_record"];
var MAX_QUOTE_BYTES = 16384;
var STRING_ARRAY_FIELDS = ["terms", "based_on", "about", "answer_ids"];
var RecordEngine = class {
  constructor(adapter, files, rewrite = null, withCascade = false) {
    this.adapter = adapter;
    this.files = files;
    this.rewrite = rewrite;
    this.cascade = withCascade ? new Cascade(adapter, {
      bytes: (docId) => this.current.get(docId)?.bytes,
      version: async (docId) => {
        const doc = this.current.get(docId);
        return doc === void 0 ? void 0 : toHex((await this.chunksOf(doc)).version);
      }
    }) : null;
  }
  adapter;
  files;
  rewrite;
  current = /* @__PURE__ */ new Map();
  records = [];
  byId = /* @__PURE__ */ new Map();
  byName = /* @__PURE__ */ new Map();
  ordinals = /* @__PURE__ */ new Map();
  /** Leaves of the last frame, in order (for the forger and the tests). */
  lastFrameLeaves = [];
  quotes = 0;
  /** Amendment 5, P5-2: the genesis record names the rules 4. */
  rules4 = false;
  /** Amendment 6: the state of level J4a, kept when asked for. */
  cascade;
  /** The position of the frame being checked. */
  position = 0;
  get recordCount() {
    return this.records.length;
  }
  /** All records accepted so far, in order. */
  get accepted() {
    return this.records;
  }
  /** J3-0 on the genesis record (already checked by J2). */
  async genesis(body) {
    this.rules4 = body.get("rules_version") === RULES_VERSION_4;
    const sources = body.get("source_documents");
    for (const docId of [...sources.keys()].sort()) {
      const desc = sources.get(docId);
      const bytes = this.files.get(desc.get("raw_sha256"));
      if (bytes === void 0) return { notSupplied: docId };
      if (desc.get("kind") === "git_manifest" && bytes.length !== desc.get("size_bytes")) {
        return { code: "SOURCE_IDENTITY", detail: `the file of ${JSON.stringify(docId)} has ${bytes.length} bytes, size_bytes says ${String(desc.get("size_bytes"))}` };
      }
      this.current.set(docId, { bytes, chunks: null });
    }
    return null;
  }
  /**
   * The steps of P3-7 for a frame at position i >= 1, then J3-9. With the
   * cascade, the commands of amendment 6, P6-3 are applied at their place.
   */
  async frame(header, body, position = 0) {
    this.position = position;
    this.lastFrameLeaves = [];
    const leaves = [];
    const actor = body.get("actor");
    const command = body.get("command");
    const outcome = body.get("outcome");
    const outcomeKind = outcome.get("kind");
    const kind = commandKind(command);
    this.cascade?.noteFrame(command, outcome);
    if (outcomeKind === "records") {
      const result = outcome.get("result");
      const f = await this.group({ actor, command, accepted: result.get("accepted") }, leaves);
      if (f !== null) return f;
    } else if (kind === "batch" && outcomeKind === "value") {
      const ops = command.get("operations");
      const results = outcome.get("result").get("results");
      for (let k = 0; k < results.length; k++) {
        const op = ops[k];
        const opKind = commandKind(op);
        let f = null;
        if (opKind === "submit") {
          f = await this.group({ actor, command: op, accepted: results[k].get("accepted") }, leaves);
        } else if (opKind === "put_document") {
          f = await this.putDocument(op, results[k], (v) => this.setVersion(results[k], v));
        } else if (this.cascade !== null) {
          await this.cascade.command(op);
        }
        if (f !== null) return f;
      }
    } else if (kind === "put_document" && outcomeKind === "value") {
      const f = await this.putDocument(command, outcome.get("result"), (v) => this.setVersion(outcome.get("result"), v));
      if (f !== null) return f;
    } else if (outcomeKind === "value" && this.cascade !== null) {
      await this.cascade.command(command);
    }
    const root = toHex(await recordsRoot(this.adapter, leaves));
    if (root !== header.get("records_root")) {
      if (this.rewrite === null) return { code: "RECORDS_ROOT_MISMATCH", detail: "the records root of the frame's accepted records is not header.records_root" };
      header.set("records_root", root);
    }
    return null;
  }
  setVersion(result, version) {
    if (this.rewrite !== null && isObject(result)) result.set("document_version", version);
  }
  /** J3-8: a new version of a document. */
  async putDocument(command, result, rewriteVersion) {
    const docId = command.get("doc_id");
    const text = command.get("text");
    if (!isIdentifier(docId) || typeof text !== "string" || !isObject(result)) {
      return { code: "DOCUMENT_VERSION_MISMATCH", detail: "put_document needs an identifier doc_id, a string text and an object result" };
    }
    const bytes = utf8(text);
    const chunks = await documentChunks(this.adapter, bytes);
    const version = toHex(chunks.version);
    if (result.get("document_version") !== version) {
      if (this.rewrite === null) return { code: "DOCUMENT_VERSION_MISMATCH", detail: `the version of the new bytes of ${JSON.stringify(docId)} is not document_version` };
      rewriteVersion(version);
    }
    this.current.set(docId, { bytes, chunks });
    if (this.cascade !== null) await this.cascade.reclose(docId);
    return null;
  }
  async chunksOf(doc) {
    doc.chunks ??= await documentChunks(this.adapter, doc.bytes);
    return doc.chunks;
  }
  /** J3-1 ... J3-7 for the records of one group. */
  async group(g, leaves) {
    const fail = (code, detail) => ({ code, detail });
    const directive = g.command.get("directive");
    const scope = g.command.get("scope");
    const lines = g.command.get("lines");
    if (typeof directive !== "string") return fail("RECORD_FORM", "directive is not a string");
    if (!isScope(scope)) return fail("RECORD_FORM", "scope is not an object with an array of strings docs and an array of [string, number, number] ranges");
    if (!Array.isArray(lines)) return fail("RECORD_FORM", "lines is not an array");
    if (g.accepted.length > lines.length) return fail("RECORD_FORM", "more accepted ids than lines");
    for (let j = 0; j < g.accepted.length; j++) {
      const f = await this.line(g, directive, scope, lines[j], j, leaves);
      if (f !== null) return f;
    }
    return null;
  }
  async line(g, directive, scope, line, j, leaves) {
    const fail = (code, detail) => ({ code, detail: `line ${j}: ${detail}` });
    const form = lineFormProblem(line, this.rules4);
    if (form !== null) return fail("RECORD_FORM", form);
    const l = line;
    const kind = l.get("kind");
    if (this.byName.has(jcs([g.actor, directive, l.get("local_id")]))) {
      return fail("DUPLICATE_LOCAL_ID", `local_id ${quoted(l.get("local_id"))} already names an accepted record of this actor and directive`);
    }
    const resolve = (name, where) => this.resolve(g.actor, directive, name, where);
    const supports = [];
    let from = null;
    let to = null;
    if (kind === "claim" || kind === "relation" || kind === "hypothesis") {
      const arr = l.get("based_on");
      for (let k = 0; k < arr.length; k++) {
        const r = resolve(arr[k], (v) => arr[k] = v);
        if (r === null) return fail("UNRESOLVED_REFERENCE", `based_on ${quoted(arr[k])} does not resolve`);
        supports.push(r);
      }
    }
    if (kind === "relation") {
      from = resolve(l.get("from"), (v) => l.set("from", v));
      if (from === null) return fail("UNRESOLVED_REFERENCE", `from ${quoted(l.get("from"))} does not resolve`);
      to = resolve(l.get("to"), (v) => l.set("to", v));
      if (to === null) return fail("UNRESOLVED_REFERENCE", `to ${quoted(l.get("to"))} does not resolve`);
    }
    if (kind === "done") {
      const arr = l.get("answer_ids");
      for (let k = 0; k < arr.length; k++) {
        const r = resolve(arr[k], (v) => arr[k] = v);
        if (r === null) return fail("UNRESOLVED_REFERENCE", `answer_ids ${quoted(arr[k])} does not resolve`);
        supports.push(r);
      }
    }
    let about = null;
    if (kind === "question" && l.has("about_record")) {
      about = resolve(l.get("about_record"), (v) => l.set("about_record", v));
      if (about === null) return fail("UNRESOLVED_REFERENCE", `about_record ${quoted(l.get("about_record"))} does not resolve`);
    }
    let evidence = null;
    if (kind === "observe") {
      const docId = l.get("doc_id");
      const doc = this.current.get(docId);
      if (doc === void 0) return fail("UNKNOWN_DOCUMENT", `document ${quoted(docId)} is not among the current documents`);
      const q = utf8(l.get("exact_quote"));
      const found = occurrences(doc.bytes, q, 2);
      let fallback;
      if (found.length !== 1 && this.rewrite?.originalEvidence !== void 0) fallback = this.rewrite.originalEvidence.get(g.accepted[j]);
      if (fallback !== void 0) {
        evidence = fallback;
      } else {
        if (found.length === 0) return fail("QUOTE_NOT_IN_SOURCE", `the quote has no occurrence in the current bytes of ${quoted(docId)}`);
        if (found.length > 1) return fail("QUOTE_AMBIGUOUS", `the quote occurs more than once in ${quoted(docId)}`);
        const start = found[0];
        const end = start + q.length;
        if (!inScope(scope, docId, start, end, doc.bytes.length)) return fail("QUOTE_OUTSIDE_SCOPE", `the quote [${start}, ${end}) of ${quoted(docId)} is outside the scope of the task`);
        const chunks = await this.chunksOf(doc);
        let bytes;
        try {
          bytes = await anchorBytes(this.adapter, docId, q, segmentsOf(chunks, start, end));
        } catch (e) {
          if (e instanceof AnchorEncodingError) return fail("RECORD_ID_MISMATCH", `the evidence anchor cannot be written: ${e.message}`);
          throw e;
        }
        evidence = /* @__PURE__ */ new Map([
          ["id", toHex(await this.adapter.sha256(bytes))],
          ["span", [start, end]],
          ["version", toHex(chunks.version)]
        ]);
      }
    }
    const body = /* @__PURE__ */ new Map();
    for (const [k, v] of l) if (k !== "local_id") body.set(k, v);
    const at = (r) => "@" + r.id;
    if (Array.isArray(l.get("based_on")) && l.get("based_on").length > 0 && kind !== "done") body.set("based_on", supports.map(at));
    if (kind === "relation") {
      body.set("from", at(from));
      body.set("to", at(to));
    }
    if (kind === "done") body.set("answer_ids", supports.map(at));
    if (about !== null) body.set("about_record", at(about));
    if (evidence !== null) {
      body.set("evidence_id", evidence.get("id"));
      body.set("document_version", evidence.get("version"));
    }
    const ordinalKey = jcs([g.actor, directive]);
    const ordinal = (this.ordinals.get(ordinalKey) ?? 0) + 1;
    const id = toHex(await this.adapter.sha256(utf8(jcs(["r2r.audit.record.v1", g.actor, directive, ordinal, body]))));
    const named = g.accepted[j];
    if (id !== named) {
      if (this.rewrite === null) return fail("RECORD_ID_MISMATCH", "the record id computed from the line is not the id in the outcome");
      g.accepted[j] = id;
    }
    this.ordinals.set(ordinalKey, ordinal);
    const record = { id, kind, evidence, originalId: named };
    this.records.push(record);
    this.byId.set(id, record);
    this.byName.set(jcs([g.actor, directive, l.get("local_id")]), record);
    if (kind === "observe") this.quotes++;
    if (this.cascade !== null) {
      const opt = (k) => l.has(k) ? l.get(k) : null;
      await this.cascade.addRecord({
        id,
        kind,
        actor: g.actor,
        frame: this.position,
        grounds: supports.map((r) => r.id),
        ends: kind === "relation" ? { from: from.id, rel: l.get("rel"), to: to.id } : null,
        text: opt("text"),
        subject: kind === "claim" ? opt("subject") : null,
        object: kind === "claim" ? opt("object") : null,
        about: about === null ? null : about.id,
        obs: kind === "observe" && evidence !== null ? {
          docId: l.get("doc_id"),
          quote: l.get("exact_quote"),
          quoteBytes: utf8(l.get("exact_quote")),
          anchor: evidence.get("id"),
          version: evidence.get("version"),
          start: evidence.get("span")[0],
          end: evidence.get("span")[1]
        } : null
      });
    }
    const L = recordValue(record, this.records.length, g.actor, directive, l, body, supports, from, to);
    const leaf = await domainHash(this.adapter, DOMAIN.recordLeaf, utf8(jcs(L)));
    leaves.push(leaf);
    this.lastFrameLeaves.push({ L, leaf });
    return null;
  }
  /** P3-7: a reference by local name, else by "@" and 16 to 64 hex digits. */
  resolve(actor, directive, name, rewriteRef) {
    const byName = this.byName.get(jcs([actor, directive, name]));
    if (byName !== void 0) return byName;
    const r = uniqueByPrefix(this.records, (x) => x.id, name);
    if (r !== null || this.rewrite === null) return r;
    const old = uniqueByPrefix(this.records, (x) => x.originalId, name);
    if (old !== null) rewriteRef("@" + old.id);
    return old;
  }
};
function uniqueByPrefix(items, id, name) {
  if (!/^@[0-9a-fA-F]{16,64}$/.test(name)) return null;
  const prefix = name.slice(1).toLowerCase();
  let found = null;
  for (const item of items) {
    if (id(item).startsWith(prefix)) {
      if (found !== null) return null;
      found = item;
    }
  }
  return found;
}
function quoted(s) {
  return JSON.stringify(s.length > 80 ? s.slice(0, 80) + "..." : s);
}
function isScope(v) {
  if (!isObject(v)) return false;
  const docs = v.get("docs");
  const ranges = v.get("ranges");
  return Array.isArray(docs) && docs.every((d) => typeof d === "string") && Array.isArray(ranges) && ranges.every((r) => Array.isArray(r) && r.length === 3 && typeof r[0] === "string" && typeof r[1] === "number" && typeof r[2] === "number");
}
function inScope(scope, docId, start, end, length) {
  const docs = scope.get("docs");
  if (!docs.includes(docId)) return false;
  const ranges = scope.get("ranges");
  if (ranges.length === 0) return true;
  return ranges.some(([d, a, z]) => d === docId && a <= start && end <= z && a < z && z <= length);
}
function lineFormProblem(line, rules4 = false) {
  if (!isObject(line)) return "the line is not an object";
  const kind = line.get("kind");
  if (typeof kind !== "string" || !Object.hasOwn(LINE_KEYS, kind)) return "kind is not one of the six kinds";
  const allowed = rules4 && kind === "question" ? QUESTION_KEYS_RULES_4 : LINE_KEYS[kind];
  for (const k of line.keys()) if (!allowed.includes(k)) return `key ${JSON.stringify(k)} is not allowed for ${kind}`;
  if (typeof line.get("local_id") !== "string") return "local_id is not a string";
  for (const k of STRING_FIELDS) if (line.has(k) && typeof line.get(k) !== "string") return `${k} is not a string`;
  for (const k of STRING_ARRAY_FIELDS) {
    if (!line.has(k)) continue;
    const v = line.get(k);
    if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) return `${k} is not an array of strings`;
  }
  for (const k of LINE_REQUIRED[kind]) if (!line.has(k)) return `${kind} needs ${k}`;
  const quote = line.get("exact_quote");
  if (typeof quote === "string" && utf8(quote).length > MAX_QUOTE_BYTES) return `exact_quote is longer than ${MAX_QUOTE_BYTES} bytes`;
  return null;
}
function termsOf(kind, line) {
  const raw = [];
  if (kind === "observe") raw.push(...line.get("terms") ?? []);
  else if (kind === "claim") {
    raw.push(line.get("subject"));
    if (line.has("object")) raw.push(line.get("object"));
  } else if (kind === "hypothesis") {
    if (line.has("subject")) raw.push(line.get("subject"));
  } else if (kind === "question") raw.push(...line.get("about"));
  return raw.filter((t, k) => raw.indexOf(t) === k);
}
function recordValue(record, seq, actor, directive, line, body, supports, from, to) {
  const kind = record.kind;
  const str = (k) => line.has(k) ? line.get(k) : null;
  let text = null;
  if (kind === "claim" || kind === "hypothesis" || kind === "question") text = line.get("text");
  else if (kind === "done") text = str("text");
  let stance = null;
  if (kind === "claim") stance = line.get("stance");
  else if (kind === "hypothesis") stance = str("stance");
  const L = /* @__PURE__ */ new Map([
    ["id", record.id],
    ["seq", seq],
    ["kind", kind],
    ["author", actor],
    ["directive", directive],
    ["doc_id", kind === "observe" ? line.get("doc_id") : null],
    ["quote", kind === "observe" ? line.get("exact_quote") : null],
    ["terms", termsOf(kind, line)],
    ["text", text],
    ["stance", stance],
    ["based_on", supports.map((s) => s.id)],
    ["ends", kind === "relation" ? [from.id, line.get("rel"), to.id] : null],
    ["body", body]
  ]);
  if (record.evidence !== null) L.set("evidence", record.evidence);
  if (supports.length > 0) {
    L.set(
      "grounds",
      supports.map((s) => {
        const g = /* @__PURE__ */ new Map([["id", s.id]]);
        if (s.kind === "observe" && s.evidence !== null) g.set("evidence", s.evidence);
        return g;
      })
    );
  }
  return L;
}

// src/verify.ts
var JOURNAL_FORMAT = "sbgk-session-log/3";
var SEAL_FORMAT_ID = "r2r-seal/2";
var ZERO_HASH = "0".repeat(64);
var DEFAULT_MAX_LINE_BYTES = 64 * 1024 * 1024 - 1;
var DEFAULT_MAX_DEPTH = 64;
var OUTER_KEYS = ["body", "hash", "header"];
var HEADER_KEYS = ["body_hash", "format", "previous", "records_root", "seq", "wal_op"];
async function indexDocuments(files, adapter) {
  const map = /* @__PURE__ */ new Map();
  for (const f of files) map.set(toHex(await adapter.sha256(f)), f);
  return map;
}
var ReadError = class extends Error {
};
async function verifyJournal(source, options, adapter) {
  return (await verifyJournalDetailed(source, options, adapter)).report;
}
async function verifyJournalDetailed(source, options, adapter) {
  const maxLineBytes = options.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES;
  const fileHash = adapter.createSha256();
  const files = options.documents === void 0 ? null : await indexDocuments(options.documents, adapter);
  const v = new FrameVerifier(adapter, options, files);
  let bytes = 0;
  let lines = 0;
  let pending = [];
  let pendingLen = 0;
  const iterator = toAsyncIterator(source);
  for (; ; ) {
    let next;
    try {
      next = await iterator.next();
    } catch (e) {
      throw new ReadError(e instanceof Error ? e.message : String(e));
    }
    if (next.done === true) break;
    const chunk = next.value;
    fileHash.update(chunk);
    bytes += chunk.length;
    let start = 0;
    for (; ; ) {
      const lf = chunk.indexOf(10, start);
      if (lf < 0) break;
      lines++;
      if (!v.j0Stopped) {
        const piece = chunk.subarray(start, lf);
        if (pendingLen + piece.length > maxLineBytes) v.lineTooLong(maxLineBytes);
        else await v.line(pending.length === 0 ? piece : concatBytes([...pending, piece]));
      }
      pending = [];
      pendingLen = 0;
      start = lf + 1;
    }
    if (start < chunk.length) {
      pendingLen += chunk.length - start;
      if (!v.j0Stopped) {
        if (pendingLen > maxLineBytes) {
          v.lineTooLong(maxLineBytes);
          pending = [];
        } else pending.push(chunk.slice(start));
      }
    }
  }
  if (!v.j0Stopped) {
    if (bytes === 0) v.failJ0(null, "EMPTY_JOURNAL", "the file has 0 bytes");
    else if (pendingLen > 0) {
      v.failJ0(v.position, "TORN_TAIL", `${pendingLen} bytes after the last LF are not a frame`);
    }
  }
  const report = v.finish(toHex(await fileHash.digest()), bytes, lines, options.documents === void 0 ? null : options.documents.length);
  return { report, cascade: report.levels.J4a.result === "NOT_RUN" ? null : v.cascade };
}
function toAsyncIterator(source) {
  const s = source;
  if (typeof s[Symbol.asyncIterator] === "function") return s[Symbol.asyncIterator]();
  if (typeof s[Symbol.iterator] === "function") return s[Symbol.iterator]();
  if (typeof s.getReader === "function") {
    const reader = s.getReader();
    return {
      async next() {
        const r = await reader.read();
        return r.done ? { done: true, value: void 0 } : { done: false, value: r.value };
      }
    };
  }
  throw new TypeError("the journal source is not iterable");
}
var FrameVerifier = class {
  constructor(adapter, options, files) {
    this.adapter = adapter;
    this.options = options;
    this.maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
    this.tree = new LogTree(adapter);
    this.j2 = new J2Checker(adapter);
    this.j3 = files === null ? null : new RecordEngine(adapter, files, null, true);
    this.quittances = (options.quittances ?? []).map((q) => parseQuittance(q.file, q.bytes));
  }
  adapter;
  options;
  decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  maxDepth;
  // J0 state
  i = 0;
  prevHash = null;
  j0Failure = null;
  format = null;
  // J1 state
  j1Failure = null;
  tree;
  prevBodyAuditRoot = void 0;
  prevBodyEngineRoot = void 0;
  prevWasSeal = false;
  seals = [];
  genesisRunId = null;
  lastSealPos = -1;
  closedAt = -1;
  lastIsClose = false;
  // J2 state
  j2Failure = null;
  j2;
  // J3 state (only with --docs)
  j3Failure = null;
  j3NotSupplied = null;
  j3;
  // J4a state (with --docs)
  j4aFailure = null;
  sealsCompared = 0;
  lastCompared = null;
  quittances;
  /** The seals the quittances name: the header and body of the frame, and the rows J4a computed there. */
  quittanceSeals = /* @__PURE__ */ new Map();
  get cascade() {
    return this.j3?.cascade ?? null;
  }
  get j0Stopped() {
    return this.j0Failure !== null;
  }
  get position() {
    return this.i;
  }
  failJ0(frame, code, detail) {
    this.j0Failure ??= { level: "J0", frame, code, detail };
  }
  lineTooLong(max) {
    this.failJ0(this.i, "LIMIT_EXCEEDED", `line longer than ${max} bytes`);
  }
  failJ1(frame, code, detail) {
    this.j1Failure ??= { level: "J1", frame, code, detail };
  }
  /** One complete line (without its LF) at position this.i. */
  async line(bytes) {
    const i = this.i;
    const fail = (code, detail) => this.failJ0(i, code, detail);
    if (depthExceeds(bytes, this.maxDepth)) return fail("LIMIT_EXCEEDED", `nesting deeper than ${this.maxDepth}`);
    let text;
    try {
      text = this.decoder.decode(bytes);
    } catch {
      return fail("INVALID_UTF8", "the line is not valid UTF-8");
    }
    const parsed = parseJson(text);
    if (!parsed.ok) return fail("INVALID_JSON", parsed.error);
    const frame = parsed.value;
    if (!isObject(frame)) return fail("INVALID_JSON", "the line is not a JSON object");
    if (parsed.badNumber) return fail("BAD_NUMBER", "a number that is not an integer from 0 to 2^53-1 in plain digits");
    const canonical = jcs(frame);
    if (canonical !== text) {
      return fail("NOT_CANONICAL", `the line differs from its canonical form at character ${firstDifference(canonical, text)}`);
    }
    const header = frame.get("header");
    if (isObject(header)) {
      const fmt = header.get("format");
      if (i === 0 && typeof fmt === "string") this.format = fmt;
      if (typeof fmt === "string" && fmt !== JOURNAL_FORMAT) {
        return i === 0 ? fail("UNSUPPORTED_FORMAT", `header.format is ${quoted2(fmt)}`) : fail("MIXED_FORMAT", `header.format is ${quoted2(fmt)}, frame 0 is ${quoted2(this.format)}`);
      }
    }
    if (!hasExactKeys(frame, OUTER_KEYS)) return fail("OUTER_KEYS", "the frame must have exactly the keys body, hash, header");
    if (!isObject(header) || !hasExactKeys(header, HEADER_KEYS)) {
      return fail("HEADER_KEYS", "header must be an object with exactly the keys body_hash, format, previous, records_root, seq, wal_op");
    }
    const hash = frame.get("hash");
    const body = frame.get("body");
    const seq = header.get("seq");
    const walOp = header.get("wal_op");
    const previous = header.get("previous");
    const bodyHash = header.get("body_hash");
    if (!isHashText(hash)) return fail("BAD_TYPE", "hash is not 64 lowercase hex characters");
    for (const k of ["body_hash", "previous", "records_root"]) {
      if (!isHashText(header.get(k))) return fail("BAD_TYPE", `header.${k} is not 64 lowercase hex characters`);
    }
    if (typeof seq !== "number") return fail("BAD_TYPE", "header.seq is not a number");
    if (typeof header.get("format") !== "string") return fail("BAD_TYPE", "header.format is not a string");
    if (typeof walOp !== "string") return fail("BAD_TYPE", "header.wal_op is not a string");
    if (!isObject(body)) return fail("BAD_TYPE", "body is not an object");
    if (seq !== i) return fail("SEQ_MISMATCH", `header.seq is ${seq}, expected ${i}`);
    const expectedOp = i === 0 ? "genesis" : "audit";
    if (walOp !== expectedOp) return fail("WAL_OP_MISMATCH", `header.wal_op is ${quoted2(walOp)}, expected "${expectedOp}"`);
    const expectedPrevious = i === 0 ? ZERO_HASH : this.prevHash;
    if (previous !== expectedPrevious) {
      return fail(
        "PREVIOUS_MISMATCH",
        i === 0 ? "header.previous of frame 0 is not 64 zeros" : `header.previous is not the hash of frame ${i - 1}`
      );
    }
    const computedBodyHash = toHex(await domainHash(this.adapter, DOMAIN.frameBody, utf8(jcs(body))));
    if (bodyHash !== computedBodyHash) return fail("BODY_HASH_MISMATCH", `header.body_hash is not H("${DOMAIN.frameBody}", JCS(body))`);
    const computedHash = toHex(await domainHash(this.adapter, DOMAIN.frameHeader, utf8(jcs(header))));
    if (hash !== computedHash) return fail("FRAME_HASH_MISMATCH", `hash is not H("${DOMAIN.frameHeader}", JCS(header))`);
    if (this.j1Failure === null) await this.j1Frame(i, body, hash, this.prevHash);
    if (this.j1Failure === null && this.j2Failure === null) {
      const f = i === 0 ? await this.j2.frame0(header, body) : await this.j2.frame(body);
      if (f !== null) this.j2Failure = { level: "J2", frame: i, code: f.code, detail: f.detail };
    }
    if (this.j3 !== null && this.j1Failure === null && this.j2Failure === null && this.j3Failure === null && this.j3NotSupplied === null) {
      const r = i === 0 ? await this.j3.genesis(body) : await this.j3.frame(header, body, i);
      if (r !== null && "notSupplied" in r) this.j3NotSupplied = r.notSupplied;
      else if (r !== null) this.j3Failure = { level: "J3", frame: i, code: r.code, detail: r.detail };
      else if (this.lastSealPos === i) await this.j4aSeal(i, header, body);
    }
    this.prevHash = hash;
    this.i++;
  }
  // -------------------------------------------------------------------------
  // J1
  // -------------------------------------------------------------------------
  /** Level J1 for the frame at position i, in the order of SPEC 6.2. */
  async j1Frame(i, body, hash, prevHash) {
    if (i === 0) {
      const runId = body.get("run_id");
      this.genesisRunId = typeof runId === "string" ? runId : null;
    }
    if (this.closedAt >= 0) {
      return this.failJ1(i, "FRAME_AFTER_CLOSE", `a frame after the close frame at position ${this.closedAt}`);
    }
    const actor = body.get("actor");
    const command = body.get("command");
    const isKernel = actor === "kernel";
    const kindValue = isObject(command) ? command.get("kind") : void 0;
    const kind = typeof kindValue === "string" ? kindValue : void 0;
    if ((kind === "seal" || kind === "close") && !isKernel) {
      return this.failJ1(
        i,
        "KERNEL_COMMAND_NOT_FROM_KERNEL",
        `a ${kind} command from the actor ${typeof actor === "string" ? quoted2(actor) : "(missing or not a string)"}`
      );
    }
    let isSeal = false;
    if (isKernel && kind === "seal") {
      if (!await this.checkSeal(i, body, command, prevHash)) return;
      isSeal = true;
    }
    let isClose = false;
    if (isKernel) {
      const sid = body.get("submission_id");
      if (typeof sid === "string" && sid.startsWith("seal-") && !isSeal) {
        return this.failJ1(i, "KERNEL_ID_MISUSE", `a kernel frame takes the id ${quoted2(sid)} but is not a seal`);
      }
      isClose = kind === "close";
      if (isClose && command.size !== 1) {
        return this.failJ1(i, "KERNEL_ID_MISUSE", 'the close frame has a command other than {"kind":"close"}');
      }
      if (isClose !== (sid === "audit-close")) {
        return this.failJ1(
          i,
          "KERNEL_ID_MISUSE",
          isClose ? 'the close frame has a submission_id other than "audit-close"' : 'submission_id "audit-close" on a frame that is not the close frame'
        );
      }
      if (isClose) {
        if (!this.prevWasSeal) return this.failJ1(i, "CLOSE_WITHOUT_SEAL", `the close frame is not preceded by a seal at position ${i - 1}`);
        this.closedAt = i;
      }
    }
    this.prevWasSeal = isSeal;
    this.lastIsClose = isClose;
    this.prevBodyAuditRoot = body.get("audit_root");
    this.prevBodyEngineRoot = body.get("engine_root");
    await this.tree.push(fromHex(hash));
  }
  /** SPEC 6.3, J1-1 ... J1-9. Returns false after recording a failure. */
  async checkSeal(i, body, command, prevHash) {
    const fail = (code, detail) => {
      this.failJ1(i, code, detail);
      return false;
    };
    const form = (detail) => fail("SEAL_FORM", detail);
    const outcome = body.get("outcome");
    const problem = sealFormProblem(command, outcome);
    if (problem !== null) return form(problem);
    const result = outcome.get("result");
    const seal = command.get("seal");
    const sealHash = result.get("seal_hash");
    const sealJcs = jcs(seal);
    if (jcs(result.get("seal")) !== sealJcs) return form("outcome.result.seal differs from command.seal");
    if (seal.get("format") !== SEAL_FORMAT_ID) return fail("SEAL_FORMAT", `seal.format is not "${SEAL_FORMAT_ID}"`);
    if (i < 1 || seal.get("log_size") !== i || body.get("submission_id") !== `seal-${i}`) {
      return fail("SEAL_LOG_SIZE", `a seal at position ${i} must have log_size ${i} and submission_id "seal-${i}"`);
    }
    if (seal.get("wal_head") !== prevHash) return fail("SEAL_WAL_HEAD", `seal.wal_head is not the hash of frame ${i - 1}`);
    const root = await this.tree.root();
    if (root === null || seal.get("log_root") !== toHex(root)) {
      return fail("SEAL_LOG_ROOT", `seal.log_root is not the log root over frames 0..${i - 1}`);
    }
    if (seal.get("audit_root") !== this.prevBodyAuditRoot || seal.get("engine_root") !== this.prevBodyEngineRoot) {
      return fail("SEAL_ROOT_CONTINUITY", `seal.audit_root and seal.engine_root must equal those of the body of frame ${i - 1}`);
    }
    const computed = toHex(await domainHash(this.adapter, DOMAIN.seal, utf8(sealJcs)));
    if (sealHash !== computed) return fail("SEAL_HASH_MISMATCH", `outcome.result.seal_hash is not H("${DOMAIN.seal}", JCS(seal))`);
    if (this.genesisRunId === null) return fail("SEAL_RUN_ID", "the body of frame 0 has no string run_id");
    if (seal.get("run_id") !== this.genesisRunId) return fail("SEAL_RUN_ID", "seal.run_id differs from body.run_id of frame 0");
    this.seals.push({ n: i, seal_hash: computed });
    this.lastSealPos = i;
    return true;
  }
  // -------------------------------------------------------------------------
  // J4a
  // -------------------------------------------------------------------------
  /** Amendment 6, P6-1: the projections over the state after frames 0 ... n-1, compared with the seal at n. */
  async j4aSeal(n, header, body) {
    const cascade = this.j3.cascade;
    if (this.j4aFailure !== null && this.options.onProjections === void 0) return;
    const st = await cascade.status();
    const projections = body.get("command").get("seal").get("projections");
    const statusOk = st.status === projections.get("status");
    const dependenciesOk = st.dependencies === projections.get("dependencies");
    this.options.onProjections?.({
      seal_position: n,
      status_hash: st.status,
      dependencies_hash: st.dependencies,
      status_rows: st.rows,
      dependency_pairs: st.pairs,
      equals_seal: statusOk && dependenciesOk
    });
    if (this.j4aFailure !== null) return;
    this.sealsCompared++;
    this.lastCompared = n;
    if (!statusOk) {
      this.j4aFailure = {
        level: "J4a",
        frame: n,
        code: "PROJECTION_STATUS_MISMATCH",
        detail: `the status projection computed over frames 0..${n - 1} is ${st.status}, the seal names ${String(projections.get("status"))}`
      };
      return;
    }
    if (!dependenciesOk) {
      this.j4aFailure = {
        level: "J4a",
        frame: n,
        code: "PROJECTION_DEPENDENCIES_MISMATCH",
        detail: `the dependency projection computed over frames 0..${n - 1} is ${st.dependencies}, the seal names ${String(projections.get("dependencies"))}`
      };
      return;
    }
    if (this.quittances.some((q) => q.n === n)) this.quittanceSeals.set(n, { header: jcs(header), body: jcs(body), rows: st.rows });
    await this.options.onSeal?.(n, st, cascade);
  }
  /** Amendment 6, P6-11: every quittance, in the order given, after the last frame. */
  checkQuittances(j4aRan) {
    const out = [];
    for (const q of this.quittances) {
      if (!j4aRan) {
        out.push({ file: q.file, verdict: "NOT_RUN", code: null });
        continue;
      }
      let failure;
      if (q.problem !== null || q.n === null) failure = checkQuittance(q, void 0);
      else {
        const f = this.j4aFailure;
        if (f !== null && f.frame !== null && q.n >= f.frame) {
          out.push({ file: q.file, verdict: "NOT_RUN", code: null });
          continue;
        }
        failure = checkQuittance(q, this.quittanceSeals.get(q.n));
      }
      out.push({ file: q.file, verdict: failure === null ? "PASS" : "FAIL", code: failure === null ? null : failure.code });
      if (failure !== null) this.j4aFailure ??= { level: "J4a", frame: null, code: failure.code, detail: `${q.file}: ${failure.detail}` };
    }
    return out;
  }
  /** Amendment 6, P6-1: the reach of the cascade check. */
  reach(n) {
    if (this.lastCompared === null) return { seals_checked: 0, checked_through_frame: null, unchecked_frames: n - 1 };
    const after = n - 1 - this.lastCompared;
    const close = this.closedAt === this.lastCompared + 1 ? 1 : 0;
    return { seals_checked: this.sealsCompared, checked_through_frame: this.lastCompared, unchecked_frames: after - close };
  }
  // -------------------------------------------------------------------------
  // End of file
  // -------------------------------------------------------------------------
  finish(journalSha256, bytes, lines, documentFiles) {
    const n = this.i;
    const { expectSeal, expectHead } = this.options;
    if (this.j0Failure === null && expectHead !== void 0 && expectHead !== this.prevHash) {
      this.failJ0(null, "HEAD_MISMATCH", "the journal head differs from --expect-head");
    }
    const j0Pass = this.j0Failure === null;
    let anchorSeal;
    if (j0Pass && this.j1Failure === null && expectSeal !== void 0) {
      anchorSeal = this.seals.find((s) => s.seal_hash === expectSeal);
      if (anchorSeal === void 0) this.failJ1(null, "ANCHOR_NOT_FOUND", "no seal of this journal has the --expect-seal hash");
    }
    const j1Pass = j0Pass && this.j1Failure === null;
    let j1;
    let tail = null;
    if (!j0Pass) j1 = { result: "NOT_CHECKABLE", reason: "J0 failed" };
    else if (!j1Pass) j1 = { result: "FAIL" };
    else {
      tail = this.tail(n);
      j1 = { result: "PASS", seals: this.seals, tail };
    }
    let seal = { given: false, matched: null };
    if (expectSeal !== void 0) {
      if (anchorSeal !== void 0 && j1Pass) {
        seal = { given: true, matched: true, at_n: anchorSeal.n, frames_after: n - 1 - anchorSeal.n };
      } else seal = { given: true, matched: this.j1Failure?.code === "ANCHOR_NOT_FOUND" ? false : null };
    }
    let head = { given: false, matched: null };
    if (expectHead !== void 0) {
      head = { given: true, matched: j0Pass ? true : this.j0Failure?.code === "HEAD_MISMATCH" ? false : null };
    }
    const anchor = { seal, head };
    const j2Pass = j1Pass && this.j2Failure === null;
    let j2;
    if (!j0Pass) j2 = { result: "NOT_CHECKABLE", reason: "J0 failed" };
    else if (!j1Pass) j2 = { result: "NOT_CHECKABLE", reason: "J1 failed" };
    else if (!j2Pass) j2 = { result: "FAIL" };
    else j2 = { result: "PASS", documents: this.j2.genesis.documents, settings_hash: this.j2.genesis.settingsHash };
    let j3;
    if (this.j3 === null) j3 = { result: "NOT_CHECKED" };
    else if (!j0Pass) j3 = { result: "NOT_CHECKABLE", reason: "J0 failed" };
    else if (!j1Pass) j3 = { result: "NOT_CHECKABLE", reason: "J1 failed" };
    else if (!j2Pass) j3 = { result: "NOT_CHECKABLE", reason: "J2 failed" };
    else if (this.j3Failure !== null) j3 = { result: "FAIL" };
    else if (this.j3NotSupplied !== null) j3 = { result: "NOT_CHECKABLE", reason: `document ${this.j3NotSupplied} not supplied` };
    else j3 = { result: "PASS", records: this.j3.recordCount, quotes: this.j3.quotes };
    const j3Pass = j3.result === "PASS";
    let j4a;
    let cascade = null;
    const quittances = this.checkQuittances(j3Pass);
    if (!j3Pass) j4a = { result: "NOT_RUN", reason: j3.result === "NOT_CHECKED" ? "J3 not run" : j3.result === "FAIL" ? "J3 failed" : "J3 not checkable" };
    else {
      j4a = { result: this.j4aFailure === null ? "PASS" : "FAIL" };
      cascade = this.reach(n);
    }
    let notVerified;
    if (!j3Pass) notVerified = [...NOT_VERIFIED];
    else if (j4a.result !== "PASS" || cascade.checked_through_frame === null) notVerified = [...NOT_VERIFIED_AFTER_J3];
    else if (cascade.unchecked_frames > 0) notVerified = ["withdrawal_cascade_after_last_seal", "signatures"];
    else notVerified = ["signatures"];
    if (this.quittances.length > 0) notVerified.splice(notVerified.indexOf("signatures"), 0, "quittance_inclusion");
    const j0Result = j0Pass ? "PASS" : "FAIL";
    const results = [j0Result, j1.result, j2.result, j3.result, j4a.result];
    const verdict = results.includes("FAIL") ? "FAIL" : this.j3NotSupplied !== null && j3.result === "NOT_CHECKABLE" ? "INCOMPLETE" : "PASS";
    return {
      verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION, spec: SPEC_ID },
      input: {
        journal_sha256: journalSha256,
        bytes,
        frames: lines,
        format: this.format,
        sources: documentFiles === null ? { given: false } : { given: true, files: documentFiles }
      },
      levels: {
        J0: { result: j0Result },
        J1: j1,
        J2: j2,
        J3: j3,
        J4a: j4a,
        J5: { result: "NOT_CHECKED" }
      },
      cascade,
      quittances,
      anchor,
      computed: {
        wal_head: j0Pass ? this.prevHash : null,
        closed: tail === null ? null : tail.kind === "closed"
      },
      not_verified: notVerified,
      verdict,
      first_failure: this.j0Failure ?? this.j1Failure ?? (j1Pass ? this.j2Failure : null) ?? (j2Pass ? this.j3Failure : null) ?? (j3Pass ? this.j4aFailure : null)
    };
  }
  /** SPEC 6.5: the tail after the last seal. */
  tail(n) {
    if (this.lastSealPos < 0) return { kind: "no_seals" };
    const k = n - 1 - this.lastSealPos;
    if (k === 0) return { kind: "sealed", frames_after_last_seal: 0 };
    if (k === 1 && this.lastIsClose) return { kind: "closed", frames_after_last_seal: 1 };
    return { kind: "unsealed", frames_after_last_seal: k };
  }
};
function quoted2(v) {
  if (v === null) return "null";
  return JSON.stringify(v.length > 80 ? v.slice(0, 80) + "..." : v);
}
function firstDifference(a, b) {
  const m = Math.min(a.length, b.length);
  for (let k = 0; k < m; k++) if (a.charCodeAt(k) !== b.charCodeAt(k)) return k;
  return m;
}

// src/cut.ts
var CUT_FORMAT = "yuce-cut/1";
var CUT_REPORT_FORMAT = "yuce-cut-report/1";
var EXPORT_FORMAT = "yuce-export/1";
var CUT_DOMAIN = "YUCE-CUT/1";
var CUT_NOT_VERIFIED = ["meaning", "undeclared_dependencies", "signatures"];
var NAME = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,64}$/;
var MANIFEST_KEYS = ["deliveries", "exports", "format", "journals", "mode", "previous_cut"];
var JOURNAL_KEYS = ["closed", "log_size", "name", "rules_version", "run_id", "seal_hash", "wal_head"];
var EXPORT_KEYS = ["journal", "name", "records", "seal_hash", "sha256"];
var DELIVERY_KEYS = ["doc_id", "export", "frame", "journal"];
async function cutHash(adapter, manifest) {
  return toHex(await domainHash(adapter, CUT_DOMAIN, utf8(jcs(manifest))));
}
function exportEscape(s) {
  return s.replaceAll("\\", "\\\\").replaceAll("\n", "\\n").replaceAll("\r", "\\r");
}
function exportParagraph(claim, recordOf) {
  const grounds = [...new Set(claim.grounds)].map((id) => recordOf(id));
  const rests = grounds.filter((g) => g !== void 0 && g.kind === "claim").map((g) => g.id);
  const quotes = grounds.filter((g) => g !== void 0 && g.obs !== null).map((g) => `[${exportEscape(g.obs.docId)}] "${exportEscape(g.obs.quote)}"`);
  let p = `Record ${claim.id}: ${exportEscape(claim.text ?? "")}`;
  if (rests.length > 0) p += ` Rests on: ${rests.join(", ")}`;
  if (quotes.length > 0) p += ` Quotes: ${quotes.join(" ; ")}`;
  return p;
}
function exportText(runId, sealHash, paragraphs) {
  let t = `${EXPORT_FORMAT} run=${exportEscape(runId)} seal=${sealHash} records=${paragraphs.length}
`;
  for (const p of paragraphs) t += `
${p}
`;
  return t;
}
var PARAGRAPH = /^Record ([0-9a-f]{64}): /;
function exportParagraphs(bytes) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  const out = [];
  const firstLf = text.indexOf("\n");
  if (firstLf < 0) return null;
  let offset = utf8(text.slice(0, firstLf + 1)).length;
  const rest = text.slice(firstLf + 1);
  const lines = rest.split("\n");
  for (let k = 0; k < lines.length; k++) {
    const line = lines[k];
    const len = utf8(line).length;
    if (line !== "") {
      const m = PARAGRAPH.exec(line);
      out.push({ record: m === null ? null : m[1], start: offset, end: offset + len });
    }
    offset += len + 1;
  }
  return out;
}
function parseManifest(bytes) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
  const p = parseJson(text);
  return p.ok ? { value: p.value, badNumber: p.badNumber, duplicateKey: p.duplicateKey } : null;
}
var isInt = (v) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
function checkManifest(m) {
  if (!isObject(m) || !hasExactKeys(m, MANIFEST_KEYS)) return null;
  if (m.get("format") !== CUT_FORMAT || m.get("mode") !== "observe") return null;
  const prev = m.get("previous_cut");
  if (prev !== null && !isHashText(prev)) return null;
  const js = m.get("journals");
  const es = m.get("exports");
  const ds = m.get("deliveries");
  if (!Array.isArray(js) || !Array.isArray(es) || !Array.isArray(ds)) return null;
  const journals = [];
  for (const j of js) {
    if (!isObject(j) || !hasExactKeys(j, JOURNAL_KEYS)) return null;
    const name = j.get("name");
    const runId = j.get("run_id");
    const rules = j.get("rules_version");
    const seal = j.get("seal_hash");
    const size = j.get("log_size");
    const head = j.get("wal_head");
    const closed = j.get("closed");
    if (typeof name !== "string" || !NAME.test(name) || typeof runId !== "string" || typeof rules !== "string") return null;
    if (!isHashText(seal) || !isInt(size) || !isHashText(head) || typeof closed !== "boolean") return null;
    journals.push({ name, run_id: runId, rules_version: rules, seal_hash: seal, log_size: size, wal_head: head, closed });
  }
  const exports = [];
  for (const e of es) {
    if (!isObject(e) || !hasExactKeys(e, EXPORT_KEYS)) return null;
    const name = e.get("name");
    const journal = e.get("journal");
    const seal = e.get("seal_hash");
    const sha = e.get("sha256");
    const records = e.get("records");
    if (typeof name !== "string" || !NAME.test(name) || typeof journal !== "string" || !NAME.test(journal)) return null;
    if (!isHashText(seal) || !isHashText(sha) || !isInt(records)) return null;
    exports.push({ name, journal, seal_hash: seal, sha256: sha, records });
  }
  const deliveries = [];
  for (const d of ds) {
    if (!isObject(d) || !hasExactKeys(d, DELIVERY_KEYS)) return null;
    const exp = d.get("export");
    const journal = d.get("journal");
    const docId = d.get("doc_id");
    const frame = d.get("frame");
    if (typeof exp !== "string" || !NAME.test(exp) || typeof journal !== "string" || !NAME.test(journal)) return null;
    if (typeof docId !== "string" || !isInt(frame)) return null;
    deliveries.push({ export: exp, journal, doc_id: docId, frame });
  }
  for (let k = 1; k < journals.length; k++) if (cmp(journals[k - 1].name, journals[k].name) >= 0) return null;
  for (let k = 1; k < exports.length; k++) if (cmp(exports[k - 1].name, exports[k].name) >= 0) return null;
  const deliveryOrder = (a, b) => cmp(a.journal, b.journal) || a.frame - b.frame || cmp(a.doc_id, b.doc_id);
  for (let k = 1; k < deliveries.length; k++) if (deliveryOrder(deliveries[k - 1], deliveries[k]) > 0) return null;
  const seen = /* @__PURE__ */ new Set();
  for (const d of deliveries) {
    const key = d.frame === 0 ? jcs([d.journal, 0, d.doc_id]) : jcs([d.journal, d.frame]);
    if (seen.has(key)) return null;
    seen.add(key);
  }
  const journalNames = new Set(journals.map((j) => j.name));
  const exportNames = new Set(exports.map((e) => e.name));
  if (!exports.every((e) => journalNames.has(e.journal))) return null;
  if (!deliveries.every((d) => journalNames.has(d.journal) && exportNames.has(d.export))) return null;
  return { journals, exports, deliveries };
}
function journalPart(file, n, closed) {
  const want = n + 1 + (closed ? 1 : 0);
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const frames = [];
  let start = 0;
  let end = file.length;
  while (frames.length < want) {
    const lf = file.indexOf(10, start);
    if (lf < 0) break;
    const parsed = parseJson(decoder.decode(file.subarray(start, lf)));
    frames.push(parsed.ok && isObject(parsed.value) ? parsed.value : null);
    start = lf + 1;
    if (frames.length === want) end = start;
  }
  return { frames, bytes: file.subarray(0, end) };
}
var get = (o, ...path) => {
  let v = o;
  for (const k of path) v = isObject(v) ? v.get(k) : void 0;
  return v;
};
function putsOf(frame) {
  const body = get(frame, "body");
  const command = get(body, "command");
  const outcome = get(body, "outcome");
  const kind = get(command, "kind");
  const out = [];
  const put = (c) => {
    const d = get(c, "doc_id");
    const t = get(c, "text");
    if (get(c, "kind") === "put_document" && typeof d === "string" && typeof t === "string") out.push({ docId: d, text: t });
  };
  if (get(outcome, "kind") !== "value") return out;
  if (kind === "put_document") put(command);
  else if (kind === "batch") {
    const ops = get(command, "operations");
    const results = get(outcome, "result", "results");
    if (Array.isArray(ops) && Array.isArray(results)) for (let k = 0; k < results.length && k < ops.length; k++) put(ops[k]);
  }
  return out;
}
async function verifyCut(bundle, adapter) {
  const failures = [];
  const states = /* @__PURE__ */ new Map();
  const delivered = [];
  const report = {
    format: CUT_REPORT_FORMAT,
    cut_hash: null,
    verdict: "FAIL",
    journals: [],
    exports: [],
    deliveries: [],
    across: { paragraphs_fallen: 0, observations_checked: 0 },
    failures,
    not_verified: [...CUT_NOT_VERIFIED]
  };
  const result = { report, manifest: null, states, delivered };
  const m = parseManifest(bundle.manifest);
  if (m !== null && isObject(m.value) && !m.badNumber && !m.duplicateKey) report.cut_hash = await cutHash(adapter, m.value);
  const manifest = m === null || m.badNumber || m.duplicateKey ? null : checkManifest(m.value);
  if (manifest === null) {
    failures.push({ code: "CUT_FORM" });
    return result;
  }
  result.manifest = manifest;
  const parts = /* @__PURE__ */ new Map();
  const sealGrounded = /* @__PURE__ */ new Map();
  const genesisDocs = /* @__PURE__ */ new Map();
  for (const j of manifest.journals) {
    const files = bundle.journals.get(j.name);
    const jf = (field) => void failures.push({ code: "CUT_JOURNAL_MISMATCH", journal: j.name, field });
    const n = j.log_size;
    const part = journalPart(files?.journal ?? new Uint8Array(), n, j.closed);
    parts.set(j.name, part);
    const seal = part.frames[n];
    const isSealFrame = (f) => get(f, "body", "actor") === "kernel" && get(f, "body", "command", "kind") === "seal" && get(f, "body", "outcome", "kind") === "value";
    if (n < 1 || !isSealFrame(seal) || get(seal, "body", "outcome", "result", "seal_hash") !== j.seal_hash) jf("seal_hash");
    const previous = n >= 1 ? part.frames[n - 1] : void 0;
    if (j.wal_head !== get(seal, "body", "command", "seal", "wal_head") || j.wal_head !== get(previous, "hash")) jf("wal_head");
    if (j.closed) {
      const close = part.frames[n + 1];
      if (!(get(close, "body", "actor") === "kernel" && get(close, "body", "command", "kind") === "close" && get(close, "body", "outcome", "kind") === "value")) jf("closed");
    }
    const genesis = get(part.frames[0], "body");
    if (get(genesis, "run_id") !== j.run_id) jf("run_id");
    if (get(genesis, "rules_version") !== j.rules_version) jf("rules_version");
    const grounded = /* @__PURE__ */ new Map();
    const detailed = await verifyJournalDetailed(
      [part.bytes],
      {
        expectSeal: j.seal_hash,
        documents: files?.documents ?? [],
        onSeal: (pos, st) => void grounded.set(pos, st.grounded.slice())
      },
      adapter
    );
    const r = detailed.report;
    const passed = r.verdict === "PASS" && r.levels.J3.result === "PASS" && r.levels.J4a.result === "PASS";
    report.journals.push({ name: j.name, verdict: "PASS", levels: r.levels });
    if (!passed) {
      failures.push({ code: "CUT_JOURNAL_FAILED", journal: j.name, failure: r.first_failure?.code ?? null });
      continue;
    }
    sealGrounded.set(j.name, grounded);
    states.set(j.name, { name: j.name, seal_hash: j.seal_hash, log_size: n, report: r, cascade: detailed.cascade, status: await detailed.cascade.status() });
    const docs = /* @__PURE__ */ new Map();
    const byHash = /* @__PURE__ */ new Map();
    for (const f of files?.documents ?? []) byHash.set(toHex(await adapter.sha256(f)), f);
    const sources = get(genesis, "source_documents");
    if (isObject(sources)) {
      for (const [docId, desc] of sources) {
        const b = byHash.get(get(desc, "raw_sha256"));
        if (b !== void 0) docs.set(docId, b);
      }
    }
    genesisDocs.set(j.name, docs);
  }
  for (const entry of report.journals) {
    if (failures.some((f) => f.journal === entry.name && (f.code === "CUT_JOURNAL_MISMATCH" || f.code === "CUT_JOURNAL_FAILED"))) entry.verdict = "FAIL";
  }
  const journalOf = new Map(manifest.journals.map((j) => [j.name, j]));
  for (const e of manifest.exports) {
    const before = failures.length;
    const file = bundle.exports.get(e.name) ?? new Uint8Array();
    const state = states.get(e.journal);
    const j = journalOf.get(e.journal);
    let mismatch = false;
    const fail = (code, extra = {}) => {
      if (code === "EXPORT_MISMATCH") {
        if (mismatch) return;
        mismatch = true;
      }
      failures.push({ code, export: e.name, ...extra });
    };
    const paragraphs = exportParagraphs(file);
    let fallen = 0;
    const sha = toHex(await adapter.sha256(file));
    const header = `${EXPORT_FORMAT} run=${exportEscape(j.run_id)} seal=${e.seal_hash} records=${e.records}
`;
    const headerBytes = utf8(header);
    const headerOk = file.length >= headerBytes.length && headerBytes.every((b, k) => file[k] === b);
    if (sha !== e.sha256 || !headerOk) fail("EXPORT_MISMATCH");
    if (state !== void 0) {
      const seals = state.report.levels.J1.result === "PASS" ? state.report.levels.J1.seals : [];
      const seal = seals.find((s) => s.seal_hash === e.seal_hash);
      if (seal === void 0) fail("EXPORT_SEAL_UNKNOWN");
      else {
        const grounded = sealGrounded.get(e.journal).get(seal.n);
        const named = [];
        if (paragraphs === null) fail("EXPORT_MISMATCH");
        else {
          for (const p of paragraphs) {
            const r = p.record === null ? void 0 : state.cascade.record(p.record);
            if (r === void 0 || r.kind !== "claim" || r.frame >= seal.n || named.includes(r)) {
              fail("EXPORT_MISMATCH");
              continue;
            }
            named.push(r);
          }
          for (const r of named) if (grounded[r.index] !== true) fail("EXPORT_NOT_STANDING", { record: r.id });
          const ordered = [...named].sort((a, b) => a.index - b.index);
          const canonical = exportText(j.run_id, e.seal_hash, ordered.map((r) => exportParagraph(r, (id) => state.cascade.record(id))));
          const cb = utf8(canonical);
          if (cb.length !== file.length || !cb.every((b, k) => file[k] === b)) fail("EXPORT_MISMATCH");
          fallen = named.filter((r) => state.status.grounded[r.index] !== true).length;
        }
      }
    }
    report.exports.push({ name: e.name, verdict: failures.length === before ? "PASS" : "FAIL", paragraphs: paragraphs?.length ?? 0, fallen_at_cut: fallen });
  }
  const exportOf = new Map(manifest.exports.map((e) => [e.name, e]));
  const deliveryFailed = /* @__PURE__ */ new Set();
  for (const d of manifest.deliveries) {
    const state = states.get(d.journal);
    if (state === void 0) {
      deliveryFailed.add(d);
      continue;
    }
    const e = exportOf.get(d.export);
    const part = parts.get(d.journal);
    const j = journalOf.get(d.journal);
    let bytes = null;
    let version = null;
    const inPart = d.frame <= j.log_size + (j.closed ? 1 : 0) && d.frame < part.frames.length;
    if (inPart && d.frame === 0) {
      const desc = get(part.frames[0], "body", "source_documents", d.doc_id);
      const b = genesisDocs.get(d.journal).get(d.doc_id);
      if (isObject(desc) && desc.get("raw_sha256") === e.sha256 && b !== void 0) {
        bytes = b;
        version = toHex((await documentChunks(adapter, b)).version);
      }
    } else if (inPart) {
      const body = get(part.frames[d.frame], "body");
      const command = get(body, "command");
      const text = get(command, "text");
      if (get(command, "kind") === "put_document" && get(body, "outcome", "kind") === "value" && get(command, "doc_id") === d.doc_id && typeof text === "string") {
        const b = utf8(text);
        const v = toHex((await documentChunks(adapter, b)).version);
        if (toHex(await adapter.sha256(b)) === e.sha256 && get(body, "outcome", "result", "document_version") === v) {
          bytes = b;
          version = v;
        }
      }
    }
    if (bytes === null || version === null) {
      failures.push({ code: "DELIVERY_MISSING", export: d.export, journal: d.journal, doc_id: d.doc_id, frame: d.frame });
      deliveryFailed.add(d);
      continue;
    }
    const paragraphs = (exportParagraphs(bytes) ?? []).filter((p) => p.record !== null);
    delivered.push({ delivery: d, bytes, version, paragraphs });
  }
  const exportShas = manifest.exports;
  const undeclared = [];
  for (const j of manifest.journals) {
    if (!states.has(j.name)) continue;
    const part = parts.get(j.name);
    const found = [];
    const sources = get(part.frames[0], "body", "source_documents");
    if (isObject(sources)) {
      for (const [docId, desc] of sources) {
        const e = exportShas.find((x) => x.sha256 === get(desc, "raw_sha256"));
        if (e !== void 0) found.push({ frame: 0, doc_id: docId, export: e.name });
      }
    }
    for (let f = 1; f < part.frames.length; f++) {
      for (const p of putsOf(part.frames[f])) {
        const sha = toHex(await adapter.sha256(utf8(p.text)));
        const e = exportShas.find((x) => x.sha256 === sha);
        if (e !== void 0) found.push({ frame: f, doc_id: p.docId, export: e.name });
      }
    }
    found.sort((a, b) => a.frame - b.frame || cmp(a.doc_id, b.doc_id));
    for (const imp of found) {
      const declared = manifest.deliveries.some((d) => d.journal === j.name && d.frame === imp.frame && (imp.frame !== 0 || d.doc_id === imp.doc_id));
      if (declared) continue;
      const fl = { code: "CUT_UNDECLARED_DELIVERY", journal: j.name, frame: imp.frame, doc_id: imp.doc_id, export: imp.export };
      if (!undeclared.some((u) => jcs(u) === jcs(fl))) undeclared.push(fl);
    }
  }
  failures.push(...undeclared);
  for (const dx of delivered) {
    const d = dx.delivery;
    const part = parts.get(d.journal);
    const named = (f) => f === 0 && isObject(get(part.frames[0], "body", "source_documents", d.doc_id)) || f > 0 && putsOf(part.frames[f]).some((p) => p.docId === d.doc_id);
    let at = null;
    for (let f = 0; f < d.frame && at === null; f++) if (named(f)) at = d.frame;
    for (let f = d.frame + 1; f < part.frames.length && at === null; f++) if (named(f)) at = f;
    if (at !== null) {
      failures.push({ code: "CUT_IMPORT_MODIFIED", journal: d.journal, doc_id: d.doc_id, frame: at });
      deliveryFailed.add(d);
    }
  }
  for (const dx of delivered) {
    const d = dx.delivery;
    const source = states.get(exportOf.get(d.export).journal);
    const target = states.get(d.journal);
    if (source === void 0) continue;
    const seen = /* @__PURE__ */ new Set();
    for (const p of dx.paragraphs) {
      const r = source.cascade.record(p.record);
      if (r !== void 0 && source.status.grounded[r.index] === true) continue;
      report.across.paragraphs_fallen++;
      for (const o of target.cascade.accepted) {
        if (o.obs === null || o.obs.docId !== d.doc_id || o.obs.version !== dx.version) continue;
        if (!(o.obs.start < p.end && p.start < o.obs.end)) continue;
        if (!seen.has(o.id)) {
          seen.add(o.id);
          report.across.observations_checked++;
        }
        if (target.status.grounded[o.index] === true) {
          failures.push({ code: "WITHDRAWAL_NOT_DELIVERED", export: d.export, record: p.record, observation: o.id });
          deliveryFailed.add(d);
        }
      }
    }
  }
  for (const d of manifest.deliveries) report.deliveries.push({ export: d.export, journal: d.journal, verdict: deliveryFailed.has(d) ? "FAIL" : "PASS" });
  report.verdict = failures.length === 0 ? "PASS" : "FAIL";
  return result;
}
function cutHumanLine(r) {
  const nv = `Not verified: ${r.not_verified.map((s) => s.replaceAll("_", " ")).join(", ")}.`;
  if (r.verdict === "PASS") {
    return `Cut PASS. Journals: ${r.journals.length}. Exports: ${r.exports.length}. Deliveries: ${r.deliveries.length}. Paragraphs fallen: ${r.across.paragraphs_fallen}; observations checked: ${r.across.observations_checked}. ${nv}`;
  }
  const first = r.failures[0];
  const fields = Object.entries(first).filter(([k]) => k !== "code").map(([k, v]) => `${k} ${String(v)}`).join(", ");
  const more = r.failures.length > 1 ? ` (${r.failures.length} failures)` : "";
  return `Cut FAIL: ${first.code}${fields === "" ? "" : ` (${fields})`}${more}. ${nv}`;
}

// src/obs.ts
var OBS_REPORT_FORMAT = "yuce-observation-report/1";
var OBS_REPORT_DOMAIN = "YUCE-OBS-REPORT/1";
var zeroDebt = () => ({
  affected: 0,
  contested: 0,
  resting_on_contested: 0,
  stale: 0,
  questions_about_claims: 0,
  key_conflicts: 0,
  rejected_submissions: 0,
  late_submissions: 0
});
var uniqueBy = (items, key) => {
  const seen = /* @__PURE__ */ new Set();
  return items.filter((t) => {
    const k = key(t);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
};
async function observationReport(input, adapter) {
  const claims = [];
  const keyConflicts = [];
  const debtBy = /* @__PURE__ */ new Map();
  for (const j of input.journals) {
    const { cascade, status } = j;
    const records = cascade.accepted;
    const grounded = (id) => {
      const r = cascade.record(id);
      return r !== void 0 && status.grounded[r.index] === true;
    };
    const links = cascade.allLinks;
    const fallenBy = (r) => status.rows[r.index][4];
    const entryOf = (l, other) => ({
      link: l.id,
      rel: l.rel,
      from: l.from,
      to: l.to,
      status: l.status,
      other_grounded: grounded(other),
      usable: cascade.linkEffective(l, status)
    });
    const declared = new Set(records.filter((r) => r.kind === "relation" && r.ends !== null).map((r) => jcs([r.ends.from, r.ends.rel, r.ends.to])));
    for (const c of records) {
      if (c.kind !== "claim") continue;
      const grounds = c.grounds.map((id) => cascade.record(id)).filter((g) => g !== void 0);
      const obsGrounds = grounds.filter((g) => g.obs !== null);
      const quotes = uniqueBy(
        obsGrounds.map((g) => ({ doc_id: g.obs.docId, version: g.obs.version, start: g.obs.start, end: g.obs.end })),
        (q) => jcs(fromPlain(q))
      );
      const restsOn = uniqueBy(
        grounds.filter((g) => g.kind === "claim").map((g) => g.id),
        (x) => x
      );
      const across = [];
      for (const g of obsGrounds) {
        for (const d of input.deliveries) {
          if (d.journal !== j.name || d.doc_id !== g.obs.docId || d.version !== g.obs.version) continue;
          for (const p of d.paragraphs) if (g.obs.start < p.end && p.start < g.obs.end) across.push({ journal: d.source, record: p.record });
        }
      }
      const restsOnAcross = uniqueBy(across, (a) => jcs([a.journal, a.record])).sort((a, b) => cmp(a.journal, b.journal) || cmp(a.record, b.record));
      const questions = [...new Set(records.filter((q) => q.kind === "question" && q.about === c.id).map((q) => q.id))].sort(cmp);
      const isGrounded = status.grounded[c.index] === true;
      const causes = [];
      if (!isGrounded) {
        const visited = /* @__PURE__ */ new Set();
        const stack = [...fallenBy(c)];
        while (stack.length > 0) {
          const id = stack.shift();
          if (visited.has(id)) continue;
          visited.add(id);
          const r = cascade.record(id);
          if (r === void 0) continue;
          if (r.kind === "observe") {
            if (status.grounded[r.index] !== true) causes.push(r);
          } else stack.push(...fallenBy(r));
        }
        causes.sort((a, b) => a.index - b.index);
      }
      const rootCauses = causes.map((r) => ({ record: r.id, reason: cascade.revoked.get(r.obs.anchor) ?? "version_replaced" }));
      const K = links.filter((l) => l.rel === "contradicts" && (l.from === c.id || l.to === c.id));
      const other = (l) => l.from === c.id ? l.to : l.from;
      let dispute;
      if (K.some((l) => l.status === "accepted" && grounded(other(l)))) dispute = "contested";
      else if (K.some((l) => l.status === "proposed" || l.status === "accepted" && !grounded(other(l)))) dispute = "unknown";
      else dispute = "uncontested";
      const disputeLinks = K.map((l) => entryOf(l, other(l))).sort((a, b) => cmp(a.link, b.link));
      const supersedes = links.filter((l) => l.rel === "supersedes" && l.to === c.id);
      const R = supersedes.filter((l) => l.status !== "rejected");
      let time;
      if (R.some((l) => grounded(l.from) && (l.status === "accepted" || declared.has(jcs([l.from, l.rel, l.to]))))) time = "stale";
      else if (R.length > 0) time = "unknown";
      else time = "current";
      const timeLinks = supersedes.map((l) => entryOf(l, l.from)).sort((a, b) => cmp(a.link, b.link));
      claims.push({
        journal: j.name,
        id: c.id,
        author: c.actor,
        frame: c.frame,
        quotes,
        rests_on: restsOn,
        rests_on_across: restsOnAcross,
        questions,
        support: isGrounded ? "grounded" : "affected",
        root_causes: rootCauses,
        dispute,
        dispute_links: disputeLinks,
        time,
        time_links: timeLinks
      });
    }
    const supersededByKey = (c) => records.some((r) => {
      if (r.kind !== "relation" || r.ends === null || r.ends.rel !== "supersedes" || r.ends.to !== c.id || status.grounded[r.index] !== true) return false;
      const l = links.find((x) => x.from === r.ends.from && x.rel === r.ends.rel && x.to === r.ends.to);
      return l !== void 0 && l.status !== "rejected";
    });
    const byKey = /* @__PURE__ */ new Map();
    const valueOf = /* @__PURE__ */ new Map();
    for (const c of records) {
      if (c.kind !== "claim" || c.subject === null || status.grounded[c.index] !== true || supersededByKey(c)) continue;
      const v = jcs(c.object);
      valueOf.set(v, c.object);
      let set = byKey.get(c.subject);
      if (set === void 0) byKey.set(c.subject, set = /* @__PURE__ */ new Set());
      set.add(v);
    }
    const conflicts = [...byKey.entries()].filter(([, vs]) => vs.size >= 2).sort((a, b) => cmp(a[0], b[0]));
    for (const [subject, vs] of conflicts) keyConflicts.push({ journal: j.name, subject, values: [...vs].sort(cmp).map((v) => valueOf.get(v)) });
    const debt = zeroDebt();
    debt.key_conflicts = conflicts.length;
    debt.questions_about_claims = records.filter((q) => q.kind === "question" && q.about !== null && cascade.record(q.about)?.kind === "claim").length;
    debt.rejected_submissions = cascade.rejectedSubmissions;
    debt.late_submissions = cascade.lateSubmissions;
    debtBy.set(j.name, debt);
  }
  const disputeOf = new Map(claims.map((c) => [jcs([c.journal, c.id]), c.dispute]));
  for (const c of claims) {
    const debt = debtBy.get(c.journal);
    if (c.support === "affected") debt.affected++;
    if (c.dispute === "contested") debt.contested++;
    if (c.time === "stale") debt.stale++;
    const resting = c.rests_on.some((id) => disputeOf.get(jcs([c.journal, id])) === "contested") || c.rests_on_across.some((a) => disputeOf.get(jcs([a.journal, a.record])) === "contested");
    if (resting) debt.resting_on_contested++;
  }
  const total = zeroDebt();
  for (const d of debtBy.values()) for (const k of Object.keys(total)) total[k] += d[k];
  keyConflicts.sort((a, b) => cmp(a.journal, b.journal) || cmp(a.subject, b.subject));
  const body = fromPlain({
    format: OBS_REPORT_FORMAT,
    mode: "observe",
    cut_hash: input.cut_hash,
    journals: input.journals.map((j) => ({ name: j.name, seal_hash: j.seal_hash, log_size: j.log_size })),
    claims,
    key_conflicts: keyConflicts,
    debt: { total, by_journal: Object.fromEntries([...debtBy.entries()]) }
  });
  body.set("report_hash", await reportHash(adapter, body));
  return { value: body, text: jcs(body) };
}
async function reportHash(adapter, report) {
  const without = new Map([...report].filter(([k]) => k !== "report_hash"));
  return toHex(await domainHash(adapter, OBS_REPORT_DOMAIN, utf8(jcs(without))));
}
async function checkReport(given, computed, adapter) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(given);
  } catch {
    return { verdict: "FAIL", code: "REPORT_FORM", path: null };
  }
  const parsed = parseJson(text);
  if (!parsed.ok || parsed.badNumber || !isObject(parsed.value) || !sameBytes(utf8(jcs(parsed.value)), given) || !isHashText(parsed.value.get("report_hash"))) {
    return { verdict: "FAIL", code: "REPORT_FORM", path: null };
  }
  if (parsed.value.get("report_hash") !== await reportHash(adapter, parsed.value)) return { verdict: "FAIL", code: "REPORT_HASH_MISMATCH", path: null };
  if (sameBytes(utf8(jcs(computed)), given)) return { verdict: "PASS", code: null, path: null };
  return { verdict: "FAIL", code: "REPORT_MISMATCH", path: firstDifference2(parsed.value, computed, "") };
}
function sameBytes(a, b) {
  return a.length === b.length && a.every((x, k) => x === b[k]);
}
function firstDifference2(a, b, path) {
  if (a === void 0 || b === void 0) return path;
  if (isObject(a) && isObject(b)) {
    const keys = [.../* @__PURE__ */ new Set([...a.keys(), ...b.keys()])].sort(cmp);
    for (const k of keys) {
      const d = firstDifference2(a.get(k), b.get(k), path === "" ? k : `${path}.${k}`);
      if (d !== null) return d;
    }
    return null;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      const d = firstDifference2(a[i], b[i], `${path}[${i}]`);
      if (d !== null) return d;
    }
    return null;
  }
  return jcs(a) === jcs(b) ? null : path;
}
function partThroughSeal(journal, n) {
  let at = 0;
  for (let k = 0; k <= n; k++) {
    const lf = journal.indexOf(10, at);
    if (lf < 0) return null;
    at = lf + 1;
  }
  return journal.subarray(0, at);
}
async function observationReportForJournal(journal, documents, sealFrame, adapter) {
  const part = partThroughSeal(journal, sealFrame);
  if (part === null) return { ok: false, reason: `the journal has no frame ${sealFrame}` };
  const { report, cascade } = await verifyJournalDetailed([part], { documents }, adapter);
  if (report.verdict !== "PASS" || report.levels.J4a.result !== "PASS" || cascade === null) {
    const f = report.first_failure;
    return { ok: false, reason: f !== null ? `the part fails at ${f.level}${f.frame === null ? "" : `, frame ${f.frame}`}: ${f.code}` : `the part is not verified through J4a (${report.verdict})` };
  }
  const seal = report.levels.J1.result === "PASS" ? report.levels.J1.seals.find((s) => s.n === sealFrame) : void 0;
  if (seal === void 0) return { ok: false, reason: `frame ${sealFrame} is not a seal` };
  const firstLf = part.indexOf(10);
  const genesis = parseJson(new TextDecoder().decode(part.subarray(0, firstLf)));
  const body = genesis.ok && isObject(genesis.value) ? genesis.value.get("body") : void 0;
  const runId = isObject(body) ? body.get("run_id") : void 0;
  const status = await cascade.status();
  const r = await observationReport(
    { cut_hash: null, journals: [{ name: typeof runId === "string" ? runId : "", seal_hash: seal.seal_hash, log_size: sealFrame, cascade, status }], deliveries: [] },
    adapter
  );
  return { ok: true, ...r };
}
async function observationReportForCut(bundle, adapter) {
  const cut = await verifyCut(bundle, adapter);
  if (cut.report.verdict !== "PASS" || cut.manifest === null) {
    const f = cut.report.failures[0];
    return { ok: false, reason: `the cut fails${f === void 0 ? "" : `: ${f.code}`}` };
  }
  const journals = cut.manifest.journals.map((j) => {
    const s = cut.states.get(j.name);
    return { name: j.name, seal_hash: j.seal_hash, log_size: j.log_size, cascade: s.cascade, status: s.status };
  });
  const sourceOf = new Map(cut.manifest.exports.map((e) => [e.name, e.journal]));
  const deliveries = cut.delivered.map((d) => ({
    journal: d.delivery.journal,
    doc_id: d.delivery.doc_id,
    version: d.version,
    source: sourceOf.get(d.delivery.export),
    paragraphs: d.paragraphs
  }));
  return { ok: true, ...await observationReport({ cut_hash: cut.report.cut_hash, journals, deliveries }, adapter) };
}

// src/vectors.ts
var NOT_RECOMPUTED = /^(V5_|V6_|V8_)/;
var NOT_RECOMPUTED_REASON = "state-root, projection and session-root formulas are not recomputed by levels J0-J3";
var SETTINGS_DOMAIN = "R2R-SETTINGS/2";
var INPUTS = /* @__PURE__ */ new Set([
  "V2_L_jcs",
  "V2_real_leaf_value_jcs",
  "V3_B_jcs",
  "V3_Hd_jcs",
  "V7_P_jcs",
  "V9_real_seal_pair_source",
  "V9_seal_frame_index",
  "V9_line_frame_n_minus_1",
  "V9_line_seal_frame_n",
  "V10_request_actor",
  "V10_request_command_jcs",
  "V10_request_preimage_jcs",
  "V11_gear_index",
  "V13_record_author",
  "V13_record_directive",
  "V13_record_ordinal",
  "V13_record_body_jcs",
  "V13_record_preimage_jcs",
  "V14_journal",
  "V14_documents",
  "V14_frames",
  "V15_settings_jcs",
  "V16_git_document_text",
  "V16_git_identity",
  "V16_git_id_preimage_jcs"
]);
async function checkVectors(file, adapter) {
  if (!isObject(file)) throw new Error("the vectors file is not a JSON object");
  const vectors = file.get("vectors");
  if (!isObject(vectors)) throw new Error('the vectors file has no "vectors" object');
  const out = [];
  const used = /* @__PURE__ */ new Set();
  const get2 = (name) => {
    used.add(name);
    return vectors.get(name);
  };
  const str = (name) => {
    const v = get2(name);
    if (typeof v !== "string") throw new VectorShapeError(`${name} is missing or not a string`);
    return v;
  };
  const strList = (name) => {
    const v = get2(name);
    if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) throw new VectorShapeError(`${name} is not a list of strings`);
    return v;
  };
  const check = async (name, run, key = name) => {
    if (!vectors.has(key)) return;
    used.add(key);
    try {
      const problem = await run();
      out.push({ name, status: problem === null ? "PASS" : "FAIL", detail: problem ?? "" });
    } catch (e) {
      out.push({ name, status: "FAIL", detail: e instanceof Error ? e.message : String(e) });
    }
  };
  const H = async (domain, ...parts) => toHex(await domainHash(adapter, domain, ...parts));
  const eq = (what, got, want) => got === want ? null : `${what}: got ${got}, expected ${want}`;
  await check("V1_rec_empty", async () => eq("H(R2R-REC-EMPTY/2)", await H(DOMAIN.recordEmpty), str("V1_rec_empty")));
  const v2Leaves = [];
  await check("V2_leaf", async () => {
    const ls = strList("V2_L_jcs");
    const want = strList("V2_leaf");
    if (ls.length !== want.length) return "V2_L_jcs and V2_leaf differ in length";
    for (let k = 0; k < ls.length; k++) {
      const c = canonicalProblem(ls[k], `V2_L_jcs[${k}]`);
      if (c !== null) return c;
      const leaf = await recordLeaf(adapter, utf8(ls[k]));
      v2Leaves.push(leaf);
      const p = eq(`V2_leaf[${k}]`, toHex(leaf), want[k]);
      if (p !== null) return p;
    }
    return null;
  });
  for (const n of [1, 2, 3]) {
    await check(`V2_root_n${n}`, async () => {
      if (v2Leaves.length < n) return "V2 leaves unavailable";
      return eq(`records root over ${n} leaves`, toHex(await recordsRoot(adapter, v2Leaves.slice(0, n))), str(`V2_root_n${n}`));
    });
  }
  const realLeaves = [];
  await check("V2_real_leaf", async () => {
    const values = strList("V2_real_leaf_value_jcs");
    const want = strList("V2_real_leaf");
    if (values.length !== want.length) return "V2_real_leaf_value_jcs and V2_real_leaf differ in length";
    for (let k = 0; k < values.length; k++) {
      const c = canonicalProblem(values[k], `V2_real_leaf_value_jcs[${k}]`);
      if (c !== null) return c;
      const leaf = await recordLeaf(adapter, utf8(values[k]));
      realLeaves.push(leaf);
      const p = eq(`V2_real_leaf[${k}]`, toHex(leaf), want[k]);
      if (p !== null) return p;
    }
    return null;
  });
  await check("V2_real_records_root", async () => {
    if (realLeaves.length === 0) return "V2_real leaves unavailable";
    return eq("records root", toHex(await recordsRoot(adapter, realLeaves)), str("V2_real_records_root"));
  });
  await check("V3_body_hash", async () => {
    const b = str("V3_B_jcs");
    return canonicalProblem(b, "V3_B_jcs") ?? eq("H(R2R-FRAME-BODY/2, B)", await H(DOMAIN.frameBody, utf8(b)), str("V3_body_hash"));
  });
  await check("V3_h", async () => {
    const hd = str("V3_Hd_jcs");
    const c = canonicalProblem(hd, "V3_Hd_jcs");
    if (c !== null) return c;
    const header = parseObject(hd);
    if (header.get("body_hash") !== str("V3_body_hash")) return "V3_Hd_jcs does not name V3_body_hash";
    return eq("H(R2R-FRAME-HDR/2, Hd)", await H(DOMAIN.frameHeader, utf8(hd)), str("V3_h"));
  });
  await check("V3_line", async () => {
    const line = str("V3_line");
    const built = /* @__PURE__ */ new Map([
      ["body", parseObject(str("V3_B_jcs"))],
      ["hash", str("V3_h")],
      ["header", parseObject(str("V3_Hd_jcs"))]
    ]);
    const p = eq("JCS({body, hash, header}) + LF", JSON.stringify(jcs(built) + "\n"), JSON.stringify(line));
    if (p !== null) return p;
    const report = await verifyJournal([utf8(line)], {}, adapter);
    if (report.levels.J0.result !== "PASS" || report.levels.J1.result !== "PASS") {
      return `levels J0-J1 do not accept V3_line: ${JSON.stringify(report.first_failure)}`;
    }
    return null;
  });
  await check("V3_line_sha256", async () => eq("SHA-256(V3_line)", toHex(await adapter.sha256(utf8(str("V3_line")))), str("V3_line_sha256")));
  await check("V3_line_len", async () => {
    const want = get2("V3_line_len");
    return eq("byte length of V3_line", String(utf8(str("V3_line")).length), String(want));
  });
  for (const n of [1, 2, 3]) {
    await check(`V4_log_root_n${n}`, async () => {
      const hashes = strList("V4_frame_hashes");
      if (hashes.length < n) return "V4_frame_hashes too short";
      const tree = new LogTree(adapter);
      for (const h of hashes.slice(0, n)) await tree.push(fromHex(h));
      return eq(`log root over ${n} frames`, toHex(await tree.root()), str(`V4_log_root_n${n}`));
    });
  }
  if (vectors.has("V4_frame_hashes")) {
    await check("V4_frame_hashes", async () => eq("V4_frame_hashes[0] is V3_h", strList("V4_frame_hashes")[0] ?? "", str("V3_h")));
  }
  await check("V7_seal_hash", async () => {
    const p = str("V7_P_jcs");
    return canonicalProblem(p, "V7_P_jcs") ?? eq("H(R2R-SEAL/2, JCS(P))", await H(DOMAIN.seal, utf8(p)), str("V7_seal_hash"));
  });
  let pair = null;
  const v9 = async () => pair ??= await loadV9(adapter, str, get2);
  await check("V9_frame_hash_n_minus_1", async () => {
    const p = await v9();
    return frameProblem(p.before, p.n - 1, str("V9_frame_hash_n_minus_1"));
  });
  await check("V9_frame_hash_n", async () => {
    const p = await v9();
    const f = frameProblem(p.seal, p.n, str("V9_frame_hash_n"));
    if (f !== null) return f;
    return p.seal.header.get("previous") === p.before.hash ? null : "the seal frame does not name the frame before it";
  });
  await check("V9_seal_hash", async () => {
    const p = await v9();
    if (p.seal.body.get("actor") !== "kernel" || p.seal.body.get("submission_id") !== `seal-${p.n}`) return "not a kernel seal-n frame";
    if (jcs(p.result.get("seal") ?? null) !== jcs(p.P)) return "the seal differs between command and outcome";
    return eq("H(R2R-SEAL/2, JCS(P))", p.sealHash, str("V9_seal_hash")) ?? eq("outcome.result.seal_hash", String(p.result.get("seal_hash")), p.sealHash);
  });
  await check("V9_checks", async () => {
    const p = await v9();
    const names = strList("V9_checks");
    if (names.length === 0) return "no checks listed";
    const problems = [];
    for (const name of names) {
      const run = V9_CHECKS[name];
      if (run === void 0) problems.push(`unknown check ${JSON.stringify(name)}`);
      else if (!await run(p, adapter)) problems.push(`fails: ${name}`);
    }
    return problems.length === 0 ? null : problems.join("; ");
  });
  await check("V10_request_hash", async () => {
    const command = parseObject(str("V10_request_command_jcs"));
    const actor = str("V10_request_actor");
    const preimage = jcs(["r2r-audit-request/1", actor, command]);
    return eq("the request preimage", JSON.stringify(preimage), JSON.stringify(str("V10_request_preimage_jcs"))) ?? eq("request_hash", await requestHash(adapter, actor, command), str("V10_request_hash"));
  });
  await check("V11_gear_hex", async () => {
    const idx = get2("V11_gear_index");
    const want = strList("V11_gear_hex");
    if (!Array.isArray(idx) || idx.length !== want.length) return "V11_gear_index and V11_gear_hex differ in length";
    for (let k = 0; k < idx.length; k++) {
      const p = eq(`GEAR[${String(idx[k])}]`, gearHex(idx[k]), want[k]);
      if (p !== null) return p;
    }
    return null;
  });
  await check("V11_cdc", async () => {
    const cdc = get2("V11_cdc");
    if (!isObject(cdc)) return "V11_cdc is not an object";
    return eq("window w", String(cdc.get("window_w")), String(CDC_WINDOW)) ?? eq("maximum chunk", String(cdc.get("max_chunk")), String(CDC_MAX_CHUNK));
  });
  const docs = get2("V11_documents");
  const v11Texts = /* @__PURE__ */ new Map();
  if (Array.isArray(docs)) {
    for (let k = 0; k < docs.length; k++) {
      const d = docs[k];
      const docId = isObject(d) && typeof d.get("doc_id") === "string" ? d.get("doc_id") : String(k);
      await check(
        `V11_documents[${docId}]`,
        async () => {
          if (!isObject(d) || typeof d.get("text") !== "string") return "not an object with a text";
          const text = d.get("text");
          v11Texts.set(docId, text);
          const bytes = utf8(text);
          const c = await documentChunks(adapter, bytes);
          const ranges = JSON.stringify(c.chunks.map((x) => [x.start, x.end]));
          return eq("bytes", String(bytes.length), String(d.get("bytes"))) ?? eq("raw_sha256", toHex(await adapter.sha256(bytes)), String(d.get("raw_sha256"))) ?? eq("chunk_ranges", ranges, jcs(d.get("chunk_ranges") ?? null)) ?? eq("chunk_hashes", jcs(c.hashes.map(toHex)), jcs(d.get("chunk_hashes") ?? null)) ?? eq("version", toHex(c.version), String(d.get("version")));
        },
        "V11_documents"
      );
    }
  }
  await check(
    "V11_version_empty_document",
    async () => eq("version of the empty document", toHex((await documentChunks(adapter, new Uint8Array(0))).version), str("V11_version_empty_document"))
  );
  const shorts = get2("V11_short_documents");
  if (Array.isArray(shorts)) {
    for (let k = 0; k < shorts.length; k++) {
      await check(
        `V11_short_documents[${k}]`,
        async () => {
          const d = shorts[k];
          if (!isObject(d) || typeof d.get("text") !== "string") return "not an object with a text";
          const c = await documentChunks(adapter, utf8(d.get("text")));
          return eq("chunk_ranges", JSON.stringify(c.chunks.map((x) => [x.start, x.end])), jcs(d.get("chunk_ranges") ?? null)) ?? eq("chunk_hashes", jcs(c.hashes.map(toHex)), jcs(d.get("chunk_hashes") ?? null)) ?? eq("version", toHex(c.version), String(d.get("version")));
        },
        "V11_short_documents"
      );
    }
  }
  await check("V11_version_one_chunk", async () => {
    const v = get2("V11_version_one_chunk");
    if (!isObject(v) || typeof v.get("text") !== "string") return "not an object with a text";
    const c = await documentChunks(adapter, utf8(v.get("text")));
    return eq("version", toHex(c.version), String(v.get("version")));
  });
  const evidence = get2("V12_evidence");
  if (Array.isArray(evidence)) {
    for (let k = 0; k < evidence.length; k++) {
      await check(
        `V12_evidence[${k}]`,
        async () => {
          const e = evidence[k];
          if (!isObject(e)) return "not an object";
          const docId = e.get("doc_id");
          const text = v11Texts.get(docId);
          if (text === void 0) return `no V11 document ${docId}`;
          const bytes = utf8(text);
          const q = utf8(e.get("quote"));
          const span = e.get("span");
          const found = occurrences(bytes, q, 2);
          if (found.length !== 1 || found[0] !== span[0] || found[0] + q.length !== span[1]) return `the quote occurs at ${JSON.stringify(found)}, span is ${JSON.stringify(span)}`;
          const c = await documentChunks(adapter, bytes);
          const segs = segmentsOf(c, span[0], span[1]);
          const segJcs = jcs(segs.map((x) => [toHex(x.hash), x.from, x.to]));
          const node = await anchorBytes(adapter, docId, q, segs);
          return eq("segments", segJcs, jcs(e.get("segments") ?? null)) ?? eq("node bytes", toHex(node), String(e.get("node_bytes_hex"))) ?? eq("evidence id", toHex(await adapter.sha256(node)), String(e.get("evidence_id")));
        },
        "V12_evidence"
      );
    }
  }
  await check("V13_record_id", async () => {
    const body = parseObject(str("V13_record_body_jcs"));
    const preimage = jcs(["r2r.audit.record.v1", str("V13_record_author"), str("V13_record_directive"), get2("V13_record_ordinal") ?? null, body]);
    return eq("the record preimage", JSON.stringify(preimage), JSON.stringify(str("V13_record_preimage_jcs"))) ?? eq("record id", toHex(await adapter.sha256(utf8(preimage))), str("V13_record_id"));
  });
  const byFrame = /* @__PURE__ */ new Map();
  await check("V14_records", async () => {
    const recs = get2("V14_records");
    if (!Array.isArray(recs)) return "not an array";
    for (let k = 0; k < recs.length; k++) {
      const r = recs[k];
      if (!isObject(r) || typeof r.get("L_jcs") !== "string") return `V14_records[${k}] has no L_jcs`;
      const L = r.get("L_jcs");
      const c = canonicalProblem(L, `V14_records[${k}].L_jcs`);
      if (c !== null) return c;
      const leaf = await recordLeaf(adapter, utf8(L));
      const p = eq(`V14_records[${k}].leaf`, toHex(leaf), String(r.get("leaf")));
      if (p !== null) return p;
      const frame = r.get("frame");
      byFrame.set(frame, [...byFrame.get(frame) ?? [], leaf]);
    }
    return null;
  });
  await check("V14_records_roots", async () => {
    const roots = strList("V14_records_roots");
    if (get2("V14_frames") !== roots.length) return "V14_frames is not the number of roots";
    if (byFrame.size === 0) return "V14 leaves unavailable";
    for (let i = 0; i < roots.length; i++) {
      const p = eq(`records root of frame ${i}`, toHex(await recordsRoot(adapter, byFrame.get(i) ?? [])), roots[i]);
      if (p !== null) return p;
    }
    return null;
  });
  await check("V15_settings_hash", async () => {
    const settingsJcs = str("V15_settings_jcs");
    return canonicalProblem(settingsJcs, "V15_settings_jcs") ?? eq("settings hash", await H(SETTINGS_DOMAIN, utf8(settingsJcs)), str("V15_settings_hash"));
  });
  await check("V15_settings_hash_empty", async () => eq("settings hash of {}", await H(SETTINGS_DOMAIN, utf8("{}")), str("V15_settings_hash_empty")));
  await check("V8_settings_hash_empty", async () => eq("settings hash of {}", await H(SETTINGS_DOMAIN, utf8("{}")), str("V8_settings_hash_empty")));
  await check("V16_git_document_id", async () => {
    const identity = get2("V16_git_identity");
    if (!isObject(identity)) return "V16_git_identity is not an object";
    const bytes = utf8(str("V16_git_document_text"));
    const s = (k) => String(identity.get(k));
    const preimage = jcs(["R2R-AUDIT-GIT-DOCUMENT/1", s("repo"), s("commit"), s("path"), s("raw_sha256")]);
    return eq("raw_sha256 of the text", toHex(await adapter.sha256(bytes)), s("raw_sha256")) ?? eq("size_bytes", String(bytes.length), s("size_bytes")) ?? eq("the identity preimage", JSON.stringify(preimage), JSON.stringify(str("V16_git_id_preimage_jcs"))) ?? eq("doc_id", await gitDocumentId(adapter, s("repo"), s("commit"), s("path"), s("raw_sha256")), str("V16_git_document_id"));
  });
  const covered = new Set(out.map((o) => o.name));
  for (const name of [...vectors.keys()].sort()) {
    if (used.has(name) || covered.has(name) || INPUTS.has(name)) continue;
    if (NOT_RECOMPUTED.test(name)) out.push({ name, status: "SKIP", detail: NOT_RECOMPUTED_REASON });
    else out.push({ name, status: "SKIP", detail: "not known to this verifier" });
  }
  return out;
}
var VectorShapeError = class extends Error {
};
function parseObject(text) {
  const r = parseJson(text);
  if (!r.ok || !isObject(r.value)) throw new VectorShapeError("not a JSON object: " + (r.ok ? "" : r.error));
  return r.value;
}
function canonicalProblem(text, what) {
  const r = parseJson(text);
  if (!r.ok) return `${what} is not JSON: ${r.error}`;
  if (r.badNumber) return `${what} has a number outside the journal's integer range`;
  return jcs(r.value) === text ? null : `${what} is not canonical`;
}
async function loadFrame(adapter, line, what) {
  const c = canonicalProblem(line, what);
  if (c !== null) throw new VectorShapeError(c);
  const f = parseObject(line);
  const header = f.get("header");
  const body = f.get("body");
  if (!isObject(header) || !isObject(body)) throw new VectorShapeError(`${what} has no header or body object`);
  return {
    line,
    header,
    body,
    hash: toHex(await domainHash(adapter, DOMAIN.frameHeader, utf8(jcs(header)))),
    bodyHash: toHex(await domainHash(adapter, DOMAIN.frameBody, utf8(jcs(body))))
  };
}
async function loadV9(adapter, str, get2) {
  const n = get2("V9_seal_frame_index");
  if (typeof n !== "number") throw new VectorShapeError("V9_seal_frame_index is not a number");
  const before = await loadFrame(adapter, str("V9_line_frame_n_minus_1"), "V9_line_frame_n_minus_1");
  const seal = await loadFrame(adapter, str("V9_line_seal_frame_n"), "V9_line_seal_frame_n");
  const command = seal.body.get("command");
  const outcome = seal.body.get("outcome");
  const P = isObject(command) ? command.get("seal") : void 0;
  const result = isObject(outcome) ? outcome.get("result") : void 0;
  if (!isObject(P) || !isObject(result)) throw new VectorShapeError("the seal frame has no command.seal or outcome.result");
  const sealHash = toHex(await domainHash(adapter, DOMAIN.seal, utf8(jcs(P))));
  return { n, before, seal, P, result, sealHash };
}
function frameProblem(f, position, wantHash) {
  if (f.header.get("seq") !== position) return `seq is not ${position}`;
  if (f.header.get("wal_op") !== "audit") return "wal_op is not audit";
  if (f.header.get("body_hash") !== f.bodyHash) return "body_hash mismatch";
  if (parseObject(f.line).get("hash") !== f.hash) return "frame hash mismatch";
  return f.hash === wantHash ? null : `frame hash ${f.hash}, expected ${wantHash}`;
}
var V9_CHECKS = {
  "P.log_size == n": async (p) => p.P.get("log_size") === p.n,
  "P.wal_head == hash of frame n-1": async (p) => p.P.get("wal_head") === p.before.hash,
  "P.audit_root == body.audit_root of frame n-1": async (p) => p.P.get("audit_root") === p.before.body.get("audit_root"),
  "P.engine_root == body.engine_root of frame n-1": async (p) => p.P.get("engine_root") === p.before.body.get("engine_root"),
  "body.audit_root of frame n != P.audit_root (the seal receipt)": async (p) => p.seal.body.get("audit_root") !== p.P.get("audit_root"),
  "outcome.result.seal_hash == H(R2R-SEAL/2, JCS(P))": async (p) => p.result.get("seal_hash") === p.sealHash,
  "P.log_root == RFC 6962 root over the hashes of frames 0..n-1": async (p, adapter) => {
    if (p.n !== 2) return false;
    const frame0 = p.before.header.get("previous");
    if (typeof frame0 !== "string" || !/^[0-9a-f]{64}$/.test(frame0)) return false;
    const tree = new LogTree(adapter);
    await tree.push(fromHex(frame0));
    await tree.push(fromHex(p.before.hash));
    return p.P.get("log_root") === toHex(await tree.root());
  }
};

// src/cli.ts
var USAGE = [
  "usage:",
  "  yuce-verify journal <file> [--docs <folder>] [--expect-seal <hex>] [--expect-head <hex>]",
  "                             [--quittance <file>]... [--dump-projections <file>]",
  "                             [--max-line-bytes <n>] [--max-depth <n>] [--json] [--quiet]",
  "  yuce-verify cut <folder> [--json] [--quiet]",
  "  yuce-verify report <journal> --seal-frame <n> [--docs <folder>] [--check <report>] [--json] [--quiet]",
  "  yuce-verify report <cut folder> [--check <report>] [--json] [--quiet]",
  "  yuce-verify vectors <file.json> [--json] [--quiet]"
].join("\n");
var UsageError = class extends Error {
};
var VALUE_FLAGS = {
  journal: /* @__PURE__ */ new Set(["--docs", "--expect-seal", "--expect-head", "--max-line-bytes", "--max-depth", "--quittance", "--dump-projections"]),
  vectors: /* @__PURE__ */ new Set(),
  cut: /* @__PURE__ */ new Set(),
  report: /* @__PURE__ */ new Set(["--docs", "--seal-frame", "--check"])
};
var REPEATABLE = /* @__PURE__ */ new Set(["--quittance"]);
function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (command !== "journal" && command !== "vectors" && command !== "cut" && command !== "report") {
    throw new UsageError(command === void 0 ? "missing command" : `unknown command ${JSON.stringify(command)}`);
  }
  const values = /* @__PURE__ */ new Map();
  const switches = /* @__PURE__ */ new Set();
  const positional = [];
  for (let k = 0; k < rest.length; k++) {
    const arg = rest[k];
    if (arg === "--") {
      positional.push(...rest.slice(k + 1));
      break;
    }
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const eqAt = arg.indexOf("=");
    const name = eqAt < 0 ? arg : arg.slice(0, eqAt);
    if (VALUE_FLAGS[command].has(name)) {
      let value;
      if (eqAt >= 0) value = arg.slice(eqAt + 1);
      else value = rest[++k];
      if (value === void 0) throw new UsageError(`${name} needs a value`);
      const list = values.get(name) ?? [];
      if (list.length > 0 && !REPEATABLE.has(name)) throw new UsageError(`${name} given twice`);
      list.push(value);
      values.set(name, list);
    } else if ((name === "--json" || name === "--quiet") && eqAt < 0) {
      switches.add(name);
    } else throw new UsageError(`unknown option ${JSON.stringify(arg)}`);
  }
  if (positional.length !== 1) throw new UsageError(`expected exactly one ${command === "cut" ? "folder" : "file"}, got ${positional.length}`);
  const one = (name) => values.get(name)?.[0];
  const parsed = { command, file: positional[0], quittances: values.get("--quittance") ?? [], json: switches.has("--json"), quiet: switches.has("--quiet") };
  const docs = one("--docs");
  if (docs !== void 0) {
    if (docs === "") throw new UsageError("--docs needs a folder");
    parsed.docs = docs;
  }
  const seal = one("--expect-seal");
  if (seal !== void 0) parsed.expectSeal = hashArg("--expect-seal", seal);
  const head = one("--expect-head");
  if (head !== void 0) parsed.expectHead = hashArg("--expect-head", head);
  const mlb = one("--max-line-bytes");
  if (mlb !== void 0) parsed.maxLineBytes = positiveInt("--max-line-bytes", mlb);
  const md = one("--max-depth");
  if (md !== void 0) parsed.maxDepth = positiveInt("--max-depth", md);
  for (const q of parsed.quittances) if (q === "") throw new UsageError("--quittance needs a file");
  const dump = one("--dump-projections");
  if (dump !== void 0) {
    if (dump === "") throw new UsageError("--dump-projections needs a file");
    parsed.dumpProjections = dump;
  }
  const sf = one("--seal-frame");
  if (sf !== void 0) parsed.sealFrame = positiveInt("--seal-frame", sf);
  const check = one("--check");
  if (check !== void 0) {
    if (check === "") throw new UsageError("--check needs a file");
    parsed.check = check;
  }
  return parsed;
}
function hashArg(name, value) {
  const v = value.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(v)) throw new UsageError(`${name} must be 64 hex characters`);
  return v;
}
function positiveInt(name, value) {
  if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value))) {
    throw new UsageError(`${name} must be a positive integer`);
  }
  return Number(value);
}
var InputError = class extends Error {
};
async function runCli(argv, io, adapter) {
  const quiet = argv.includes("--quiet");
  const say = (text) => {
    if (!quiet) io.stdout(text + "\n");
  };
  const complain = (text) => {
    if (!quiet) io.stderr(`yuce-verify: ${text}
`);
  };
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help")) {
    io.stdout(USAGE + "\n");
    return EXIT.pass;
  }
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    complain(`${e.message}
${USAGE}`);
    return EXIT.usage;
  }
  try {
    if (args.command === "vectors") return await runVectors(args, io, adapter, say, complain);
    if (args.command === "cut") return await runCut(args, io, adapter, say);
    if (args.command === "report") return await runReport(args, io, adapter, say, complain, quiet);
    return await runJournal(args, io, adapter, say);
  } catch (e) {
    if (e instanceof InputError) {
      complain(e.message);
      return EXIT.usage;
    }
    throw e;
  }
}
var read = async (io, path, what = path) => {
  try {
    return await io.readFile(path);
  } catch (e) {
    throw new InputError(`cannot read ${what}: ${e.message}`);
  }
};
var readDocs = async (io, path) => {
  try {
    return await io.readDocs(path);
  } catch (e) {
    throw new InputError(`cannot read the documents folder ${path}: ${e.message}`);
  }
};
async function runJournal(args, io, adapter, say) {
  const documents = args.docs === void 0 ? void 0 : await readDocs(io, args.docs);
  const quittances = [];
  for (const q of args.quittances) quittances.push({ file: q, bytes: await read(io, q) });
  const points = [];
  let report;
  try {
    const source = await io.openJournal(args.file);
    report = await verifyJournal(
      source,
      {
        expectSeal: args.expectSeal,
        expectHead: args.expectHead,
        maxLineBytes: args.maxLineBytes,
        maxDepth: args.maxDepth,
        documents,
        quittances,
        onProjections: args.dumpProjections === void 0 ? void 0 : (p) => void points.push(p)
      },
      adapter
    );
  } catch (e) {
    if (e instanceof ReadError || isNodeFsError(e)) throw new InputError(`cannot read ${args.file}: ${e.message}`);
    throw e;
  }
  if (args.dumpProjections !== void 0) {
    const dump = {
      journal: args.file.split(/[\\/]/).pop() ?? args.file,
      mismatches: points.filter((p) => !p.equals_seal).length,
      pair_form: "[record, ground]",
      points,
      row_form: "[id, kind, grounded, established, fallen_by]",
      seals: points.length
    };
    if (io.writeFile === void 0) throw new InputError("--dump-projections: this environment cannot write files");
    try {
      await io.writeFile(args.dumpProjections, jcs(fromPlain(dump)) + "\n");
    } catch (e) {
      throw new InputError(`cannot write ${args.dumpProjections}: ${e.message}`);
    }
  }
  say(args.json ? reportToJcs(report) : humanLine(report));
  return exitCodeFor(report.verdict);
}
async function readCut(io, folder) {
  const manifest = await read(io, `${folder}/cut.json`);
  const journals = /* @__PURE__ */ new Map();
  const exports = /* @__PURE__ */ new Map();
  const parsed = parseManifest(manifest);
  const m = parsed !== null && !parsed.badNumber && !parsed.duplicateKey ? checkManifest(parsed.value) : null;
  if (m === null) return { manifest, journals, exports };
  for (const j of m.journals) {
    const journal = await read(io, `${folder}/${j.name}/run.wal`);
    let documents = [];
    try {
      documents = await io.readDocs(`${folder}/${j.name}/docs`);
    } catch {
      documents = [];
    }
    journals.set(j.name, { journal, documents });
  }
  for (const e of m.exports) exports.set(e.name, await read(io, `${folder}/${e.name}.txt`));
  return { manifest, journals, exports };
}
async function runCut(args, io, adapter, say) {
  const bundle = await readCut(io, args.file);
  const { report } = await verifyCut(bundle, adapter);
  say(args.json ? jcs(fromPlain(report)) : cutHumanLine(report));
  return report.verdict === "PASS" ? EXIT.pass : EXIT.fail;
}
async function runReport(args, io, adapter, say, complain, quiet) {
  let out;
  if (args.sealFrame !== void 0) {
    const documents = args.docs === void 0 ? [] : await readDocs(io, args.docs);
    out = await observationReportForJournal(await read(io, args.file), documents, args.sealFrame, adapter);
  } else {
    if (args.docs !== void 0) throw new InputError("--docs is for a journal (with --seal-frame); a cut has its documents in <journal>/docs");
    out = await observationReportForCut(await readCut(io, args.file), adapter);
  }
  const given = args.check === void 0 ? null : await read(io, args.check);
  if (!out.ok) {
    complain(`cannot compute the report: ${out.reason}`);
    return EXIT.fail;
  }
  if (given === null) {
    if (!quiet) io.stdout(out.text);
    return EXIT.pass;
  }
  const check = await checkReport(given, out.value, adapter);
  if (args.json) say(jcs(fromPlain(check)));
  else if (check.verdict === "PASS") say("Report PASS: the given report equals the report recomputed from the journals.");
  else say(`Report FAIL: ${check.code}${check.path === null ? "" : ` at ${check.path}`}.`);
  return check.verdict === "PASS" ? EXIT.pass : EXIT.fail;
}
async function runVectors(args, io, adapter, say, complain) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(await io.readFile(args.file));
  } catch (e) {
    complain(`cannot read ${args.file}: ${e.message}`);
    return EXIT.usage;
  }
  const parsed = parseJson(text);
  if (!parsed.ok) {
    complain(`${args.file} is not JSON: ${parsed.error}`);
    return EXIT.usage;
  }
  let outcomes;
  try {
    outcomes = await checkVectors(parsed.value, adapter);
  } catch (e) {
    complain(`${args.file}: ${e.message}`);
    return EXIT.usage;
  }
  const count = (s) => outcomes.filter((o) => o.status === s).length;
  const passed = count("PASS");
  const failed = count("FAIL");
  const skipped = count("SKIP");
  if (args.json) {
    say(
      jcs(
        fromPlain({
          vectors: outcomes.map((o) => ({ name: o.name, status: o.status, detail: o.detail })),
          passed,
          failed,
          skipped
        })
      )
    );
  } else {
    for (const o of outcomes) say(o.detail === "" ? `${o.status} ${o.name}` : `${o.status} ${o.name}: ${o.detail}`);
    say(`Vectors: ${passed} passed, ${failed} failed, ${skipped} skipped.`);
  }
  return failed === 0 ? EXIT.pass : EXIT.fail;
}
function isNodeFsError(e) {
  return e instanceof Error && typeof e.code === "string" && "syscall" in e;
}

// src/index.ts
async function nodeMain(proc2) {
  const fs = await import("node:fs");
  const adapter = await nodeHashAdapter();
  const code = await runCli(
    proc2.argv.slice(2),
    {
      stdout: (t) => void proc2.stdout.write(t),
      stderr: (t) => void proc2.stderr.write(t),
      readFile: async (path) => fs.promises.readFile(path),
      openJournal: async (path) => {
        const st = await fs.promises.stat(path);
        if (!st.isFile()) throw new ReadError("not a regular file");
        return fs.createReadStream(path, { highWaterMark: 1 << 16 });
      },
      readDocs: async (path) => {
        const st = await fs.promises.stat(path);
        if (!st.isDirectory()) throw new ReadError("not a folder");
        const out = [];
        const walk = async (dir) => {
          const entries = await fs.promises.readdir(dir, { withFileTypes: true });
          entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
          for (const e of entries) {
            const full = dir + "/" + e.name;
            if (e.isDirectory()) await walk(full);
            else if (e.isFile()) out.push(await fs.promises.readFile(full));
          }
        };
        await walk(path);
        return out;
      },
      writeFile: async (path, text) => fs.promises.writeFile(path, text)
    },
    adapter
  );
  proc2.exitCode = code;
  return code;
}
var proc = globalThis.process;
if (proc?.versions?.node !== void 0 && proc.argv[1] !== void 0) {
  const { pathToFileURL } = await import("node:url");
  const { realpathSync } = await import("node:fs");
  let entry;
  try {
    entry = pathToFileURL(realpathSync(proc.argv[1])).href;
  } catch {
    entry = void 0;
  }
  if (entry === import.meta.url) await nodeMain(proc);
}
export {
  CDC_MAX_CHUNK,
  CDC_WINDOW,
  CUT_DOMAIN,
  CUT_FORMAT,
  CUT_NOT_VERIFIED,
  CUT_REPORT_FORMAT,
  Cascade,
  DEFAULT_MAX_DEPTH,
  DEFAULT_MAX_LINE_BYTES,
  DOMAIN,
  EMPTY_PROJECTIONS,
  EMPTY_RECORDS_ROOT,
  EXIT,
  EXPORT_FORMAT,
  GENESIS_FORMATS,
  J2Checker,
  JOURNAL_FORMAT,
  LINE_KEYS,
  LINE_REQUIRED,
  LINK_DOMAIN,
  LogTree,
  MAX_QUOTE_BYTES,
  NOT_VERIFIED,
  NOT_VERIFIED_AFTER_J3,
  OBS_REPORT_DOMAIN,
  OBS_REPORT_FORMAT,
  PROJECTION_DOMAIN,
  PROJECTION_KEYS,
  QUESTION_KEYS_RULES_4,
  QUITTANCE_FORMAT,
  RULES_VERSIONS,
  RULES_VERSION_4,
  ReadError,
  RecordEngine,
  SEAL_FORMAT_ID,
  SEAL_HASH_FIELDS,
  SEAL_KEYS,
  SPEC_ID,
  USAGE,
  VERIFIER_VERSION,
  ZERO_HASH,
  anchorBytes,
  checkManifest,
  checkQuittance,
  checkReport,
  checkVectors,
  chunksOf,
  commandKind,
  cutHash,
  cutHumanLine,
  cutPoints,
  defaultHashAdapter,
  depthExceeds,
  documentChunks,
  domainHash,
  exitCodeFor,
  exportEscape,
  exportParagraph,
  exportParagraphs,
  exportText,
  firstDifference2 as firstDifference,
  fromHex,
  fromPlain,
  gearHex,
  gitDocumentId,
  hasExactKeys,
  humanLine,
  indexDocuments,
  isHashText,
  isIdentifier,
  isObject,
  isSubmitResult,
  jcs,
  jcsString,
  lineFormProblem,
  linkId,
  logRootRecursive,
  nodeHashAdapter,
  nodeMain,
  observationReport,
  observationReportForCut,
  observationReportForJournal,
  occurrences,
  parseJson,
  parseManifest,
  parseQuittance,
  partThroughSeal,
  projectionHashes,
  recordLeaf,
  recordsRoot,
  reportHash,
  reportToJcs,
  requestHash,
  runCli,
  sealFormProblem,
  segmentsOf,
  subtleHashAdapter,
  toHex,
  uniqueByPrefix,
  utf8,
  verifyCut,
  verifyJournal
};
