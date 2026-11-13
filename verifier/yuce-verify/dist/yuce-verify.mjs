#!/usr/bin/env node
// yuce-verify 0.1.3: independent verifier of YuCe journals, delivery 1 (levels J0, J1).
// Built from src/ by scripts/build.mjs. No runtime dependencies.

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
    return { ok: true, value: result, badNumber };
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

// src/report.ts
var VERIFIER_NAME = "yuce-verify";
var VERIFIER_VERSION = "0.1.3";
var SPEC_ID = "SPEC_INDEPENDENT_VERIFIER/4";
var NOT_VERIFIED = ["quotes_against_sources", "withdrawal_cascade", "signatures"];
function computeVerdict(results) {
  if (results.includes("FAIL")) return "FAIL";
  if (results.includes("NOT_CHECKABLE")) return "INCOMPLETE";
  return "PASS";
}
function reportToJcs(report) {
  return jcs(fromPlain(report));
}
var NOT_VERIFIED_SENTENCE = "Not verified: quotes against sources, withdrawal cascade, signatures.";
function humanLine(report) {
  const parts = [];
  const f = report.first_failure;
  if (report.verdict === "FAIL" && f !== null) {
    parts.push(f.frame === null ? `FAIL at ${f.level}: ${f.code}.` : `FAIL at ${f.level}, frame ${f.frame}: ${f.code}.`);
  } else if (report.levels.J1.result === "PASS") {
    const j1 = report.levels.J1;
    parts.push(`J0-J1 PASS. Frames: ${report.input.frames}. Seals: ${j1.seals.length}.`);
    parts.push(tailSentence(j1.tail));
    parts.push(anchorSentence(report.anchor, report.input.frames));
  } else {
    parts.push(`${report.verdict}.`);
  }
  parts.push(NOT_VERIFIED_SENTENCE);
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
var EXIT = { pass: 0, fail: 1, usage: 2, notCheckable: 3 };
function exitCodeFor(verdict) {
  if (verdict === "PASS") return EXIT.pass;
  if (verdict === "FAIL") return EXIT.fail;
  return EXIT.notCheckable;
}

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

// src/verify.ts
var JOURNAL_FORMAT = "sbgk-session-log/3";
var SEAL_FORMAT_ID = "r2r-seal/2";
var ZERO_HASH = "0".repeat(64);
var DEFAULT_MAX_LINE_BYTES = 64 * 1024 * 1024 - 1;
var DEFAULT_MAX_DEPTH = 64;
var OUTER_KEYS = ["body", "hash", "header"];
var HEADER_KEYS = ["body_hash", "format", "previous", "records_root", "seq", "wal_op"];
var SEAL_KEYS = [
  "audit_root",
  "engine_root",
  "format",
  "log_root",
  "log_size",
  "projections",
  "run_id",
  "wal_head"
];
var SEAL_HASH_FIELDS = ["log_root", "wal_head", "audit_root", "engine_root"];
var PROJECTION_KEYS = ["dependencies", "status"];
var ReadError = class extends Error {
};
async function verifyJournal(source, options, adapter) {
  const maxLineBytes = options.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES;
  const fileHash = adapter.createSha256();
  const v = new FrameVerifier(adapter, options);
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
  return v.finish(toHex(await fileHash.digest()), bytes, lines);
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
  constructor(adapter, options) {
    this.adapter = adapter;
    this.options = options;
    this.maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
    this.tree = new LogTree(adapter);
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
        return i === 0 ? fail("UNSUPPORTED_FORMAT", `header.format is ${quoted(fmt)}`) : fail("MIXED_FORMAT", `header.format is ${quoted(fmt)}, frame 0 is ${quoted(this.format)}`);
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
    if (walOp !== expectedOp) return fail("WAL_OP_MISMATCH", `header.wal_op is ${quoted(walOp)}, expected "${expectedOp}"`);
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
        `a ${kind} command from the actor ${typeof actor === "string" ? quoted(actor) : "(missing or not a string)"}`
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
        return this.failJ1(i, "KERNEL_ID_MISUSE", `a kernel frame takes the id ${quoted(sid)} but is not a seal`);
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
    if (!hasExactKeys(command, ["kind", "seal"])) return form("command must have exactly the keys kind, seal");
    const outcome = body.get("outcome");
    if (!isObject(outcome) || !hasExactKeys(outcome, ["kind", "result"])) return form("outcome must have exactly the keys kind, result");
    if (outcome.get("kind") !== "value") return form('outcome.kind is not "value"');
    const result = outcome.get("result");
    if (!isObject(result) || !hasExactKeys(result, ["seal", "seal_hash"])) {
      return form("outcome.result must have exactly the keys seal, seal_hash");
    }
    const seal = command.get("seal");
    if (!isObject(seal) || !hasExactKeys(seal, SEAL_KEYS)) return form("the seal must have exactly its eight keys");
    const projections = seal.get("projections");
    if (!isObject(projections) || !hasExactKeys(projections, PROJECTION_KEYS)) {
      return form("seal.projections must have exactly the keys dependencies, status");
    }
    if (typeof seal.get("format") !== "string") return form("seal.format is not a string");
    if (typeof seal.get("run_id") !== "string") return form("seal.run_id is not a string");
    if (typeof seal.get("log_size") !== "number") return form("seal.log_size is not a number");
    for (const k of SEAL_HASH_FIELDS) if (!isHashText(seal.get(k))) return form(`seal.${k} is not a hash`);
    for (const k of PROJECTION_KEYS) if (!isHashText(projections.get(k))) return form(`seal.projections.${k} is not a hash`);
    const sealHash = result.get("seal_hash");
    if (!isHashText(sealHash)) return form("outcome.result.seal_hash is not a hash");
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
  // End of file
  // -------------------------------------------------------------------------
  finish(journalSha256, bytes, lines) {
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
    const j0Result = j0Pass ? "PASS" : "FAIL";
    return {
      verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION, spec: SPEC_ID },
      input: { journal_sha256: journalSha256, bytes, frames: lines, format: this.format },
      levels: {
        J0: { result: j0Result },
        J1: j1,
        J2: { result: "NOT_CHECKED" },
        J3: { result: "NOT_CHECKED" },
        J5: { result: "NOT_CHECKED" }
      },
      anchor,
      computed: {
        wal_head: j0Pass ? this.prevHash : null,
        closed: tail === null ? null : tail.kind === "closed"
      },
      not_verified: [...NOT_VERIFIED],
      verdict: computeVerdict([j0Result, j1.result]),
      first_failure: this.j0Failure ?? this.j1Failure
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
function quoted(v) {
  if (v === null) return "null";
  return JSON.stringify(v.length > 80 ? v.slice(0, 80) + "..." : v);
}
function firstDifference(a, b) {
  const m = Math.min(a.length, b.length);
  for (let k = 0; k < m; k++) if (a.charCodeAt(k) !== b.charCodeAt(k)) return k;
  return m;
}

// src/vectors.ts
var NOT_RECOMPUTED = /^(V5_|V6_|V8_)/;
var NOT_RECOMPUTED_REASON = "state-root, projection and session-root formulas are not recomputed by levels J0-J1";
var INPUTS = /* @__PURE__ */ new Set([
  "V2_L_jcs",
  "V2_real_leaf_value_jcs",
  "V3_B_jcs",
  "V3_Hd_jcs",
  "V7_P_jcs",
  "V9_real_seal_pair_source",
  "V9_seal_frame_index",
  "V9_line_frame_n_minus_1",
  "V9_line_seal_frame_n"
]);
async function checkVectors(file, adapter) {
  if (!isObject(file)) throw new Error("the vectors file is not a JSON object");
  const vectors = file.get("vectors");
  if (!isObject(vectors)) throw new Error('the vectors file has no "vectors" object');
  const out = [];
  const used = /* @__PURE__ */ new Set();
  const get = (name) => {
    used.add(name);
    return vectors.get(name);
  };
  const str = (name) => {
    const v = get(name);
    if (typeof v !== "string") throw new VectorShapeError(`${name} is missing or not a string`);
    return v;
  };
  const strList = (name) => {
    const v = get(name);
    if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) throw new VectorShapeError(`${name} is not a list of strings`);
    return v;
  };
  const check = async (name, run) => {
    if (!vectors.has(name)) return;
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
    if (report.verdict !== "PASS") return `the verifier does not accept V3_line: ${JSON.stringify(report.first_failure)}`;
    return null;
  });
  await check("V3_line_sha256", async () => eq("SHA-256(V3_line)", toHex(await adapter.sha256(utf8(str("V3_line")))), str("V3_line_sha256")));
  await check("V3_line_len", async () => {
    const want = get("V3_line_len");
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
  const v9 = async () => pair ??= await loadV9(adapter, str, get);
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
async function loadV9(adapter, str, get) {
  const n = get("V9_seal_frame_index");
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
  "  yuce-verify journal <file> [--expect-seal <hex>] [--expect-head <hex>]",
  "                             [--max-line-bytes <n>] [--max-depth <n>] [--json] [--quiet]",
  "  yuce-verify vectors <file.json> [--json] [--quiet]"
].join("\n");
var UsageError = class extends Error {
};
var VALUE_FLAGS = /* @__PURE__ */ new Set(["--expect-seal", "--expect-head", "--max-line-bytes", "--max-depth"]);
function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (command !== "journal" && command !== "vectors") {
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
    if (VALUE_FLAGS.has(name) && command === "journal") {
      let value;
      if (eqAt >= 0) value = arg.slice(eqAt + 1);
      else value = rest[++k];
      if (value === void 0) throw new UsageError(`${name} needs a value`);
      if (values.has(name)) throw new UsageError(`${name} given twice`);
      values.set(name, value);
    } else if ((name === "--json" || name === "--quiet") && eqAt < 0) {
      switches.add(name);
    } else throw new UsageError(`unknown option ${JSON.stringify(arg)}`);
  }
  if (positional.length !== 1) throw new UsageError(`expected exactly one file, got ${positional.length}`);
  const parsed = { command, file: positional[0], json: switches.has("--json"), quiet: switches.has("--quiet") };
  const seal = values.get("--expect-seal");
  if (seal !== void 0) parsed.expectSeal = hashArg("--expect-seal", seal);
  const head = values.get("--expect-head");
  if (head !== void 0) parsed.expectHead = hashArg("--expect-head", head);
  const mlb = values.get("--max-line-bytes");
  if (mlb !== void 0) parsed.maxLineBytes = positiveInt("--max-line-bytes", mlb);
  const md = values.get("--max-depth");
  if (md !== void 0) parsed.maxDepth = positiveInt("--max-depth", md);
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
  if (args.command === "vectors") return runVectors(args, io, adapter, say, complain);
  let report;
  try {
    const source = await io.openJournal(args.file);
    report = await verifyJournal(
      source,
      {
        expectSeal: args.expectSeal,
        expectHead: args.expectHead,
        maxLineBytes: args.maxLineBytes,
        maxDepth: args.maxDepth
      },
      adapter
    );
  } catch (e) {
    if (e instanceof ReadError || isNodeFsError(e)) {
      complain(`cannot read ${args.file}: ${e.message}`);
      return EXIT.usage;
    }
    throw e;
  }
  say(args.json ? reportToJcs(report) : humanLine(report));
  return exitCodeFor(report.verdict);
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
      }
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
  DEFAULT_MAX_DEPTH,
  DEFAULT_MAX_LINE_BYTES,
  DOMAIN,
  EXIT,
  JOURNAL_FORMAT,
  LogTree,
  NOT_VERIFIED,
  ReadError,
  SEAL_FORMAT_ID,
  SPEC_ID,
  USAGE,
  VERIFIER_VERSION,
  ZERO_HASH,
  checkVectors,
  computeVerdict,
  defaultHashAdapter,
  depthExceeds,
  domainHash,
  exitCodeFor,
  fromHex,
  fromPlain,
  hasExactKeys,
  humanLine,
  isHashText,
  isObject,
  jcs,
  jcsString,
  logRootRecursive,
  nodeHashAdapter,
  nodeMain,
  parseJson,
  recordLeaf,
  recordsRoot,
  reportToJcs,
  runCli,
  subtleHashAdapter,
  toHex,
  utf8,
  verifyJournal
};
