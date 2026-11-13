// Strict JSON (RFC 8259) parsing and JSON canonicalization (RFC 8785, JCS),
// written for this verifier without third-party code (SPEC section 2).
//
// Objects are represented as Map<string, JsonValue> so that keys such as
// "__proto__" are ordinary data. A repeated key keeps its last value; the
// canonical form then has fewer members than the line, which is how a repeated
// key surfaces as NOT_CANONICAL (SPEC J0-6).

export type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
export type JsonObject = Map<string, JsonValue>;

export type ParseResult =
  | { ok: true; value: JsonValue; badNumber: boolean }
  | { ok: false; error: string };

/** Largest integer a journal may contain: 2^53 - 1 (SPEC section 2). */
export const MAX_JOURNAL_INTEGER_TEXT = "9007199254740991";

export function isObject(v: JsonValue | undefined): v is JsonObject {
  return v instanceof Map;
}

/** A hash as written in the journal: exactly 64 characters [0-9a-f] (SPEC section 1). */
export function isHashText(v: JsonValue | undefined): v is string {
  return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
}

/** True when the object has exactly the given keys, no more and no fewer. */
export function hasExactKeys(obj: JsonObject, keys: readonly string[]): boolean {
  if (obj.size !== keys.length) return false;
  for (const k of keys) if (!obj.has(k)) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Nesting depth (SPEC J0-1)
// ---------------------------------------------------------------------------

/**
 * Counts nesting of '{' and '[' outside string literals, on raw bytes, before
 * any decoding. The outermost container has depth 1. Returns true as soon as
 * the depth exceeds maxDepth. Works on bytes because every structural JSON
 * character is ASCII and UTF-8 continuation bytes are never ASCII.
 */
export function depthExceeds(bytes: Uint8Array, maxDepth: number): boolean {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    if (inString) {
      if (escaped) escaped = false;
      else if (b === 0x5c) escaped = true;
      else if (b === 0x22) inString = false;
      continue;
    }
    if (b === 0x22) inString = true;
    else if (b === 0x7b || b === 0x5b) {
      depth++;
      if (depth > maxDepth) return true;
    } else if ((b === 0x7d || b === 0x5d) && depth > 0) depth--;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

class ParseError extends Error {}

type Container =
  | { kind: "array"; items: JsonValue[] }
  | { kind: "object"; members: JsonObject; key: string };

/**
 * Parses text strictly by RFC 8259: no comments, no trailing commas, no BOM,
 * whitespace only from {space, tab, LF, CR}. Numbers must follow the RFC
 * grammar (else the text is not JSON); numbers that are valid JSON but are not
 * an integer from 0 to 2^53-1 written as plain digits set badNumber (SPEC
 * section 2, J0-5). A lone surrogate, raw or escaped, is a parse error.
 * The parser is iterative, so deep nesting cannot overflow the call stack.
 */
export function parseJson(text: string): ParseResult {
  const n = text.length;
  let pos = 0;
  let badNumber = false;

  const fail = (msg: string): never => {
    throw new ParseError(`${msg} at character ${pos}`);
  };

  const skipWs = (): void => {
    while (pos < n) {
      const c = text.charCodeAt(pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) pos++;
      else break;
    }
  };

  const hex4 = (): number => {
    if (pos + 4 > n) fail("truncated \\u escape");
    let v = 0;
    for (let k = 0; k < 4; k++) {
      const c = text.charCodeAt(pos + k);
      let d: number;
      if (c >= 0x30 && c <= 0x39) d = c - 0x30;
      else if (c >= 0x61 && c <= 0x66) d = c - 0x61 + 10;
      else if (c >= 0x41 && c <= 0x46) d = c - 0x41 + 10;
      else return fail("bad hex digit in \\u escape");
      v = v * 16 + d;
    }
    pos += 4;
    return v;
  };

  const parseString = (): string => {
    if (text.charCodeAt(pos) !== 0x22) fail("expected string");
    pos++;
    let out = "";
    let runStart = pos;
    for (;;) {
      if (pos >= n) fail("unterminated string");
      const c = text.charCodeAt(pos);
      if (c === 0x22) {
        out += text.slice(runStart, pos);
        pos++;
        return out;
      }
      if (c < 0x20) fail("unescaped control character in string");
      if (c >= 0xd800 && c <= 0xdfff) {
        // Raw surrogates: only a well-formed pair is allowed.
        const next = pos + 1 < n ? text.charCodeAt(pos + 1) : -1;
        if (c <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) {
          pos += 2;
          continue;
        }
        fail("lone surrogate in string");
      }
      if (c !== 0x5c) {
        pos++;
        continue;
      }
      out += text.slice(runStart, pos);
      pos++;
      if (pos >= n) fail("unterminated escape");
      const e = text.charCodeAt(pos);
      pos++;
      switch (e) {
        case 0x22: out += '"'; break;
        case 0x5c: out += "\\"; break;
        case 0x2f: out += "/"; break;
        case 0x62: out += "\b"; break;
        case 0x66: out += "\f"; break;
        case 0x6e: out += "\n"; break;
        case 0x72: out += "\r"; break;
        case 0x74: out += "\t"; break;
        case 0x75: {
          const u = hex4();
          if (u >= 0xd800 && u <= 0xdbff) {
            if (text.charCodeAt(pos) === 0x5c && text.charCodeAt(pos + 1) === 0x75) {
              pos += 2;
              const low = hex4();
              if (low >= 0xdc00 && low <= 0xdfff) {
                out += String.fromCharCode(u, low);
                break;
              }
            }
            fail("lone surrogate escape in string");
          }
          if (u >= 0xdc00 && u <= 0xdfff) fail("lone surrogate escape in string");
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

  const parseNumber = (): number => {
    const start = pos;
    let negative = false;
    if (text.charCodeAt(pos) === 0x2d) {
      negative = true;
      pos++;
    }
    const intStart = pos;
    const c0 = text.charCodeAt(pos);
    if (c0 === 0x30) pos++;
    else if (c0 >= 0x31 && c0 <= 0x39) {
      while (pos < n && isDigit(text.charCodeAt(pos))) pos++;
    } else fail("bad number");
    const intEnd = pos;
    let fraction = false;
    let exponent = false;
    if (text.charCodeAt(pos) === 0x2e) {
      fraction = true;
      pos++;
      if (!isDigit(text.charCodeAt(pos))) fail("bad number fraction");
      while (pos < n && isDigit(text.charCodeAt(pos))) pos++;
    }
    const ce = text.charCodeAt(pos);
    if (ce === 0x65 || ce === 0x45) {
      exponent = true;
      pos++;
      const cs = text.charCodeAt(pos);
      if (cs === 0x2b || cs === 0x2d) pos++;
      if (!isDigit(text.charCodeAt(pos))) fail("bad number exponent");
      while (pos < n && isDigit(text.charCodeAt(pos))) pos++;
    }
    const digits = text.slice(intStart, intEnd);
    if (negative || fraction || exponent || !integerInRange(digits)) {
      badNumber = true;
      // The value is never used: BAD_NUMBER stops the check of the line.
      return Number(text.slice(start, pos));
    }
    return Number(digits);
  };

  const parseLiteral = (): JsonValue => {
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

  const parseKeyAndColon = (): string => {
    skipWs();
    const key = parseString();
    skipWs();
    if (text.charCodeAt(pos) !== 0x3a) fail("expected ':'");
    pos++;
    return key;
  };

  try {
    const stack: Container[] = [];
    let result: JsonValue = null;
    let done = false;
    while (!done) {
      // Parse the start of one value.
      skipWs();
      if (pos >= n) fail("unexpected end of input");
      const c = text.charCodeAt(pos);
      let value: JsonValue;
      if (c === 0x7b) {
        pos++;
        skipWs();
        if (text.charCodeAt(pos) === 0x7d) {
          pos++;
          value = new Map();
        } else {
          stack.push({ kind: "object", members: new Map(), key: parseKeyAndColon() });
          continue;
        }
      } else if (c === 0x5b) {
        pos++;
        skipWs();
        if (text.charCodeAt(pos) === 0x5d) {
          pos++;
          value = [];
        } else {
          stack.push({ kind: "array", items: [] });
          continue;
        }
      } else if (c === 0x22) value = parseString();
      else if (c === 0x2d || isDigit(c)) value = parseNumber();
      else value = parseLiteral();

      // Attach the finished value to its containers, closing them as needed.
      for (;;) {
        const top = stack[stack.length - 1];
        if (top === undefined) {
          result = value;
          done = true;
          break;
        }
        skipWs();
        const d = text.charCodeAt(pos);
        if (top.kind === "array") {
          top.items.push(value);
          if (d === 0x2c) {
            pos++;
            break;
          }
          if (d === 0x5d) {
            pos++;
            stack.pop();
            value = top.items;
            continue;
          }
          fail("expected ',' or ']'");
        } else {
          top.members.set(top.key, value);
          if (d === 0x2c) {
            pos++;
            top.key = parseKeyAndColon();
            break;
          }
          if (d === 0x7d) {
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

function isDigit(c: number): boolean {
  return c >= 0x30 && c <= 0x39;
}

function integerInRange(digits: string): boolean {
  if (digits.length < MAX_JOURNAL_INTEGER_TEXT.length) return true;
  if (digits.length > MAX_JOURNAL_INTEGER_TEXT.length) return false;
  return digits <= MAX_JOURNAL_INTEGER_TEXT;
}

// ---------------------------------------------------------------------------
// Canonical form (RFC 8785)
// ---------------------------------------------------------------------------

class Literal {
  constructor(readonly text: string) {}
}

/**
 * JCS(v): keys sorted by UTF-16 code units, no whitespace, strings escaped
 * minimally, integers as plain digits. Iterative, like the parser.
 * Throws on values a journal can never hold (non-integers, lone surrogates).
 */
export function jcs(value: JsonValue): string {
  const out: string[] = [];
  const stack: (JsonValue | Literal)[] = [value];
  while (stack.length > 0) {
    const t = stack.pop()!;
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
        stack.push(t[i]!);
        if (i > 0) stack.push(new Literal(","));
      }
    } else {
      // Default sort compares strings by UTF-16 code units, as RFC 8785 requires.
      const keys = [...t.keys()].sort();
      out.push("{");
      stack.push(new Literal("}"));
      for (let i = keys.length - 1; i >= 0; i--) {
        const k = keys[i]!;
        stack.push(t.get(k)!);
        stack.push(new Literal(jcsString(k) + ":"));
        if (i > 0) stack.push(new Literal(","));
      }
    }
  }
  return out.join("");
}

function jcsNumber(v: number): string {
  if (!Number.isSafeInteger(v)) {
    throw new Error("JCS: only safe integers occur in this format");
  }
  return String(v);
}

const SHORT_ESCAPES: Record<number, string> = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
};

export function jcsString(s: string): string {
  let out = '"';
  let runStart = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x22 || c === 0x5c) {
      out += s.slice(runStart, i);
      out += SHORT_ESCAPES[c] ?? "\\u00" + c.toString(16).padStart(2, "0");
      runStart = i + 1;
    } else if (c >= 0xd800 && c <= 0xdfff) {
      const next = s.charCodeAt(i + 1);
      if (c <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) i++;
      else throw new Error("JCS: lone surrogate");
    }
  }
  return out + s.slice(runStart) + '"';
}

// ---------------------------------------------------------------------------
// Plain JS values -> JsonValue (for building reports)
// ---------------------------------------------------------------------------

export type Plain = null | boolean | number | string | readonly Plain[] | { readonly [k: string]: Plain };

export function fromPlain(v: Plain): JsonValue {
  if (v === null || typeof v === "boolean" || typeof v === "number" || typeof v === "string") return v;
  if (Array.isArray(v)) return v.map((x: Plain) => fromPlain(x));
  const m: JsonObject = new Map();
  for (const [k, x] of Object.entries(v as { readonly [k: string]: Plain })) m.set(k, fromPlain(x));
  return m;
}
