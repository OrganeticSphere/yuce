// Self-check on the control vectors (TZ v4 section 4; acceptance A1 and B1).
// Checks every vector this delivery can compute (V1-V4, V7, V9-V16, and the
// settings hash of V8) and names the ones it skips.

import type { HashAdapter } from "./hash.ts";
import { fromHex, toHex, utf8 } from "./hash.ts";
import type { JsonObject, JsonValue } from "./json.ts";
import { isObject, jcs, parseJson } from "./json.ts";
import { DOMAIN, LogTree, domainHash, recordLeaf, recordsRoot } from "./trees.ts";
import { verifyJournal } from "./verify.ts";
import { CDC_MAX_CHUNK, CDC_WINDOW, anchorBytes, documentChunks, gearHex, occurrences, segmentsOf } from "./cdc.ts";
import { gitDocumentId, requestHash } from "./j2.ts";

export interface VectorOutcome {
  name: string;
  status: "PASS" | "FAIL" | "SKIP";
  detail: string;
}

/** Vectors of formulas this verifier does not recompute (SPEC section 12, P3-13). */
const NOT_RECOMPUTED = /^(V5_|V6_|V8_)/;
const NOT_RECOMPUTED_REASON = "state-root, projection and session-root formulas are not recomputed by levels J0-J3";

/** The settings hash: H("R2R-SETTINGS/2", JCS(settings)) (P3-3). Checked by the vectors only. */
const SETTINGS_DOMAIN = "R2R-SETTINGS/2";

/** Vector entries read as inputs of the checks above (not results of their own). */
const INPUTS = new Set([
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
  "V16_git_id_preimage_jcs",
]);

export async function checkVectors(file: JsonValue, adapter: HashAdapter): Promise<VectorOutcome[]> {
  if (!isObject(file)) throw new Error("the vectors file is not a JSON object");
  const vectors = file.get("vectors");
  if (!isObject(vectors)) throw new Error('the vectors file has no "vectors" object');

  const out: VectorOutcome[] = [];
  const used = new Set<string>();
  const get = (name: string): JsonValue | undefined => {
    used.add(name);
    return vectors.get(name);
  };
  const str = (name: string): string => {
    const v = get(name);
    if (typeof v !== "string") throw new VectorShapeError(`${name} is missing or not a string`);
    return v;
  };
  const strList = (name: string): string[] => {
    const v = get(name);
    if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) throw new VectorShapeError(`${name} is not a list of strings`);
    return v as string[];
  };
  const check = async (name: string, run: () => Promise<string | null>, key: string = name): Promise<void> => {
    if (!vectors.has(key)) return;
    used.add(key);
    try {
      const problem = await run();
      out.push({ name, status: problem === null ? "PASS" : "FAIL", detail: problem ?? "" });
    } catch (e) {
      out.push({ name, status: "FAIL", detail: e instanceof Error ? e.message : String(e) });
    }
  };
  const H = async (domain: string, ...parts: Uint8Array[]): Promise<string> => toHex(await domainHash(adapter, domain, ...parts));
  const eq = (what: string, got: string, want: string): string | null => (got === want ? null : `${what}: got ${got}, expected ${want}`);

  // V1: empty records tree.
  await check("V1_rec_empty", async () => eq("H(R2R-REC-EMPTY/2)", await H(DOMAIN.recordEmpty), str("V1_rec_empty")));

  // V2: records leaves and roots on synthetic leaves.
  const v2Leaves: Uint8Array[] = [];
  await check("V2_leaf", async () => {
    const ls = strList("V2_L_jcs");
    const want = strList("V2_leaf");
    if (ls.length !== want.length) return "V2_L_jcs and V2_leaf differ in length";
    for (let k = 0; k < ls.length; k++) {
      const c = canonicalProblem(ls[k]!, `V2_L_jcs[${k}]`);
      if (c !== null) return c;
      const leaf = await recordLeaf(adapter, utf8(ls[k]!));
      v2Leaves.push(leaf);
      const p = eq(`V2_leaf[${k}]`, toHex(leaf), want[k]!);
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

  // V2_real: leaves of a real observation and a real claim, and their records root.
  const realLeaves: Uint8Array[] = [];
  await check("V2_real_leaf", async () => {
    const values = strList("V2_real_leaf_value_jcs");
    const want = strList("V2_real_leaf");
    if (values.length !== want.length) return "V2_real_leaf_value_jcs and V2_real_leaf differ in length";
    for (let k = 0; k < values.length; k++) {
      const c = canonicalProblem(values[k]!, `V2_real_leaf_value_jcs[${k}]`);
      if (c !== null) return c;
      const leaf = await recordLeaf(adapter, utf8(values[k]!));
      realLeaves.push(leaf);
      const p = eq(`V2_real_leaf[${k}]`, toHex(leaf), want[k]!);
      if (p !== null) return p;
    }
    return null;
  });
  await check("V2_real_records_root", async () => {
    if (realLeaves.length === 0) return "V2_real leaves unavailable";
    return eq("records root", toHex(await recordsRoot(adapter, realLeaves)), str("V2_real_records_root"));
  });

  // V3: body hash, header hash and the whole frame line, byte for byte.
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
    const built: JsonObject = new Map<string, JsonValue>([
      ["body", parseObject(str("V3_B_jcs"))],
      ["hash", str("V3_h")],
      ["header", parseObject(str("V3_Hd_jcs"))],
    ]);
    const p = eq("JCS({body, hash, header}) + LF", JSON.stringify(jcs(built) + "\n"), JSON.stringify(line));
    if (p !== null) return p;
    // The line is a whole one-frame journal for J0-J1. It is a hashing vector, not a
    // real genesis record (SPEC section 12), so J2 is expected to refuse it.
    const report = await verifyJournal([utf8(line)], {}, adapter);
    if (report.levels.J0.result !== "PASS" || report.levels.J1.result !== "PASS") {
      return `levels J0-J1 do not accept V3_line: ${JSON.stringify(report.first_failure)}`;
    }
    return null;
  });
  await check("V3_line_sha256", async () => eq("SHA-256(V3_line)", toHex(await adapter.sha256(utf8(str("V3_line")))), str("V3_line_sha256")));
  await check("V3_line_len", async () => {
    const want = get("V3_line_len");
    return eq("byte length of V3_line", String(utf8(str("V3_line")).length), String(want));
  });

  // V4: the log tree over 1, 2 and 3 frame hashes, through the running tree of SPEC 6.5.
  for (const n of [1, 2, 3]) {
    await check(`V4_log_root_n${n}`, async () => {
      const hashes = strList("V4_frame_hashes");
      if (hashes.length < n) return "V4_frame_hashes too short";
      const tree = new LogTree(adapter);
      for (const h of hashes.slice(0, n)) await tree.push(fromHex(h));
      return eq(`log root over ${n} frames`, toHex((await tree.root())!), str(`V4_log_root_n${n}`));
    });
  }
  if (vectors.has("V4_frame_hashes")) {
    await check("V4_frame_hashes", async () => eq("V4_frame_hashes[0] is V3_h", strList("V4_frame_hashes")[0] ?? "", str("V3_h")));
  }

  // V7: the seal hash.
  await check("V7_seal_hash", async () => {
    const p = str("V7_P_jcs");
    return canonicalProblem(p, "V7_P_jcs") ?? eq("H(R2R-SEAL/2, JCS(P))", await H(DOMAIN.seal, utf8(p)), str("V7_seal_hash"));
  });

  // V9: a real pair of lines, the frame before a seal and the seal frame (SPEC 12).
  let pair: V9Pair | null = null;
  const v9 = async (): Promise<V9Pair> => (pair ??= await loadV9(adapter, str, get));
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
    const problems: string[] = [];
    for (const name of names) {
      const run = V9_CHECKS[name];
      if (run === undefined) problems.push(`unknown check ${JSON.stringify(name)}`);
      else if (!(await run(p, adapter))) problems.push(`fails: ${name}`);
    }
    return problems.length === 0 ? null : problems.join("; ");
  });

  // ---------------------------------------------------------------------------
  // Delivery 2 (amendment 3, P3-13)
  // ---------------------------------------------------------------------------

  // V10: request_hash.
  await check("V10_request_hash", async () => {
    const command = parseObject(str("V10_request_command_jcs"));
    const actor = str("V10_request_actor");
    const preimage = jcs(["r2r-audit-request/1", actor, command]);
    return (
      eq("the request preimage", JSON.stringify(preimage), JSON.stringify(str("V10_request_preimage_jcs"))) ??
      eq("request_hash", await requestHash(adapter, actor, command), str("V10_request_hash"))
    );
  });

  // V11: the GEAR table, chunks and versions.
  await check("V11_gear_hex", async () => {
    const idx = get("V11_gear_index");
    const want = strList("V11_gear_hex");
    if (!Array.isArray(idx) || idx.length !== want.length) return "V11_gear_index and V11_gear_hex differ in length";
    for (let k = 0; k < idx.length; k++) {
      const p = eq(`GEAR[${String(idx[k])}]`, gearHex(idx[k] as number), want[k]!);
      if (p !== null) return p;
    }
    return null;
  });
  await check("V11_cdc", async () => {
    const cdc = get("V11_cdc");
    if (!isObject(cdc)) return "V11_cdc is not an object";
    return eq("window w", String(cdc.get("window_w")), String(CDC_WINDOW)) ?? eq("maximum chunk", String(cdc.get("max_chunk")), String(CDC_MAX_CHUNK));
  });
  const docs = get("V11_documents");
  const v11Texts = new Map<string, string>();
  if (Array.isArray(docs)) {
    for (let k = 0; k < docs.length; k++) {
      const d = docs[k];
      const docId = isObject(d) && typeof d.get("doc_id") === "string" ? (d.get("doc_id") as string) : String(k);
      await check(
        `V11_documents[${docId}]`,
        async () => {
          if (!isObject(d) || typeof d.get("text") !== "string") return "not an object with a text";
          const text = d.get("text") as string;
          v11Texts.set(docId, text);
          const bytes = utf8(text);
          const c = await documentChunks(adapter, bytes);
          const ranges = JSON.stringify(c.chunks.map((x) => [x.start, x.end]));
          return (
            eq("bytes", String(bytes.length), String(d.get("bytes"))) ??
            eq("raw_sha256", toHex(await adapter.sha256(bytes)), String(d.get("raw_sha256"))) ??
            eq("chunk_ranges", ranges, jcs(d.get("chunk_ranges") ?? null)) ??
            eq("chunk_hashes", jcs(c.hashes.map(toHex)), jcs(d.get("chunk_hashes") ?? null)) ??
            eq("version", toHex(c.version), String(d.get("version")))
          );
        },
        "V11_documents",
      );
    }
  }
  await check("V11_version_empty_document", async () =>
    eq("version of the empty document", toHex((await documentChunks(adapter, new Uint8Array(0))).version), str("V11_version_empty_document")),
  );
  // Amendment 4, P4-1: two short documents, of two chunks and of one.
  const shorts = get("V11_short_documents");
  if (Array.isArray(shorts)) {
    for (let k = 0; k < shorts.length; k++) {
      await check(
        `V11_short_documents[${k}]`,
        async () => {
          const d = shorts[k];
          if (!isObject(d) || typeof d.get("text") !== "string") return "not an object with a text";
          const c = await documentChunks(adapter, utf8(d.get("text") as string));
          return (
            eq("chunk_ranges", JSON.stringify(c.chunks.map((x) => [x.start, x.end])), jcs(d.get("chunk_ranges") ?? null)) ??
            eq("chunk_hashes", jcs(c.hashes.map(toHex)), jcs(d.get("chunk_hashes") ?? null)) ??
            eq("version", toHex(c.version), String(d.get("version")))
          );
        },
        "V11_short_documents",
      );
    }
  }
  // The vectors file of 19.11 before amendment 4 had this key instead.
  await check("V11_version_one_chunk", async () => {
    const v = get("V11_version_one_chunk");
    if (!isObject(v) || typeof v.get("text") !== "string") return "not an object with a text";
    // Only the version is compared: by P3-8 this text is cut into two chunks, not one,
    // and the kernel's version is that of two chunks (SPEC-DEFECT-16).
    const c = await documentChunks(adapter, utf8(v.get("text") as string));
    return eq("version", toHex(c.version), String(v.get("version")));
  });

  // V12: evidence anchors on vector-a.txt of V11.
  const evidence = get("V12_evidence");
  if (Array.isArray(evidence)) {
    for (let k = 0; k < evidence.length; k++) {
      await check(
        `V12_evidence[${k}]`,
        async () => {
          const e = evidence[k];
          if (!isObject(e)) return "not an object";
          const docId = e.get("doc_id") as string;
          const text = v11Texts.get(docId);
          if (text === undefined) return `no V11 document ${docId}`;
          const bytes = utf8(text);
          const q = utf8(e.get("quote") as string);
          const span = e.get("span") as number[];
          const found = occurrences(bytes, q, 2);
          if (found.length !== 1 || found[0] !== span[0] || found[0]! + q.length !== span[1]) return `the quote occurs at ${JSON.stringify(found)}, span is ${JSON.stringify(span)}`;
          const c = await documentChunks(adapter, bytes);
          const segs = segmentsOf(c, span[0]!, span[1]!);
          const segJcs = jcs(segs.map((x) => [toHex(x.hash), x.from, x.to]));
          const node = await anchorBytes(adapter, docId, q, segs);
          return (
            eq("segments", segJcs, jcs(e.get("segments") ?? null)) ??
            eq("node bytes", toHex(node), String(e.get("node_bytes_hex"))) ??
            eq("evidence id", toHex(await adapter.sha256(node)), String(e.get("evidence_id")))
          );
        },
        "V12_evidence",
      );
    }
  }

  // V13: the record id.
  await check("V13_record_id", async () => {
    const body = parseObject(str("V13_record_body_jcs"));
    const preimage = jcs(["r2r.audit.record.v1", str("V13_record_author"), str("V13_record_directive"), get("V13_record_ordinal") ?? null, body]);
    return (
      eq("the record preimage", JSON.stringify(preimage), JSON.stringify(str("V13_record_preimage_jcs"))) ??
      eq("record id", toHex(await adapter.sha256(utf8(preimage))), str("V13_record_id"))
    );
  });

  // V14: leaves of the records of kinds-batch-put.wal and the records root of every frame.
  const byFrame = new Map<number, Uint8Array[]>();
  await check("V14_records", async () => {
    const recs = get("V14_records");
    if (!Array.isArray(recs)) return "not an array";
    for (let k = 0; k < recs.length; k++) {
      const r = recs[k];
      if (!isObject(r) || typeof r.get("L_jcs") !== "string") return `V14_records[${k}] has no L_jcs`;
      const L = r.get("L_jcs") as string;
      const c = canonicalProblem(L, `V14_records[${k}].L_jcs`);
      if (c !== null) return c;
      const leaf = await recordLeaf(adapter, utf8(L));
      const p = eq(`V14_records[${k}].leaf`, toHex(leaf), String(r.get("leaf")));
      if (p !== null) return p;
      const frame = r.get("frame") as number;
      byFrame.set(frame, [...(byFrame.get(frame) ?? []), leaf]);
    }
    return null;
  });
  await check("V14_records_roots", async () => {
    const roots = strList("V14_records_roots");
    if (get("V14_frames") !== roots.length) return "V14_frames is not the number of roots";
    if (byFrame.size === 0) return "V14 leaves unavailable";
    for (let i = 0; i < roots.length; i++) {
      const p = eq(`records root of frame ${i}`, toHex(await recordsRoot(adapter, byFrame.get(i) ?? [])), roots[i]!);
      if (p !== null) return p;
    }
    return null;
  });

  // V15 (and V8): the settings hash.
  await check("V15_settings_hash", async () => {
    const settingsJcs = str("V15_settings_jcs");
    return canonicalProblem(settingsJcs, "V15_settings_jcs") ?? eq("settings hash", await H(SETTINGS_DOMAIN, utf8(settingsJcs)), str("V15_settings_hash"));
  });
  await check("V15_settings_hash_empty", async () => eq("settings hash of {}", await H(SETTINGS_DOMAIN, utf8("{}")), str("V15_settings_hash_empty")));
  await check("V8_settings_hash_empty", async () => eq("settings hash of {}", await H(SETTINGS_DOMAIN, utf8("{}")), str("V8_settings_hash_empty")));

  // V16: the doc_id of a git_manifest description.
  await check("V16_git_document_id", async () => {
    const identity = get("V16_git_identity");
    if (!isObject(identity)) return "V16_git_identity is not an object";
    const bytes = utf8(str("V16_git_document_text"));
    const s = (k: string): string => String(identity.get(k));
    const preimage = jcs(["R2R-AUDIT-GIT-DOCUMENT/1", s("repo"), s("commit"), s("path"), s("raw_sha256")]);
    return (
      eq("raw_sha256 of the text", toHex(await adapter.sha256(bytes)), s("raw_sha256")) ??
      eq("size_bytes", String(bytes.length), s("size_bytes")) ??
      eq("the identity preimage", JSON.stringify(preimage), JSON.stringify(str("V16_git_id_preimage_jcs"))) ??
      eq("doc_id", await gitDocumentId(adapter, s("repo"), s("commit"), s("path"), s("raw_sha256")), str("V16_git_document_id"))
    );
  });

  // Names of everything else: skipped, with the reason.
  const covered = new Set(out.map((o) => o.name));
  for (const name of [...vectors.keys()].sort()) {
    if (used.has(name) || covered.has(name) || INPUTS.has(name)) continue;
    if (NOT_RECOMPUTED.test(name)) out.push({ name, status: "SKIP", detail: NOT_RECOMPUTED_REASON });
    else out.push({ name, status: "SKIP", detail: "not known to this verifier" });
  }
  return out;
}

class VectorShapeError extends Error {}

function parseObject(text: string): JsonObject {
  const r = parseJson(text);
  if (!r.ok || !isObject(r.value)) throw new VectorShapeError("not a JSON object: " + (r.ok ? "" : r.error));
  return r.value;
}

/** null when the text is canonical JSON (RFC 8785) as level J0 would require. */
function canonicalProblem(text: string, what: string): string | null {
  const r = parseJson(text);
  if (!r.ok) return `${what} is not JSON: ${r.error}`;
  if (r.badNumber) return `${what} has a number outside the journal's integer range`;
  return jcs(r.value) === text ? null : `${what} is not canonical`;
}

interface V9Frame {
  line: string;
  header: JsonObject;
  body: JsonObject;
  /** hex(H("R2R-FRAME-HDR/2", JCS(header))) */
  hash: string;
  /** hex(H("R2R-FRAME-BODY/2", JCS(body))) */
  bodyHash: string;
}

interface V9Pair {
  n: number;
  before: V9Frame;
  seal: V9Frame;
  P: JsonObject;
  result: JsonObject;
  sealHash: string;
}

async function loadFrame(adapter: HashAdapter, line: string, what: string): Promise<V9Frame> {
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
    bodyHash: toHex(await domainHash(adapter, DOMAIN.frameBody, utf8(jcs(body)))),
  };
}

async function loadV9(
  adapter: HashAdapter,
  str: (name: string) => string,
  get: (name: string) => JsonValue | undefined,
): Promise<V9Pair> {
  const n = get("V9_seal_frame_index");
  if (typeof n !== "number") throw new VectorShapeError("V9_seal_frame_index is not a number");
  const before = await loadFrame(adapter, str("V9_line_frame_n_minus_1"), "V9_line_frame_n_minus_1");
  const seal = await loadFrame(adapter, str("V9_line_seal_frame_n"), "V9_line_seal_frame_n");
  const command = seal.body.get("command");
  const outcome = seal.body.get("outcome");
  const P = isObject(command) ? command.get("seal") : undefined;
  const result = isObject(outcome) ? outcome.get("result") : undefined;
  if (!isObject(P) || !isObject(result)) throw new VectorShapeError("the seal frame has no command.seal or outcome.result");
  const sealHash = toHex(await domainHash(adapter, DOMAIN.seal, utf8(jcs(P))));
  return { n, before, seal, P, result, sealHash };
}

/** J0-11 ... J0-15 on one line of V9, and its hash against the vector. */
function frameProblem(f: V9Frame, position: number, wantHash: string): string | null {
  if (f.header.get("seq") !== position) return `seq is not ${position}`;
  if (f.header.get("wal_op") !== "audit") return "wal_op is not audit";
  if (f.header.get("body_hash") !== f.bodyHash) return "body_hash mismatch";
  if (parseObject(f.line).get("hash") !== f.hash) return "frame hash mismatch";
  return f.hash === wantHash ? null : `frame hash ${f.hash}, expected ${wantHash}`;
}

/**
 * The equalities named in V9_checks (SPEC 12). log_root: with n = 2 the frames
 * 0..n-1 are frame 0, whose hash is header.previous of frame 1, and frame 1.
 */
const V9_CHECKS: Record<string, (p: V9Pair, adapter: HashAdapter) => Promise<boolean>> = {
  "P.log_size == n": async (p) => p.P.get("log_size") === p.n,
  "P.wal_head == hash of frame n-1": async (p) => p.P.get("wal_head") === p.before.hash,
  "P.audit_root == body.audit_root of frame n-1": async (p) => p.P.get("audit_root") === p.before.body.get("audit_root"),
  "P.engine_root == body.engine_root of frame n-1": async (p) => p.P.get("engine_root") === p.before.body.get("engine_root"),
  "body.audit_root of frame n != P.audit_root (the seal receipt)": async (p) => p.seal.body.get("audit_root") !== p.P.get("audit_root"),
  "outcome.result.seal_hash == H(R2R-SEAL/2, JCS(P))": async (p) => p.result.get("seal_hash") === p.sealHash,
  "P.log_root == RFC 6962 root over the hashes of frames 0..n-1": async (p, adapter) => {
    if (p.n !== 2) return false; // two lines carry the hashes of frames 0..n-1 only when n = 2
    const frame0 = p.before.header.get("previous");
    if (typeof frame0 !== "string" || !/^[0-9a-f]{64}$/.test(frame0)) return false;
    const tree = new LogTree(adapter);
    await tree.push(fromHex(frame0));
    await tree.push(fromHex(p.before.hash));
    return p.P.get("log_root") === toHex((await tree.root())!);
  },
};
