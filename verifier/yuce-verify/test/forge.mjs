#!/usr/bin/env node
// The forger (acceptance A6 and B4): changes a value in a journal and
// recomputes everything it knows, so that the result is internally consistent.
//
// - Delivery 1: every frame hash and the seals. Levels J0-J1 accept the result.
// - Delivery 2 (the task statement, B4): also request_hash (J2) and, with the documents,
//   the record ids, the anchors and the records root of every frame by the
//   formulas of amendment 3 (`rewriteRecords`). Levels J0-J2 accept the result;
//   J3 catches it when a changed quote is not in its source. A quote replaced by
//   another phrase that occurs once in the same document passes J0-J3: only an
//   external seal or head can tell it from the original.
// - Delivery 3 (amendment 6): with the documents, also the projections every
//   seal names, recomputed by the verifier's own cascade (`rewriteProjections`).
//   The same-document replacement then passes J0-J4a as well.
//
// Library: loadFrames, saveFrames, rechain, getPath, setPath, forge,
//          rewriteRecords, rewriteProjections, originalEvidence, forgeWithRecords, readDocs.
// Command line:
//   node test/forge.mjs <in.wal> <out.wal> <frame> <path> <json-value> [--docs <folder>]
//   e.g. node test/forge.mjs in.wal out.wal 1 body.command.lines.0.exact_quote '"Forged."' --docs in.docs
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as yv from "../dist/yuce-verify.mjs";

const adapter = await yv.nodeHashAdapter();

export function parseLine(line) {
  const r = yv.parseJson(line);
  if (!r.ok) throw new Error(r.error);
  return r.value;
}

export const clone = (v) => parseLine(yv.jcs(v));

/** Parsed frames (Maps) of a journal text. */
export function loadFrames(text) {
  const lines = text.split("\n");
  if (lines.pop() !== "") throw new Error("journal does not end with LF");
  return lines.map(parseLine);
}

/** Canonical journal text of the frames. */
export function saveFrames(frames) {
  return frames.map((f) => yv.jcs(f) + "\n").join("");
}

/** Every regular file of a folder and its subfolders, as bytes. */
export function readDocs(dir) {
  return readdirSync(dir)
    .sort()
    .flatMap((name) => {
      const p = join(dir, name);
      return statSync(p).isDirectory() ? readDocs(p) : [new Uint8Array(readFileSync(p))];
    });
}

function step(container, key) {
  if (Array.isArray(container)) return container[Number(key)];
  if (container instanceof Map) return container.get(key);
  throw new Error(`cannot step into ${typeof container} with ${key}`);
}

/** Value at a dotted path such as "body.command.seal.log_size". */
export function getPath(root, path) {
  return path.split(".").reduce(step, root);
}

export function setPath(root, path, value) {
  const keys = path.split(".");
  const last = keys.pop();
  const parent = keys.reduce(step, root);
  if (Array.isArray(parent)) parent[Number(last)] = value;
  else parent.set(last, value);
}

const H = async (domain, text) => yv.toHex(await yv.domainHash(adapter, domain, yv.utf8(text)));

function isKernelSeal(body) {
  const command = body.get("command");
  return body.get("actor") === "kernel" && command instanceof Map && command.get("kind") === "seal";
}

/**
 * Recomputes hashes in place, frame by frame:
 *   - always: header.previous, header.body_hash, hash (and header.seq if renumber);
 *   - requestHash (default true): body.request_hash of frames i >= 1 (amendment 3, P3-3);
 *   - resealHash: for kernel seals, copies command.seal into outcome.result.seal
 *     and recomputes seal_hash from it;
 *   - reseal: also recomputes the seal's log_size, log_root, wal_head,
 *     audit_root, engine_root and submission_id from the frames before it
 *     (implies resealHash).
 */
export async function rechain(frames, { reseal = false, resealHash = false, renumber = false, requestHash = true } = {}) {
  const hashes = [];
  for (let k = 0; k < frames.length; k++) {
    const frame = frames[k];
    const header = frame.get("header");
    const body = frame.get("body");
    if (renumber) {
      header.set("seq", k);
      header.set("wal_op", k === 0 ? "genesis" : "audit");
    }
    if (body instanceof Map && isKernelSeal(body) && (reseal || resealHash)) {
      const seal = body.get("command").get("seal");
      if (reseal && k > 0) {
        const before = frames[k - 1].get("body");
        seal.set("log_size", k);
        body.set("submission_id", `seal-${k}`);
        seal.set("log_root", yv.toHex(await yv.logRootRecursive(adapter, hashes.map(yv.fromHex))));
        seal.set("wal_head", hashes[k - 1]);
        // A missing root stays as it was in the seal (J1-7 then refuses it).
        if (before.has("audit_root")) seal.set("audit_root", before.get("audit_root"));
        if (before.has("engine_root")) seal.set("engine_root", before.get("engine_root"));
      }
      const result = body.get("outcome").get("result");
      result.set("seal", clone(seal));
      result.set("seal_hash", await H(yv.DOMAIN.seal, yv.jcs(seal)));
    }
    if (requestHash && k > 0 && body instanceof Map && body.has("actor") && body.has("command") && body.has("request_hash")) {
      body.set("request_hash", await yv.requestHash(adapter, body.get("actor"), body.get("command")));
    }
    header.set("previous", k === 0 ? yv.ZERO_HASH : hashes[k - 1]);
    header.set("body_hash", await H(yv.DOMAIN.frameBody, yv.jcs(body)));
    const hash = await H(yv.DOMAIN.frameHeader, yv.jcs(header));
    frame.set("hash", hash);
    hashes.push(hash);
  }
  return frames;
}

/** Evidence of every record of a valid journal, by record id (J3 of the verifier, read only). */
export async function originalEvidence(frames, files) {
  const engine = new yv.RecordEngine(adapter, await yv.indexDocuments(files, adapter));
  const g = await engine.genesis(frames[0].get("body"));
  if (g !== null) throw new Error(`genesis: ${JSON.stringify(g)}`);
  for (let k = 1; k < frames.length; k++) {
    const f = await engine.frame(frames[k].get("header"), frames[k].get("body"));
    if (f !== null) throw new Error(`frame ${k}: ${JSON.stringify(f)}`);
  }
  return new Map(engine.accepted.filter((r) => r.evidence !== null).map((r) => [r.id, r.evidence]));
}

/**
 * Rewrites, in place, the record ids in the outcomes, the "@" references in the
 * lines, put_document versions and the records root of every frame, by the
 * formulas of amendment 3. A changed quote that is no longer found keeps the
 * evidence of the original record (from `evidence`, by its original id).
 */
export async function rewriteRecords(frames, files, evidence = new Map(), collect = null) {
  const engine = new yv.RecordEngine(adapter, await yv.indexDocuments(files, adapter), { originalEvidence: evidence });
  const g = await engine.genesis(frames[0].get("body"));
  if (g !== null) throw new Error(`genesis: ${JSON.stringify(g)}`);
  for (let k = 1; k < frames.length; k++) {
    const f = await engine.frame(frames[k].get("header"), frames[k].get("body"));
    if (f !== null) throw new Error(`the forger cannot rewrite frame ${k}: ${JSON.stringify(f)}`);
  }
  // The evidence of every record by its new id, for rewriteProjections.
  if (collect !== null) for (const r of engine.accepted) if (r.evidence !== null) collect.set(r.id, r.evidence);
  return frames;
}

/**
 * Delivery 3 (amendment 6): rewrites, in place, the projections every seal
 * names (status and dependencies) with the cascade the verifier's own J3/J4a
 * engine computes over the frames before the seal. Run after rewriteRecords and
 * before rechain, which then rehashes the seals.
 */
export async function rewriteProjections(frames, files, evidence = new Map()) {
  // A changed quote that is no longer found keeps the evidence of the original record, as in rewriteRecords.
  const engine = new yv.RecordEngine(adapter, await yv.indexDocuments(files, adapter), { originalEvidence: evidence }, true);
  const g = await engine.genesis(frames[0].get("body"));
  if (g !== null) throw new Error(`genesis: ${JSON.stringify(g)}`);
  for (let k = 1; k < frames.length; k++) {
    const body = frames[k].get("body");
    if (isKernelSeal(body)) {
      const st = await engine.cascade.status();
      const projections = body.get("command").get("seal").get("projections");
      projections.set("status", st.status);
      projections.set("dependencies", st.dependencies);
    }
    const f = await engine.frame(frames[k].get("header"), body, k);
    if (f !== null) throw new Error(`the forger cannot replay frame ${k}: ${JSON.stringify(f)}`);
  }
  return frames;
}

/** Changes one value and recomputes the frame hashes, request hashes and seals (no documents). */
export async function forge(text, frameIndex, path, value) {
  const frames = loadFrames(text);
  setPath(frames[frameIndex], path, value);
  await rechain(frames, { reseal: true });
  return saveFrames(frames);
}

/**
 * Changes one value and recomputes everything, records and records roots
 * included (B4), and, unless `projections` is false, the projections of every
 * seal (delivery 3, amendment 6).
 */
export async function forgeWithRecords(text, files, frameIndex, path, value, { projections = true } = {}) {
  const evidence = await originalEvidence(loadFrames(text), files);
  const frames = loadFrames(text);
  setPath(frames[frameIndex], path, value);
  const rewritten = new Map();
  await rewriteRecords(frames, files, evidence, rewritten);
  if (projections) await rewriteProjections(frames, files, rewritten);
  await rechain(frames, { reseal: true });
  return saveFrames(frames);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const d = args.indexOf("--docs");
  const docs = d >= 0 ? args.splice(d, 2)[1] : undefined;
  const [input, output, frame, path, json] = args;
  if (json === undefined) {
    console.error("usage: node test/forge.mjs <in.wal> <out.wal> <frame> <path> <json-value> [--docs <folder>]");
    process.exit(2);
  }
  const text = readFileSync(input, "utf8");
  const forged =
    docs === undefined
      ? await forge(text, Number(frame), path, parseLine(json))
      : await forgeWithRecords(text, readDocs(docs), Number(frame), path, parseLine(json));
  writeFileSync(output, forged);
  console.log(`forged ${output}: frame ${frame}, ${path} = ${json}; hashes, request hashes and seals recomputed${docs === undefined ? "" : ", records and records roots too"}`);
}
