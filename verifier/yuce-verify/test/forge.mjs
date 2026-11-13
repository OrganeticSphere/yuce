#!/usr/bin/env node
// The forger (task statement, acceptance A6): changes a value in a journal and recomputes
// every hash again, the seals included, so that the result is internally
// consistent. Levels J0-J1 must accept such a journal: only a seal kept out of
// the writer's reach (--expect-seal) or a separately kept head (--expect-head)
// can tell it from the original.
//
// It does not know, and does not recompute, values outside levels J0-J1
// (body.request_hash, header.records_root): their formulas are not in the
// specification of delivery 1.
//
// Library: loadFrames, saveFrames, rechain, getPath, setPath.
// Command line:
//   node test/forge.mjs <in.wal> <out.wal> <frame> <path> <json-value>
//   e.g. node test/forge.mjs in.wal out.wal 1 body.command.lines.0.exact_quote '"Forged."'
import { readFileSync, writeFileSync } from "node:fs";
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
 *   - resealHash: for kernel seals, copies command.seal into outcome.result.seal
 *     and recomputes seal_hash from it;
 *   - reseal: also recomputes the seal's log_size, log_root, wal_head,
 *     audit_root, engine_root and submission_id from the frames before it
 *     (implies resealHash).
 */
export async function rechain(frames, { reseal = false, resealHash = false, renumber = false } = {}) {
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
    header.set("previous", k === 0 ? yv.ZERO_HASH : hashes[k - 1]);
    header.set("body_hash", await H(yv.DOMAIN.frameBody, yv.jcs(body)));
    const hash = await H(yv.DOMAIN.frameHeader, yv.jcs(header));
    frame.set("hash", hash);
    hashes.push(hash);
  }
  return frames;
}

/** Changes one value and recomputes everything, seals included. */
export async function forge(text, frameIndex, path, value) {
  const frames = loadFrames(text);
  setPath(frames[frameIndex], path, value);
  await rechain(frames, { reseal: true });
  return saveFrames(frames);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [input, output, frame, path, json] = process.argv.slice(2);
  if (json === undefined) {
    console.error("usage: node test/forge.mjs <in.wal> <out.wal> <frame> <path> <json-value>");
    process.exit(2);
  }
  const forged = await forge(readFileSync(input, "utf8"), Number(frame), path, parseLine(json));
  writeFileSync(output, forged);
  console.log(`forged ${output}: frame ${frame}, ${path} = ${json}; all hashes and seals recomputed`);
}
