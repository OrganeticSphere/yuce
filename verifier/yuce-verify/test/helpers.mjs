// Shared helpers for the tests. Everything is tested through the built
// delivery file dist/yuce-verify.mjs.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as yv from "../dist/yuce-verify.mjs";

export { yv };

export const ROOM = fileURLToPath(new URL("../../", import.meta.url));
export const BUNDLE = fileURLToPath(new URL("../dist/yuce-verify.mjs", import.meta.url));
export const room = (p) => fileURLToPath(new URL(`../../${p}`, import.meta.url));
export const fixture = (p) => fileURLToPath(new URL(`./fixtures/${p}`, import.meta.url));

export const adapter = await yv.nodeHashAdapter();
export const EXPECTED = JSON.parse(readFileSync(room("inputs/expected.json"), "utf8"));
export const SMALL = "inputs/valid/withdrawal-version-close.wal";

export const readBytes = (p) => new Uint8Array(readFileSync(p));
export const readRoom = (p) => readBytes(room(p));

const enc = new TextEncoder();
const dec = new TextDecoder();
export const bytesOf = (s) => (typeof s === "string" ? enc.encode(s) : s);
export const textOf = (b) => dec.decode(b);

/** Runs levels J0-J1 in-process on a byte string or text. */
export async function verify(input, options = {}) {
  return yv.verifyJournal([bytesOf(input)], options, adapter);
}

/** The lines of a journal text, without their LF. */
export function linesOf(text) {
  const lines = text.split("\n");
  if (lines[lines.length - 1] !== "") throw new Error("journal does not end with LF");
  lines.pop();
  return lines;
}

export const joinLines = (lines) => lines.map((l) => l + "\n").join("");

/** Short summary of a report: verdict, code, level, frame. */
export function outcome(report) {
  const f = report.first_failure;
  return f === null
    ? { verdict: report.verdict }
    : { verdict: report.verdict, level: f.level, code: f.code, frame: f.frame };
}

export const OTHER_HASH = "ab".repeat(32);
