// The verification report (SPEC section 8, as amendment 3, P3-10, and
// amendment 6, P6-1 and P6-11, change it): JSON form, human line, exit code.

import { fromPlain, jcs } from "./json.ts";

export const VERIFIER_NAME = "yuce-verify";
export const VERIFIER_VERSION = "0.3.1";
/** SPEC v3 with amendments 1 ... 6. */
export const SPEC_ID = "SPEC_INDEPENDENT_VERIFIER/8";

/** What is not verified when J3 did not pass (SPEC 8.1, `not_verified`). */
export const NOT_VERIFIED = ["quotes_against_sources", "withdrawal_cascade", "signatures"] as const;
/** What is not verified when J3 passed (P3-10). */
export const NOT_VERIFIED_AFTER_J3 = ["withdrawal_cascade", "signatures"] as const;

export type FailureLevel = "J0" | "J1" | "J2" | "J3" | "J4a";

export interface Failure {
  level: FailureLevel;
  /** Frame position; null only for EMPTY_JOURNAL, HEAD_MISMATCH, ANCHOR_NOT_FOUND and the failures of a quittance. */
  frame: number | null;
  code: string;
  detail: string;
}

export interface SealEntry {
  n: number;
  seal_hash: string;
}

export type Tail =
  | { kind: "no_seals" }
  | { kind: "sealed" | "closed" | "unsealed"; frames_after_last_seal: number };

export type J1Level =
  | { result: "PASS"; seals: SealEntry[]; tail: Tail }
  | { result: "FAIL" }
  | { result: "NOT_CHECKABLE"; reason: string };

export type J2Level =
  | { result: "PASS"; documents: number; settings_hash: string }
  | { result: "FAIL" }
  | { result: "NOT_CHECKABLE"; reason: string };

export type J3Level =
  | { result: "PASS"; records: number; quotes: number }
  | { result: "FAIL" }
  | { result: "NOT_CHECKED" }
  | { result: "NOT_CHECKABLE"; reason: string };

/** Amendment 6, P6-1. */
export type J4aLevel = { result: "PASS" } | { result: "FAIL" } | { result: "NOT_RUN"; reason: string };

/** Amendment 6, P6-1: how far the cascade check reached. */
export interface CascadeReach {
  seals_checked: number;
  checked_through_frame: number | null;
  unchecked_frames: number;
}

/** Amendment 6, P6-11: the outcome of one quittance (NOT_RUN when J4a did not reach its seal). */
export interface QuittanceResult {
  file: string;
  verdict: "PASS" | "FAIL" | "NOT_RUN";
  code: string | null;
}

/** SPEC 8.2: anchor.seal. */
export type SealAnchor =
  | { given: false; matched: null }
  | { given: true; matched: true; at_n: number; frames_after: number }
  | { given: true; matched: false | null };

/** SPEC 8.2: anchor.head. */
export type HeadAnchor = { given: false; matched: null } | { given: true; matched: boolean | null };

export interface Anchor {
  seal: SealAnchor;
  head: HeadAnchor;
}

export type Verdict = "PASS" | "FAIL" | "INCOMPLETE";

export interface Report {
  verifier: { name: string; version: string; spec: string };
  input: {
    journal_sha256: string;
    bytes: number;
    frames: number;
    format: string | null;
    sources: { given: false } | { given: true; files: number };
  };
  levels: {
    J0: { result: "PASS" | "FAIL" };
    J1: J1Level;
    J2: J2Level;
    J3: J3Level;
    J4a: J4aLevel;
    J5: { result: "NOT_CHECKED" };
  };
  /** Amendment 6, P6-1: null when J4a did not run. */
  cascade: CascadeReach | null;
  /** Amendment 6, P6-11: one entry per --quittance, in the order given. */
  quittances: QuittanceResult[];
  anchor: Anchor;
  computed: { wal_head: string | null; closed: boolean | null };
  not_verified: string[];
  verdict: Verdict;
  first_failure: Failure | null;
}

/** The report as printed: JCS of the JSON value (SPEC 8.1). */
export function reportToJcs(report: Report): string {
  return jcs(fromPlain(report as unknown as Parameters<typeof fromPlain>[0]));
}

/** The sentence of not_verified: its items in order, underscores written as spaces. */
function notVerifiedSentence(items: readonly string[]): string {
  return `Not verified: ${items.map((s) => s.replaceAll("_", " ")).join(", ")}.`;
}

/** Amendment 6, P6-1: the sentence of the cascade, for J4a PASS. */
function cascadeSentence(c: CascadeReach): string {
  if (c.checked_through_frame === null) return "Cascade: no seal to check.";
  if (c.unchecked_frames === 0) return `Cascade: checked at ${c.seals_checked} seals.`;
  return `Cascade: checked at ${c.seals_checked} seals through frame ${c.checked_through_frame}; ${c.unchecked_frames} later frames not checked.`;
}

/** The line for a human (SPEC 8.3, P3-10, P6-1), built only from fixed parts. */
export function humanLine(report: Report): string {
  const parts: string[] = [];
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
    // Not reachable: a verdict other than FAIL means J0-J2 passed.
    parts.push(`${report.verdict}.`);
  }
  parts.push(notVerifiedSentence(report.not_verified));
  return parts.join(" ");
}

function tailSentence(tail: Tail): string {
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

function anchorSentence(anchor: Anchor, frames: number): string {
  const seal = anchor.seal.matched === true ? anchor.seal : null;
  const head = anchor.head.matched === true;
  if (seal !== null && head) return `Anchor: matched seal at n=${seal.at_n} and head at n=${frames}.`;
  if (seal !== null) return `Anchor: matched seal at n=${seal.at_n}.`;
  if (head) return `Anchor: matched head at n=${frames}.`;
  return "Anchor: not given - journal is internally consistent; authenticity not established.";
}

/** Exit codes (P3-10, TZ v4 section 4): 0 PASS, 1 FAIL, 2 call or read error, 3 INCOMPLETE. */
export const EXIT = { pass: 0, fail: 1, usage: 2, incomplete: 3 } as const;

export function exitCodeFor(verdict: Verdict): number {
  if (verdict === "PASS") return EXIT.pass;
  if (verdict === "FAIL") return EXIT.fail;
  return EXIT.incomplete;
}
