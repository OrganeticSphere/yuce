// The verification report (SPEC section 8): JSON form, human line, exit code.

import { fromPlain, jcs } from "./json.ts";

export const VERIFIER_NAME = "yuce-verify";
export const VERIFIER_VERSION = "0.1.3";
/** SPEC v3 with amendments 1 and 2. */
export const SPEC_ID = "SPEC_INDEPENDENT_VERIFIER/4";

/** What delivery 1 does not check (SPEC 8.1, `not_verified`). */
export const NOT_VERIFIED = ["quotes_against_sources", "withdrawal_cascade", "signatures"] as const;

export type FailureLevel = "J0" | "J1";

export interface Failure {
  level: FailureLevel;
  /** Frame position; null for failures of the file as a whole. */
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
  input: { journal_sha256: string; bytes: number; frames: number; format: string | null };
  levels: {
    J0: { result: "PASS" | "FAIL" };
    J1: J1Level;
    J2: { result: "NOT_CHECKED" };
    J3: { result: "NOT_CHECKED" };
    J5: { result: "NOT_CHECKED" };
  };
  anchor: Anchor;
  computed: { wal_head: string | null; closed: boolean | null };
  not_verified: string[];
  verdict: Verdict;
  first_failure: Failure | null;
}

/**
 * SPEC 8.2: FAIL if any level failed, else PASS. INCOMPLETE (a requested level
 * NOT_CHECKABLE without any FAIL) is reserved for delivery 2 (SPEC 8.4).
 */
export function computeVerdict(results: readonly string[]): Verdict {
  if (results.includes("FAIL")) return "FAIL";
  if (results.includes("NOT_CHECKABLE")) return "INCOMPLETE";
  return "PASS";
}

/** The report as printed: JCS of the JSON value (SPEC 8.1). */
export function reportToJcs(report: Report): string {
  return jcs(fromPlain(report as unknown as Parameters<typeof fromPlain>[0]));
}

const NOT_VERIFIED_SENTENCE = "Not verified: quotes against sources, withdrawal cascade, signatures.";

/** The line for a human (SPEC 8.3), built only from fixed parts. */
export function humanLine(report: Report): string {
  const parts: string[] = [];
  const f = report.first_failure;
  if (report.verdict === "FAIL" && f !== null) {
    parts.push(f.frame === null ? `FAIL at ${f.level}: ${f.code}.` : `FAIL at ${f.level}, frame ${f.frame}: ${f.code}.`);
  } else if (report.levels.J1.result === "PASS") {
    const j1 = report.levels.J1;
    parts.push(`J0-J1 PASS. Frames: ${report.input.frames}. Seals: ${j1.seals.length}.`);
    parts.push(tailSentence(j1.tail));
    parts.push(anchorSentence(report.anchor, report.input.frames));
  } else {
    // Not reachable in delivery 1 (SPEC 8.4).
    parts.push(`${report.verdict}.`);
  }
  parts.push(NOT_VERIFIED_SENTENCE);
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

/** Exit codes, SPEC 8.4 and the task statement, section 4. Code 3 is reserved for delivery 2. */
export const EXIT = { pass: 0, fail: 1, usage: 2, notCheckable: 3 } as const;

export function exitCodeFor(verdict: Verdict): number {
  if (verdict === "PASS") return EXIT.pass;
  if (verdict === "FAIL") return EXIT.fail;
  return EXIT.notCheckable;
}
