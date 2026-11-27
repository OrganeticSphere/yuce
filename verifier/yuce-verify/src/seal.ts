// The form and types of a seal (SPEC 6.1 and 6.3, rule J1-1), shared by level
// J1 and by the check of a quittance's seal body (amendment 6, P6-11, step 1).

import type { JsonValue } from "./json.ts";
import { hasExactKeys, isHashText, isObject } from "./json.ts";

export const SEAL_KEYS = ["audit_root", "engine_root", "format", "log_root", "log_size", "projections", "run_id", "wal_head"] as const;
export const SEAL_HASH_FIELDS = ["log_root", "wal_head", "audit_root", "engine_root"] as const;
export const PROJECTION_KEYS = ["dependencies", "status"] as const;

/** J1-1: why the command and outcome of a seal candidate fail the form and types, or null when they pass. */
export function sealFormProblem(command: JsonValue | undefined, outcome: JsonValue | undefined): string | null {
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
