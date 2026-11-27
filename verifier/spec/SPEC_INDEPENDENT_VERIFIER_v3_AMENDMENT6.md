# Amendment 6 to the specification of the independent journal verifier, version 3: level J4a, the withdrawal cascade recomputed

OrganeticSphere, 27 November 2026. Written from the kernel code of release 0.3.0. Its rules were checked against the journals in two ways:
- a model built on the J3 engine of `yuce-verify` 0.3.0 computed hashes equal to the seal's on all 138 seals of sets A and D (129 after the answers of 27 November, and 9 the first code round added);
- Codex recomputed them independently, on the 101 seals of those sets in draft 2.

**Status: normative** since 27 November 2026: the architect and Codex passed it. The answers to the clean room's questions SPEC-DEFECT-22 to 25 of the same day are written in: where the fields of J4a go in the report, how a quittance's failure counts, and a reference that does not resolve. Draft 2 answered Codex's review of 27 November 2026 (findings J1–J4 and the vectors). Draft 3 answers his recheck of the same day: the path of a record id in a quittance, one limit of J4a when `--expect-seal` names an earlier seal, and which sample the evidence of P6-4 counts. With draft 4 of the cut specification, set A gains the journals of `V-CUT-18` to `V-CUT-23`, and the counts below follow. It applies together with specification version 3 and amendments 1–5. Where amendment 6 differs from their text, amendment 6 applies.

**Identifier.** Specification version 3 with amendments 1–6 is `SPEC_INDEPENDENT_VERIFIER/8`.

**What the amendment does.** Every seal names the hashes of two projections of the state it seals: `P.projections.status` and `P.projections.dependencies` (specification version 3, section 6.1). Up to amendment 5 the verifier checked their form only, and the report said `not_verified: withdrawal_cascade`. Level **J4a** recomputes both projections at every seal, from the journal and its documents alone, and compares them with the seal. A journal that passes J4a has a cascade the verifier recomputed: which records stand, which fell, and on what.

**What does not change.** The journal format, the root format and the seal format do not change. No input that passed amendment 5 changes its outcome at J0–J3.

**Who implements.** The implementer reads this amendment, the earlier ones and the vectors. They do not read the kernel code. The rules below are written so that this is enough. Where the kernel's form and an equivalent simpler form both exist, the amendment states the simpler one with the argument (P6-4).

---

## P6-1. Level J4a

- J4a runs after J3, and only when J3 passed: it needs the records, anchors, document versions and document bytes of J3.
- It runs over every seal frame with outcome `value`: the frame at position `n` whose body is a seal (specification version 3, section 6.1).
- For each such seal it computes `status` and `dependencies` (P6-8) over **the state after frames `0 … n−1`** and compares them with `P.projections`.

**Failure codes:**
- `PROJECTION_STATUS_MISMATCH` — the computed status hash differs from the seal's;
- `PROJECTION_DEPENDENCIES_MISMATCH` — the computed dependency hash differs.

The failure names the frame `n`. The first failing seal ends J4a, and it counts as compared in `cascade`: the seals before it and the failing one.

**Report.** `levels.J4a` is an object, as for the other levels: `{"result": "PASS"}`, `{"result": "FAIL"}`, or `{"result": "NOT_RUN", "reason": …}` with the reason `J3 not run`, `J3 failed` or `J3 not checkable`. J4a is `NOT_RUN` when an earlier level failed or J3 did not run. Two fields sit at the top level of the report: `cascade`, which is `null` when J4a did not run, and `quittances` (P6-11), which is an empty list without `--quittance`. Three fields of `cascade` say how far the check reached:

| Field | Value |
|---|---|
| `cascade.seals_checked` | the number of seals compared |
| `cascade.checked_through_frame` | the position of the last seal compared, or `null` when none was |
| `cascade.unchecked_frames` | the number of frames after that seal, not counting a close frame right after it. With no seal compared: all frames after frame 0 |

`not_verified` and the human line follow from them:

| Case | `not_verified` | Human line |
|---|---|---|
| J4a `PASS`, at least one seal, `unchecked_frames = 0` | `["signatures"]` | `Cascade: checked at <k> seals. Not verified: signatures.` |
| J4a `PASS`, at least one seal, `unchecked_frames > 0` | `["withdrawal_cascade_after_last_seal", "signatures"]` | `Cascade: checked at <k> seals through frame <n>; <m> later frames not checked. Not verified: …` |
| J4a `PASS` with no seal | `["withdrawal_cascade", "signatures"]` | `Cascade: no seal to check. Not verified: …` |
| J4a `NOT_RUN` or `FAIL` | keeps `withdrawal_cascade` | as before |

- **An open journal.** J4a compares every seal of the file, the last one included. Frames after the last seal are reported as unchecked; they are never presented as checked.
- **`--expect-seal` does not limit J4a.** It stays the anchor check of J1 (specification version 3, section 6.5), and the report gives its place in `anchor.seal` (`at_n`, `frames_after`). When the caller names an earlier seal, J4a still compares every seal of the file, and `cascade` is the same as without the option. To check a journal only up to a seal, give the part up to that seal as a file of its own, as a cut does (`SPEC_CUT_AND_BUNDLE_v1`, B1).
- **Vectors:**
  - `valid/live-server-unsealed-tail.wal`: last seal at frame 3, then records and a withdrawal;
  - `valid/gap-primary-exhausted.wal`: no seal;
  - `j4a/boundary/open-two-seals.wal`: the journal `a` of `V-CUT-1` through its second seal (frame 6), not closed, seals at frames 3 and 6. With and without `--expect-seal` naming the seal of frame 3: `cascade` is `(2, 6, 0)`; with it, `anchor.seal` is `at_n` 3, `frames_after` 3.

**Exit codes** as in specification version 3, section 8.4: a J4a failure is a verification failure.

**Diagnostics.** With the option `--dump-projections <file>` the verifier writes, for each seal, its rows and pairs (P6-8) as JSON. The vectors of P6-10 carry the kernel's rows in the same form.

## P6-2. The state J4a keeps

J3 computes these values while it checks a frame, and need not keep them after the frame. J4a must keep them for the whole journal, for each accepted record, in record order:

| Value | For |
|---|---|
| `id` (64 hex digits) | every record |
| `kind` | every record |
| `grounds`: the resolved `based_on` as full ids, in line order (for an answer: its resolved `answer_ids`) | every record |
| `ends`: `from`, `rel`, `to` as full ids and the relation name | a relation |
| the document name, the exact bytes of `exact_quote`, the anchor id (P3-8), the version id it was bound to, and the span `[start, end)` in that version | an observation |

It also keeps:
- per document name, its current bytes and version id (P3-6, P3-8);
- the frame at which each record was accepted, and the actor of that frame (for the report of `SPEC_OBSERVATION_REPORT`).

**Batch order.** Inside a batch the operations apply one by one, in order, and only those that have a result (P6-3). Inside a `submit` the lines apply in P3-7 order. An accepted relation line creates its link right after its record is appended, before the next line.

J4a adds four things:

| What | Content |
|---|---|
| `revoked` | the set of anchor ids whose evidence is revoked. It only grows |
| `withdrawn[D]` | per document name, the set of byte strings withdrawn from it. It only grows |
| `links` | a table keyed by the triple `(from, rel, to)`: `status` (`proposed` / `accepted` / `rejected`), `basis` (a list of record ids), `acceptance_basis` (a list of record ids or absent) |
| `link_ids` | the map from link id to triple (P6-6) |

## P6-3. Which commands change the state, and when

An effect is applied only if the command ran:

| Case | Applied when |
|---|---|
| a frame | its outcome is `value`, or `records` for `submit` |
| a `submit` with a refused line | its accepted prefix is applied (P3-7) |
| a `batch` | operations `0 … k−1` only, where `k` is the length of the outcome's `results` (P3-4) |

A frame with outcome `error` changes nothing in the state the two projections read. It still exists as a frame with its receipt, and J0–J2 check it as such. Example: `valid/kinds-batch-put.wal`, frame 4: operation 1 of the batch is a `put_document` that ran.

The commands, in the order they occur, operation by operation inside a batch, interleaved with record acceptance in P3-7 order:

| Command | Keys | Effect |
|---|---|---|
| `submit` | as P3-7 | records appended (already in J3). In addition, each accepted record of kind `relation` creates its link (P6-6), at its place among the lines |
| `put_document` | `doc_id`, `text` | new current bytes and version (already in J3). In addition, the re-close step of P6-5 |
| `revoke` | `record`, and under the rules 4 an optional `reason_source_id` | P6-5 |
| `revoke_text` | `doc_id`, `exact_quote`, optional `reason_source_id` (rules 4) | P6-5 |
| `add_link` | `from`, `rel`, `to`, `basis` | P6-6 |
| `set_link_status` | `link`, `status`, `basis`, optional `expected_status`, optional `arbitration` | P6-6 |

- **No other command changes a row or a pair:** `checkpoint` of any key, `seal`, `close`, and the ontology commands (`propose_concept`, `concept_status`, `ontology_unattested`, `ontology_review_keep`, `revise_concept`, `map_term`).
- **Hex case.** `revoke.record`, `set_link_status.link`, and 64-digit references in `add_link` and `basis` may be written in upper case in a valid journal. Lower-case them before lookup.
- **`revoke.record` is a full 64-digit id.** The `@` form of P6-6 is for `add_link` and `basis` only; the kernel refuses it in `revoke`.
- **A reference that does not resolve.** In a journal the kernel accepted, every reference of `revoke`, `add_link` and `set_link_status` resolves: otherwise the command would not have run. If a command with a result still has one that does not resolve, the command changes nothing, and a reference in a basis that names no record is kept as one that is never admissible. Such a forgery shows as a mismatch at the next seal; there is no code of its own, and frames after the last seal are reported as unchecked anyway.

**What J4a does not re-decide.** Admission rules are the kernel's and are visible as outcomes. Among them: four eyes, the version map, scopes and visibility, the check of an answer at acceptance, and that a basis is grounded when it is named. J4a takes the outcomes as written; it never decides whether a command should have been accepted.

## P6-4. When an observation is grounded

An observation `r` is grounded in a state when both hold:
1. its anchor id is not in `revoked`;
2. the current version of its document equals the version it was bound to.

**Why this is the kernel's rule.** The kernel tests three things: an evidence node with status ACTIVE, an existing binding, and an equal version. Here is why those reduce to the two conditions above:
- the binding is written once, at acceptance, and never changes;
- a node's status is set to REVOKED only by the withdrawals of P6-5, and never leaves REVOKED;
- every new version of a document re-evaluates every non-revoked node of that document. A node is ACTIVE exactly when its chunk window occurs, contiguous, in the current chunks;
- when the current version equals the binding version, the current chunks are the ones the anchor was cut from, so the window occurs and the node is ACTIVE.

**Evidence.** A draft model with the form above recomputes both hashes at every seal of sets A and D, on top of the verifier's own J3 record engine. It matches all 138 seals: 115 in set A, 23 in set D (129 before the first code round of 0.3.1 added its journals). Draft 1 named 58 seals, the sets of that draft. The kernel's own recomputation matches the same seals, but it uses the kernel's rule and so is no evidence of the equivalence. A kernel test pins the equivalence over random histories (open point 1).

**Shared evidence.** Two observations share evidence when their anchor ids are equal. Revocation is by anchor id, so every observation on a revoked anchor loses its ground, whatever version it was bound to. The anchor id (P3-8) holds the document name, the quote's hash and length, and per segment the chunk hash and the offsets inside the chunk. It holds neither the version nor the absolute offset, so it can be shared across versions.

**Restoring a version.** Putting back the bytes of an earlier version restores that version's id, and its observations are grounded again, except those the re-close step of P6-5 revokes.

## P6-5. Withdrawals

Every journal J4a can check closes bytes on a withdrawal: the genesis format `r2r-audit-genesis/1`, the only one that does not, occurs only in journals of the format `sbgk-session-log/2`, which have no seals.

**`hits(D, T)`** — the observations bound to document `D` whose bound version equals the current version of `D`, whose anchor id is not in `revoked`, and whose span `[s, e)` overlaps some occurrence `[o, o + |T|)` of `T` in the current bytes of `D`.
- Overlap is strict: `s < o + |T|` and `o < e`. Touching spans do not overlap.
- Every occurrence counts, overlapping occurrences included. An empty `T` occurs nowhere.
- The rule is not transitive: a quote that overlaps only a revoked quote, and no occurrence of `T`, stays.

**`close(D, T, H)`** — add the anchor id of every observation in `H` to `revoked`; add `T` to `withdrawn[D]`.

**`revoke_text {doc_id: D, exact_quote: T}`** that ran: `close(D, T, hits(D, T))`.

**`revoke {record: R}`** that ran, where `R` is an observation with anchor `E`, quote text `T` and document `D`:
1. if `T` is not in `withdrawn[D]`: `H := hits(D, T)`, computed **before** step 2; otherwise `H := ∅`;
2. add `E` to `revoked`;
3. if `T` was not in `withdrawn[D]`: `close(D, T, H)`.

If `R` is bound to an older version, `T` is searched in the current bytes; it may occur nowhere. Then only `E` goes, and `T` is still added to `withdrawn[D]`.

**The re-close step of `put_document {doc_id: D}`.** After the new bytes and version are in place, for each `T` in `withdrawn[D]`: `close(D, T, hits(D, T))`. This is what revokes the quotes of a restored version that overlap a text withdrawn meanwhile. A withdrawn text stays withdrawn in every later version.

## P6-6. Links

**Link id.** `link_id = hex(SHA-256(ASCII("R2R-AUDIT-LINK/1") ‖ JCS([hex(from), rel, hex(to)])))`. **There is no zero byte after the domain here**, unlike every other domain of the journal.

**Creation.** An accepted `relation` record, and an `add_link` command that ran, both name a triple `(from, rel, to)` and a basis:
- **relation record:** `from`, `rel` and `to` are its ends, and the basis is its resolved `based_on`;
- **`add_link`:** the triple is its resolved `from`, `rel` and `to`, and the basis is its resolved `basis`.

If the triple is not in `links`, insert it with status `proposed` and that basis. If it is there, nothing changes: whoever made the triple first fixed its basis.

**`set_link_status {link, status, basis}`** that ran: `link` names a link id. Set the triple's `status` to `status`. If `status` is `accepted`, set its `acceptance_basis` to the resolved `basis`, replacing any earlier one. On `proposed` or `rejected` the old acceptance basis stays, but it matters only while the status is `accepted`.

**References in `add_link` and `basis`.** A 64-digit hex string names a record id. Otherwise the reference is `@` followed by 16 to 64 hex digits that exactly one record accepted so far starts with. Local names never match in these commands.

**What links change.** Only the `established` value of relation records (P6-7), and through it the `grounded` value of an answer that names such a relation, and the `established` value of a relation whose ends are relations. Never a pair.

## P6-7. The support rule

Each record gets two values, `grounded` and `established`, computed **in record order** in one pass: a reference always names an earlier record.

| Kind | `grounded` | `established` |
|---|---|---|
| `observe` | P6-4 | equal to `grounded` |
| `claim` | `based_on` is not empty, and every record in it is grounded. Under the rules 4 a ground may be a claim; the formula is the same | equal to `grounded` |
| `hypothesis` | `based_on` is not empty, and every record in it is grounded | `false` |
| `question` | `false` (a question has no grounds) | `false` |
| `relation` | `based_on` is not empty and every record in it is grounded, and `from` and `to` are grounded | `grounded`, and the triple `(from, rel, to)` is effective, and `from` and `to` are established |
| `done` | `based_on` (its resolved answers) is not empty, and every record in it is grounded and established | `false` |

**Effective link.** A triple is effective when every one of these holds:
- its status is `accepted`;
- `proof(from)` and `proof(to)` hold;
- its `basis` is not empty and `proof` holds for every record in it;
- its `acceptance_basis` exists, is not empty, and `proof` holds for every record in it.

**`proof` and `structural`.** Both are computed in record order:

```
structural(r) = r is observe:  P6-4
                otherwise:     r.kind ≠ done, based_on not empty, structural of every ground,
                               and for a relation structural(from) and structural(to)
proof(r)      = structural(r), r.kind ∉ {hypothesis, question, done},
                proof of every ground, and for a relation proof(from) and proof(to)
```

When no link has status `accepted`, no triple is effective, and `proof` need not be computed.

**Under the rules 4**, `about_record` of a question is not a ground. It adds nothing to the support of any record and is not a pair.

## P6-8. Rows, pairs and their hashes

**Status rows**, one per record, **in record order** (never sorted):

```
row = [hex(id), kind, grounded, established, fallen_by]
```

- `kind` is one of `observe`, `claim`, `relation`, `hypothesis`, `question`, `done`.
- `fallen_by` is the list of the record's direct grounds whose **`grounded`** value (not `established`) is `false`, written as `hex(id)`, sorted ascending as strings, duplicates removed.
- A record's direct grounds are its `based_on`, followed, for a relation, by `from` and `to`.
- An observation and a question always have `[]`.
- An answer can be not grounded with an empty `fallen_by`: an answer record that is grounded but not established makes it fall without being listed.

```
status = hex(H("R2R-PROJ-STATUS/2", JCS(rows)))
```

**Dependency pairs.** One pair `[hex(record), hex(ground)]` for every record, standing or not, and every one of its direct grounds as above. Pairs are sorted by the 128-character string `hex(record) ‖ hex(ground)`, and exact duplicates are removed.

```
dependencies = hex(H("R2R-PROJ-DEPS/2", JCS(pairs)))
```

- Builder links (`add_link`), `about_record` and evidence are not pairs.
- For a run with no record:
  - `status = 88f19ee44d285b626e63507ebd361e8ce71ccc967e93d303dad85d908ac5a875`;
  - `dependencies = 65ec2af34b368787092fa5d7b6e498b243c7b7eaedf11eb45f3033fd5ba49133`.

## P6-9. Traps

1. Rows in record order, pairs sorted.
2. `fallen_by` reads `grounded`.
3. A refused command leaves either a frame with outcome `error` or no frame at all. Neither changes the state.
4. Inside a batch, apply exactly the operations that have a result.
5. Withdrawals and `put_document` read the current version and the records that exist at that moment. Run them at their place.
6. Revoke by anchor id, not by record.
7. The link-id domain has no zero byte.
8. Compute a seal's projections over the state **before** the seal frame. A seal frame changes no record, link, evidence or document.
9. Compare only seals with outcome `value`.

## P6-10. Vectors

All under `verifier/inputs/`; `j4a/expected.json` gives the expected answer of each.

| Set | What | Expected |
|---|---|---|
| A. Sealed journals that pass J0–J3 | `valid/` and `cut/` (the bundles of `SPEC_CUT_AND_BUNDLE`): 58 journal paths, 57 of them sealed, 25 sealed ones distinct by SHA-256, 115 seals; k017 alone has 35 seals and 2,314 records. In draft 1 the set held 18 sealed paths with 57 seals, and in draft 2 34 sealed paths with 81 seals; Codex recomputed both. The journals of `V-CUT-25` and `V-CUT-26` joined after the first code round of 0.3.1 | every seal: J4a recomputes its own `P.projections`; `cascade` as P6-1 |
| A′. Journals that fail earlier | `boundary/auto-seal-ack.wal` (J1 `KERNEL_ID_MISUSE`, frame 1), `boundary/nested-seal.wal` (J2 `KERNEL_OP_IN_BATCH`, frame 2) | the earlier failure, J4a `NOT_RUN` |
| B. Kernel rows | `j4a/rows/`: for each distinct journal of A and of D, the kernel's rows and pairs at each seal, in the form of `--dump-projections`. k017 is compressed (`.rows.json.gz`). A journal that is a byte copy of another names that other's file in `expected.json` | for finding the first differing row when a hash differs |
| C. A forged cascade | `j4a/set-c/forged-cascade.wal`: made from `cut/V-CUT-1/a`; in its last seal the fallen claim is written as standing, and every later hash is recomputed (seal hash, frame hashes) | J0–J3 `PASS`; J4a `FAIL`, `PROJECTION_STATUS_MISMATCH` at frame 6 (the dependency hash is unchanged) |
| D. Rules no journal of A exercises | `j4a/set-d/`, sealed journals written by the kernel: d1 `revoke` taking other overlapping quotes; d2 a withdrawn text with several occurrences; d3 a version put back, its quotes coming back and the re-close taking one; d4 an anchor shared across two versions; d5 a repeated ground; d6 a relation proposed, accepted with a separate quote as its acceptance basis, an answer resting on it, that quote withdrawn (relation `[grounded, not established]`, answer `[false, false, []]`), the link rejected; d7 an old version quoted, the same text withdrawn in a new version with no live quote, then the old quote revoked by name (its root cause is `revoked`); d8 and d9, made in the first code round (below) | every seal: equal to its own `P.projections`; 9 journals, 23 seals |
| E. Quittances | `j4a/set-e/`, cut from `cut/V-CUT-1/a` at its last seal with a throwaway test key: E1 with `status`, E2 without, E3 = E1 with the status row of its target written as not standing, E4 cut from another journal | E1, E2 pass; E3 `QUITTANCE_STATUS_MISMATCH`; E4 `QUITTANCE_SEAL_UNKNOWN` |

- Sets d1–d5, the bundles and set E are written with `sbgk` 0.3.0 (`audit-stream`, `audit-sign`, `audit-proof`).
- d6 and d7 are Codex's probes of 27 November, written by the kernel and accepted by `sbgk audit-verify`.

**Made in the first code round**, written through the library and published with the kernel's rows (`j4a/rows/`):
- `j4a/set-d/d8-batch-prefix-put-not-applied.wal`: a batch whose `submit` keeps an accepted prefix and whose next operation, a `put_document` of a new version of the quoted document, has no result (P6-3). Applying that put would make the quote and the claim on it fall; both seals say they stand. A test of the kernel writes the journal and fails if the kernel no longer writes those bytes;
- `j4a/set-d/d9-refused-and-late-answers.wal`: a reading written by the dispatcher with two answers refused (one in part, one whole) and two answers sent after the task was closed, each a checkpoint of a batch of the kernel that changes no row: the journal of the counters `rejected_submissions` and `late_submissions` of the observation report. A task id holds a nonce of its dispatcher, so its test checks the published file and does not write it again;
- the journals of the bundles `V-CUT-25` and `V-CUT-26` (`SPEC_CUT_AND_BUNDLE_v1`, B3.2).

The draft model recomputes both hashes at every seal the first code round added: 9 seals, 6 in set A (the four journals of `V-CUT-25` and `V-CUT-26`) and 3 in set D (d8 and d9). `j4a/expected.json` lists them, and the counts of sets A and D above include them.

**Internal acceptance.** On the kernel's side, 51 archived journals with 573 seals were replayed by the 0.3.0 kernel: every seal's projections equal the kernel's recomputation. They are not published; the verifier is run on them before the release.

## P6-11. A quittance given with the journal

A quittance (`yuce-proof/1`) is cut from a journal at one of its seals, only for a record that stands there. J4a reads four of its fields:

| Field | What |
|---|---|
| `target` | the record id |
| `records` | the target and the records it rests on. Each element is an object `{frame, index, path, value}`; J4a reads only `value.id`, the record id. The other keys are for the inclusion check |
| `seal.header`, `seal.body` | the header and the body of the seal frame, in the form of a journal line (specification version 3, J0-9 and section 6.1). `seal.header` has exactly the keys `body_hash`, `format`, `previous`, `records_root`, `seq`, `wal_op` |
| `status` | the status rows of that seal (optional) |

Everything else in it — the inclusion paths, the frames, the checkpoint and its signature, the documents and evidence of a self-contained quittance — is the quittance's own check (`sbgk audit-proof-verify`), not J4a's.

**The check.** With the option `--quittance <file>` (repeatable), for each quittance, in this order:
1. **Form.** `format` is `"yuce-proof/1"`; `target` is a 64-digit id; `records` is a non-empty list of objects, each with an object `value` whose `id` is a 64-digit id; the target is one of those ids; `seal.header` is an object with the six keys above; `seal.body` is a seal body: the body of a frame of section 6.1 of specification version 3 with `actor = "kernel"` and `command.kind = "seal"`, that passes the form and types of J1-1 (among them `outcome.result` with exactly `seal` and `seal_hash`). Otherwise `QUITTANCE_FORM`. This is checked before the journal is looked at: a malformed body is never `QUITTANCE_SEAL_UNKNOWN`.
2. **Which journal and which seal.** The journal is the one given in the same call. The seal is the frame at position `n = seal.body.command.seal.log_size`: the journal must have a seal frame with outcome `value` there, whose `header` and `body` are equal to the quittance's `seal.header` and `seal.body` as JSON values. Otherwise `QUITTANCE_SEAL_UNKNOWN`. The check needs J4a to pass up to that seal.
3. **Status.** Every `records[i].value.id`, the target among them, has `grounded = true` in the rows J4a computed at that seal. Otherwise `QUITTANCE_STATUS_MISMATCH`, naming the first such id in record order.
4. **Status rows.** If `status` is present, it equals those rows, row for row. Otherwise `QUITTANCE_STATUS_MISMATCH`, naming the first differing row.

**Report.**
- Each quittance gets `{"file": …, "verdict": "PASS" | "FAIL", "code": …}` under `quittances`. `code` is `null` with `PASS`.
- `not_verified` gains `quittance_inclusion` whenever a quittance was given, since J4a does not check the inclusion paths. It goes just before `signatures`, which stays.
- **A quittance that fails** makes J4a `FAIL` and the verdict `FAIL`, exit code 1. `first_failure` is `{"level": "J4a", "frame": null, "code": "QUITTANCE_…"}`. Quittances are checked after the last frame, in the order of the options; when every seal agreed, the first failing quittance is the first failure.
- **A quittance that was not checked**, because J4a did not run or failed at or before the quittance's seal, gets `"verdict": "NOT_RUN"` and `"code": null`.

The acceptance matrix is set E: a correct quittance with status, one without, one with a wrong status, one from another journal, and E5, the first with `seal.body.outcome.result` taken out (`QUITTANCE_FORM`).

## P6-12. Open points

1. *(Done in the first code round of 0.3.1.)* **The equivalence of P6-4.** A kernel test pins it over the kernel's random histories (`a_put_document_keeps_the_flags_and_the_indices_a_whole_pass_computes` in `crates/sbgk-core/src/audit/state/stream_tests.rs`): after every command of ten histories of sixty commands each (new documents, new versions and earlier bytes again, quotes, withdrawals by record and by text, a put inside a batch), every observation is grounded by the kernel's rule exactly when it is grounded by P6-4; a binding never changes; an anchor once revoked stays revoked. The histories are the kernel's own and small: the test is evidence of the equivalence on them, not a proof. The argument of P6-4 and the draft model's 138 seals of sets A and D stand beside it.
2. **A seal frame with outcome `error`.** The kernel can replay one; J1-1 refuses it as `SEAL_FORM`. No change is proposed; J4a compares only seals with outcome `value`.

**Decided in review** (architect, 27 November 2026):
- J4a compares with the seal itself;
- a quittance given with the journal is checked against the recomputed rows (P6-11).
