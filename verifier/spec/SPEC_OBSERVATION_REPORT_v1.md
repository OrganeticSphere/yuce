# Specification of the observation report (`yuce-observation-report/1`), draft 2

OrganeticSphere, 27 November 2026.

**Status: normative** since 27 November 2026: the architect and Codex passed it. The counters `rejected_submissions` and `late_submissions` follow the architect's choice of the same day for recording refused and late answers (task item 4). The answers to the clean room's question SPEC-DEFECT-27 of the same day are written in: which inputs give a report, a claim without grounds, the form of a path, and a report without its hash. Draft 2 answers Codex's review of 27 November 2026 (findings O1–O5 and the note on usable links). The expected reports of section 8 were added on the same day, with vector `V-OBS-6`. After Codex's recheck, section 5 states when a link is declared by a relation record.

**What the report is.** A deterministic JSON report over one sealed journal, or over a cut of several (`SPEC_CUT_AND_BUNDLE_v1`). For every claim it gives three independent axes, plus the map around them:
- **support:** does the claim stand on its evidence now;
- **dispute:** is it contradicted by a standing claim;
- **time:** has a standing later claim replaced it.

The map around the axes covers:
- who made each claim and on which bytes;
- what the claim rests on, within its journal and across journals;
- the questions about it;
- the conflicting values of exact keys.

Anyone with the same files recomputes the report byte for byte: the rules are open and every input is in the journals. `sbgk` writes the report; `yuce-verify` recomputes it and compares.

**What the report is not.**
- It holds no judgement of meaning and no model's verdict.
- It has no single score: the axes are never merged into one status, and the debt counters (section 6) are never summed.
- It has no colours: a visual rendering of the axes is not part of this specification.

---

## 1. Notation and inputs

- Notation as in specification version 3, section 1.
- **Input:**
  - either one journal with its documents and the seal that ends its part (as in `SPEC_CUT_AND_BUNDLE_v1`, section 3);
  - or a cut with its bundle.
- **Only a checked input gives a report.** A cut gives one only when it passes B0–B4; a single journal only when its part `0 … n` passes J0–J4a and frame `n` is a seal. A close frame after the seal is not part of the input. Otherwise there is no report: exit code 1, and the reason on the error stream.
- **The state of a journal** is its state after the frames of its part, as replayed by amendment 6. Every value below is read from that state:
  - the status projection rows `[id, kind, grounded, established, fallen_by]`;
  - the links with their statuses;
  - the withdrawal fates of observations;
  - the document versions.

## 2. Which records get a row

- One entry per record of kind `claim`, in each journal, in record order. Journals are taken in the order of the cut's `journals`.
- Observations, relations, hypotheses, questions and answers get no entry of their own. They appear as causes, links and questions of claims.

## 3. The support axis

`support` is `grounded` or `affected`.

- **`grounded`:** the claim's `grounded` value in the status projection is `true`.
- **`affected`:** it is `false`.

**Root causes.** With `affected`, the entry lists the claim's root causes (`root_causes`, the architect's name; the kernel's own reads call them first causes).
- They are found by following `fallen_by` from the claim down to records of kind `observe` that do not stand. Each record is visited once. The causes are listed in record order, without duplicates.
- Each cause is `{"record": <id>, "reason": <reason>}`. The reason is fixed by **the first command that revoked the observation's anchor** (amendment 6, P6-5), and never changes later:

| Reason | When |
|---|---|
| `withdrawn` | the anchor was revoked by a `revoke_text`; or by the re-close step of a `put_document`; or by a `revoke` whose quote text was not yet withdrawn in that document, so the text closed with it — whether the observation was the one named or another on the same anchor or overlapping the text |
| `revoked` | the anchor was revoked by a `revoke` whose quote text was **already** withdrawn in that document: the observation went by name, and no text closed with it. This holds under the rules 3 and 4 alike (set D, d7) |
| `version_replaced` | the anchor was never revoked, but the document's current version differs from the version the quote was bound to |

**Why a claim is never `withdrawn`.** A claim is not withdrawn in the kernel: only observations are (`revoke` takes an observation). The kernel's own reading of a claim says `AFFECTED_BY_EVIDENCE_CHANGE`, and the report agrees with it:
- `withdrawn` names the first cause, the observation or source taken back;
- `affected` names the consequence, the claim that fell with it.

An `affected` claim lists its root causes (decided in review: the architect, 27 November 2026). A claim without any ground is `affected` with `root_causes: []`: nothing fell under it.

## 4. The dispute axis

`dispute` is `contested`, `uncontested` or `unknown`.

`K(C)` is the set of links with `rel = "contradicts"` that have the claim `C` as one end. Links come from relation records, which make a link at acceptance, and from `add_link` commands; their status is set by `set_link_status`. `other(L)` is the end of `L` that is not `C`.

- **`contested`** — some `L` in `K(C)` has status `accepted`, and `other(L)` stands.
- **`unknown`** — not `contested`, and some `L` in `K(C)` has status `proposed`, or has status `accepted` while `other(L)` does not stand.
- **`uncontested`** — `K(C)` is empty, or every link in it is `rejected`.

The entry lists every link of `K(C)` in `dispute_links`, the rejected ones too, sorted by link id. Each is an object:
- `link`, the link id (amendment 6, P6-6);
- `rel`, `from`, `to`;
- `status`;
- `other_grounded`, whether `other(L)` stands;
- `usable`, whether the link is effective by amendment 6, P6-7: accepted, its ends, its basis and its acceptance basis admissible as proof.

The axis reads `status` and `other_grounded` only. `usable` is reported beside it, because the kernel's own readings use usable links: an accepted link whose acceptance basis fell is still `accepted`, but not `usable` (set D, d6).

The dispute axis does not depend on the claim's own support, and it does not change support: a contradiction makes no claim fall, as in the kernel.

## 5. The time axis

`time` is `current`, `stale` or `unknown`.

`R(C)` is the set of links with `rel = "supersedes"`, `to = C` and a status other than `rejected`.

- **`stale`** — some `L` in `R(C)` has a `from` that stands, and either its status is `accepted` or the link is declared by a relation record (a planned change of the rules 4 that the journal itself declares).
- **Declared by a relation record** means: some accepted record of kind `relation` in the journal has the ends `(from, rel, to)` of `L`, whether it stands or not. This does not depend on which event made the link first. By amendment 6, P6-6, a relation record on a triple that already exists creates no new link and changes neither its status nor its basis, but it still declares the triple. A link that only an `add_link` made is not declared.
- **`unknown`** — not `stale`, and `R(C)` is not empty. Two cases: a replacement that is only proposed by an outside link, and a replacement that does not stand.
- **`current`** — otherwise. It means "the journal declares no later state", not "true now".

The entry lists every link of `R(C)`, and every rejected `supersedes` link to `C`, in `time_links`, sorted by link id, in the same form as `dispute_links` (`other_grounded` is about `from`).

The time axis does not depend on the claim's own support: a claim that no longer stands can still be `stale`. It reads no clock, no document date and no setting.

**This rule is canonical for the observation report only.** The kernel has two other readings of a later state: the temporal status of `quality/stale.rs`, and the state that the exact-key reads give (`SUPERSEDED`). Their rules differ from this one and from each other, so for the same claim they can answer differently. Aligning them is planned for 0.3.2. Until then, the release's LIMITATIONS.md says so in one line (architect, 27 November 2026).

## 6. The map

**Each claim entry carries**, in this key set (canonical JSON sorts the keys):

| Field | Type and order |
|---|---|
| `journal` | the journal's name. For a single journal without a cut, its name is its `run_id` |
| `id` | 64 hex digits |
| `author` | the `actor` of the frame that accepted it |
| `frame` | the position of that frame |
| `quotes` | for each ground that is an observation, in `based_on` order, without duplicates: `{"doc_id", "version", "start", "end"}`, the version id and the span of the quote in that version |
| `rests_on` | the grounds that are claims, in `based_on` order, without duplicates, as ids |
| `rests_on_across` | in a cut only, else `[]`. For each observation ground that quotes, wholly or in part, a paragraph of a delivered export: `{"journal", "record"}` for the source journal and the record the paragraph names. Sorted by `journal`, then `record`, without duplicates |
| `questions` | ids of records of kind `question` whose `about_record` names this claim (rules 4), sorted, without duplicates |
| `support`, `root_causes` | section 3. `root_causes` is `[]` for a `grounded` claim |
| `dispute`, `dispute_links` | section 4 |
| `time`, `time_links` | section 5 |

**Exact-key conflicts.** They follow the kernel's own exact-key reads (`sbgk audit-read keys`, `VALUE_CONFLICT`), so the report and the kernel agree on them.
- **A claim is active** when it stands and is not superseded by the kernel's exact-key rule: no record of kind `relation` with `rel = "supersedes"` and `to` = the claim stands while its link is not `rejected`. This is the rule of the exact-key reads, and it differs from the time axis of section 5.
- **The key** of a claim is its `subject`, compared as the exact string. A claim without `subject` has no key.
- **The value** is its `object`; a claim without `object` has the value `null`, which counts as a value.
- **A conflict** is a key for which two or more active claims of one journal have different values.
- An entry is `{"journal", "subject", "values"}`.

**Debt counters**, per journal and for the whole report, never summed into one number:
- `affected` — claims with support `affected`;
- `contested` — claims with dispute `contested`;
- `resting_on_contested` — claims with a claim ground, within the journal or across, whose dispute is `contested`;
- `stale` — claims with time `stale`;
- `questions_about_claims` — questions whose `about_record` names a claim. The journal has no link from an answer back to a question record, so the report does not say whether such a question is answered;
- `key_conflicts` — the number of conflicting keys;
- `rejected_submissions` — the number of frames of the journal's part that record a refused answer: a `batch` frame with outcome `value` whose `command.checkpoint.key` starts with `task-repair:` and whose `outcome.result.checkpointed` is `true`. Each is one answer the kernel refused, wholly or in part;
- `late_submissions` — the number of frames of the journal's part that record a late answer: a `batch` frame with outcome `value` whose `command.checkpoint.key` starts with `task-conflict:` and whose `outcome.result.checkpointed` is `true`. Each is an answer sent to a task that was already closed. They belong to no claim, so they are no axis of one; this counter is where the receiver sees them (the architect, 27 November 2026).

**Arrays and strings.**
- Every array of the report has the order this section states. Where it says "sorted", strings are compared by their UTF-16 code units, the order canonical JSON uses for object keys.
- `values` of a conflict are sorted by the canonical JSON of each value, compared the same way; `null` is the string `null`.
- `claims` are in the order of the journals (section 2), then record order. `key_conflicts` are sorted by `journal`, then `subject`. `journals` are in the cut's order.
- No array holds a duplicate.

## 7. The report

```
{"format": "yuce-observation-report/1",
 "mode": "observe",
 "cut_hash": <hash> | null,
 "journals": [{"name": <name>, "seal_hash": <hash>, "log_size": <n>}],
 "claims": [ … section 6 … ],
 "key_conflicts": [{"journal": <name>, "subject": <string>, "values": [ … ]}],
 "debt": {"total": { … }, "by_journal": {<name>: { … }}},
 "report_hash": <hash>}
```

- In canonical JSON. A report file holds exactly those bytes, without a trailing newline.
- `report_hash = hex(H("YUCE-OBS-REPORT/1", JCS(report without "report_hash")))`.
**Checking a given report.** A verifier given a report, with the same journals or cut, does three things in order:
1. The bytes of the given file, as they are, are the UTF-8 of a canonical JSON object whose `report_hash` is a string of 64 lowercase hex digits. Otherwise `REPORT_FORM`: a report without its hash is one, and so is a file with a byte-order mark, a trailing newline or any other byte outside the canonical form. The check reads bytes, not a decoded string.
2. Its `report_hash` equals the hash of its own body without `report_hash`. Otherwise `REPORT_HASH_MISMATCH`. This catches a body changed after hashing.
3. It recomputes the report from the journals and compares it with the given one, byte for byte. Otherwise `REPORT_MISMATCH`, naming the first differing path: depth first, object keys in canonical order, array positions ascending, for example `claims[0].support`. Object keys are joined by `.` without escaping, array positions are written `[i]`, and the path of the root is the empty string.

**What binds the report to the journals.** The seals the report names, and through them each journal's status projection, which is under the seal. The fates and the link statuses are not under the seal itself: they are recomputed by replay (amendment 6), and a journal that replays to the seal's roots fixes them.

## 8. Vectors

| Vector | Input | What it must show |
|---|---|---|
| `V-OBS-1` | the bundle of `V-CUT-1` | `a`: the first claim `affected`, its root cause the withdrawn observation, reason `withdrawn`; the second `grounded`. `b`: its claim `affected`, root cause its own observation, reason `withdrawn`, `rests_on_across` = journal `a`, the first claim. All `uncontested`, `current`; no key conflict |
| `V-OBS-2` | `valid/stream-context-checkpoints.wal` alone | the replaced claim `stale` through the relation record; a question about a record; key `A` with values `10` (superseded) and `12` (active) is **no** conflict, as `sbgk audit-read key --key A` says |
| `V-OBS-3` | `j4a/set-d/d6-relation-link-lifecycle.wal` alone, its part up to the seal of frame 11 | after the acceptance basis is withdrawn: `contradicts` still `accepted` with `usable: false` and `contested` by the rule of section 4; the fallen `supersedes` record's `from` stands, `stale` by section 5, while the kernel's exact-key reads count the old claim active again and report a key conflict |
| `V-OBS-4` | the report of `V-OBS-1` with `claims[0].support` changed and `report_hash` kept | `REPORT_HASH_MISMATCH` |
| `V-OBS-5` | the same with `report_hash` recomputed over the changed body | `REPORT_MISMATCH` at `claims[0].support` |
| `V-OBS-7` | the report of `V-OBS-1` with a UTF-8 byte-order mark before it, nothing else changed | `REPORT_FORM` |
| `V-OBS-8` | `valid/baicalin-n3-shard1.wal` alone, its part up to its last seal | a real run of `sbgk` 0.2.2 on three open articles: 275 claims, 113 of them `affected` with root causes equal to the kernel's first causes; 22 key conflicts equal to the kernel's exact-key reads; `rejected_submissions` 10, its `task-repair` frames; `late_submissions` 0 |
| `V-OBS-9` | `j4a/set-d/d9-refused-and-late-answers.wal` alone, its part up to its seal at frame 8 | a reading written by the dispatcher of 0.3.1: 2 claims; `rejected_submissions` 2, its `task-repair` frames (one answer refused in part, one whole); `late_submissions` 2, its `task-conflict` frames |
| `V-OBS-6` | the same journal as `V-OBS-3`, its part up to its last seal (frame 13) | after the link is `rejected`: both claims `uncontested`, the rejected link still listed in `dispute_links`; the old claim still `stale`; the key conflict stays |

**Expected reports.** The full expected reports are published before either implementation starts, in `verifier/inputs/obs/V-OBS-<n>/`:
- `input.json` names the input: a cut, or one journal and the frame of the seal that ends its part;
- `report.json` is the expected report, the canonical JSON bytes without a trailing newline (for `V-OBS-4` and `V-OBS-5`, the given report);
- `expected.json` is the verdict: `PASS`, or the code and, for `REPORT_MISMATCH`, the path.

Each report is computed with the kernel's own reads as the oracle, and every field they give is cross-checked against the rules above:
- the kernel's state at the seal: the status rows, every link with its status, and whether the kernel counts it usable;
- `sbgk audit-read record` for the authors, the grounds, the quotes with their versions and spans, the causes, and the kernel's first causes, which equal `root_causes`;
- `sbgk audit-read keys` for the value conflicts, which equal `key_conflicts`;
- `sbgk audit-read status` for the seal hashes.

The dispute and time axes are the rules of sections 4 and 5 over those values. Each report is then checked by hand against the column "what it must show". `V-OBS-4` and `V-OBS-5` are derived from `V-OBS-1`.

## 9. Open points for the review

1. *(Decided: `affected` with root causes; section 3.)*
2. **Accepted, or accepted and usable.** The kernel's own temporal reading (`quality/stale.rs`) requires a link that is accepted **and** usable. The axes ask only that the status be `accepted` and the other end stand, and draft 2 reports `usable` beside each link. Should an axis read `usable` instead?
3. **A proposed planned change under the rules 3.** Draft 1 counts a `supersedes` relation record as declared in both versions of the rules.
4. **Document dates.** The kernel's `evidence_gap` uses dates from document front matter. Draft 1 leaves dates out.
5. **Answers.** An `unresolved_conflict` outcome of an answer record is not an axis of a claim. Should the report carry it per question? A question about a claim cannot be linked to its answer in the journal today (section 6, `questions_about_claims`).
6. **Single score.** None, by the architect's verdict. Confirm that the debt counters as a vector are enough for comparing groups.
