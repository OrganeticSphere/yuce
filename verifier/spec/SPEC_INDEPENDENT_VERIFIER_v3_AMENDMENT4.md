# Amendment 4 to the specification of the independent journal verifier, version 3: answers to SPEC-DEFECT-16…21 and release 0.2.3

OrganeticSphere, 19 November 2026. Written from the kernel code, branch `dev`, commit `1a88f0d3` (PR 59, 60 and 61 merged).

**Status: normative.** It applies together with specification version 3, amendments 1, 2 and 3, and the clean-room task statement of delivery 2 (not published). Where amendment 4 differs from their text, amendment 4 applies.

**Identifier.** Specification version 3 with amendments 1–4 is called `SPEC_INDEPENDENT_VERIFIER/6`. The verifier report must name exactly this identifier.

**What the amendment does.**
- It answers the implementer's questions `SPEC-DEFECT-16…21` (P4-1…P4-6). No answer changes an outcome on the earlier inputs.
- It pins section P3-11 (release 0.2.3) against the merged code (P4-7).
- It adds a journal of 0.2.3 to `valid/` (P4-8).
- It replaces the vectors file: the vector `V11_version_one_chunk` is corrected (P4-1, P4-9).

---

## P4-1. "A document of one chunk" (SPEC-DEFECT-16)

The implementer is right: the formula and the value of the vector are correct, its label is wrong.

- The text `Prior witness.` (14 bytes) is cut into two chunks, `[0,7)` and `[7,14)`. The boundary is byte 6: its score is the highest of the whole document. The version `16c4bc86…81a7` is the version of these two chunks.
- **A short document is usually two chunks.** A document of at most 513 bytes lies whole in the window of each of its positions. So it has exactly one boundary — the position of the highest score. It is one chunk only if that position is the last byte.

**What changes.**
- In P3-8 the words "a document of one chunk" read: "two short documents: of two chunks and of one".
- The new vectors file (P4-9) has no key `V11_version_one_chunk`. In its place `V11_short_documents` gives two documents with their chunks, chunk hashes and version:
  - `Prior witness.` — chunks `[0,7)`, `[7,14)`, version `16c4bc86…81a7`, as before;
  - `Short note.` — one chunk `[0,11)`: the highest score is on the last byte.

Both values were given by a function of the kernel (P4-9).

## P4-2. A repeated local name (SPEC-DEFECT-17)

**Format norm.** The kernel does not accept a line if a record with the same `local_id` was already accepted for the same `actor` in the same `directive` (the kernel's refusal "local id already belongs to an accepted record"). So in a correct journal a local name is unique within the pair `(actor, directive)`, and the question "the first or the last" does not arise.

**New rule J3-2a** (between J3-2 and J3-3): the line's `local_id` does not equal the `local_id` of a record accepted earlier by the same `actor` in the same `directive`. Records of earlier frames and of earlier lines of the same group count. Otherwise failure `DUPLICATE_LOCAL_ID`.

The code `DUPLICATE_LOCAL_ID` is added to the list of J3 codes after `RECORD_FORM`. The implementer's choice "the last one is taken" is replaced by this failure; the inputs have no repeats.

## P4-3. The description of a document (SPEC-DEFECT-18)

**The implementer's choice is confirmed** and written as a norm.

1. **The keys of a description are exactly those listed:**
   - `opaque` — `doc_id`, `kind`, `raw_sha256`;
   - `git_manifest` — `commit`, `kind`, `path`, `raw_sha256`, `repo`, `revision_refs`, `size_bytes` (all required) and the optional `date`.

   A missing or extra key — `GENESIS_FIELD`. The values of `date` and `revision_refs` are not parsed; `revision_refs` is an object.
2. **Order.** Descriptions go in the order of the keys of `source_documents` by JCS. For each, first its form (`GENESIS_FIELD`), then its id (`SOURCE_ID_MISMATCH`). The first violation decides.
3. **A key of `source_documents` is an identifier** (P3-1). Otherwise `GENESIS_FIELD`.

The kernel writes descriptions with exactly these keys, and document ids as identifiers of at most 1024 bytes. On replay the kernel lets an extra key of a description pass. This difference is of the same kind as P3-12, item 7: the verifier is stricter than the kernel where the kernel always writes one way.

## P4-4. Limits of the anchor fields (SPEC-DEFECT-19)

**The kernel's behavior.** The kernel does not write such an anchor: it refuses the line when it is submitted, and the journal does not hold it.
- A quote longer than 16,384 bytes is refused when the line is parsed.
- A quote that would take more than 255 chunks is refused when it is anchored.
- A document id is an identifier of at most 1024 bytes.

**Why with these limits the fields do not overflow.**
- Two neighbouring boundaries (P3-8, step 3) are more than `w = 512` bytes apart: otherwise each would lie in the other's window, and both could not be the best.
- A gap of length `g` between them is cut at the limit 2048 into `⌈g/2048⌉` chunks, which is at most `g/513`.
- So gaps lying whole inside a quote of 16,384 bytes give at most 31 chunks. The two edge gaps the quote touches in part give at most 9 each.
- In total fewer than 50 chunks, far from the limit 255.

The length of a quote fits in `u32le`, a document id in `u16le`.

**New norms.**
- **J3-2:** `exact_quote` is at most 16,384 bytes in UTF-8. Otherwise `RECORD_FORM`.
- **J3-8:** the `doc_id` of a command `put_document` is an identifier. Otherwise `DOCUMENT_VERSION_MISMATCH`.
- Keys of `source_documents` are identifiers (P4-3).

With them the case "does not fit" does not arise in a journal that passed J2 and J3-2. The path "the evidence anchor cannot be written" in the implementer's code may stay as an internal check: on such a journal it cannot be reached.

## P4-5. `local_id` is required (SPEC-DEFECT-20)

**The implementer's choice is confirmed.** `local_id` is required in a line of every kind and is a string; otherwise `RECORD_FORM`. The kernel refuses a line without it when it is parsed. In J3-2 "`local_id` is a string" reads as "`local_id` is present and is a string". The verifier does not repeat the length limits of the name (P3-9).

## P4-6. `submit` with an outcome `value` (SPEC-DEFECT-21)

**The table of P3-3 is normative.** The command `submit` gives in the kernel the outcome `records` or, if refused as a whole, `error`. It never has an outcome `value`. The kernel refuses a journal where one is written: on replay the outcome differs from the recorded one.

**J2-7 is extended:** for a command object with `kind = "submit"` the outcome is `records` or `error`. Otherwise `BODY_FIELD`. The other direction (`records` only on `submit`) stays.

## P4-7. Release 0.2.3: section P3-11 pinned

Merged on 19 November 2026:
- PR 59 — `99817071`;
- PR 60 — `406874c8`;
- PR 61 — `1a88f0d3`.

The merged code of PR 60 and 61 is the code of the branch heads section P3-11 was written from (`27e411da` and `650a6289`). The code of PR 59 came on top of it.

Section P3-11 was checked against the merged code and becomes normative with these clarifications:

1. **The format of a frame, of the genesis record and of a batch, and the formulas of J0–J3 do not change.** No rule of J0–J3 is added or removed because of 0.2.3. On all 21 earlier inputs of the clean room the kernel with the merged PRs answers as kernel 0.2.2 does: checked on a build of `dev` `1a88f0d3`.
2. **The kernel's replay rule changes for runs whose settings mark names `four_eyes: true`.** These are all new runs of the server.
   - If the new rule acted in a journal (a "four eyes" refusal or the mark `arbitration`), kernel 0.2.2 refuses it: on replay the outcome differs from the recorded one.
   - The genesis record of such a journal names the same rules `r2r-audit-rules/3`; the settings mark turns the rule on, not `rules_version`.
   - For the verifier this changes nothing: J0–J3 do not repeat the meaning of commands.
   - The comparison with the kernel (acceptance B5) for a journal of 0.2.3 uses kernel 0.2.3. In `expected.json` it has two answers: `kernel` — the merged `dev` (accepts), `kernel_0_2_2` — kernel 0.2.2 (refuses).
3. **The settings mark** is a description of data, not a rule of the verifier:
   - the key of the mark is `audit:mcp:coverage`;
   - the server writes it before the first record, as a batch of the kernel with no operations, `submission_id = "audit-mcp-coverage-config"`;
   - its `context` is the settings of the run `S`;
   - for a run the server started, `settings_hash = H("R2R-SETTINGS/2", JCS(S))`. It is so on every journal of the server in `valid/`, the new journal of 0.2.3 included.

   The equality is not a rule of the kernel: a journal rewritten by the library (`k017-oracle-v3.wal`) names the empty settings, and its mark names others. J2 does not require the equality.
4. **Keys of `S` from 0.2.3:**
   - `unit_is_task` — always, `true` or `false`; before 0.2.3 it was there only when `true`, its absence reads as `false`;
   - `auto_reread_limit` — a number, 20 by default; before 0.2.3 there is no key;
   - `corpus_description` — a string of 1 to 200 bytes on one line, only if given;
   - `four_eyes` — `true` for every new run.

   A journal before 0.2.3 has none of these keys and keeps on resume the earlier form of the mark and the earlier `settings_hash`.
5. **Four eyes and arbitration** are rules of meaning of the kernel (P3-9); the verifier does not repeat them:
   - in a run with `four_eyes: true` a command `set_link_status` that accepts or rejects a link is refused if its author wrote one of the link's ends: outcome `error`;
   - with the key `"arbitration": true` (only `true`) such a command passes, and the decision in the state gets the mark `arbitration: true`;
   - in the journal the mark is in the frame's command itself, and `request_hash` covers it (J2-8);
   - in a run without `four_eyes` the key `arbitration` is unknown, and a command with it is refused, as before;
   - a settings mark that drops `four_eyes` from a run where it was set is refused;
   - the owner's tool `audit_link_status` sets the mark. The kernel does not know roles: the mark records the decision as the server identified the caller, not the owner's signature.

   `set_link_status` accepts no records: the records root of its frame is empty.
6. **Coverage (PR 59).** The state `reading_given_up` and the count `units_reading_given_up` in the report of the gap pass are values of command results. For J0–J3 they are opaque.
7. **The field `settings` of the J2 report** (the proposal of P3-11) is not part of the delivery. It is the owner's decision.

## P4-8. A journal of 0.2.3 in `valid/`

The new input is `valid/four-eyes-arbitration.wal` with the documents folder `valid/four-eyes-arbitration.docs/`, two files.

**How it was made.** The server and the kernel of the merged `dev` `1a88f0d3` wrote the journal in a test run with no model (a test in a working copy, not committed):

| frame | who | what |
|---|---|---|
| 0 | — | genesis record: `git_manifest`, two documents |
| 1 | `kernel` | settings mark: `four_eyes: true`, `unit_is_task: false`, `auto_reread_limit: 20` |
| 2 | `own` | `submit`: an observation and a claim (added by the kernel library) |
| 3 | `w1` | `submit`: an observation and a claim (added by the kernel library) |
| 4 | `builder` | `add_link`: a link `supports` from the claim of `own` to the claim of `w1` |
| 5 | `own` | `set_link_status` without the mark — outcome `error`: the owner wrote one end |
| 6 | `own` | `set_link_status` with `"arbitration": true` — outcome `value`: the link is accepted (through the server, over the wire) |
| 7 | `kernel` | seal of the first 7 frames (the owner's `audit_seal`) |

**Expected outcome** (a row of `expected.json`):
- J0–J1 — 8 frames, one seal `n = 7`, tail `sealed`;
- J2 — `PASS`, 2 documents, `settings_hash = 1e3cdcc5…ca51`;
- J3 with the documents folder — `PASS`, 4 records, 2 quotes.

`settings_hash` equals the hash of the settings of frame 1.

**The kernel's answers:**
- the merged `dev` — `VERIFIED`;
- 0.2.2 — `REFUSED`: "semantic replay diverged from the committed outcome/roots" (P4-7, item 2).

Delivery 2 of the clean room (`00bcc99`) gives J0–J3 `PASS` on this journal with its documents folder: checked by running it, with no change to its code.

## P4-9. The vectors file

The file `VECTORS_INDEPENDENT_VERIFIER_20261119_v2.json` replaces `VECTORS_INDEPENDENT_VERIFIER_20261119.json`. In it:
- V1–V10 and V12–V16 are the same, unchanged;
- in V11 the key `V11_version_one_chunk` is replaced by the key `V11_short_documents` (P4-1).

**How it was computed.** The whole file was computed again by functions of the kernel on the merged `dev` `1a88f0d3`, with the same test module as for amendment 3, not committed to the repository. Every value of V1–V16 but the replaced one equals the earlier one. A separate script, written from the text of amendments 3 and 4, computed V10–V16 again with the same result.

The command `vectors` checks for `V11_short_documents` the chunks, their hashes and the version.

**In this repository.** Current version: 52,779 bytes, SHA-256 `a2ab88cfcb7cb802a8756bf590519d24e380b02fc3ee660ea65a591876565f7f`. It is the version checked against the kernel (52,866 bytes, SHA-256 `82904e6d6aa6ad18e7f6e7802b034364b5dfcc472d7834e5d3d36c91a4bbf40e`) with its note `_status` put into English and its note `_note` in the wording published on 13 November; every vector is the same. The tests of `yuce-verify` check that the file in this folder has the size and SHA-256 named here.

## P4-10. What to change: summary

1. The identifier in the report — `SPEC_INDEPENDENT_VERIFIER/6`.
2. J2-5: the keys of descriptions exactly those listed; a key of `source_documents` is an identifier (P4-3).
3. J2-7: for `submit` the outcome is `records` or `error` (P4-6).
4. J3-2: `local_id` is required; `exact_quote` is at most 16,384 bytes (P4-4, P4-5).
5. J3-2a: a new code `DUPLICATE_LOCAL_ID` (P4-2).
6. J3-8: the `doc_id` of a command `put_document` is an identifier (P4-4).
7. Vectors — a new file (P4-9); the command `vectors` checks `V11_short_documents`.
8. A new input `valid/four-eyes-arbitration.wal` with its documents folder; tests B2 and B5 include it. For B5 this input takes the answer `kernel` — of kernel 0.2.3. In the task statement, section 6, `valid/` now has eight journals.
9. The receipt test: `spec/` has seven files:
   - specification version 3;
   - amendments 1, 2, 3 and 4;
   - the task statement version 4;
   - `VECTORS_INDEPENDENT_VERIFIER_20261119_v2.json`.

   The earlier vectors file of 19 November is removed; it stays in the git history. In this repository `spec/` has six files: the task statement is not published.

Each change gets a test. The earlier outcomes on `valid/`, `corrupt/` and `boundary/` do not change.
