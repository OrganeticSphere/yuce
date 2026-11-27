# Specification of a cut of several journals and of its offline check (`yuce-cut/1`), draft 4

OrganeticSphere, 27 November 2026.

**Status: normative** since 27 November 2026: the architect and Codex passed draft 4. The answers to the clean room's question SPEC-DEFECT-26 of the same day are written in: names `.` and `..`, repeated grounds in a paragraph, what a check needs from an earlier one, and how `across` counts. Draft 2 answered Codex's review of 27 November 2026 (findings C1–C6). Draft 3 answered his recheck of the same day: an export's bytes brought in by the receiving journal's genesis, and the order of paragraphs. Draft 4 answers his third check and the architect's ruling on it: several deliveries into one genesis, the four ways a document enters a journal, the fields and order of failures, and an executable check of B0–B4. The text is written for an implementer who reads this document, specification version 3 with amendments 1–6, and the vectors, and does not read the kernel.

**What a cut is.** A cut binds the journals of several parties at named seals, the exports from one journal to another, and the deliveries of those exports. A receiver who gets the bundle (the cut, the journals, their documents and the exports) checks the whole set offline:

- every journal, as `yuce-verify` checks one journal, with the withdrawal cascade recomputed (amendment 6);
- every export, against the journal it was made from;
- every delivery, against the journal it was delivered to;
- and that a withdrawal on one side reached what the other side built on the exported text.

**What a cut does not do:**
- it does not deliver withdrawals: an operator's process does that, and this document does not specify it;
- it does not judge meaning;
- it sees no dependency that does not pass through the bytes of an export: a claim that restates another party's claim without quoting a delivered export is invisible to it. Every import of an export's exact bytes, by a put or as a document of a genesis record, must be declared (B3);
- B4 states that the set agrees **at the cut**. It is not a durable record of a withdrawal event, and it proves no origin of a journal without an external anchor;
- `previous_cut` is checked for its form only and proves no succession;
- it carries no decisions (mode `govern` is reserved).

**The base journal does not change.** An export enters the receiving journal as an ordinary document: by `put_document`, or as a document of the receiving journal's genesis record. No frame gets a new field. This is the shape the two-party probe of 19 November 2026 used.

**What is open and what is not** (architect, 27 November 2026):
- open: the export format and its deterministic making (section 2), since without them an outside verifier cannot reproduce an export byte for byte;
- not part of this specification: the policy of which claims to export, and the delivery of withdrawals between parties.

---

## 1. Notation

As in specification version 3, section 1: `H(d, …)`, `JCS(v)`, hash strings of 64 lowercase hex digits, RFC 6962 trees.

A **name** in this document is a string matching `[A-Za-z0-9._-]{1,64}`, other than `.` and `..`: a journal's name is also a folder of the bundle.

## 2. The export (`yuce-export/1`)

An export is a UTF-8 text document made from one journal at one of its seals, deterministically. It carries claims of that journal and the quotes they rest on, so that another party's agents can quote them byte for byte.

### 2.1. Bytes

```
yuce-export/1 run=<run_id> seal=<seal_hash> records=<n>\n
\n
<paragraph 1>\n
\n
<paragraph 2>\n
…
<paragraph n>\n
```

- The first line is the header. `<run_id>` is escaped as below; `<n>` is the number of paragraphs, in decimal digits without leading zeros.
- Paragraphs follow in the journal's record order (the order of the status projection, amendment 6). Each paragraph is one line; one empty line separates the header and each paragraph from the next; the file ends with `\n` after the last paragraph.
- An export with no paragraph is the header line alone.

### 2.2. A paragraph

```
Record <id>: <text>[ Rests on: <id>, <id>…][ Quotes: [<doc_id>] "<quote>" ; [<doc_id>] "<quote>"…]
```

- `<id>` is the record id in full: 64 hex digits.
- `<text>` is the claim's `text`.
- `Rests on:` lists, in `based_on` order and without duplicates (each at its first place), the grounds of the claim that are claims (rules 4). The part is absent when there is none.
- `Quotes:` lists, in `based_on` order and without duplicates, the grounds that are observations: the document name and the exact quote of each. The part is absent when there is none.
- **Escapes**, in `<run_id>`, `<text>`, `<doc_id>` and `<quote>`: `\` is written `\\`, a line feed `\n`, a carriage return `\r`. Nothing else is escaped. A paragraph is therefore always one line, and paragraphs are split on `\n\n` without ambiguity.
- **Reading a paragraph.** A verifier reads only the prefix `Record <id>: ` with its 64 hex digits. It never splits the rest of the line into text, grounds and quotes: those may hold `Quotes:`, `Rests on:`, `" ; [` or any other bytes. It checks the rest by making the canonical paragraph from the record (B2) and comparing bytes. Vector `V-CUT-12` has a text and a quote with quote marks, brackets, both separators, the words `Quotes:` and `Rests on:`, a backslash and a line break.

### 2.3. What may be exported

- A paragraph names a record of kind `claim` that **stands at the export's seal**: its `grounded` value in the status projection at that seal is `true` (amendment 6).
- Which standing claims are exported is the exporting party's choice. This document does not constrain it.
- Every record is exported at most once in one export.

The export's identity is `SHA-256` of its bytes.

## 3. The cut manifest

**The file** is one JSON object (RFC 8259) in UTF-8, without duplicate keys at any depth. Its layout is free: key order, white space and a trailing newline do not matter, since the cut's identity is computed over the canonical form of its value. A duplicate key, a byte-order mark before the object, or bytes that are not such an object, give `CUT_FORM`; such a file has no single value, and the report's `cut_hash` is `null` (the clean room's SPEC-DEFECT-28). The value:

```
{
  "format": "yuce-cut/1",
  "mode": "observe",
  "journals": [
    {"name": <name>, "run_id": <string>, "rules_version": <string>,
     "seal_hash": <hash>, "log_size": <number>, "wal_head": <hash>, "closed": <bool>}, …
  ],
  "exports": [
    {"name": <name>, "journal": <name>, "seal_hash": <hash>, "sha256": <hash>, "records": <number>}, …
  ],
  "deliveries": [
    {"export": <name>, "journal": <name>, "doc_id": <string>, "frame": <number>}, …
  ],
  "previous_cut": null
}
```

- `journals` are sorted by `name`, `exports` by `name`, `deliveries` by `(journal, frame, doc_id)`. Names are unique within their list.
- **How strings are compared**, here and wherever this document sorts by a name or a `doc_id`: by their UTF-16 code units, the order canonical JSON uses for object keys. Numbers, such as `frame`, compare as numbers. For example, a `doc_id` of U+10000 sorts before one of U+E000.
- **Which deliveries may coexist** (the architect, 27 November 2026). At frame 0, two deliveries never name the same `(journal, doc_id)`: a genesis record may hold several documents, one delivery each. At a frame after 0, two deliveries never name the same `(journal, frame)`: one `put_document` frame is one delivery.
- **A journal's part in the cut** is its frames `0 … log_size`: the seal of the first `log_size` frames is the frame at position `log_size` (specification version 3, section 6.1), and `seal_hash` is that seal's hash. With `closed: true` the close frame at position `log_size + 1` belongs to the part too. Frames after the part are not in the cut: a journal file may be longer.
- `wal_head` is the hash of frame `log_size − 1`, the head the seal names.
- An export names its journal and one seal of that journal at or before the journal's seal in the cut.
- A delivery says: frame `frame` of journal `journal` brings the export `export` in as the document `doc_id`. Frame 0 is the genesis record, and the document is one of its `source_documents`. At any later frame the delivery is a `put_document` that is the frame's own command, not an operation of a batch.

**How a document enters a journal.** The kernel has four ways, and B3 covers each:

| Way | Where | A delivery? |
|---|---|---|
| the genesis record | frame 0; any number of documents in `source_documents`, in either form of description | yes: `frame: 0`, one delivery per document |
| a `put_document` frame | the frame's own command, with outcome `value` | yes |
| a `put_document` operation of a batch, with a result | written by the library and the graph builder; no agent tool writes it | no: a batch that brings in an export's exact bytes fails the cut (B3.2) |
| a new version of an existing name | a `put_document` of a name the journal already has, by a frame or a batch operation | no: a delivered name is never put again (B3.3) |

A `put_document` that the kernel refused, or whose outcome is `error`, brings nothing in.
- `mode` is `"observe"`. The value `"govern"` is reserved for a later version; a draft-1 verifier refuses it.
- `previous_cut` is `null` or the `cut_hash` of an earlier cut. A draft-1 verifier checks only its form.

**The cut's identity:** `cut_hash = hex(H("YUCE-CUT/1", JCS(manifest)))`.

## 4. The bundle

The files a verifier gets:

| File | What |
|---|---|
| the manifest | section 3 |
| per journal | the journal file and its documents folder, as level J3 needs them |
| per export | the export file |

How the files are laid out on disk is a matter of the command line, not of this document.

## 5. Checks

The checks run in this order. Each failure carries its code and the names it concerns. A failure of a level does not stop the later levels unless the later level needs what failed.

**B0. The manifest.**
- Exactly the keys of section 3, values of the stated types, numbers as in specification version 3, section 2.
- Lists sorted, names unique, deliveries that may coexist (section 3), every reference resolves: `exports[].journal` and `deliveries[].journal` name journals of the cut, `deliveries[].export` names an export.
- `mode` is `"observe"`.

Otherwise `CUT_FORM`.

**B1. Each journal.** For each journal of the cut, with `n = log_size`:
1. Frame `n` exists, is a seal frame with outcome `value`, and its seal hash equals `seal_hash`. Otherwise `CUT_JOURNAL_MISMATCH` with `field: "seal_hash"`.
2. `wal_head` equals the seal's `P.wal_head`, and both equal the hash of frame `n − 1`. Otherwise `CUT_JOURNAL_MISMATCH` with `field: "wal_head"`. This is compared on its own, not as the head of the file: the head of the part is the hash of its last frame, the seal (or the close).
3. With `closed: true`, frame `n + 1` exists and is a close frame with outcome `value`. Otherwise `CUT_JOURNAL_MISMATCH` with `field: "closed"`.
4. `run_id` and `rules_version` equal those of its genesis record. Otherwise `CUT_JOURNAL_MISMATCH` with that field.
5. Levels J0–J3 and J4a pass on the part: the frames `0 … n`, and `n + 1` when closed, read as a file of their own, with `seal_hash` as the external seal (`--expect-seal`) and without an external head. Frames after the part are not read. Otherwise `CUT_JOURNAL_FAILED`, with the journal's own failure code. When the part is not failed but incomplete (a document missing from its folder, so J3 cannot be checked), the failure is `CUT_JOURNAL_FAILED` with `failure: null`.

Vectors:
- `V-CUT-6`: `wal_head` set to the hash of the seal frame itself;
- `V-CUT-7`: `seal_hash` set to an earlier seal of the same journal;
- `V-CUT-13`: a journal that goes on after the seal the cut names, sealed and not closed — positive.

**B2. Each export.**
- `SHA-256` of the file equals `sha256`, and the header line names the journal's `run_id`, the export's `seal_hash` and `records`. Otherwise `EXPORT_MISMATCH`.
- `seal_hash` is the hash of a seal frame of the journal's part. Otherwise `EXPORT_SEAL_UNKNOWN`.
- Each paragraph begins with `Record <id>: ` (section 2.2). Each id names a record of the journal accepted before that seal, of kind `claim`, at most once in the export. Otherwise `EXPORT_MISMATCH`.
- Each named record stands at the export's seal (amendment 6). Otherwise `EXPORT_NOT_STANDING`.
- The file equals, byte for byte, the export section 2 makes from these records at that seal, the paragraphs in ascending record order (section 2.1), whatever order the file has them in. Otherwise `EXPORT_MISMATCH`. Vector `V-CUT-17`: the two paragraphs of `e1` swapped, the same ids and texts, `sha256` written for the swapped file.

**B3. Deliveries.**
1. **Declared.** Frame `frame` of the delivery's journal is inside the journal's part, and one of these holds:
   - **frame 0, the genesis record:** its `source_documents` has the key `doc_id`, and the `raw_sha256` of that description equals the export's `sha256`, for either form of description (amendment 3, P3-6). The delivered version is the version of that document at genesis (P3-8);
   - **a later frame:** its own command is a `put_document` with outcome `value`. Its `doc_id` equals the delivery's. The `SHA-256` of the bytes of its `text` equals the export's `sha256`. The version id its outcome names equals the version P3-8 computes from those bytes, and it is the delivered version.

   Otherwise `DELIVERY_MISSING`. A refused put, an error outcome or an operation inside a batch is no delivery. Vector `V-CUT-10`: the receiving journal refuses the put.
2. **Undeclared.** In the part of a journal of the cut, an **import** is a document brought in with the exact bytes of an export of the cut:
   - a document of the genesis record whose `raw_sha256` equals the export's `sha256`, at frame 0;
   - a `put_document` that ran and puts those bytes, as a frame or as a batch operation with a result.

   Every import is declared: some delivery names its journal and, at frame 0, its `doc_id`; at a later frame, its frame. A delivery that names it but fails B3.1, a batch frame among them, gives `DELIVERY_MISSING` there and nothing more here. Otherwise `CUT_UNDECLARED_DELIVERY`. Vectors: `V-CUT-9`, the journals of `V-CUT-2` with no delivery declared; `V-CUT-14`, the exact bytes of `e1` as a document of the receiving journal's genesis, with no delivery declared; `V-CUT-4`, a delivery naming the wrong frame, so that the put is undeclared as well.

   A party therefore delivers by a frame of its own: a batch that brings in an export's exact bytes always fails, with `DELIVERY_MISSING` when its frame is declared and `CUT_UNDECLARED_DELIVERY` when not. Vectors `V-CUT-25` and `V-CUT-26`, written through the library.
3. **Not modified.** The delivered document name does not exist in the journal before the delivery frame; at frame 0 this holds by itself. No later `put_document` that ran in the part, as a frame or as a batch operation, puts that name again. Otherwise `CUT_IMPORT_MODIFIED`, naming the frame of that later put, or the delivery frame when the name existed before it. A party that wants to bring a later export uses a new document name. Vector `V-CUT-11`: the receiving journal puts a new version of the delivered export, with the old paragraph, and quotes it there.

**What a check needs from an earlier one.**
- A journal that fails B1.5 has no state, and B2 to B4 do not use it.
- B3.3 and B4 use only the deliveries that passed B3.1: they need the delivered version.
- Items 1–4 and 5 of B1 run apart: one journal can give several failures.

**B4. A withdrawal across journals.** For each delivery of an export `E` to journal `J` as document `D`:
- take each paragraph of `E` whose record does **not** stand in `E`'s journal at that journal's seal in the cut;
- every observation of `J` whose quote lies, wholly or in part, inside the bytes of that paragraph in the delivered version of `D` (B3.1) must not stand in `J` at `J`'s seal in the cut.

Otherwise `WITHDRAWAL_NOT_DELIVERED`, naming the export, the record and the observation.

Vectors through the genesis: `V-CUT-15` declares the delivery of `V-CUT-14` at frame 0, and the receiver's observation still stands; in `V-CUT-16` the receiver withdrew that paragraph's text; in `V-CUT-18` two exports enter one genesis.

The bytes of a paragraph, here and for `rests_on_across` of the observation report, are those of its line without the line feed that ends it.

**`across` counts per delivery.** `paragraphs_fallen` adds, for each delivery that passed B3.1, the paragraphs of its export whose record does not stand: an export delivered twice counts twice. `observations_checked` adds, for each such delivery, the distinct observations that lie in its fallen paragraphs.

B4 compares the source journal's standing **at the cut**, not at the export's seal: the cut is the point at which the set must agree. Because of B3, every observation of `D` in `J` is bound to the delivered version, so B4 sees them all.

## 6. Report

```
{"format": "yuce-cut-report/1", "cut_hash": <hash>, "verdict": "PASS" | "FAIL",
 "journals": [{"name": …, "verdict": …, "levels": {…}}],
 "exports": [{"name": …, "verdict": …, "paragraphs": <n>, "fallen_at_cut": <n>}],
 "deliveries": [{"export": …, "journal": …, "verdict": …}],
 "across": {"paragraphs_fallen": <n>, "observations_checked": <n>},
 "failures": [{"code": …, …}],
 "not_verified": ["meaning", "undeclared_dependencies", "signatures"]}
```

**The fields of each failure**, besides `code`:

| Code | Fields |
|---|---|
| `CUT_FORM` | none |
| `CUT_JOURNAL_MISMATCH` | `journal`, `field` |
| `CUT_JOURNAL_FAILED` | `journal`, `failure` (the journal's own failure code) |
| `EXPORT_MISMATCH`, `EXPORT_SEAL_UNKNOWN` | `export` |
| `EXPORT_NOT_STANDING` | `export`, `record` |
| `DELIVERY_MISSING` | `export`, `journal`, `doc_id`, `frame` (those of the delivery) |
| `CUT_UNDECLARED_DELIVERY` | `journal`, `frame`, `doc_id`, `export` (those of the import; `export` is the first export of the manifest with those bytes) |
| `CUT_IMPORT_MODIFIED` | `journal`, `doc_id`, `frame` |
| `WITHDRAWAL_NOT_DELIVERED` | `export`, `record`, `observation` |

**Order of `failures`:** the order of the checks B0 to B4. Within B1 and B2, the order of the manifest's lists. Within B3, first B3.1 in the order of `deliveries`, then B3.2 by journal in the order of `journals`, then frame, then `doc_id` (compared as in section 3), then B3.3 in the order of `deliveries`. Within B4, the order of `deliveries`, then paragraph, then record order of the observations. B0 failing ends the check: the later levels need a manifest. An export gives at most one `EXPORT_MISMATCH`.

In the report, `journals[].levels` is the `levels` object of that journal's own report. The line for a human is not part of this specification.

Exit codes as in specification version 3, section 8.4.

## 7. Vectors

Made with `sbgk` 0.3.0 (`audit-stream`) and published under `verifier/inputs/cut/`. Each vector holds its journals (`a/`, `b/`, each a `run.wal` and `docs/`), the export, `cut.json` and `expected.json` with the expected verdict, failure codes and `cut_hash`.

| Vector | What | Expected |
|---|---|---|
| `V-CUT-1` | Journal `a` reads a source and makes two claims. Export `e1` at `a`'s first seal carries both. Journal `b` puts `e1`, quotes one paragraph and makes a claim on it. `a` withdraws the quote under one claim, with a reason document. The operator withdraws that paragraph's text in `b`. Both seal and close | `PASS`; `paragraphs_fallen` 1 |
| `V-CUT-2` | As `V-CUT-1` without the operator's withdrawal in `b` | `WITHDRAWAL_NOT_DELIVERED` |
| `V-CUT-3` | As `V-CUT-1` with one byte of `e1` changed after the cut was written | `EXPORT_MISMATCH` |
| `V-CUT-4` | As `V-CUT-1` with a delivery naming the wrong frame | `DELIVERY_MISSING` at the named frame, then `CUT_UNDECLARED_DELIVERY` at the put |
| `V-CUT-5` | As `V-CUT-1` with an export paragraph naming a claim that did not stand at the export's seal | `EXPORT_NOT_STANDING` |
| `V-CUT-6` | As `V-CUT-1` with `a`'s `wal_head` set to the hash of its seal frame | `CUT_JOURNAL_MISMATCH` (`wal_head`) |
| `V-CUT-7` | As `V-CUT-1` with `a`'s `seal_hash` set to its earlier seal | `CUT_JOURNAL_MISMATCH` (`seal_hash`) |
| `V-CUT-8` | As `V-CUT-1` with its delivery listed twice | `CUT_FORM` |
| `V-CUT-9` | The journals of `V-CUT-2` with no delivery declared | `CUT_UNDECLARED_DELIVERY` |
| `V-CUT-10` | Journal `b` refuses the put of `e1` (written by the kernel; Codex's probe) | `DELIVERY_MISSING` |
| `V-CUT-11` | Journal `b` puts a new version of the delivered `e1` and quotes the old paragraph there (Codex's probe) | `CUT_IMPORT_MODIFIED` |
| `V-CUT-12` | As `V-CUT-1` with texts and quotes holding quote marks, brackets, both separators, `Quotes:`, `Rests on:`, a backslash and a line break | `PASS` |
| `V-CUT-13` | As `V-CUT-1`, but `b` goes on after the seal the cut names: sealed, not closed | `PASS` |
| `V-CUT-14` | Journal `a` of `V-CUT-1`. Journal `b` holds the exact bytes of `e1` as the document `inbound` of its genesis record, quotes the first paragraph and makes a claim on it; no delivery is declared (Codex's probe) | `CUT_UNDECLARED_DELIVERY` at `b`, frame 0 |
| `V-CUT-15` | As `V-CUT-14`, with the delivery declared at frame 0 | `WITHDRAWAL_NOT_DELIVERED` |
| `V-CUT-16` | As `V-CUT-15`, and `b` withdrew the paragraph's text, with a reason document | `PASS`; `paragraphs_fallen` 1 |
| `V-CUT-17` | Journal `a` alone; `e1` with its two paragraphs swapped and its `sha256` written for that file; no delivery | `EXPORT_MISMATCH` |
| `V-CUT-18` | Journal `a` of `V-CUT-1`. Journal `b` holds `e1` as `inbound` and `e2` (the second claim alone, at the same seal) as `second` in its genesis record (Codex's probe), quotes a paragraph of each, and withdraws the text of the fallen one. Both deliveries declared at frame 0 | `PASS`; `paragraphs_fallen` 1 |
| `V-CUT-19` | As `V-CUT-18`, with `inbound` declared twice at frame 0, once for `e1` and once for `e2` | `CUT_FORM` |
| `V-CUT-20` | Journal `a` makes a claim whose `based_on` repeats its observation, and a claim on it whose `based_on` repeats that claim. Export `e1` carries both, each ground once. Journal `b` puts `e1`. Nothing falls | `PASS`; `paragraphs_fallen` 0 |
| `V-CUT-21` | As `V-CUT-1`, with the export named `.` | `CUT_FORM` |
| `V-CUT-22` | As `V-CUT-1`, with the key `mode` written twice in the manifest file | `CUT_FORM` |
| `V-CUT-23` | As `V-CUT-1`, with the manifest file indented and its keys in another order | `PASS`, the same `cut_hash` as `V-CUT-1` |
| `V-CUT-24` | A manifest file that holds `null`, and nothing else in the folder | `CUT_FORM`, `cut_hash` null |
| `V-CUT-25` | Journal `a` of `V-CUT-1`. Journal `b` takes the exact bytes of `e1` in by a `put_document` operation of a batch (frame 1; written by the library), quotes the first paragraph and withdraws its text; no delivery is declared | `CUT_UNDECLARED_DELIVERY` at `b`, frame 1 |
| `V-CUT-26` | The journals of `V-CUT-25`, with a delivery that names the frame of the batch | `DELIVERY_MISSING`, and nothing more |

**An executable check of these rules.** Before review, a reference program applies B0–B4 to every vector and to variants made from each (a delivery dropped, a frame moved, a delivery repeated, two deliveries of frame 0 out of order). The program is a tool of the development side, kept with the vector generators; it uses the kernel's reads for the levels J0–J4a and implements B0–B4 itself.

## 8. Open points for the review

1. **Claims resting on claims.** Section 2.2 lists them by id only. Should an export carry their text too, so that a receiver's agent can quote the chain?
2. **A journal that is sealed but not closed.** The manifest allows `closed: false`. Should a cut require every journal to be closed?
3. **Signatures.** A seal signature (`audit-verify --checkpoint --key`) exists in the kernel. Should the manifest name each journal's verifier key, and B1 check the signed checkpoint of the seal in the cut? Draft 1 leaves signatures in `not_verified`.
4. **`previous_cut`.** Its meaning (a chain of cuts, the decision receipts of mode `govern`) is left to the version that defines `govern`.
5. *(Resolved in draft 2: a paragraph is read only up to its record id, and the rest is compared with the canonical paragraph; `V-CUT-12`.)*
6. **Deliveries inside a batch.** A delivery is a `put_document` that is a frame's own command, and a batch that brings in an export's exact bytes fails the cut (B3.2). Only the library and the graph builder write such batches. Should a delivery name a batch operation too, with its index? Not in 0.3.1.
7. *(Decided: the architect, 27 November 2026.)* **An import through the genesis.** A document of the receiving journal's genesis record with an export's exact bytes is an import under the same strict contract: declared at frame 0, with `raw_sha256` checked, or `CUT_UNDECLARED_DELIVERY` (B3). A journal started from a folder (`audit-serve --docs`) is an ordinary start and stays in the cut. The rejected alternative was to refuse such a delivery and require a put.
