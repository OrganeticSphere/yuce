# yuce-verify 0.3.1 (delivery 3: levels J0-J3 and J4a, the cut check, the observation report)

An independent verifier of YuCe journals in the format `sbgk-session-log/3`: a standalone implementation of the specification, sharing no code and no dependencies with the kernel. [`../spec/`](../spec/) holds that specification, and [`../inputs/`](../inputs/) the test journals with their source documents and the results expected of them:
- `SPEC_INDEPENDENT_VERIFIER/8`: version 3 with its amendments 1-6;
- `SPEC_CUT_AND_BUNDLE_v1` (`yuce-cut/1`): a cut of several journals;
- `SPEC_OBSERVATION_REPORT_v1` (`yuce-observation-report/1`): the report of three axes.

Amendment 6 and both specifications are normative since 27 November 2026. The questions raised while delivery 3 was written, SPEC-DEFECT-22 … 28, and Codex's review of the port (PR 74) are answered in their text; none is open.

It answers four questions:
- is this file a well-formed YuCe journal whose accepted quotes are, byte for byte, in their source documents?
- does every seal of it name the withdrawal cascade the journal itself gives (J4a)?
- does it match a seal or a head I was given separately?
- do the journals, exports and deliveries of a cut agree, and does a given observation report follow from them?

## What it does not establish

Read these before you trust a PASS.

1. **Without an external anchor, J0-J4a say only "the file is internally consistent".** Anyone who can recompute the hashes and the projections passes them. `test/forge.mjs` does exactly that, and its journals pass (acceptances A6, B4).
2. **No level checks the meaning of the records.** J3 checks the bytes of quotes, record ids and records roots. J4a recomputes which records stand from the outcomes the journal records. Neither repeats the kernel's rules of acceptance (amendment 3, P3-9; amendment 6, P6-3), for example:
   - four eyes, the version map, scopes and visibility;
   - whether a reference is visible to its task;
   - whether a relation is declared in the ontology;
   - limits of values.
3. **J4a checks the cascade at the seals.** Frames after the last seal are reported as unchecked (`withdrawal_cascade_after_last_seal`), never as checked. A journal with no seal gets no cascade check.
4. **The honest boundary.** A quote replaced by **another phrase that also occurs exactly once in the same document**, with every hash, id, root, projection and seal recomputed, passes J0-J4a. Only an external seal or head kept out of the writer's reach shows it. `test/fixtures/forged/forged-records-same-document.wal` is such a journal. The same forgery with the projections of its seal left as they were fails J4a (`PROJECTION_STATUS_MISMATCH`).
5. **Signatures are not checked** (J5). A quittance's inclusion paths are not checked either (`quittance_inclusion`).

Every human line ends with `Not verified: …`, and every JSON report has `not_verified`:
- J3 not passed: `quotes against sources, withdrawal cascade, signatures`;
- J4a failed, did not run, or found no seal: `withdrawal cascade, signatures`;
- J4a passed with frames after the last seal: `withdrawal cascade after last seal, signatures`;
- J4a passed through the last frame: `signatures`;
- with `--quittance`: `quittance inclusion` comes before `signatures`.

## Levels

| level | in delivery 3 | what it checks |
|---|---|---|
| **J0** | yes | The file and its lines, read as a stream: not empty; line length and nesting limits; every frame ends with LF; valid UTF-8; strict JSON object; integers only from 0 to 2^53-1; canonical form (RFC 8785, byte for byte); the format `sbgk-session-log/3`; exactly the keys of a frame and its header; types; `seq`; `wal_op`; the chain `previous`; `body_hash`; `hash`. Last, optionally: the head equals `--expect-head`. |
| **J1** | yes | Seals (form, `P` in command and outcome, `log_size`, `wal_head`, `log_root`, root continuity, `seal_hash`, `run_id` of frame 0), kernel ids (`seal-…` only on a seal, `audit-close` only on the close frame), close right after a seal, nothing after the close, seal and close only from `kernel`. The tail kind. Last, optionally: `--expect-seal`. |
| **J2** | yes, always | The genesis record: exactly 15 keys, the formats `r2r-audit-genesis/3`, `r2r-state-root/2`, `r2r-seal/2`, the rules `r2r-audit-rules/3` or `r2r-audit-rules/4` (amendment 5), the kind of every field, `operator_meta` ≤ 4096 bytes in JCS, the document descriptions (exact keys, identifier keys, `revision_refs` an object) and the `git_manifest` doc_id formula, an empty records root on frame 0. Every later frame: exactly 7 body keys, identifiers `actor` and `submission_id`, three outcome forms (`records` only on a submit, a submit only `records` or `error`), `request_hash = hex(SHA256(JCS(["r2r-audit-request/1", actor, command])))`, no repeated `(actor, submission_id)`. Batches: the outcome form; no executed seal, close or batch inside a batch. |
| **J3** | yes, with `--docs` | Documents are found by the SHA-256 of their bytes (`raw_sha256`); file names do not matter. New versions come from `put_document`. For every accepted record: the line form (`local_id` present, `exact_quote` at most 16 384 bytes; `about_record` of a question under the rules 4), a local name used once per author and task (`DUPLICATE_LOCAL_ID`), references (by local name, or `@` and 16-64 hex digits), the quote occurs **exactly once** in the current bytes of its document and inside the task's scope, the anchor (content-defined chunks, document version, evidence id), the value `L`, the record id against the outcome, and the records root of every frame against `header.records_root`. |
| **J4a** | yes, after J3 passed | Amendment 6. The state J3 builds is kept for the whole journal. Withdrawals (`revoke`, `revoke_text`, the re-close step of `put_document`), links (`relation` records, `add_link`, `set_link_status`) apply at their place, in a frame whose outcome is `value` or as a batch operation with a result. At every seal frame the verifier computes the status rows and the dependency pairs over the state before the seal, and compares their hashes with `P.projections` (`PROJECTION_STATUS_MISMATCH`, `PROJECTION_DEPENDENCIES_MISMATCH`). Every seal of the file is compared, whatever `--expect-seal` names. Quittances given with `--quittance` are checked against the rows recomputed at their seal (P6-11); a quittance's seal body must first pass the form and types of J1-1. |
| J5 | no | seal signature, anchor, receipt |

What each level catches (SPEC section 4, amendment 2 P2-1, amendment 3 P3-12, amendment 6):

| what happened | caught by |
|---|---|
| a byte, a line, the key order or a number damaged; a frame removed, inserted or moved | J0 |
| a seal naming the wrong prefix; a kernel id misused; a seal or close not from the kernel; a close without a seal; a frame after the close | J1 |
| a missing or extra genesis key, other formats or rules | J2 |
| a frame body changed without recomputing `request_hash` (the forger of delivery 1) | J2 |
| a seal or close executed inside a batch | J2 |
| a record of a frame changed or hidden, the records root not recomputed | J3 |
| a quote whose bytes are not in its source, even with every hash recomputed | J3 |
| a seal naming a cascade the journal does not give (a fallen claim written as standing; records changed and the projections not recomputed) | J4a |
| a quittance whose seal is not in the journal, or whose record does not stand there | J4a (`--quittance`) |
| the tail of the journal cut off | only an external seal of a later point (J1) or an external head (J0) |
| a quote replaced by another phrase of the same document, everything recomputed | only an external seal or head |

Known differences with the kernel are listed in SPEC section 10 and amendment 3, P3-12. Examples:
- without `--docs` J3 and J4a are not run;
- a missing document gives `INCOMPLETE`, not `FAIL`;
- the kernel's acceptance rules are not repeated.

## The cut and the observation report

**`cut <folder>`** checks a bundle in the layout of the vectors: `cut.json`, `<journal>/run.wal`, `<journal>/docs/`, `<export>.txt`. It runs B0-B4 of `SPEC_CUT_AND_BUNDLE_v1` in order:
- B0, the manifest: one JSON object in UTF-8, without a repeated key at any depth (layout free; a byte-order mark is not JSON; any other file gives `cut_hash` null); exact keys and types, names `[A-Za-z0-9._-]{1,64}` other than `.` and `..`, lists sorted by UTF-16 code units, names unique, deliveries that may coexist, references, mode `observe`. No file of the bundle is read before B0 passes;
- B1, each journal: its part is the frames `0 … log_size`, and the close frame when `closed`. The seal, `wal_head`, the close, `run_id` and `rules_version` are checked, and J0-J4a run on the part read as a file of its own, with `seal_hash` as the external seal;
- B2, each export: SHA-256 and header; the seal is in the part; the paragraphs name claims accepted before that seal, standing at it; the file equals the canonical export, byte for byte (`Rests on:` and `Quotes:` list each ground once, at its first place);
- B3, the deliveries: declared, undeclared imports, not modified;
- B4, a withdrawal across journals.

The report `yuce-cut-report/1` lists the failures with the fields and in the order of section 6, and `cut_hash = hex(H("YUCE-CUT/1", JCS(manifest)))`. A failed B0 ends the check. A later check runs only where what it needs passed: a journal whose part failed B1.5 is not used by B2-B4, and B3.3 and B4 read only deliveries that passed B3.1.

**`report`** computes `yuce-observation-report/1`, either over one journal and the seal frame that ends its part, or over a cut that passes B0-B4. It prints the canonical bytes, without a trailing newline. Per claim it gives three axes:
- support: `grounded` or `affected`, with the root causes and their reasons;
- dispute: `contested`, `unknown` or `uncontested`, with the links;
- time: `stale`, `unknown` or `current`, with the links.

It also gives the quotes, `rests_on`, `rests_on_across`, the questions, the exact-key conflicts, the debt counters and `report_hash`. Among the counters, `rejected_submissions` and `late_submissions` count the `batch` frames of the part whose checkpoint records a refused answer (`task-repair:`) or a late one (`task-conflict:`).

With `--check <report>` it checks a given report in three steps:
1. the bytes of the file, as they are, are the UTF-8 of a canonical JSON object with a `report_hash` of 64 lowercase hex digits, else `REPORT_FORM` (a byte-order mark or a trailing newline among them);
2. its own `report_hash`, else `REPORT_HASH_MISMATCH`;
3. the report recomputed, byte for byte, else `REPORT_MISMATCH` with the first differing path, such as `claims[0].support`.

## Use

Node.js (tested on 24). No install: the delivery is the single file `dist/yuce-verify.mjs`.

```
node dist/yuce-verify.mjs journal <file> [--docs <folder>] [--expect-seal <hex>] [--expect-head <hex>]
                                         [--quittance <file>]... [--dump-projections <file>]
                                         [--max-line-bytes <n>] [--max-depth <n>] [--json] [--quiet]
node dist/yuce-verify.mjs cut <folder> [--json] [--quiet]
node dist/yuce-verify.mjs report <journal> --seal-frame <n> [--docs <folder>] [--check <report>] [--json] [--quiet]
node dist/yuce-verify.mjs report <cut folder> [--check <report>] [--json] [--quiet]
node dist/yuce-verify.mjs vectors <file.json> [--json] [--quiet]
```

- `--docs <folder>`: every regular file of the folder and its subfolders is read. A document is the file whose SHA-256 is the `raw_sha256` of its description; other files are counted in `input.sources.files` and otherwise ignored.
- `--quittance <file>` (repeatable): a quittance `yuce-proof/1` cut from this journal, checked by J4a (P6-11).
- `--dump-projections <file>`: writes the rows and pairs J4a computed at every seal, in the form of the kernel's rows in `inputs/j4a/rows/`, for finding the first differing row.
- Without `--json`: one line for a human. With `--json`: only the report, as canonical JSON. `--quiet`: only the exit code.
- Exit codes: `0` PASS; `1` FAIL (or a report that cannot be computed); `2` a call error, or a file or folder cannot be read; `3` INCOMPLETE (J3 asked for, a document of the genesis record not in the folder).
- An unsealed tail or an open run is not a failure: it is reported, and the exit code stays 0.
- Defaults equal the bounds of the journal format (amendment 1): `--max-line-bytes 67108863` and `--max-depth 64`. Values must be integers ≥ 1.
- **If you raise `--max-line-bytes` or `--max-depth` above its default, the verifier may accept a line that cannot occur in a correct journal.** Lowering them only makes the check stricter.

Examples, from this folder:

```
$ node dist/yuce-verify.mjs journal ../inputs/valid/kinds-batch-put.wal --docs ../inputs/valid/kinds-batch-put.docs
J0-J3 PASS. Frames: 8. Seals: 1. Records: 13. Quotes: 5. Tail: closed. Anchor: not given - journal is internally consistent; authenticity not established. Cascade: checked at 1 seals. Not verified: signatures.

$ node dist/yuce-verify.mjs journal ../inputs/valid/live-server-unsealed-tail.wal --docs ../inputs/valid/live-server-unsealed-tail.docs
J0-J3 PASS. Frames: 9. Seals: 1. Records: 4. Quotes: 2. Tail: 5 unsealed frames. Anchor: not given - journal is internally consistent; authenticity not established. Cascade: checked at 1 seals through frame 3; 5 later frames not checked. Not verified: withdrawal cascade after last seal, signatures.

$ node dist/yuce-verify.mjs journal ../inputs/j4a/set-c/forged-cascade.wal --docs ../inputs/j4a/set-c/forged-cascade.docs
FAIL at J4a, frame 6: PROJECTION_STATUS_MISMATCH. Not verified: withdrawal cascade, signatures.

$ node dist/yuce-verify.mjs journal ../inputs/valid/kinds-batch-put.wal
J0-J2 PASS. Frames: 8. Seals: 1. Tail: closed. Anchor: not given - journal is internally consistent; authenticity not established. Not verified: quotes against sources, withdrawal cascade, signatures.

$ node dist/yuce-verify.mjs cut ../inputs/cut/V-CUT-2
Cut FAIL: WITHDRAWAL_NOT_DELIVERED (export e1, record fc7e632f2db912c9c610c8a8f294440361675d9084798b171eae63307653ab7e, observation e3ad7d0dcfb67df067ba8423e2d714dff5f3f2ede2cd9d519938f50f7042dadf). Not verified: meaning, undeclared dependencies, signatures.

$ node dist/yuce-verify.mjs report ../inputs/cut/V-CUT-1 --check ../inputs/obs/V-OBS-5/report.json
Report FAIL: REPORT_MISMATCH at claims[0].support.
```

### In a browser

The same file loads as an ES module. Under Node.js it uses `node:crypto` (loaded lazily); elsewhere it uses `crypto.subtle`. Documents, quittances, a cut's files and a report are given as their bytes, like the journal:

```js
import { verifyJournal, verifyCut, observationReportForCut, subtleHashAdapter, humanLine } from "./yuce-verify.mjs";
const documents = await Promise.all([...docFiles].map(async (f) => new Uint8Array(await f.arrayBuffer())));
const report = await verifyJournal(journalFile.stream(), { documents }, subtleHashAdapter());
console.log(humanLine(report));
// a cut: { manifest, journals: Map(name -> { journal, documents }), exports: Map(name -> bytes) }
const { report: cutReport } = await verifyCut(bundle, subtleHashAdapter());
```

The main session checked delivery 2 in a real browser on 20 November 2026: Chromium 156, `crypto.subtle` as the hash, the file unchanged. A journal of 455 frames, 1,186 records and 788 quotes with its 6 documents gave J0-J3 PASS in 0.25 s. **Delivery 3 (J4a, the cut, the report) has been run only under Node.js**, and in the test that loads the bundle with `process` removed.

## Report

As SPEC section 8 and amendment 3, P3-10 fix it, with amendment 6:

- One failure is reported, by level: J0 anywhere in the file, then J1 (`ANCHOR_NOT_FOUND` last), then J2, then J3, then J4a (a seal first, then the quittances in the order given). All levels run in one streaming pass; each keeps its first failure.
- **J2** passed: `{"result":"PASS","documents":D,"settings_hash":"…"}`. **J3** passed: `{"result":"PASS","records":R,"quotes":Q}`. **J4a**: `{"result":"PASS"}`, `{"result":"FAIL"}` or `{"result":"NOT_RUN","reason":…}`.
- **J3 not run:**
  - `NOT_CHECKED` without `--docs`;
  - `NOT_CHECKABLE` with the reason `"<level> failed"`, or `"document <doc_id> not supplied"`.
- `cascade`: `{"seals_checked":k,"checked_through_frame":n|null,"unchecked_frames":m}`, or `null` when J4a did not run. The close frame right after the last seal is not counted as unchecked.
- `quittances`: one `{"file","verdict","code"}` per `--quittance`; `verdict` is `NOT_RUN` when J4a did not reach its seal.
- `input.sources` is `{"given":false}` or `{"given":true,"files":N}`.
- Verdict: `FAIL` if any level failed; else `INCOMPLETE` if a document is missing; else `PASS`.
- The report has no time, paths or host names: the same input gives the same bytes.

## Memory and speed

J0-J1 hold one line and O(log n) hashes. J2 adds the pairs `(actor, submission_id)`. J3 adds the documents and the ids, anchors and local names of accepted records. J4a adds, per record, its kind, grounds, ends and observation (amendment 6, P6-2), and the revoked anchors, withdrawn texts and links. The document chunking is O(n) with a sliding-window queue (P3-8). `k017-oracle-v3.wal` (3 MB, 695 frames, 2 314 records, 22 documents, 35 seals) takes about 0.5 s with `--docs` and J4a; the bound is 5 s.

## Development

Development tools only (`devDependencies`): `typescript` for the type check, `esbuild` to bundle `src/` into `dist/yuce-verify.mjs`.

```
npm install
npm test
```

`npm test` = type check + build + all tests (`node --test`), against the built delivery file:

| file | covers |
|---|---|
| `test/vectors.test.mjs` | A1/B1: V1-V4, V7, V9-V16 (with `V11_short_documents` of amendment 4) and the settings hash of V8 pass; V5, V6, V8 otherwise named as skipped |
| `test/inputs.test.mjs` | A2/B2: `valid/` with documents (J2, J3 and J4a values); B6 without documents and with a missing document; A3/B3: `corrupt/` by `level`; A6a: `boundary/`; B4: `forger-full-rehash.wal`; B5: accept/refuse equals the kernel on all 23 inputs |
| `test/amendment6.test.mjs` | amendment 6: set A (58 paths) and set D (9 journals, d8 and d9 of the first code round among them): `PASS`, `cascade` and every seal's projections; set B: the kernel's rows and pairs at every seal equal the computed ones; set A′; set C; set E (E5 among them) and the form of a quittance, its seal body by J1-1; the boundary journal with and without `--expect-seal`; `revoke.record` only as a full id; human lines; the link id; `--quittance`, `--dump-projections` |
| `test/cut.test.mjs` | the cut: V-CUT-1 … 26 (verdict, failures, `across`, `cut_hash`; a batch that brings in an export among them); B0 variants (`.` and `..`, repeated keys, a byte-order mark, free layout among them); B1-B3 variants made from the vectors; the export format (a repeated ground written once); the command line |
| `test/obs.test.mjs` | the observation report: V-OBS-1, 2, 3, 6, 8, 9 byte for byte; V-OBS-4, 5, 7; the counters of refused and late answers; `REPORT_FORM` (a report without its hash and one with a byte-order mark among them); the first differing path; the command line |
| `test/matrix23.test.mjs` | B3: the J2/J3 matrix on `kinds-batch-put.wal` (and `baicalin-n3-shard1.wal` for git descriptions) |
| `test/forger.test.mjs` | A6/B4: forged journals pass J0-J2; J3 catches a quote not in its source; the same-document replacement, its projections recomputed, passes J0-J4a and only an anchor catches it; with the projections left as they were, J4a catches it |
| `test/matrix.test.mjs`, `test/seal.test.mjs` | A3/A4/A4a/A5: J0 and J1 matrices |
| `test/delivery11.test.mjs`, `test/amendment1.test.mjs`, `test/amendment2.test.mjs` | delivery 1.1 and amendments 1, 2; A9 (J0-J1 results unchanged since delivery 1) |
| `test/amendment5.test.mjs` | amendment 5: the rules 3 and 4 of a genesis record, the record a question is about, the journal that starts without a document; the release: `package.json`, its lock file, `VERIFIER_VERSION` and the banner of `dist/yuce-verify.mjs` name one version; the lock file names the license of `package.json` |
| `test/json.test.mjs` | strict parser, JCS, depth, log tree |
| `test/stream.test.mjs` | chunking, `ReadableStream`, `crypto.subtle` adapter (also with documents), speed (3 MB < 2 s; k017 with documents < 5 s), O(n) chunking, bundle without Node.js globals |
| `test/cli.test.mjs` | commands, human lines (J0-J2, J0-J3, INCOMPLETE, failures), JSON report, `--docs`, exit codes 0/1/2/3 |

### The forger

`test/forge.mjs` changes one value and recomputes the frame hashes, `request_hash` and the seals. With `--docs` it also recomputes:
- the record ids, the `@` references, `put_document` versions and the records roots, by the formulas of amendment 3;
- the projections every seal names, with the verifier's own J4a.

Its journals are in `test/fixtures/forged/`; `npm run make-forged` rewrites them, and a test checks that they are reproducible.

```
node test/forge.mjs <in.wal> <out.wal> <frame> <path> <json-value> [--docs <folder>]
```

See `BOUNDARY_RESULTS.md` for the results on `inputs/boundary/` and `inputs/j4a/boundary/`.
