# yuce-verify 0.3.0 (delivery 2 with amendments 4 and 5: levels J0, J1, J2, J3)

An independent verifier of YuCe journals in the format `sbgk-session-log/3`: a standalone implementation of the specification, sharing no code and no dependencies with the kernel. [`../spec/`](../spec/) holds that specification (`SPEC_INDEPENDENT_VERIFIER/7`: version 3 with its amendments 1, 2, 3, 4 and 5, in an English translation of the original), and [`../inputs/`](../inputs/) the test journals with their source documents and the results expected of them.

It answers two questions:
- is this file a well-formed YuCe journal whose accepted quotes are, byte for byte, in their source documents?
- does it match a seal or a head I was given separately?

## What it does not establish

Read these before you trust a PASS.

1. **Without an external anchor, J0-J3 say only "the file is internally consistent".** Anyone who can recompute the hashes passes J0-J2. `test/forge.mjs` does exactly that, and its journals pass (acceptances A6, B4).
2. **No level checks the meaning of the records.** J3 checks the bytes of quotes, record ids and records roots. It does not repeat the kernel's rules of acceptance (amendment 3, P3-9), for example:
   - whether a basis is still active;
   - whether a reference is visible to its task;
   - whether a relation is declared in the ontology or was decided by four eyes;
   - limits of values.
3. **Levels J0-J3 and J5 confirm the integrity of the journal, the seals and the bytes of the quotes in their sources. They do not recompute the projections of statuses and dependencies, that is, the withdrawal cascade.** The withdrawal cascade stays checked by the kernel only.
4. **The honest boundary of J3.** A quote replaced by **another phrase that also occurs exactly once in the same document**, with every hash, id, root and seal recomputed, passes J0-J3. Only an external seal or head kept out of the writer's reach shows it. `test/fixtures/forged/forged-records-same-document.wal` is such a journal.

Every human line ends with `Not verified: …`: `withdrawal cascade, signatures` when J3 passed; otherwise `quotes against sources, withdrawal cascade, signatures`. Every JSON report has `not_verified`.

## Levels

| level | in delivery 2 | what it checks |
|---|---|---|
| **J0** | yes | The file and its lines, read as a stream: not empty; line length and nesting limits; every frame ends with LF; valid UTF-8; strict JSON object; integers only from 0 to 2^53-1; canonical form (RFC 8785, byte for byte); the format `sbgk-session-log/3`; exactly the keys of a frame and its header; types; `seq`; `wal_op`; the chain `previous`; `body_hash`; `hash`. Last, optionally: the head equals `--expect-head`. |
| **J1** | yes | Seals (form, `P` in command and outcome, `log_size`, `wal_head`, `log_root`, root continuity, `seal_hash`, `run_id` of frame 0), kernel ids (`seal-…` only on a seal, `audit-close` only on the close frame), close right after a seal, nothing after the close, seal and close only from `kernel`. The tail kind. Last, optionally: `--expect-seal`. |
| **J2** | yes, always | The genesis record: exactly 15 keys, the formats `r2r-audit-genesis/3`, `r2r-state-root/2`, `r2r-seal/2`, the rules `r2r-audit-rules/3` or `r2r-audit-rules/4` (amendment 5: a journal of 0.3.0, which a verifier of 0.2.1 refuses here with `GENESIS_FORMAT`), the kind of every field, `operator_meta` ≤ 4096 bytes in JCS, the document descriptions (exact keys, identifier keys, `revision_refs` an object) and the `git_manifest` doc_id formula, an empty records root on frame 0. Every later frame: exactly 7 body keys, identifiers `actor` and `submission_id`, three outcome forms (`records` only on a submit, a submit only `records` or `error`), `request_hash = hex(SHA256(JCS(["r2r-audit-request/1", actor, command])))`, no repeated `(actor, submission_id)`. Batches: the outcome form; no executed seal, close or batch inside a batch. |
| **J3** | yes, with `--docs` | Documents are found by the SHA-256 of their bytes (`raw_sha256`); file names do not matter. New versions come from `put_document`. For every accepted record: the line form (`local_id` present, `exact_quote` at most 16 384 bytes), a local name used once per author and task (`DUPLICATE_LOCAL_ID`), references (by local name, or `@` and 16-64 hex digits), the quote occurs **exactly once** in the current bytes of its document and inside the task's scope, the anchor (content-defined chunks, document version, evidence id), the value `L`, the record id against the outcome, and the records root of every frame against `header.records_root`. |
| J5 | no | seal signature, anchor, receipt |

What each level catches (SPEC section 4, amendment 2 P2-1, amendment 3 P3-12):

| what happened | caught by |
|---|---|
| a byte, a line, the key order or a number damaged; a frame removed, inserted or moved | J0 |
| a seal naming the wrong prefix; a kernel id misused; a seal or close not from the kernel; a close without a seal; a frame after the close | J1 |
| a missing or extra genesis key, other formats or rules | J2 |
| a frame body changed without recomputing `request_hash` (the forger of delivery 1) | J2 |
| a seal or close executed inside a batch | J2 |
| a record of a frame changed or hidden, the records root not recomputed | J3 |
| a quote whose bytes are not in its source, even with every hash recomputed | J3 |
| the tail of the journal cut off | only an external seal of a later point (J1) or an external head (J0) |
| a quote replaced by another phrase of the same document, everything recomputed | only an external seal or head |
| the withdrawal cascade computed wrongly | **no level of this verifier** |

Known differences with the kernel are listed in SPEC section 10 and amendment 3, P3-12. Examples:
- without `--docs` J3 is not checked;
- a missing document gives `INCOMPLETE`, not `FAIL`;
- the kernel's acceptance rules are not repeated.

The questions raised while delivery 2 was written, SPEC-DEFECT-16 … 21, are answered by amendment 4; none is open.

## Use

Node.js (tested on 24). No install: the delivery is the single file `dist/yuce-verify.mjs`.

```
node dist/yuce-verify.mjs journal <file> [--docs <folder>] [--expect-seal <hex>] [--expect-head <hex>]
                                         [--max-line-bytes <n>] [--max-depth <n>] [--json] [--quiet]
node dist/yuce-verify.mjs vectors <file.json> [--json] [--quiet]
```

- `--docs <folder>`: every regular file of the folder and its subfolders is read. A document is the file whose SHA-256 is the `raw_sha256` of its description; other files are counted in `input.sources.files` and otherwise ignored.
- Without `--json`: one line for a human. With `--json`: only the report, as canonical JSON. `--quiet`: only the exit code.
- Exit codes: `0` PASS; `1` FAIL; `2` a call error, or the file or the documents folder cannot be read; `3` INCOMPLETE (J3 asked for, a document of the genesis record not in the folder).
- An unsealed tail or an open run is not a failure: it is reported, and the exit code stays 0.
- Defaults equal the bounds of the journal format (amendment 1): `--max-line-bytes 67108863` and `--max-depth 64`. Values must be integers ≥ 1.
- **If you raise `--max-line-bytes` or `--max-depth` above its default, the verifier may accept a line that cannot occur in a correct journal.** Lowering them only makes the check stricter.

Examples, from the folder `verifier/` of the repository:

```
$ node yuce-verify/dist/yuce-verify.mjs journal inputs/valid/kinds-batch-put.wal --docs inputs/valid/kinds-batch-put.docs
J0-J3 PASS. Frames: 8. Seals: 1. Records: 13. Quotes: 5. Tail: closed. Anchor: not given - journal is internally consistent; authenticity not established. Not verified: withdrawal cascade, signatures.

$ node yuce-verify/dist/yuce-verify.mjs journal inputs/valid/kinds-batch-put.wal
J0-J2 PASS. Frames: 8. Seals: 1. Tail: closed. Anchor: not given - journal is internally consistent; authenticity not established. Not verified: quotes against sources, withdrawal cascade, signatures.

$ node yuce-verify/dist/yuce-verify.mjs journal inputs/corrupt/forger-full-rehash.wal --docs inputs/valid/baicalin-n3-shard1.docs
FAIL at J3, frame 52: QUOTE_NOT_IN_SOURCE. Not verified: quotes against sources, withdrawal cascade, signatures.

$ node yuce-verify/dist/yuce-verify.mjs journal inputs/valid/kinds-batch-put.wal --docs yuce-verify/test/fixtures/docs-without-vector-a
J0-J2 PASS. Frames: 8. Seals: 1. J3 not checkable: document vector-a.txt not supplied. Tail: closed. Anchor: not given - journal is internally consistent; authenticity not established. Not verified: quotes against sources, withdrawal cascade, signatures.
```

### In a browser

The same file loads as an ES module. Under Node.js it uses `node:crypto` (loaded lazily); elsewhere it uses `crypto.subtle`. Documents are given as their bytes, like the journal:

```js
import { verifyJournal, subtleHashAdapter, humanLine } from "./yuce-verify.mjs";
const documents = await Promise.all([...docFiles].map(async (f) => new Uint8Array(await f.arrayBuffer())));
const report = await verifyJournal(journalFile.stream(), { documents }, subtleHashAdapter());
console.log(humanLine(report));
```

Checked in a real browser on 20 November 2026 (Chromium 156, `crypto.subtle` as the hash), with this file unchanged: a journal of 455 frames, 1,186 records and 788 quotes with its 6 documents gave J0-J3 PASS in 0.25 s; the same journal with one byte of a quote changed in memory gave `FAIL at J0, frame 5: BODY_HASH_MISMATCH`; without its documents, J3 named the missing one (`INCOMPLETE`). The console showed no error.

## Report

As SPEC section 8 and amendment 3, P3-10 fix it:

- One failure is reported, by level: J0 anywhere in the file, then J1 (`ANCHOR_NOT_FOUND` last), then J2, then J3 (SPEC 9, P3-10). All levels run in one streaming pass; each keeps its first failure.
- **J2** passed: `{"result":"PASS","documents":D,"settings_hash":"…"}`. **J3** passed: `{"result":"PASS","records":R,"quotes":Q}`.
- **J3 not run:**
  - `NOT_CHECKED` without `--docs`;
  - `NOT_CHECKABLE` with the reason `"<level> failed"`, or `"document <doc_id> not supplied"`.
- `input.sources` is `{"given":false}` or `{"given":true,"files":N}`.
- Verdict: `FAIL` if any level failed; else `INCOMPLETE` if a document is missing; else `PASS`.
- The report has no time, paths or host names: the same input gives the same bytes.

## Memory and speed

J0-J1 hold one line and O(log n) hashes. J2 adds the pairs `(actor, submission_id)`. J3 adds the documents and the ids, anchors and local names of accepted records (the task statement, section 5). The document chunking is O(n) with a sliding-window queue (P3-8). `k017-oracle-v3.wal` (3 MB, 695 frames, 2 314 records, 22 documents) takes about 0.4 s with `--docs`; the bound is 5 s.

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
| `test/inputs.test.mjs` | A2/B2: `valid/` with documents (J2 and J3 values of `expected.json`); B6 without documents and with a missing document; A3/B3: `corrupt/` by `level`; A6a: `boundary/`; B4: `forger-full-rehash.wal`; B5: accept/refuse equals the kernel on all 22 inputs (for the 0.2.3 journal, the kernel 0.2.3) |
| `test/matrix23.test.mjs` | B3: the J2/J3 matrix on `kinds-batch-put.wal` (and `baicalin-n3-shard1.wal` for git descriptions). It covers: every genesis key removed, extra or of a wrong kind; every body key; `request_hash`; repeated pairs; batches with executed and refused seal, close, batch; every key of every kind of line; references (names, `@` 15/16/64/65 digits, case, ambiguous prefix); quotes (not in source, twice, empty, unknown document, outside docs, outside ranges, 16 384/16 385 bytes); repeated `local_id`; `submit` with `value`; identifier keys and `put_document` doc_id; `put_document` version; record ids; records roots |
| `test/forger.test.mjs` | A6/B4: forged journals pass J0-J2; J3 catches a quote not in its source; the same-document replacement passes J0-J3 and only an anchor catches it |
| `test/matrix.test.mjs`, `test/seal.test.mjs` | A3/A4/A4a/A5: J0 and J1 matrices |
| `test/delivery11.test.mjs`, `test/amendment1.test.mjs`, `test/amendment2.test.mjs` | delivery 1.1 and amendments 1, 2; A9 (J0-J1 results unchanged since delivery 1) |
| `test/amendment5.test.mjs` | amendment 5: the rules 3 and 4 of a genesis record, the record a question is about, the journal that starts without a document |
| `test/json.test.mjs` | strict parser, JCS, depth, log tree |
| `test/stream.test.mjs` | chunking, `ReadableStream`, `crypto.subtle` adapter (also with documents), speed (3 MB < 2 s; k017 with documents < 5 s), O(n) chunking, bundle without Node.js globals |
| `test/cli.test.mjs` | commands, human lines (J0-J2, J0-J3, INCOMPLETE, failures), JSON report, `--docs`, exit codes 0/1/2/3 |

### The forger

`test/forge.mjs` changes one value and recomputes the frame hashes, `request_hash` and the seals. With `--docs` it also recomputes the record ids, the `@` references, `put_document` versions and the records roots, by the formulas of amendment 3. Its journals are in `test/fixtures/forged/`; `npm run make-forged` rewrites them, and a test checks that they are reproducible.

```
node test/forge.mjs <in.wal> <out.wal> <frame> <path> <json-value> [--docs <folder>]
```

See `BOUNDARY_RESULTS.md` for the results on `inputs/boundary/`.
