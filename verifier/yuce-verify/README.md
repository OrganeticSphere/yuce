# yuce-verify (delivery 1.1 with amendments 1 and 2: levels J0, J1)

An independent verifier of YuCe journals in the format `sbgk-session-log/3`: a standalone implementation of the specification, sharing no code and no dependencies with the kernel. [`../spec/`](../spec/) holds that specification (`SPEC_INDEPENDENT_VERIFIER/4`: version 3 with its amendments 1 and 2, in an English translation of the original), and [`../inputs/`](../inputs/) the test journals with the results expected of them.

It answers one question: **is this file a well-formed YuCe journal, and does it match a seal or a head I was given separately?**

## What it does not establish

Read these before you trust a PASS.

1. **Without an external anchor, J0-J1 say only "the file is internally consistent".** Anyone who can recompute the hashes passes this check. `test/forge.mjs` does exactly that, and its journals pass (acceptance A6).
2. **No level checks the meaning of the records.**
3. **Levels J0-J3 and J5 confirm the integrity of the journal, the seals and the bytes of the quotes in their sources. They do not recompute the projections of statuses and dependencies, that is, the withdrawal cascade.** The withdrawal cascade stays checked by the kernel only.

Every human line ends with `Not verified: quotes against sources, withdrawal cascade, signatures.`, and every JSON report has `not_verified`.

## Levels

| level | in delivery 1.1 | what it checks |
|---|---|---|
| **J0** | yes | The file and its lines, read as a stream: not empty; line length and nesting limits; every frame ends with LF (no torn tail); valid UTF-8; strict JSON object; integers only from 0 to 2^53-1; canonical form (RFC 8785, byte for byte); the format `sbgk-session-log/3`; exactly the keys of a frame and its header; the types; `seq = position`; `wal_op` (`genesis` only at 0); the chain `previous`; `body_hash = H("R2R-FRAME-BODY/2", JCS(body))`; `hash = H("R2R-FRAME-HDR/2", JCS(header))`. Last, optionally: the head equals `--expect-head`. |
| **J1** | yes | Per frame, in this order: no frame after the close frame (J1-14); a seal or close only from `kernel` (J1-13); for a seal candidate (J1-1 … J1-9), the form and types of the seal frame, `P` the same in command and outcome, `r2r-seal/2`, `log_size = position ≥ 1`, `wal_head` = hash of the frame before, `log_root` = RFC 6962 root over the frames before, `audit_root` and `engine_root` equal those of the frame before, `seal_hash = H("R2R-SEAL/2", JCS(P))`, `run_id` = `body.run_id` of frame 0; then the kernel ids (J1-10 … J1-12): on a kernel frame any `submission_id` starting with `seal-` (exact, case-sensitive) only on a seal, `audit-close` exactly with `{"kind":"close"}`, a close frame only right after a seal. The tail: `closed`, `sealed`, `unsealed` (K frames), `no_seals`. Last, optionally: `--expect-seal` must be one of the computed seal hashes. |
| J2 | no | genesis record, batches (seal or close inside a batch) |
| J3 | no | records tree of a frame, quote bytes against sources (the records-tree code is here already and passes vectors V1, V2) |
| J5 | no | seal signature, anchor, receipt |

What each level catches (SPEC section 4):

| what happened | caught by |
|---|---|
| a byte, a line, the key order or a number damaged | J0 |
| a frame removed, inserted or moved in the middle | J0 |
| a seal naming the wrong prefix of the journal | J1 |
| a command under a kernel id; a seal or close not from the kernel; a close without a seal; a frame after the close | J1 |
| the tail of the journal cut off | only an **external** seal of a later point (J1) or an external head (J0) |
| the whole journal rewritten with all hashes recomputed | only an external seal or head kept out of the writer's reach |
| the withdrawal cascade computed wrongly | **no level of this verifier** |

The 13 questions of delivery 1 are answered in SPEC v3, appendix A; SPEC-DEFECT-14 and 15 in amendment 2. No question is open now.

## Use

Node.js (tested on 24). No install: the delivery is the single file `dist/yuce-verify.mjs`.

```
node dist/yuce-verify.mjs journal <file> [--expect-seal <hex>] [--expect-head <hex>]
                                         [--max-line-bytes <n>] [--max-depth <n>] [--json] [--quiet]
node dist/yuce-verify.mjs vectors <file.json> [--json] [--quiet]
```

- Without `--json`: one line for a human (SPEC 8.3). With `--json`: only the report (SPEC 8.1) as canonical JSON. `--quiet`: only the exit code.
- Exit codes: `0` all levels of the delivery passed; `1` a check failed; `2` a call error or the file cannot be read; `3` reserved for delivery 2 (does not occur in delivery 1).
- An unsealed tail or an open run is not a failure: it is reported, and the exit code stays 0.
- Defaults equal the bounds of the journal format (amendment 1): `--max-line-bytes 67108863` (a frame line with its LF is at most 64 MiB; the flag counts bytes without the LF) and `--max-depth 64` (a frame nests at most 64 levels of JSON; the outermost object is 1, brackets inside strings do not count). Values must be integers ≥ 1.
- **If you raise `--max-line-bytes` or `--max-depth` above its default, the verifier may accept a line that cannot occur in a correct journal.** Lowering them only makes the check stricter.

Examples, from the folder `verifier/` of the repository:

```
$ node yuce-verify/dist/yuce-verify.mjs journal inputs/valid/withdrawal-version-close.wal
J0-J1 PASS. Frames: 8. Seals: 2. Tail: closed. Anchor: not given - journal is internally consistent; authenticity not established. Not verified: quotes against sources, withdrawal cascade, signatures.

$ node yuce-verify/dist/yuce-verify.mjs journal inputs/valid/withdrawal-version-close.wal \
    --expect-seal 4c384f513689aafa314ca11505947186bf94a6dce0cffda0275a460c5de7ea1c \
    --expect-head 3431d070a4345a4b9e3b8973ce526621408c2921a5d100c00956c5ceac4d34bc
J0-J1 PASS. Frames: 8. Seals: 2. Tail: closed. Anchor: matched seal at n=6 and head at n=8. Not verified: quotes against sources, withdrawal cascade, signatures.

$ node yuce-verify/dist/yuce-verify.mjs journal inputs/corrupt/tampered-seal.wal
FAIL at J1, frame 2: SEAL_LOG_ROOT. Not verified: quotes against sources, withdrawal cascade, signatures.
```

### In a browser

The same file loads as an ES module. Under Node.js it uses `node:crypto` (loaded lazily); elsewhere it uses `crypto.subtle`:

```js
import { verifyJournal, subtleHashAdapter, humanLine } from "./yuce-verify.mjs";
const report = await verifyJournal(file.stream(), {}, subtleHashAdapter());
console.log(humanLine(report));
```

WebCrypto has no incremental digest, so in a browser the SHA-256 of the whole file (`input.journal_sha256`) keeps the file in memory. Under Node.js the verifier holds one line and O(log n) hashes. Checked in a real browser on 13 November 2026 (Chromium 156, with no `process` and `crypto.subtle` as the hash): on the 14 journals of `../inputs/` and on the journal of `control02-run2-K` of release v0.2.0 (672 frames, 34 seals, in 0.2 s), the reports were byte for byte those of Node.js.

## Report

As SPEC v3 section 8 fixes it:

- One failure is reported: the first J0 failure anywhere in the file (torn tail and `HEAD_MISMATCH` included); otherwise the first J1 failure by frame position, `ANCHOR_NOT_FOUND` last (SPEC 9).
- After a J0 failure, J1 is `{"result":"NOT_CHECKABLE","reason":"J0 failed"}`; after a J1 failure, `{"result":"FAIL"}`. A passing J1 has `seals` and `tail` only.
- `anchor` has two parts, `seal` (`given`, `matched`, and `at_n`, `frames_after` when matched) and `head` (`given`, `matched`).
- `input.frames` is the number of LF-terminated lines of the file, also on failure. `input.format` is `header.format` of frame 0.
- The report has no time, paths or host names: the same input gives the same bytes. It is printed as JCS with one LF.

## Development

Development tools only (`devDependencies`): `typescript` for the type check, `esbuild` to bundle `src/` into `dist/yuce-verify.mjs`.

```
npm install
npm test
```

`npm test` = type check + build + all tests (`node --test`). The tests run against the built delivery file:

| file | covers |
|---|---|
| `test/vectors.test.mjs` | A1: vectors V1-V4, V7, V9 (all equalities, `log_root` included) pass; V5, V6, V8 named as skipped |
| `test/inputs.test.mjs` | A2: `inputs/valid/` against `expected.json`; A3: `inputs/corrupt/`; A6a: `inputs/boundary/` |
| `test/matrix.test.mjs` | A3: the substitution matrix on a small journal (every header field, every outer field and one body byte in every frame; lines removed, repeated, swapped; torn tail, garbage, CR, BOM, key order, space, uppercase hash, `1.0`, `2^53`, lone surrogate raw and escaped, UTF-8, limits) |
| `test/seal.test.mjs` | A4: substitutions in seals; A4a: kernel commands (J1-10 … J1-14); tail kinds; anchor; A5 |
| `test/delivery11.test.mjs` | A9: one test per item of section 6 of the clean-room task statement, which is not published (items 1 and 10 as changed by amendment 1); results on all inputs unchanged since delivery 1 (`test/fixtures/delivery1-reports/`) except `anchor` and the removed fields |
| `test/amendment1.test.mjs` | amendment 1, P1-6: defaults 67108863 and 64, the length bound at N and N + 1, depth 64 and 65, brackets in strings, the README warning |
| `test/amendment2.test.mjs` | amendment 2, P2-3: J1-10 by the prefix `seal-` (`seal-`, `seal-x`, `seal-٣`, `seal-01` refused; `Seal-1`, `sealx-1` not under the rule; other actors not under the rule), J1-4 for such ids on a seal, J1-11 unchanged, spec id `/4` |
| `test/forger.test.mjs` | A6: forged journals pass J0-J1; only `--expect-seal` or `--expect-head` catch them |
| `test/json.test.mjs` | strict parser, JCS, depth, log tree against a recursive RFC 6962 root |
| `test/stream.test.mjs` | chunking does not change the report, `ReadableStream`, `crypto.subtle` adapter, speed (3 MB < 2 s), bundle without Node.js globals |
| `test/cli.test.mjs` | commands, human line, JSON report, `--quiet`, exit codes 0/1/2 |

The forger (`test/forge.mjs`) changes one value and recomputes the frame hashes and the seals. It does not recompute `request_hash` or `records_root`: their formulas are not in delivery 1. Its journals are in `test/fixtures/forged/`; `npm run make-forged` rewrites them, and a test checks that they are reproducible.

```
node test/forge.mjs <in.wal> <out.wal> <frame> <path> <json-value>
```

See `BOUNDARY_RESULTS.md` for the observed results on `inputs/boundary/`.
