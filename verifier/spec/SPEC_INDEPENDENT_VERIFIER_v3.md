# Specification of the independent verifier of YuCe journals (`yuce-verify`), version 3

OrganeticSphere, 11 November 2026.
**Identifier: `SPEC_INDEPENDENT_VERIFIER/2`.** Replaces version 2 (`SPEC_INDEPENDENT_VERIFIER/1`).
**Status: to be implemented for delivery 1 (levels J0 and J1).**

Companion documents: the clean-room task statement (not published), `VECTORS_INDEPENDENT_VERIFIER_20261110.json`.

**What is new in version 3.**
- All 13 questions of the implementer, `SPEC-DEFECT-01…13`, are resolved. A summary is in Appendix A; the decisions are written into the text of the sections.
- The kernel's answers of 10 November are included: line limits, the path to `run_id`, the ban on seals and closes not written by the kernel, the ban on frames after close. Gaps GAP-12 (length), GAP-14, GAP-15 and part of GAP-03 are closed.
- The form of the `anchor` field in the report changed; the fields `anomalies` and `frames_after_close` are removed; two failure codes are added.

**How to read.**
- The document is self-contained for levels J0 and J1.
- The words "must" and "forbidden" are requirements.
- **[CONFIRMED]** — the rule was checked against the kernel and is pinned by a kernel test.
- **[GAP-NN]** — the rule waits for an answer; what to do until then is stated next to it.
- Levels J2, J3 and J5 are described briefly and **are not part of delivery 1**.

---

## 1. Notation

- `‖` — byte concatenation.
- **`H(d, x1, x2, …)`** = `SHA-256( ASCII(d) ‖ 0x00 ‖ x1 ‖ x2 ‖ … )`. `d` is a domain string. There is one zero byte, right after the domain.
- **`JCS(v)`** — canonical JSON per RFC 8785 in UTF-8 (section 2).
- **Hash in the journal** — a string of exactly 64 characters `[0-9a-f]`. **[CONFIRMED]** Inside trees, the raw 32 bytes are hashed, not their text form.
- **RFC 6962 tree shape:** for `n > 1` leaves, the left subtree takes the largest power of two strictly less than `n`; the root of a single leaf is the leaf itself. The last node is **not duplicated**.
- **Frame position `i`** — the line number in the file, counted from zero.
- **Point `n`** — the state after frames `0 … n−1`.

## 2. Canonical JSON in the journal

The verifier implements canonicalization itself, without third-party libraries.

- **Parsing** follows RFC 8259 without extensions: no comments, no trailing commas, no BOM.
- **Lone surrogate.** A string with a `\uD800…\uDFFF` escape that does not form a valid pair is rejected by the parser: this is `INVALID_JSON`. Here the parser is intentionally stricter than the RFC 8259 grammar. A surrogate written as raw bytes is invalid UTF-8 and is caught earlier (J0-3).
- **Object keys** are sorted by UTF-16 code units.
- **No whitespace** between tokens.
- **Strings:** only `"`, `\` and control characters up to U+001F are escaped (`\b`, `\f`, `\n`, `\r`, `\t`, the rest as `\u00xx` with lowercase hexadecimal digits). Non-ASCII characters are written as is, in UTF-8.
- **Numbers.** **[CONFIRMED]** Every number in a frame is an integer from 0 to 2^53−1, written in decimal digits with no sign, no fractional part and no exponent. Any other number fails with `BAD_NUMBER`. The range is checked explicitly: the value 2^53 survives parsing and writing back unchanged.
- **Literals** `true`, `false`, `null` are allowed.

## 3. Inputs

| Input | Required | Purpose |
|---|---|---|
| journal file | yes | everything |
| `--expect-seal <hex>` | no | binding to a seal obtained **not from this file** |
| `--expect-head <hex>` | no | binding to a journal head obtained separately |
| `--max-line-bytes <n>` | no | line length limit, default 67108864 (64 MiB) |
| `--max-depth <n>` | no | nesting limit, default 128 |

- The values of `--expect-seal` and `--expect-head` are converted to lowercase; a value not of the form `[0-9a-f]{64}` is a usage error (exit code 2).
- Limit values are integers not less than 1; otherwise it is a usage error (code 2).
- The journal is untrusted input: nothing from it is executed, and the network is not used.

**Where the defaults come from.** The kernel's writer does not write a frame longer than 64 MiB. **[CONFIRMED]** The kernel's reader rejects nesting deeper than 128 levels; the writer has no depth limit. **[GAP-12, depth part]**: a writer rule "no deeper than 64" is under discussion; if it is adopted, the default will change.

## 4. What each level catches

| What happened | Where it is caught |
|---|---|
| a byte, a line, the key order or a number is corrupted | J0 |
| a frame is deleted, inserted or moved in the middle | J0 |
| a seal names the wrong prefix of the journal | J1 |
| a command under a kernel submission id; a seal or close not from the kernel; a close without a seal; a frame after close | J1 |
| the journal tail is truncated | only J1 **with an external seal** of a later point, or with an external head |
| the whole journal is rewritten with all hashes recomputed | only an external seal or head, kept out of the writer's reach |
| a seal or close inside a batch, an extra key in the genesis | J2 (not in delivery 1) |
| the kernel accepted a quote whose bytes are not in the source | J3 (not in delivery 1) |
| seal signature, quittance | J5 (not in delivery 1) |
| **the withdrawal cascade is computed incorrectly** | **no level of the verifier** |

Three consequences that must appear in the README and in the report line:
1. J0–J1 without an external binding say only "the file is internally consistent".
2. No level checks the meaning of records.
3. Levels J0–J3 and J5 confirm the integrity of the journal, the seals, and the bytes of quotes in sources. They do not recompute the projections of statuses and dependencies, that is, the withdrawal cascade.

---

## 5. Level J0: lines and the frame chain

### 5.0. Order

- **The file is read as a stream, line by line.** The J0 failure is the first failure in file reading order. A file with a corrupted frame 1 and a torn tail fails at frame 1.
- **For one line**, the checks run in numbering order: J0-1, then J0-3 … J0-15.
- **J0 goes through the whole file to the end before any J1 failure is reported** (see also section 9).

### 5.1. File and limits

- **J0-0.** An empty file (0 bytes) fails with `EMPTY_JOURNAL`, frame number `null`.
- **J0-1. Line limits.** They are checked on raw bytes, before parsing.
  - *Length* — the number of bytes of the line without the trailing LF. Failure if the length is strictly greater than `--max-line-bytes`. It is checked while reading, so it also applies to the bytes after the last LF: a tail longer than the limit is `LIMIT_EXCEEDED`, not `TORN_TAIL`.
  - *Nesting* — the largest number of `{` and `[` open at the same time outside string literals; the outer object of the frame counts as 1; arrays count the same as objects. Failure if the nesting is strictly greater than `--max-depth`.
  - The code is `LIMIT_EXCEEDED`; the frame number is the position of this line.
- **J0-2. Torn tail.** A frame is a line that ends with the LF byte (0x0A). Non-empty bytes after the last LF are not a frame: failure `TORN_TAIL`. This is checked when reading reaches them, that is, after all complete lines. The frame number is the position of the unfinished line (it equals the number of complete lines). **[CONFIRMED]** The verifier always fails; the kernel does not name such a number.

### 5.2. Line at position `i`

The line is taken without the trailing LF.

- **J0-3.** The bytes of the line are valid UTF-8; otherwise `INVALID_UTF8`.
- **J0-4.** The line parses as JSON (section 2), and the result is an object; otherwise `INVALID_JSON`. An empty line is also `INVALID_JSON`.
- **J0-5.** All numbers satisfy section 2; otherwise `BAD_NUMBER`.
- **J0-6. Canonical form.** `JCS(parsed)` must equal the line byte for byte; otherwise `NOT_CANONICAL`.
- **J0-7. Format.** If the object has the key `header`, and it holds a string `format` not equal to `"sbgk-session-log/3"`: at `i = 0` the failure is `UNSUPPORTED_FORMAT`, at `i > 0` the failure is `MIXED_FORMAT`.
- **J0-8.** The outer object has exactly three keys: `body`, `hash`, `header`; otherwise `OUTER_KEYS`.
- **J0-9.** `header` is an object with exactly six keys: `body_hash`, `format`, `previous`, `records_root`, `seq`, `wal_op`; otherwise `HEADER_KEYS`.
- **J0-10. Types.** `hash`, `header.body_hash`, `header.previous`, `header.records_root` are hashes (section 1); `header.seq` is a number; `header.format` and `header.wal_op` are strings; `body` is an object. Otherwise `BAD_TYPE`. A hash with uppercase letters is `BAD_TYPE`: the canonical form check does not catch it.
- **J0-11.** `header.seq = i`; otherwise `SEQ_MISMATCH`. **[CONFIRMED]**
- **J0-12.** `header.wal_op = "genesis"` if and only if `i = 0`; otherwise `"audit"`. A violation is `WAL_OP_MISMATCH`. **[CONFIRMED]**
- **J0-13.** `header.previous`: at `i = 0`, 64 zeros; otherwise equal to the `hash` of line `i−1`. A violation is `PREVIOUS_MISMATCH`.
- **J0-14.** `header.body_hash = hex(H("R2R-FRAME-BODY/2", JCS(body)))`; otherwise `BODY_HASH_MISMATCH`.
- **J0-15.** `hash = hex(H("R2R-FRAME-HDR/2", JCS(header)))`; otherwise `FRAME_HASH_MISMATCH`.

At this level, `header.records_root` is checked only for its form. J3 checks its value.

### 5.3. Result of J0

The number of frames `N` and the head `wal_head` = the `hash` of the last frame. If `--expect-head` is given and is not equal to `wal_head`, the failure is `HEAD_MISMATCH`, frame number `null`. This check is the last one in J0.

---

## 6. Level J1: seals, kernel commands, tail

### 6.1. Frame body: what this level needs

From `body`, level J1 reads `actor`, `submission_id`, `command`, `outcome`, `audit_root`, `engine_root`, and, for frame 0, `run_id`.

**Frame 0 [CONFIRMED].** The body of frame 0 is the genesis itself; its run identifier is `body.run_id`.

**Seal frame [CONFIRMED].** The seal of the first `n` frames is the frame at position `n`. Its body:

```
actor         = "kernel"
submission_id = "seal-<n>"            (n in decimal digits, no leading zeros)
command       = {"kind":"seal","seal":P}
outcome       = {"kind":"value","result":{"seal":P,"seal_hash":<hash>}}
```

```
P = {"format":"r2r-seal/2", "run_id":<string>, "log_size":n,
     "log_root":<hash>, "wal_head":<hash>,
     "audit_root":<hash>, "engine_root":<hash>,
     "projections":{"status":<hash>, "dependencies":<hash>}}
seal_hash = hex(H("R2R-SEAL/2", JCS(P)))
```

**Close frame [CONFIRMED].** `actor = "kernel"`, `submission_id = "audit-close"`, `command = {"kind":"close"}`. Closing a run writes a seal and, right after it, this frame. There are no frames after the close frame.

**Definitions.**
- The *command kind* of a frame is the value of `body.command.kind`, if `body.command` is an object and `kind` is a string; otherwise the frame has no command kind.
- A *seal candidate* is a frame with `body.actor = "kernel"` and command kind `"seal"`.
- A *close frame* is a frame with `body.actor = "kernel"` and command kind `"close"`.

Only the kernel writes seals and closes. **[CONFIRMED]** A journal that the kernel accepts has no frame with command kind `"seal"` or `"close"` from another actor, and no seal frame with a rejection outcome.

These rules apply to the frame's own command. J1 does not look inside a batch: the structure of a batch waits for **[GAP-11]** (level J2).

### 6.2. Order of checks for the frame at position `i`

1. J1-14 (frame after close);
2. J1-13 (seal or close not from the kernel);
3. if the frame is a seal candidate: J1-1 … J1-9;
4. J1-10, J1-11, J1-12.

### 6.3. Checks of a seal candidate

- **J1-1. Form and types.**
  - `command` has exactly the keys `kind`, `seal`;
  - `outcome` is an object with exactly the keys `kind`, `result`, and `outcome.kind = "value"`;
  - `outcome.result` is an object with exactly the keys `seal`, `seal_hash`;
  - `P = command.seal` is an object with exactly eight keys; `P.projections` is an object with exactly two;
  - `P.format` and `P.run_id` are strings, `P.log_size` is a number;
  - `P.log_root`, `P.wal_head`, `P.audit_root`, `P.engine_root`, both values of `P.projections`, and `seal_hash` are hashes.

  Any violation is `SEAL_FORM`.
- **J1-2.** `JCS(outcome.result.seal) = JCS(command.seal)`; otherwise `SEAL_FORM`.
- **J1-3.** `P.format = "r2r-seal/2"`; otherwise `SEAL_FORMAT`.
- **J1-4.** `i ≥ 1`, `P.log_size = i` and `submission_id = "seal-" + i`; otherwise `SEAL_LOG_SIZE`. A candidate at position 0 is `SEAL_LOG_SIZE`.
- **J1-5.** `P.wal_head` equals the `hash` of frame `i−1`; otherwise `SEAL_WAL_HEAD`.
- **J1-6.** `P.log_root` equals the root of the journal tree over the hashes of frames `0 … i−1` (section 6.6); otherwise `SEAL_LOG_ROOT`.
- **J1-7. Root continuity.** `P.audit_root` and `P.engine_root` equal the fields `audit_root` and `engine_root` of the body of frame `i−1`. If frame `i−1` does not have these fields, or they are not equal, the failure is `SEAL_ROOT_CONTINUITY`. **[CONFIRMED]**
  The seal frame body's own `audit_root` and `engine_root` name the state **after** the seal and are not compared with `P`.
- **J1-8.** `outcome.result.seal_hash = hex(H("R2R-SEAL/2", JCS(P)))`; otherwise `SEAL_HASH_MISMATCH`.
- **J1-9.** `P.run_id` equals `body.run_id` of frame 0. If frame 0 has no string `run_id`, or the values are not equal, the failure is `SEAL_RUN_ID`. **[CONFIRMED]**

At this level, the roots `audit_root` and `engine_root` are opaque values.

### 6.4. Kernel commands, close

- **J1-10.** For a frame with `actor = "kernel"`: if `submission_id` has the form `seal-` followed by one or more decimal digits, the frame must be a seal candidate. Otherwise `KERNEL_ID_MISUSE`. (J1-4 checks that the number equals the position.)
- **J1-11.** For a frame with `actor = "kernel"`: a close frame must have `command` equal to `{"kind":"close"}` and `submission_id = "audit-close"`; conversely, `submission_id = "audit-close"` is allowed only on a close frame. Otherwise `KERNEL_ID_MISUSE`.
- **J1-12.** A close frame at position `i` must be preceded by a seal frame at position `i−1`. Otherwise `CLOSE_WITHOUT_SEAL`. **[CONFIRMED]** A run without a server also closes only after a seal.
- **J1-13.** A frame with command kind `"seal"` or `"close"` and an `actor` not equal to `"kernel"` fails with `KERNEL_COMMAND_NOT_FROM_KERNEL`. **[CONFIRMED]**
- **J1-14.** Any frame after a close frame fails with `FRAME_AFTER_CLOSE`; the frame number is the position of the first such frame. **[CONFIRMED]**

### 6.5. Tail and external binding

The verifier does **not** require seals at regular intervals: the frequency is a writer setting.

The **tail** is the frames after the last seal of the journal. There are four kinds; none of them is a failure:

| Kind | Condition | `frames_after_last_seal` |
|---|---|---|
| `closed` | exactly one frame after the last seal, and it is a close frame | 1 |
| `sealed` | no frames after the last seal | 0 |
| `unsealed` | otherwise; the number of frames is `K` | `K` |
| `no_seals` | the journal has no seals | no field |

A run is closed if and only if the tail is of kind `closed`.

**External seal.** If `--expect-seal` is given, an equal value must be found among the computed `seal_hash` values; otherwise the failure is `ANCHOR_NOT_FOUND`, frame number `null`. This check is the last one in J1. The report names the point `n` of the found seal and the number of frames after it.

**External head.** It is checked in J0 (section 5.3). The head binds the whole file.

### 6.6. Journal tree

The leaves are the frame hashes (raw 32 bytes), in position order.

```
leaf(h)      = SHA-256(0x00 ‖ h)
node(l, r)   = SHA-256(0x01 ‖ l ‖ r)
```

Here, and only here, the domains are the bare RFC 6962 bytes: no domain string and no zero byte after it.

The root is computed as a running total:
1. Keep a stack of pairs (hash, size).
2. Push a new leaf as (leaf(h), 1). While the two top pairs have equal sizes, merge them: (node(lower, upper), sum of the sizes).
3. Root for the current number of leaves: take the top pair, then walk down the stack, replacing the result with node(next pair, result).

The root for a seal at position `i` is taken **before** the leaf of frame `i` itself is added.

---

## 7. Levels outside delivery 1 (brief, do not implement)

**J2. Genesis and batch.** A strict list of genesis keys, format values, `operator_meta` of at most 4096 bytes, `settings_hash`; a ban on seals and closes inside a batch. Waits for **[GAP-03]**, **[GAP-11]**.

**J3. Frame records and quotes.** The record tree of a frame:

```
leaf  = H("R2R-REC-LEAF/2", JCS(L))
node  = H("R2R-REC-NODE/2", left, right)
empty = H("R2R-REC-EMPTY/2")
```

The shape is RFC 6962. The root is checked against `header.records_root`; the bytes of each quote are checked against the source. Vector `V2_real` shows two real leaves. The rest waits for a later specification: **[GAP-04]**, **[GAP-05]**, **[GAP-06]**, **[GAP-09]**.

**J5. Signature, anchor, quittance.** Not part of this specification.

**J4 is canceled.** A narrow J4a (recomputing two projections) is under consideration, outside the deliveries.

---

## 8. Report

### 8.1. JSON on success

```json
{
  "verifier": {"name": "yuce-verify", "version": "…", "spec": "SPEC_INDEPENDENT_VERIFIER/2"},
  "input": {"journal_sha256": "…", "bytes": 0, "frames": 0, "format": "sbgk-session-log/3"},
  "levels": {
    "J0": {"result": "PASS"},
    "J1": {"result": "PASS",
           "seals": [{"n": 256, "seal_hash": "…"}],
           "tail": {"kind": "closed", "frames_after_last_seal": 1}},
    "J2": {"result": "NOT_CHECKED"},
    "J3": {"result": "NOT_CHECKED"},
    "J5": {"result": "NOT_CHECKED"}
  },
  "anchor": {
    "seal": {"given": true, "matched": true, "at_n": 256, "frames_after": 1},
    "head": {"given": false, "matched": null}
  },
  "computed": {"wal_head": "…", "closed": true},
  "not_verified": ["quotes_against_sources", "withdrawal_cascade", "signatures"],
  "verdict": "PASS",
  "first_failure": null
}
```

### 8.2. Fields

- **`input.frames`** — the number of file lines that end with LF. It is always computed, also on failure.
- **`input.format`** — `header.format` of frame 0, if `header` is an object and `format` is a string; otherwise `null`.
- **Level results:** `PASS`, `FAIL`, `NOT_CHECKED` (not part of the delivery), `NOT_CHECKABLE` (should have been checked, but there is nothing to check it with; the `reason` field is required).
- **On a J0 failure:** `J0` is `{"result":"FAIL"}`; `J1` is `{"result":"NOT_CHECKABLE","reason":"J0 failed"}`.
- **On a J1 failure:** `J1` is `{"result":"FAIL"}`, without seals and tail; the details are in `first_failure`.
- **`tail`** for kind `no_seals` is `{"kind":"no_seals"}`.
- **`anchor.seal`:** `given` says whether `--expect-seal` was given. With `given = false`: `{"given":false,"matched":null}`. With `given = true`: found — `{"given":true,"matched":true,"at_n":n,"frames_after":k}`; not found — `{"given":true,"matched":false}`; the check was not reached because of an earlier failure — `{"given":true,"matched":null}`.
- **`anchor.head`:** the same, without `at_n` and `frames_after`: `matched` is `true`, `false` (this is `HEAD_MISMATCH`) or `null`.
- **`computed.wal_head`** is `null` if J0 failed. **`computed.closed`** equals `tail.kind == "closed"`; it is `null` if J1 did not pass.
- **`not_verified`** is always present.
- **`verdict`:** `FAIL` if there is at least one `FAIL`; otherwise `PASS`. The value `INCOMPLETE` does not occur in delivery 1 (see 8.4).
- **`first_failure`:** `{"level", "frame", "code", "detail"}`. `frame` is the frame position; it is `null` only for `EMPTY_JOURNAL`, `HEAD_MISMATCH`, `ANCHOR_NOT_FOUND`.
- The report contains no times, paths or machine names. The report is printed as `JCS` with one LF at the end.

### 8.3. Line for a human

In English. One line, parts separated by one space, LF at the end. With the `--json` flag, only the JSON report is printed, without this line.

**On success, four parts:**
1. `J0-J1 PASS. Frames: <N>. Seals: <M>.`
2. Tail: `Tail: closed.` / `Tail: sealed, run not closed.` / `Tail: <K> unsealed frames.` / `Tail: no seals.`
3. Binding:
   - seal only: `Anchor: matched seal at n=<n>.`
   - head only: `Anchor: matched head at n=<N>.`
   - both: `Anchor: matched seal at n=<n> and head at n=<N>.`
   - neither: `Anchor: not given - journal is internally consistent; authenticity not established.`
4. `Not verified: quotes against sources, withdrawal cascade, signatures.`

**On failure, two parts:**
1. `FAIL at <level>, frame <i>: <code>.` or, if there is no frame number, `FAIL at <level>: <code>.`
2. Part 4, unchanged.

The word `verified` without a list of levels is forbidden.

### 8.4. Exit codes

0 — all levels of the delivery passed; 1 — a check failed; 2 — a usage error or a file read error; 3 — a requested level has nothing to be checked with.

**In delivery 1, code 3 and the verdict `INCOMPLETE` do not occur:** levels are not requested by a flag; J0 and J1 are always checked. They are reserved for delivery 2, where level J3 needs sources.

---

## 9. Failure codes and level order

- **J0:** `EMPTY_JOURNAL`, `LIMIT_EXCEEDED`, `TORN_TAIL`, `INVALID_UTF8`, `INVALID_JSON`, `BAD_NUMBER`, `NOT_CANONICAL`, `UNSUPPORTED_FORMAT`, `MIXED_FORMAT`, `OUTER_KEYS`, `HEADER_KEYS`, `BAD_TYPE`, `SEQ_MISMATCH`, `WAL_OP_MISMATCH`, `PREVIOUS_MISMATCH`, `BODY_HASH_MISMATCH`, `FRAME_HASH_MISMATCH`, `HEAD_MISMATCH`.
- **J1:** `FRAME_AFTER_CLOSE`, `KERNEL_COMMAND_NOT_FROM_KERNEL`, `SEAL_FORM`, `SEAL_FORMAT`, `SEAL_LOG_SIZE`, `SEAL_WAL_HEAD`, `SEAL_LOG_ROOT`, `SEAL_ROOT_CONTINUITY`, `SEAL_HASH_MISMATCH`, `SEAL_RUN_ID`, `KERNEL_ID_MISUSE`, `CLOSE_WITHOUT_SEAL`, `ANCHOR_NOT_FOUND`.

**Level order.** One failure is reported:
1. If J0 failed anywhere in the file (including a torn tail and `HEAD_MISMATCH`), the first J0 failure is reported, and J1 counts as not checked.
2. Otherwise, the first J1 failure in frame position order is reported; `ANCHOR_NOT_FOUND` comes last.

Example: the seal at frame 6 is wrong, and the tail after frame 7 is torn. The answer is `TORN_TAIL`. Conclusions about seals make sense only on a file with an intact chain.

An implementation may run both levels in one pass: it remembers the first J1 failure and continues J0 to the end of the file.

---

## 10. Known differences from the kernel

In differential testing, these do not count as divergences.

1. **Torn tail.** When the kernel checks a journal against an expected receipt, it accepts the journal if the state of the receipt lies within complete frames. The verifier always fails.
2. **Semantic rules.** The kernel replays the commands and rejects a journal whose outcome differs from the recorded one. Levels J0–J1 do not tell such journals apart. Example: `nested-seal.wal` from `boundary/`.
3. **Journal size.** The kernel's reader rejects a journal larger than 1 GiB. The verifier reads as a stream and has no such limit.
4. **Codes and numbers.** The accept/reject verdict is compared. The kernel has its own failure codes and frame numbers; the kernel does not name the frame number for a torn tail.
5. **Nesting at the boundary.** The level count of the verifier and of the kernel's reader may differ by one near the value 128.

---

## 11. State of the gaps

| No. | What | State |
|---|---|---|
| GAP-01, 02, 10, 13; numbers | hash notation; `seq` and `wal_op`; seal frame; torn tail; integers | closed [CONFIRMED] |
| GAP-12, line length | 64 MiB at the writer | closed [CONFIRMED] |
| GAP-12, depth | the writer has no limit; the kernel's reader has 128 | open: a writer rule "no deeper than 64" is under discussion |
| GAP-14 | only the kernel writes seals and closes | closed [CONFIRMED]; rule J1-13 |
| GAP-15 | no frames after close | closed [CONFIRMED]; rule J1-14 |
| GAP-03, path to `run_id` | `body.run_id` of frame 0 | closed [CONFIRMED]; rule J1-9 |
| GAP-03, the rest | structure of the frame body, `request_hash` | waiting; J2 |
| GAP-11 | structure of a batch | waiting; J2 |
| GAP-04, 05, 06, 09 | record value, list of accepted records, document identity, rules | waiting for a later specification; J3 |
| GAP-07, 08 | section schemas, engine root | dropped together with J4 |

---

## 12. Vectors

File `VECTORS_INDEPENDENT_VERIFIER_20261110.json`, status "checked against the kernel". Current version: 12,779 bytes, SHA-256 `c5e695b6800f4e8205644cfc0b075c323e0c79a81b8d361b58ef741c1c90649b`. It is the version checked against the kernel (12,860 bytes, SHA-256 `50b3193c643f86fa615010f3fa3272f8e1b036fbf21685fd183d87fe9a9d9acb`) with its two notes, `_note` and `_status`, put into English for publication; every vector is the same. That version differs from version `74a745f1…` (7601 bytes) only by the added vector V9. The tests of `yuce-verify` check that the file in this folder has the size and SHA-256 named here.

| Vector | What it checks | Needed in delivery 1 |
|---|---|---|
| `V3_*` | body hash, header hash and the whole frame line, byte for byte | yes |
| `V4_*` | journal tree on 1, 2, 3 leaves | yes |
| `V7_*` | seal hash | yes |
| `V9_*` | a real pair: the frame before a seal and the seal frame | yes |
| `V1`, `V2_*`, `V2_real_*` | record tree, including on real leaves | desirable |
| `V5_*`, `V6_*`, `V8_*` | formulas of the state root, the projections, the session root | no |

**About V9.** The vector keys have the form `V9_*`. The pair is frame 1 and seal frame 2, `log_size = 2`. The `log_root` equality can also be checked from the two lines: the hash of frame 0 is `header.previous` of frame 1, and the hash of frame 1 is written in frame 1 itself. The `vectors` command must check all V9 equalities, including `log_root`.

`V3` is a hashing vector, not a real genesis frame.

---

## 13. Divergence rule

If the verifier and the kernel give different verdicts on the same journal, and the case is not listed in section 10, the cause is one of three: a kernel defect, a verifier defect, or an ambiguity in the specification. The third is resolved first: first the text is fixed, then the code.

---

## Appendix A. Decisions on the implementer's questions

"As done" means: the implementer's decision, made before the answer, is confirmed and is now written in the text.

| Question | Decision | Where in the text | Code change needed |
|---|---|---|---|
| SPEC-DEFECT-01, order of J0 and J1 | as done: J0 over the whole file, then J1 | 5.0, 9 | no |
| SPEC-DEFECT-02, file checks and line checks | as done: the first failure in reading order; `TORN_TAIL` after all complete lines | 5.0, 5.1 | no |
| SPEC-DEFECT-03, counting nesting and length | as done. The defaults change: 64 MiB and 128 | 3, 5.1 | yes: the defaults |
| SPEC-DEFECT-04, lone surrogate | escaped: `INVALID_JSON`; as raw bytes: `INVALID_UTF8` per J0-3 | 2 | check that a raw one gives `INVALID_UTF8` |
| SPEC-DEFECT-05, GAP-14 and `anomalies` | the kernel closed the gap. A seal or close not from the kernel fails with `KERNEL_COMMAND_NOT_FROM_KERNEL`. A kernel frame with kind `seal` and a different outcome is `SEAL_FORM`, as done. The `anomalies` field is removed | 6.1, 6.4 J1-13, 8 | yes |
| SPEC-DEFECT-06, `frames_after_close` and `closed` | the kernel closed the gap. A frame after close fails with `FRAME_AFTER_CLOSE`. The `frames_after_close` field is removed. `closed = (tail.kind == "closed")`, as done | 6.4 J1-14, 6.5, 8.2 | yes |
| SPEC-DEFECT-07, binding by head | the `anchor` field now has two parts, `seal` and `head`; phrases for the head and for both bindings are added | 8.1, 8.2, 8.3 | yes |
| SPEC-DEFECT-08, line on failure | as done: without a frame number, `FAIL at <level>: <code>.`; on failure, parts 1 and 4; one line, spaces, LF at the end | 8.3 | no |
| SPEC-DEFECT-09, report fields on failure | as done; the J1 reason is the string `"J0 failed"` | 8.2 | yes: the reason text |
| SPEC-DEFECT-10, seal at position 0 | as done: `SEAL_LOG_SIZE`; the condition `i ≥ 1` is added to J1-4 | 6.3 J1-4 | no |
| SPEC-DEFECT-11, types in `P` | J1-1 checks the types: `format` and `run_id` are strings, `log_size` is a number; a violation is `SEAL_FORM` | 6.3 J1-1 | yes |
| SPEC-DEFECT-12, exit code 3 | intended: it does not occur in delivery 1 and is reserved for delivery 2 | 8.4 | no |
| SPEC-DEFECT-13, frame number for `TORN_TAIL` and `LIMIT_EXCEEDED` | as done: the line position. This is now a rule of the specification, not information taken from `expected.json` | 5.1, 8.2 | no |

**New beyond the questions:** J1-9 now checks `P.run_id` against `body.run_id` of frame 0; the `vectors` command checks `log_root` in V9.

**On the implementer's remarks.**
- The report is described in section 8.
- The five journals in `valid/` are the correct set; the list in the clean-room task statement (not published) has been corrected.
- The forger does not recompute `request_hash` and `records_root`: this is correct for delivery 1; their formulas will appear in delivery 2.
