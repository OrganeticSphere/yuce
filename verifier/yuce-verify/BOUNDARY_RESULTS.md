# Results on the boundary journals (acceptance A6a; amendment 6, P6-1 and P6-10)

`yuce-verify` 0.3.1 (`SPEC_INDEPENDENT_VERIFIER/8`, with amendment 6). `test/inputs.test.mjs` and `test/amendment6.test.mjs` pin these results.

## `inputs/boundary/` (set A′ of amendment 6)

The kernel refuses both journals by meaning (SPEC section 10, item 2). Delivery 2 has an expected outcome for each (`delivery2` in `expected.json`). Amendment 6 adds J4a: both fail before it, so J4a does not run (set A′ in `inputs/j4a/expected.json`). The verdict equals the kernel's on both (B5).

| journal | SHA-256 | frames | J0 | J1 | J2 | J3 (`--docs`) | J4a | `cascade` | verdict, exit | first failure | kernel (from `expected.json`) |
|---|---|---:|---|---|---|---|---|---|---|---|---|
| `auto-seal-ack.wal` | `db09ecc5…adb77` | 3 | PASS | FAIL | not checkable (J1 failed) | not checkable (J1 failed) | NOT_RUN | `null` | FAIL, 1 | J1, frame 1, `KERNEL_ID_MISUSE` | REFUSED: a frame takes an id of the kernel's own (`seal-<n>`) |
| `nested-seal.wal` | `73a36135…f936a` | 3 | PASS | PASS | FAIL | not checkable (J2 failed) | NOT_RUN | `null` | FAIL, 1 | J2, frame 2, `KERNEL_OP_IN_BATCH` | REFUSED: semantic replay diverged |

The result is the same with and without `--docs <name>.docs`: the failure comes before J3.

### Why

- **`auto-seal-ack.wal`.** Frame 1 is a kernel frame with `submission_id = "seal-3"` and a `batch` command. Its kind of command is `batch`, so it is not a seal candidate. By J1-10 (as amendment 2 words it), a kernel frame whose `submission_id` starts with `seal-` must be a seal candidate, so J1 refuses it. Same as in delivery 1.
- **`nested-seal.wal`.** Frame 1 is a valid seal of the first frame. Frame 2 is a kernel `batch` whose operation 0 is a seal, executed: its index is below the length of `results`. J0-J1 do not look inside a batch and pass it, as in delivery 1. J2-11 (amendment 3, P3-5) refuses an executed seal, close or batch inside a batch: `KERNEL_OP_IN_BATCH` at frame 2. Amendment 3 names this journal as the vector of J2-11.

## `inputs/j4a/boundary/open-two-seals.wal` (amendment 6, P6-1)

The journal `a` of `V-CUT-1` through its second seal (frame 6), not closed: seals at frames 3 and 6. J4a compares every seal of the file; `--expect-seal` stays the anchor check of J1 and does not limit J4a.

| run | J0-J3 | J4a | `cascade` (`seals_checked`, `checked_through_frame`, `unchecked_frames`) | `anchor.seal` | `not_verified` | verdict, exit |
|---|---|---|---|---|---|---|
| `--docs open-two-seals.docs` | PASS | PASS | (2, 6, 0) | not given | `["signatures"]` | PASS, 0 |
| the same, `--expect-seal b56a5a86…cfac` (the seal of frame 3) | PASS | PASS | (2, 6, 0) | `at_n` 3, `frames_after` 3 | `["signatures"]` | PASS, 0 |

The status and dependency hashes at both seals equal `projections` in `inputs/j4a/expected.json`, and the rows equal the kernel's rows in `inputs/j4a/rows/open-two-seals.rows.json`.
