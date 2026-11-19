# Results on `inputs/boundary/` (acceptance A6a)

The kernel refuses both journals by meaning (SPEC section 10, item 2). Delivery 1 recorded what J0-J1 answered. Delivery 2 has an expected outcome for each (`delivery2` in `expected.json`), and `yuce-verify` 0.2.1 (`SPEC_INDEPENDENT_VERIFIER/6`, with amendment 4) meets it, as 0.2.0 did. The verdict now equals the kernel's on both (B5). `test/inputs.test.mjs` pins these results.

| journal | SHA-256 | frames | J0 | J1 | J2 | J3 (`--docs`) | verdict, exit | first failure | kernel (from `expected.json`) |
|---|---|---:|---|---|---|---|---|---|---|
| `auto-seal-ack.wal` | `db09ecc5…adb77` | 3 | PASS | FAIL | not checkable (J1 failed) | not checkable (J1 failed) | FAIL, 1 | J1, frame 1, `KERNEL_ID_MISUSE` | REFUSED: a frame takes an id of the kernel's own (`seal-<n>`) |
| `nested-seal.wal` | `73a36135…f936a` | 3 | PASS | PASS | FAIL | not checkable (J2 failed) | FAIL, 1 | J2, frame 2, `KERNEL_OP_IN_BATCH` | REFUSED: semantic replay diverged |

The result is the same with and without `--docs <name>.docs`: the failure comes before J3.

## Why

- **`auto-seal-ack.wal`.** Frame 1 is a kernel frame with `submission_id = "seal-3"` and a `batch` command. Its kind of command is `batch`, so it is not a seal candidate. By J1-10 (as amendment 2 words it), a kernel frame whose `submission_id` starts with `seal-` must be a seal candidate, so J1 refuses it. Same as in delivery 1.
- **`nested-seal.wal`.** Frame 1 is a valid seal of the first frame. Frame 2 is a kernel `batch` whose operation 0 is a seal, executed: its index is below the length of `results`. J0-J1 do not look inside a batch and pass it, as in delivery 1. J2-11 (amendment 3, P3-5) refuses an executed seal, close or batch inside a batch: `KERNEL_OP_IN_BATCH` at frame 2. Amendment 3 names this journal as the vector of J2-11.
