# Observed results on `inputs/boundary/` (acceptance A6a)

No expected outcome is given for these journals. The kernel refuses both by meaning (SPEC v3, section 10, item 2). This table records what levels J0-J1 of `yuce-verify` 0.1.3 (delivery 1.1 with amendments 1 and 2, `SPEC_INDEPENDENT_VERIFIER/4`) actually answer. The results are the same as in delivery 1 (0.1.0), 1.1 (0.1.1) and with amendment 1 (0.1.2). The tests `test/inputs.test.mjs` and `test/delivery11.test.mjs` pin them, so the table stays true.

| journal | SHA-256 | frames | J0 | J1 | verdict, exit | first failure | seals | tail | kernel (from `expected.json`) |
|---|---|---:|---|---|---|---|---|---|---|
| `auto-seal-ack.wal` | `db09ecc5…adb77` | 3 | PASS | FAIL | FAIL, 1 | J1, frame 1, `KERNEL_ID_MISUSE` | — | — | REFUSED: a frame takes an id of the kernel's own (`seal-<n>`) |
| `nested-seal.wal` | `73a36135…f936a` | 3 | PASS | PASS | PASS, 0 | — | `n=1`, `6cfa54bc…e1f62` | unsealed, 1 frame | REFUSED: semantic replay diverged |

## Why

- **`auto-seal-ack.wal`.** Frame 1 is a kernel frame with `submission_id = "seal-3"` and a `batch` command. Its kind of command is `batch`, so J1-14 and J1-13 do not apply and it is not a seal candidate. By J1-10 (as amendment 2 words it) a kernel frame whose `submission_id` starts with `seal-` must be a seal candidate, so J1 refuses it. Here J0-J1 catch what the kernel catches, under the same rule.
- **`nested-seal.wal`.** Frame 1 is a valid seal of the first frame; its `run_id` equals `body.run_id` of frame 0 (`codex-step2`), as J1-9 now requires. Frame 2 is a kernel `batch` whose operations contain a seal command. J1 does not look inside a batch: the batch structure waits for GAP-11 (level J2, not in delivery 1). Its own kind of command is `batch`, not `seal` or `close`, and its submission id `nested-seal` does not start with `seal-`. So J0-J1 pass: the file is internally consistent. The kernel's refusal comes from replaying the meaning, which no level of this verifier does (SPEC section 4: "seal or close inside a batch" is J2).
