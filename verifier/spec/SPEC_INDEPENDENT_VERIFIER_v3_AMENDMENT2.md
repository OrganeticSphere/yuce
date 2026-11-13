# Amendment 2 to the specification of the independent journal verifier, version 3

OrganeticSphere, 11 November 2026.

**Status: normative.** It applies together with specification version 3, the clean-room task statement (not published), version 3, and amendment 1. Where the amendment differs from their text, the amendment applies.

**Identifier.** Specification version 3 with amendments 1 and 2 is called `SPEC_INDEPENDENT_VERIFIER/4`. The verifier report must name exactly this identifier.

This amendment answers the implementer's questions `SPEC-DEFECT-14` and `SPEC-DEFECT-15`.

---

## P2-1. Truncated tail and external head (SPEC-DEFECT-14)

The implementer's decision is confirmed: the check of the external head is the last check of level J0 (sections 5.3, 6.5 and 9), and the failure `HEAD_MISMATCH` belongs to level J0.

The row of the table in section 4 reads as follows:

| What happened | Where it is caught |
|---|---|
| the journal tail is truncated | only with an external binding: a seal of a later point (J1, `ANCHOR_NOT_FOUND`) or a head (J0, `HEAD_MISMATCH`) |

No code change is needed.

## P2-2. Kernel submission ids that start with `seal-` (SPEC-DEFECT-15)

**Format rule.** For a frame with `actor = "kernel"`, any `submission_id` that starts with the five characters `seal-` belongs only to a seal, and only to its own seal: the seal of the first `n` frames has the id `seal-<n>`. What follows `seal-` does not matter: ASCII digits, digits of other scripts, letters, or nothing.

**Rule J1-10 is replaced by this one.** For a frame with `actor = "kernel"`: if `submission_id` is a string that starts with `seal-`, the frame must be a seal candidate. Otherwise `KERNEL_ID_MISUSE`.

- The prefix comparison is exact and case-sensitive: `Seal-1` and `sealx-1` do not fall under the rule.
- If `submission_id` is not a string, the rule does not apply.
- The rule does not apply to frames of other actors.
- J1-4 still checks that the number of a seal candidate equals its position: `submission_id` must equal `"seal-" + i` byte for byte, where `i` is the frame position written in ASCII digits `0–9` without leading zeros. A candidate with the id `seal-x` or `seal-٣` gives `SEAL_LOG_SIZE`.

**Section 6.1,** description of the seal frame: `n` is written in ASCII digits `0–9`, without leading zeros.

**Rule J1-11 does not change.** The id `audit-close` is compared for exact equality, and the link with the close frame works both ways, as written.

**Tests.** A frame from `kernel` that is not a seal candidate:
- with the id `seal-`, `seal-x`, `seal-٣`, `seal-01` — `KERNEL_ID_MISUSE`;
- with the id `Seal-1`, `sealx-1` — rule J1-10 passes.

A frame of another actor with the id `seal-5` and an ordinary command — rule J1-10 passes.

## P2-3. What to change: summary

1. J1-10: check by the string prefix `seal-` instead of "`seal-` and digits".
2. The specification identifier in the report: `SPEC_INDEPENDENT_VERIFIER/4`.
3. The tests from P2-2.
4. There are five files in `spec/`: specification version 3, the task statement version 3, the vectors file, amendment 1, amendment 2. In this repository there are four: the task statement is not published.

The vectors file does not change.
