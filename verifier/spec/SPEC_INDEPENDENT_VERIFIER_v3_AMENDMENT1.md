# Amendment 1 to the specification and the clean-room task statement (not published) of the independent journal verifier, version 3

OrganeticSphere, 11 November 2026.

**Status: normative.** It applies together with `SPEC_INDEPENDENT_VERIFIER_v3.md` and the clean-room task statement (not published). Where the amendment differs from their text, the amendment applies.

**Identifier.** Specification version 3 with this amendment is called `SPEC_INDEPENDENT_VERIFIER/3`. The verifier report must name exactly this identifier.

**Reason.** Two rules of the journal format `sbgk-session-log/3` were clarified: the length limit of a frame line counts the LF, and a nesting limit for a frame was introduced. The defaults in version 3 did not match them.

---

## P1-1. Line length limit

**Format rule.** A frame line, together with its trailing LF byte, is no longer than 67,108,864 bytes (64 MiB). The largest length of a line without LF is 67,108,863 bytes.

**What changes.**
- The default value of `--max-line-bytes` is **67108863** (it was 67108864).
- The meaning of the flag is unchanged, as in rule J0-1: it is the line length in bytes without LF; the failure is `LIMIT_EXCEEDED` if the length is strictly greater than the value.
- The limit applies to a torn tail as before: to the length of the tail in bytes.

**Tests.**
- The default value equals 67108863.
- Boundary: with `--max-line-bytes N`, a line of exactly `N` bytes without LF passes the length check; a line of `N + 1` bytes gives `LIMIT_EXCEEDED`. It is enough to test the boundary with a small `N`.

## P1-2. Nesting limit

**Format rule.** A journal frame nests no deeper than 64 JSON levels. Counting: a scalar is 0; an object or an array is one more than its deepest member; an empty object or array is 1. So the outer object of a frame has a depth of at least 1. A frame deeper than 64 does not occur in a valid journal.

This count matches the count of rule J0-1 of version 3: the largest number of `{` and `[` open at the same time outside strings.

**What changes.**
- The default value of `--max-depth` is **64** (it was 128).
- Rule J0-1 is otherwise unchanged: the failure is `LIMIT_EXCEEDED` if the depth is strictly greater than the value.
- The item about the depth offset near the boundary of 128 is removed from the list of known differences from the kernel (specification, section 10). With default values, the depth verdicts must match.

**Tests.**
- The default value equals 64.
- A line with a depth of exactly 64 passes the depth check; a line with a depth of 65 gives `LIMIT_EXCEEDED`.
- Brackets inside string values do not count toward the depth.

## P1-3. Defaults and format rules

The defaults of both flags equal the format limits. The README must say: if either flag is raised above its default, the verifier may accept a line that cannot exist in a valid journal.

## P1-4. Confirmation without a change in behavior

`run_id` in the genesis and in a seal is a string. Rules J1-1 and J1-9 of version 3 stay as written.

## P1-5. What changes in the task statement, version 3

| Place in the task statement | Was | Now |
|---|---|---|
| Section 6, item 1 | line limit 67108864, nesting 128 | line limit 67108863, nesting 64 |
| Section 6, item 10 | `SPEC_INDEPENDENT_VERIFIER/2` | `SPEC_INDEPENDENT_VERIFIER/3` |
| Section 6, new item 12 | — | the README line from P1-3 |
| Section 7, item A3 | — | add to the tampering matrix: depth 64 and 65; line length at the limit boundary |
| Section 8 | three files in `spec/` | four files in `spec/`: this amendment is added to the three earlier ones |
| Section 10, item 1 | the depth question waits for an answer | closed by P1-2 |

## P1-6. What to change in the code: summary

1. The default of `--max-line-bytes`: 67108863.
2. The default of `--max-depth`: 64.
3. The specification identifier in the report: `SPEC_INDEPENDENT_VERIFIER/3`.
4. The tests from P1-1 and P1-2.
5. The README line from P1-3.

Everything else follows section 6 of the task statement, version 3. The vectors file does not change.
