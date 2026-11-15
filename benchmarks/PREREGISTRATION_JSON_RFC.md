# Preregistration: withdrawals on the JSON RFC corpus

Written 2026-11-16, before any run on the corpus. Fixed here: the question, the corpus and its reference, the run, what is measured,
what would count against the kernel, and what is not claimed.

## Question

When the text a team's answers rest on is withdrawn sentence by sentence, does exactly what rested on each sentence stop standing,
while what rests on unchanged text stays? The earlier corpora are specification sites in Markdown; this one is a standard published
as plain text, whose editions changed sentences that implementations relied on.

## Corpus and reference

- `benchmarks/corpora/json-rfc-4627-7159`: RFC 4627 and RFC 7159 from the RFC Editor, 43,770 bytes in two files, unchanged except
  for the `.md` file names the corpus manifest needs (its README says why the kernel cuts them the same way).
- Reference: `benchmarks/corpora/gold/json-rfc-4627-7159-reference.json`, fixed before any run, SHA-256
  `7ebaf0a2710785d798e8230fad58e8585c78ae4c3afcde784160aa24331b041b`. It names four sentences a later edition changed (W1, W2,
  W3 in RFC 4627; W4 in RFC 7159, changed by RFC 8259) and one control no edition changed (C1).
- The withdrawal plan `withdrawal.json` and the blind checklist `checklist.md` of the corpus are fixed with this file and ship in
  the run's archive. The plan has four steps, each with one sentence, withdrawn whether or not the run quotes it: 2A W1, 2B W2,
  2C W3, 2D W4. The withdrawals are a synthetic benchmark intervention: the IETF withdrew none of these sentences.

## The run

- One run of the kernel's side, with the flags of the runs of 0.2 and of the A2A corpus (`--freeze-arm-a`, `--build-scope none`,
  `--dynamic-roles --circles`, section bytes 6000), the gap pass off.
- Three readers on `deepseek-flash`, thinking off, temperature 0.
- The questions RQ1 and RQ2 of every corpus (`benchmarks/sbgk_bench/pilot_ac.py`), unchanged.
- Spending cap: $1.
- From a clean tree of `OrganeticSphere/yuce` and the binary built from it. A run with changed tracked files does not count. The
  archive leaves out `arm_c/subjects.json`, which holds the run's tokens.

## What is measured

From the run's journal, no model:
1. **Hits.** For each step, whether the run quoted its sentence before the step. A step whose sentence was never quoted has
   nothing to withdraw: it is `not hit`, not a success.
2. **Graph level.** After each step, the claims the kernel reports as grounded that rest on a quote overlapping the withdrawn
   sentence, and the quotes overlapping it stored after the step. Expected: 0 and 0.
3. **What fell.** For each step, the records `sbgk audit-read fallen --since <the frame before it>` names, and the questions the
   kernel sends back to be answered again.
4. **The control.** If C1 was quoted, whether every claim that rests only on C1 quotes stands at the end. If it was not quoted:
   `not hit`.
5. **The journal.** `sbgk audit-verify` verifies it, and every seal checks against the frames before it.
6. **Cost.** Calls, tokens and the spend estimate of the runner's brake.

Graded blind, Gemini 4 Argon through the Antigravity CLI, in one pass, on `checklist.md`:
7. Statement grades, the reference per item at each phase, stale-current errors and the control.
8. Withdrawal discipline at each step: `ok`, `leak`, `over-removal` or `not applicable`.
9. Planted lines: two per step in a separate packet; the share the grader finds is published.

## What would count against the kernel

Any one of these is a defect of the kernel, not a result:
- after a step, a claim reported as grounded that rests on a quote overlapping the withdrawn sentence, or such a quote stored
  after the step;
- a claim resting only on C1 quotes that stops standing although nothing it rests on was withdrawn;
- a journal that `audit-verify` does not verify.

## What is not claimed

- Completeness: the answers cover what the readers quoted, not every change between the editions.
- Any comparison with another tool, team or model.
- That the IETF withdrew anything: the plan withdraws sentences that later editions changed.

Whatever the run shows is published with it, including results against the kernel.
