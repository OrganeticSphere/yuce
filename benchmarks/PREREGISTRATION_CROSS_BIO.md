# Preregistration: withdrawals and links across three papers on bacteria under flow

Written 2026-11-16, before any run on the corpus. Fixed here: the question, the corpus and its reference, the run, what is measured,
what would count against the kernel, and what is not claimed.

## Question

When a team's answers join the findings of several papers, and one finding is withdrawn, does exactly what rested on it stop
standing, while what rests on the other findings stays, including the claims that join papers? The earlier corpora are
specifications and a standard: editions of one text. This one is three papers by different groups, each with its own setup and
units.

## Corpus and reference

- `benchmarks/corpora/bacteria-under-flow`: excerpts of three CC BY 4.0 papers, 106,620 bytes in three Markdown files (their README
  names the papers, the licence and what was changed).
- The reference and its two addenda were fixed before any run. They are not shown to the readers, and they are published under
  `benchmarks/corpora/gold/` after the run, with these SHA-256:
  - the reference, `1fe4a773a9869dc117c0148e97dea606ff8db691b9e9b7bc177cf4e3738b0d6b`: 17 facts, 6 links between papers,
    4 traps, the two withdrawals with what must fall and what must stand, the three questions and the scoring rules;
  - the scoring addendum, `ad33514ff0cfc381b9d497081b34908b4624cbbde7af359d3ffb0a15da30762e`: one rule for the link that compares
    the thresholds;
  - the run-plan addendum, `d01e0e809ced6fb3907a02cc61a87bb2536f3fce6b69cf271c60f0fd56ba00df`: both withdrawals applied, when the
    second counts, and the topics of the questions.
- The corpus's `questions.json`, `withdrawal.json` and `checklist.md` are fixed with this file and ship in the run's archive.
  - The questions are the reference's three, word for word. Their topics are stems of words of each question's own text, so a
    topic hints at no line of the reference.
  - The plan has two steps, applied in this order on one journal: 2A withdraws W1, a clause of B; 2B withdraws W2, a sentence of A.
  - The withdrawals are a synthetic benchmark intervention: neither paper is retracted.

## The run

- One run of the kernel's side, with the flags of the earlier runs of 0.2 (`--freeze-arm-a`, `--build-scope none`,
  `--dynamic-roles --circles`, section bytes 6000), the gap pass off.
- The corpus's own questions (`--questions benchmarks/corpora/bacteria-under-flow/questions.json`).
- Three readers on `deepseek-flash`, thinking off, temperature 0.
- Spending cap: $1.
- From a clean tree of `OrganeticSphere/yuce` and the binary built from it. A run with changed tracked files does not count. The
  archive leaves out `arm_c/subjects.json`, which holds the run's tokens.

## What is measured

From the run's journal, with no model (part I of `checklist.md`):
1. **Each step's checks:** what must fall, what must stand, the failure rule, the collateral records, and the questions sent back.
2. **The condition of W2:** whether an answer line of Q1–Q3 lost a ground at 2A. W2 counts toward the result "an answer fell and was
   given again" only if none did. Its checks are reported either way.
3. **Links:** the standing claims whose quotes come from two or more papers, with the byte intervals of their quotes.
4. **The journal:** `sbgk audit-verify` verifies it, and every seal checks against the frames before it.
5. **Cost:** calls, tokens and the spend estimate of the runner's brake.

Graded against the reference:
6. **Primary:** the case's researcher, an AI agent, from the export: facts, links in two steps, traps (part II of `checklist.md`).
7. **Secondary, blind:** Gemini 4 Argon through the Antigravity CLI (part III). It never changes the primary score.

## What would count against the kernel

Any one of these is a defect of the kernel, not a result:
- after a step, a record that falls although its quotes overlap only intervals that must stand, and not the withdrawn one;
- after a step, a claim reported as grounded that rests on a quote overlapping the withdrawn interval, or such a quote stored
  after the step;
- a journal that `audit-verify` does not verify.

## What is not claimed

- Domain expertise: the reference was written by an AI model from the papers' text, not by a microbiologist or a physicist.
- Completeness: the answers cover what the readers quoted.
- Any comparison with another tool, team or model.
- That a paper is wrong: a withdrawal stops relying on a passage. It does not refute it.

Whatever the run shows is published with it, including results against the kernel.
