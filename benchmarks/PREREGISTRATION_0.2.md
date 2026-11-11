# What the 0.2 control runs will measure, fixed before they run

This file is in the candidate branch of the public repository, pushed before the runs start: the commit's date and the times in each run's
`provenance.json` show the order. `provenance.json` holds the SHA-256 of this file and of every runner source. As for 0.1.7, the runs come before
the tag: the tag `v0.2.0` follows them, on the same `crates` tree. A defect a run finds is fixed first, and the runs are made again from the new
tree. Whatever they show is published with them, including results against the kernel.

## Why these runs

0.2 changes the kernel under the same team: the journal is written in frames with a header and a body, a tree over the records of each
frame, a state root in named sections and seals as entries of the journal; the reading tools answer what stands and what fell after a
withdrawal; seals are signed as C2SP checkpoints; one record with all it rests on is cut into a quittance that checks without the journal;
an index in SQLite is built beside the journal. The tasks the agents see do not change on a pinned corpus. This run checks, on the team,
corpus and withdrawals of the 0.1.7 run, that the outcomes of 0.1.7 hold on the new kernel, and that what 0.2 adds checks out on a real run.
A second run, of three DeepSeek readers, shows the gap pass of 0.2 at work.

## The runs

Two runs of side K of section 1 of BENCHMARKS.md, from the candidate branch: its source, the binary its release workflow builds, its
runner. T and L are not run again. They run in this order:

| | Run 1: three DeepSeek readers, gap pass on | Run 2: four makers, gap pass off (the control run) |
|---|---|---|
| Team | three readers on `deepseek-flash` with thinking off, as the DeepSeek runs of v0.1.0 | as in 0.1.7: four readers of four makers, the same model in the same seat: `deepseek-flash` with thinking off, Claude Haiku 5.5, GPT-5.6 Luna through Codex, and Gemini 3.8 Flash through the Antigravity CLI, at medium effort where the transport has one |
| Settings | the v0.1 profile, with the gap pass of 0.2 on: at most 12 packs of 8 units (the example of its specification) | the v0.1 profile, as in 0.1.7; the gap pass is off, so that against 0.1.7 one factor changes, the kernel |
| Compared with | nothing before it on equal terms: it shows the gap pass at work on a real run, and is published as that | the K run of 0.1.7, side by side |
| Spending cap | $3 | $6, on the seats with a price per call, as in 0.1.7 |

For both:

| | |
|---|---|
| Corpus | `benchmarks/corpora/mcp-spec-2026-07-28`, the 22 pages of the published runs |
| Withdrawals | the plan of the published runs: 2A a quote in a peripheral page, 2B a quote in the changelog, the same bytes, withdrawn whether or not the side quotes them. It is in `withdrawal.json` of each archive |
| Grading | blind, one grader in one pass over the answers of both runs and of T and L, answers shuffled, Claude Opus 5.5 in a clean session, with the rules of `grade_common.py` in the archive `deepseek1-grading-opus` of release v0.1.0, SHA-256 `50ee02287d2d183d4e631dc04ad2019590e8b1baace38b1fa37394b91e3ecc7d`, unchanged |

The two runs differ in two things, the team and the gap pass: what differs between them is not said to come from either one alone.

A run with changed tracked files does not count. The archive leaves out `arm_c/subjects.json`, which holds the run's tokens, and the signing
key of the run.

## Primary outcomes

Fixed before the runs, for each run. Outcomes 1 to 5 are those of 0.1.7, unchanged.

1. **Graph level.** After each withdrawal, the share of claims the kernel reports as grounded that rest on a quote overlapping the withdrawn
   text, and the quotes overlapping it stored after the withdrawal. Expected: 0 and 0. Any other value is a defect of the kernel, not a
   result, and it stops the tag.
2. **Text level.** The grader's `withdrawal` verdict for K at 2A and 2B, in both label orders, and the facts it marks `stated current` that
   the plan withdrew, paraphrase included. Expected: `ok`, or `not applicable` where no answer rests on the quote. Two planted lines per stage
   go into a copy of one side's answer in a separate packet, as in 0.1.7, and the share the grader finds is published.
3. **The repair.** At each withdrawal that touched an answer: the rows that fell, the lines the model sent and the limit it had, the copies
   left out, the lines refused, and the answer's rows before and after. From the journal, no model.
4. **Repeats.** Claims in K's answers, with and without repeats, case and spacing aside, at 2A and 2B.
5. **Collateral and cost.** As in 0.1.7, by `benchmarks/revision_outcomes.py`, no model.
6. **What 0.2 adds, on each run's journal, no model.** Each is pass or fail; a fail is a defect of 0.2 and stops the tag.
   - `sbgk audit-verify` verifies the journal; every seal checks against the frames before it.
   - The seals, signed after the run with a key made for it by `sbgk audit-sign`, check with `audit-verify --checkpoint` under a trusted
     keys file, and a checkpoint of another prefix is refused.
   - After each withdrawal, `sbgk audit-read fallen --since <the frame before it>` names exactly the claims whose grounded flag the
     withdrawal turned off, and shows none of the withdrawn text.
   - For every row of K's last answer that stands, `sbgk audit-proof` cuts a quittance at the last seal and `sbgk audit-proof-verify`
     checks it without the journal; a row that fell gets no quittance.
   - `sbgk audit-index` builds the index, and `--check` finds it equal to the journal.
   - The independent verifier `yuce-verify` (levels J0 and J1) passes the journal.

## Secondary outcomes

Blind checklist points per stage for each side, with the caveat of section 1 of BENCHMARKS.md. Wall time and cost. The size of the journal, of
the index and of the quittances. For run 1, the gap pass: the units it handed out, the quotes it added, the units answered empty and those
left by its budget, from the journal, no model.

## What the tag waits for

Both runs end, their journals verify, outcome 1 is 0 and 0, every check of outcome 6 passes, and no defect of the kernel is found in
outcomes 2 to 4. A `partly` whose cause is not in the kernel does not hold the tag back, and is published as it came.

## What will not be claimed

These are two runs with two withdrawals each and one grader: anecdotes. They can show that 0.2 keeps the outcomes of 0.1.7 on this team
and corpus, that its new checks work on real runs and what the gap pass adds on one, not how often. No gain in answer quality from it,
and no comparison of K with T and L beyond what section 1 of BENCHMARKS.md already allows.
