# Benchmarks

What was measured, on what, by whom, and with which caveats. Every comparison names its grader and is made within that
grader's numbers.

## The setup common to all runs

* **Corpus.** 22 documents of the Model Context Protocol specification (MDX), 293,854 bytes, five consecutive protocol
  revisions: 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, 2026-07-28 ([benchmarks/corpora/mcp-spec-2026-07-28](benchmarks/corpora/mcp-spec-2026-07-28/README.md)).
  The specification records its own changes, so the corpus tests whether an answer tells what is current from what was
  replaced.
* **Questions.** RQ1: which conclusions were later superseded, made stale or qualified? RQ2: which limitations and
  future-work items remain open?
* **Stages.** Stage 1 reads the corpus and answers. Then two sources are withdrawn, each fixed before the run: 2A a cell of
  the deprecated-features registry, 2B an item of the 2026-07-28 changelog; after each, the answers are given again.
* **Team.** Three readers and a checker, all on one model.
* **Grading.** Blind: the variants carry neutral labels and self-identifying text is neutralized (every edit logged, no
  quote changed). One grader call per stage with all variants, in two label orders; the share of correct statements is the
  mean of the two. The grader sees the checklist, the 22 pages and a gold file of the corpus's version transitions.
* **Naming rule, fixed before each run.** "Kernel better" when the kernel's share of correct statements is more than
  7 points higher (the spread of two identical earlier runs, which are not attached), or when it keeps a withdrawal the other side breaks; "on par" within
  ±7; "kernel worse" when more than 7 points lower. It names the rows below; see "How far these numbers go" for what it does
  not establish.
* **Runs.** One per side on Claude Haiku 5.5; two series per side on DeepSeek Flash.

## 1. The kernel against the same team without it

The side without the kernel is the same team with the same prompts and answer guidance, on its own orchestration: native
[Temporal](https://temporal.io/) (T) or native [LangGraph](https://www.langchain.com/langgraph) (L). The runner gives it
what a careful team would build: it checks every quote byte for byte, keeps the readers' notes, answers by map-reduce over
the pages and rebuilds its answer after a withdrawal. What it lacks is the kernel: registered `based_on` dependencies, the
cascade on revocation, a replayable journal and leased coordination. K is the kernel's side in the v0.1 profile, with the
runner's own retry and timeout settings (`agent_attempts`, `answer_timeout_ms`).

### Agents on Claude Haiku 5.5, grader Fable 5.1

| Stage | K | T | L | Named by the rule |
|---|---|---|---|---|
| 1: reading and answers, share of correct statements | 89.9% | 79.3% | 84.9% | K better than T (+10.6); on par with L (+5.0) |
| 2A: after the first withdrawal | 90.5% | 86.6% | 88.8% | on par |
| 2B: after the second withdrawal | 88.7% | 86.7% | 85.8% | on par |
| Withdrawal kept (2A, 2B) | yes | yes; once partly in 2B | yes | |
| An outdated rule given as current | 0 | 0 | 1 (2A) | |
| A current rule given as replaced | 1 control fact, in every stage | 0 | 0 | the kernel side's known error |
| Quotes byte for byte in the named page | 203 of 204 | 134 of 134 | 126 of 126 | not a difference: the runner checks both sides |
| Model calls to answer again after 2A | 0 | 6 | 6 | the withdrawal touched no answer of K: see below |
| Whole run: wall time, cost | 54.2 min, $1.37 | 23.3 min, $0.96 | 22.0 min, $0.96 | the kernel ×2.3–2.5 slower, ×1.4 the cost |

K ran on an earlier revision than T and L (the kernel side's code did not change between them); the cost of the Claude
models is the API-equivalent list price.

### Agents on DeepSeek Flash, grader Opus 5.5

All three sides on one revision; agents `deepseek-flash` (V4.1 Flash, thinking off).

Series 2 is the same with one change: an output limit of 32,000 tokens per call instead of 8,192 (series 1 cut one long
answer of L, its stage 1 RQ2 summary, at 8,192; series 2 cut none).

| Stage | Series | K | T | L | Named by the rule |
|---|---|---|---|---|---|
| 1 | 1 | 91.8% | 83.3% | 83.0% | K better than T (+8.4) and L (+8.8) |
| 1 | 2 | 89.6% | 92.1% | 84.9% | on par (−2.4, +4.7) |
| 2A | 1 | 91.8% | 74.6% | 81.4% | K better than T (+17.2) and L (+10.3; the grader's two orders 11 points apart for L) |
| 2A | 2 | 89.6% | 83.8% | 85.2% | on par (+5.9, +4.4) |
| 2B | 1 | 91.7% | 91.9% | 86.7% | on par (−0.2, +5.0) |
| 2B | 2 | 89.7% | 81.0% | 88.9% | K better than T (+8.7, the grader's two orders 20 points apart for T); on par with L |

| | K | T | L |
|---|---|---|---|
| Withdrawal kept (2A and 2B, two orders, two series: 8 gradings) | 8 of 8 | 7 of 8, once partly | 4 of 8, 4 times partly |
| An outdated rule given as current (of 13, per stage) | series 1: 0; series 2: 1 | series 1: 5 in 2A; series 2: 0 | 0 |
| A current rule given as replaced (per stage) | 0 | series 1: 0; series 2: 1 in 2A and 2B | series 2: 1 in 2A |
| Version transitions named (of 13, stage 1) | 9; 7 to 8 | 13 and 12 | 6 (the cut answer) and 12 |
| Model calls to answer again after 2A (most of T's and L's are unrelated: see below) | 0 and 0 | 62 and 55 | 65 and 40 |
| Wall time (series 1, series 2) | 15.0, 14.7 min | 11.8, 11.8 min | 12.9, 11.8 min |
| Cost (series 1, series 2) | $0.50, $0.48 | $0.32, $0.30 | $0.33, $0.30 |

The advantage of series 1 in stage 1 and 2A did not repeat in series 2; the kernel's side kept every withdrawal in both.
It took 1.2 to 1.3 times the wall time and 1.5 to 1.6 times the cost of the sides without it. The sides without the kernel
often wrote a closing line over its length limit, which the runner then refused (their pages were marked incomplete; since 0.1.4
such a line is cut, with a mark); their claims were kept (in series 1, 6 of about 2,000 were refused).

### Agents of four makers, grader Opus 5.5

The same four readers on every side: `deepseek-flash`, Claude Haiku 5.5, GPT-5.6 Luna and Gemini 3.8 Flash, as
`benchmarks/PREREGISTRATION_0.1.5.md` and `PREREGISTRATION_0.1.6.md` fixed them before each run. Run 1 is from the tag v0.1.5, run 2
from v0.1.6. Run 1 found a defect of the kernel, which v0.1.6 fixes, so its K is not the kernel of today.

| Stage | Run | K | T | L | Named by the rule |
|---|---|---|---|---|---|
| 1 | 1 | 87.8% | 86.6% | 84.0% | on par (+1.2, +3.8) |
| 1 | 2 | 88.2% | 50.0% | 81.8% | K better than T (+38.2); on par with L (+6.4) |
| 2A | 1 | 83.6% | 93.7% | 67.1% | T better than K (−10.1); K better than L (+16.5) |
| 2A | 2 | 85.9% | 80.5% | 77.5% | on par with T (+5.4, the grader's two orders 16 points apart for T); K better than L (+8.4) |
| 2B | 1 | 87.0% | 92.5% | 82.3% | on par (−5.5, +4.7) |
| 2B | 2 | 82.2% | 70.4% | 76.9% | K better than T (+11.8, the grader's two orders 20 points apart for T); on par with L (+5.3, 16 points apart for L) |

| | K | T | L |
|---|---|---|---|
| Withdrawal kept (2A and 2B, two orders, per run: 4 gradings) | run 1: 2, 2 partly; run 2: 2, 2 partly | 4 and 4 | run 1: 4; run 2: 2, 2 partly |
| Statements graded (stage 1, 2A, 2B) | 82, 119, 158; 85, 85, 118 | 67, 79, 60; 72, 77, 71 | 78, 76, 65; 77, 71, 80 |
| Model calls after 2A and after 2B | 5 and 5; 0 and 1 | 13 and 9; 24 and 10 | 24 and 16; 22 and 8 |
| Cited quotes the withdrawal did not touch and the next answer dropped (2A, 2B) | 0 and 0; 0 and 1 | 31 and 71; 71 and 30 | 37 and 65; 54 and 26 |
| Wall time | 35.0, 33.6 min | 22.0, 25.6 min | 23.1, 23.4 min |
| Cost of the seats with a price | $0.45, $0.60 | $0.29, $0.46 | $0.37, $0.48 |

* **What run 1 found.** After the second withdrawal a reader went back to the page and stored the withdrawn sentence with its list
  number, three bytes wider. The kernel refused only the exact span, so that quote was a new record with its support, and the answer
  of K cited it. Counted by record, the graph-level outcome of the pre-registration was 0; counted by text it was not. The grader
  marked the withdrawal partly kept in both orders. The numbers of that run were held until this was explained and fixed.
* **Run 2 on the graph.** After each withdrawal no record the kernel reports as grounded rests on a quote overlapping the withdrawn
  text: 0 of 897 and 0 of 895 grounded claims, with 2 and then 3 stored quotes touched and 9 records resting on them, and 0 quotes
  touching the text stored afterwards. Read from the journal, no model.
* **Run 2 in the answers.** K's 2B was again graded partly kept, for the opposite reason: the answer cites no withdrawn text, but it
  drops a conclusion that another page supports on its own. The claim on that page stood and was shown: the kernel's request for a
  repair did not say what had fallen, and the model wrote the answer again without it. L was partly kept once in 2A and once in 2B.
* **Repeats in K's answers.** The same request made a repair repeat rows it was told to keep, so K's counts of statements grow after
  a withdrawal: the answer to the first question has 71 rows, 48 of them distinct, at 2B of run 2, and 80 and 47 at 2B of run 1.
  Without the repeats K's 2B of run 2 is 82.1% rather than 82.2%. The request is fixed in 0.1.7: see its control run below.
* **The grader's control.** Two lines restating the withdrawn content in other words were planted in a copy of T's answer of 2A and
  of 2B, fixed before the answers were read, in a separate packet. The grader found all four and changed its verdict from `ok` to
  `failed` and `partly`.
* **A run is not a measure.** Nothing on T's side changed between the runs, and its stage 1 moved by 36.6 points: in run 2 its second
  answer listed gaps of the earliest revision as open, and the grader marked 17 and 18 statements as stale in its two orders. K moved by at most 4.8 points
  in a stage, on two runs. This says how far apart two runs can fall, not which side is better.
* **By model, on K (lines sent, refused).** `deepseek-flash` 1,703 and 190, then 1,523 and 163; Haiku 688 and 77, then 705 and 105;
  Luna 444 and 57, then 406 and 55; Gemini 335 and 13, then 358 and 14. A faster reader takes more of the work. These numbers
  describe this corpus and these runs, not the models.

### The control run of 0.1.7, grader Opus 5.5

Side K alone, run again from the candidate tree of 0.1.7 before its tag, as `benchmarks/PREREGISTRATION_0.1.7.md` fixed it: the
same four readers, corpus and withdrawals as run 2. T and L are the answers of run 2, graded again with the new K in one pass.

| Stage | K | T | L |
|---|---|---|---|
| 1 | 82.0% | 56.9% | 86.4% |
| 2A | 87.1% | 87.7% | 77.5% |
| 2B | 82.6% | 78.2% | 83.8% |

* **The repair.** At 2B one row fell in each of the two answers. The kernel named it with the quotes under it that stand, and the
  model sent one claim for each question: 2 calls, 1.4 KB of replies, no copy, no line refused. The other 40 and 49 rows stayed,
  with no repeats, and no cited quote the withdrawal did not touch was dropped. In both label orders the grader found the
  conclusion that run 2 lost: it rests on the standing quote.
* **Withdrawal kept.** 2A `ok` in both orders, 2B `ok` and `partly`. The `partly` is for other text: the answer to the second
  question lists optional session ids as open, though sessions are removed. That statement was there before the withdrawals: K's
  answers after stage 1 and after 2A are the same text, and on it the grader marked three earlier states as current at 2A and one at
  stage 1.
* **Earlier states.** At 2A and 2B the grader marks 14 of K's statements as stale in one order and 5 and 14 in the other, against 0
  or 1 for T and L. At stage 1 T has more, 16 and 17 against K's 10. K's answers keep what each revision said, and some of it is
  written as if it still held.
* **The graph.** After each withdrawal no record the kernel reports as grounded rests on a quote overlapping the withdrawn text: 0 of
  888 and 0 of 885, with 1 and then 2 stored quotes touched and 2 and then 9 records resting on them, and no quote touching the text
  stored afterwards. From the journal, no model.
* **Two gradings of the same answers.** This grading put T and L of run 2 at 78.2% and 83.8% at 2B, against 70.4% and 76.9% in
  the first: 7.8 and 6.9 points apart on the same text. Differences of that size in these tables say nothing.
* **The grader's control.** Two lines per stage restating the withdrawn content were planted in a copy of T's answer: it found all
  four.
* **Cost.** 282 calls, none failed, 38.9 minutes, $0.45 for the seats with a price. The run comes from the public branch of its
  candidate, with the binary its release workflow built: its `provenance.json` names public commits.

### The control runs of 0.2, grader Fable 5.2

Side K alone, twice, from the candidate tree of 0.2 before its tag, as `benchmarks/PREREGISTRATION_0.2.md` fixed it: run 1 with three
readers on `deepseek-flash` and the gap pass (at most 12 packs of 8 units), run 2 with the four readers of four makers of 0.1.7 and
the gap pass off, so that against 0.1.7 one thing changed, the kernel. The corpus and the withdrawals are those of the runs above. The
two runs differ in the team and the gap pass, and what differs between them is not said to come from either one alone. The blind
grading of the first two runs found a defect of the repair, fixed in this tree (the amendment of 12 November in the pre-registration);
both runs were made again, and the grading below is of the second ones. One grader, Claude Fable 5.2 at high effort, graded in one
pass the answers of both runs, of the K run of 0.1.7 and of T and L of run 2; each share is the mean of two label orders.

| Stage | Run 2: four makers | Run 1: DeepSeek, gap pass | K of 0.1.7 | T | L |
|---|---|---|---|---|---|
| 1 | 98.9% | 91.5% | 86.5% | 66.7% | 89.6% |
| 2A | 98.9% | 90.4% | 86.5% | 89.6% | 83.8% |
| 2B | 98.9% | 91.4% | 88.8% | 85.9% | 92.5% |

* **The graph.** After each withdrawal no claim the kernel reports as grounded rests on a quote overlapping the withdrawn text: 0 of
  940 and 0 of 936 in run 1, 0 of 815 and 0 of 816 in run 2. The withdrawals touched 2 and then 4 stored quotes in run 1, with 4 and
  12 records resting on them, and 3 and 4 in run 2, with 8 and 13; no quote touching the text was stored afterwards. From the
  journal, no model.
* **Withdrawal kept.** Run 2 `ok` at 2A and 2B in both orders, as K of 0.1.7. Run 1 `ok` at 2A and `partly` at 2B in both orders, for
  the repair below. T and L `ok` at 2A and `partly` at 2B.
* **Earlier states.** No statement of either run of 0.2 is marked stale, at any stage, in either order. K of 0.1.7 has 11 and 10 at
  stage 1, 10 and 12 at 2A, 8 and 10 at 2B, the same old state as current among them each time; T 15 and 13 at stage 1, L one at 2A.
* **The repair.** In run 2 each withdrawal touched one row of the first answer, and each repair took one call: three claims and the
  done line, all accepted, no copy left out, nothing refused. That answer went from 40 rows to 42 and then to 44; the other stayed at
  47. In run 1 the first withdrawal touched no answer and took no call. The second took two rows of the first answer, both saying
  that 2026-07-28 removed protocol-level sessions. Its task showed 8 claims of live support and allowed at most 6 claim lines of up
  to 240 characters. The model took 5 calls: in the first, both of its claims named claims in `based_on`, where only quotes go, and
  one ran to 252 characters; it then sent that one 4 more times without shortening it. The one claim accepted says that "the
  2026-07-28 stateless revision removing the initialize handshake was withdrawn": the model read the withdrawal of one changelog line
  as the withdrawal of the whole revision, and the kernel checks form, not meaning. The answer closed as partial at 39 rows, without
  the sessions conclusion that a standing page still supports. Run 2 kept it, on a quote of `streamable-http.mdx`.
* **Repeats.** No answer of either run holds the same text twice, case and spacing aside, at any stage: run 1 has 40, 40 and 39 rows
  for the first question and 54 for the second, run 2 has 40, 42 and 44, and 47. One row added at 2B in run 2 says in other words
  what a row added at 2A says, on the same four quotes.
* **A defect of the kernel, found by this outcome after the grading.** The record of run 1's second answer names 11 of its 54 records
  twice (65 ids). A repair after a reader failed, in stage 1, took several attempts: the done line of the last one named records
  that the same task had stored in its earlier attempts, by their local names, and the kernel added the same records again, by their
  short ids, as rows the answer keeps. The first run 1 had the same, 82 ids for 42 records. It changes no text and no number above:
  an answer as read and graded shows each record once, and the quittances were cut per record. The done record keeps the repeated
  list as well, so a count over its grounds, such as the grounds still standing in the report of what fell, can come out too high.
  We judged that it does not hold the tag, which stays on the tree of the runs, and say so here; 0.2.1 is to list each record of an
  answer once (LIMITATIONS.md).
* **What 0.2 adds, on both journals, no model.** All of it passed. `audit-verify` verifies each journal and every seal in it (1,099
  entries and 2,990 records; 672 and 2,126). Its 46 and 34 seals, signed after the run with a key made for it, check with
  `audit-verify --checkpoint` under a trusted keys file, and a checkpoint of another prefix is refused. After each withdrawal
  `audit-read fallen` names exactly the claims whose grounded flag it turned off, and none of the withdrawn text. Each of the 93 and
  91 rows of the last answers gets a quittance that checks without the journal, 7.2 to 24.2 KB (median 11.0 and 10.4); none of the
  6 fallen claims tried in each run gets one. The index (8.1 and 5.6 MB) is equal to its journal, and the independent verifier
  `yuce-verify` (levels J0 and J1), written in a clean room from the specification of the format and not published yet, passes both
  journals.
* **The gap pass (run 1).** It used all 12 of its packs: 94 units in 15 calls, 111 records added (61 quotes, 38 claims, 12
  questions), and 33 units with no quote. The packs went to the documents in order, so all 12 went to the first two, the
  authorization and lifecycle pages of 2025-03-26; the other 20 got none. At this budget the run shows the pass at work, not what it
  adds to the coverage of a corpus.
* **The grader's control.** Two lines per stage restating the withdrawn content were planted in a copy of T's answer: it found all
  four, and its verdict on T's withdrawal went from `ok` to `partly` at 2A and from `partly` to `failed` at 2B.
* **Two gradings of the same answers.** The packets with the planted lines are copies of the first label order with T's answer
  changed. On the other four sides the same text in the same order was graded up to 2.6 points apart, and L's withdrawal at 2B was
  `partly` in one and `ok` in the other. The two label orders differ by up to 5.6 points (T, stage 1).
* **By model (lines sent, refused).** Run 2: `deepseek-flash` 1,253 and 127, Haiku 795 and 86, Luna 402 and 60, Gemini 322 and 17.
  Run 1: the three DeepSeek readers 1,779 and 190, 1,519 and 164, 1,380 and 188.
* **Cost.** Run 1: 467 calls, none failed, 18 minutes, $0.79 of DeepSeek balance. Run 2: 263 calls, one failed, 33 minutes, $0.13 of
  DeepSeek balance; Haiku through Claude Code, Luna through Codex and Gemini through the Antigravity CLI ran on subscriptions (81
  calls with no price). Journals of 4.3 and 2.9 MB. Both runs come from the public branch of the candidate, with the binary its
  release workflow built: their `provenance.json` names public commits.
* **Checking a journal of 0.2.** After its last stage the server seals and closes the run, so the journal goes on past the last
  receipt by a seal and the close: check it against `arm_c.phase3.receipt` without `--at-end`, or against the signed checkpoints in
  the archive's `signed/` folder with the verifier key in `signed/trusted.txt`.

### The gap pass on a second corpus (0.2.1), grader Gemini 4 Argon

As `benchmarks/PREREGISTRATION_0.2.1_A2A.md` fixed it before any run, with its amendment written before any answer was read: the
A2A specification of v0.2.5, v0.3.0 and v1.0.1 with the v1.0.1 changelog and the summary of v1 (five files, 380,731 bytes, 2,562
read units), side K alone, three readers on `deepseek-flash`, two runs with the gap pass (at most 12 packs of 8 units) and two
without, one after the other, on one binary and one tree. Run 3 stopped during the reading, before the pass, on a reply that two
repairs did not mend, with no answers; it is kept and does not count, and run 5, made in its place, counts as the second run with
the pass. The oracle holds 14 facts that ended by v1.0.1 and 2 controls that still hold. One grader, Gemini 4 Argon at high effort
through the Antigravity CLI, graded the answers blind, one run per call, in one label order.

| Stage | With the pass: run 1 | Run 5 | Without: run 2 | Run 4 |
|---|---|---|---|---|
| 1: facts stated current / statements correct | 8 / 52.5% | 6 / 53.9% | 2 / 76.2% | 1 / 86.2% |
| 2A: facts stated current / statements correct | 7 / 66.7% | 6 / 69.7% | 2 / 82.5% | 1 / 80.7% |

No run stated a control as ended. At 2B every run's answers are the bytes of its 2A answers, because no answer rested on the line 2B
withdraws, so 2B was not graded again.

* **By the pre-registered rule this counts against the gap pass:** both runs with it stated more ended facts as current than both
  runs without, at stage 1 and at 2A.
* **What the journals show.** A defect in how the kernel admitted claims on the changelog to the first question; it explains why
  that question's window was narrow in the runs with the pass. How much of the difference in errors comes from this defect and how
  much from the pass, this comparison does not separate.
  - None of the 13 such errors at 2A on the side with the pass rests on a record the pass made: by the grounds the journal
    records, each of those answer rows rests on quotes of the first reading or of later investigations. Some of them say what
    claims of the pass also say; whether the model took them from there, the journal cannot tell.
  - The removals are stated in the changelog. The window of claims the kernel gives the summary of the first question (which
    conclusions were superseded, made stale or qualified) held 1 claim on the changelog in each run with the pass, and 14 and 8 in
    the runs without. Those were all the claims on the changelog that the rule of 0.2.0 admitted, and the window took all of them;
    the rule's count is no measure of what the changelog held that mattered. Run 5's readers recorded 62 claims on it, 60 with the
    stance `reported`, 9 of these saying in their text that something was removed or renamed; for this question the kernel took a
    `reported` claim only by its words (`replaced`, `superseded`, `no longer` and a few more), and these were not among them. Run
    1's readers stored 10 claims on the changelog. Run 2's gave 13 of their 16 the stance `superseded`.
  - In both runs with the pass the changelog was read before the first pack, and its first reading had the prompts of the runs
    without it, apart from the list of records already in the journal: the claims on it were there before the pass. That does not
    rule out an effect of the pass's records on what else the window took and on the answers.
* **What 0.2.1 changes.** For a question about what changed the kernel now also takes a `reported` claim that says something was
  removed or renamed, as words of their own and where the sentence does not negate them (CHANGELOG.md). Replayed from the journals
  without a model, through the kernel's own prompt: the window of run 5 holds 11 claims on the changelog instead of 1 and that of
  run 4 11 instead of 8; run 1's still holds 1, its readers having stored few. The window keeps its size: 6, 18, 3 and 9 of its
  claims go out and 11, 19, 2 and 11 come in, in runs 1, 5, 2 and 4; on the first control run of 0.2, 2 go out and 3 come in, and
  the second's does not change. The runs above were made before the change, and no run with a model has measured it.
* **The pass itself.** In both runs it used all 12 packs: 123 and 126 units (111 and 116 quoted, 12 and 10 answered empty), 137 and
  138 records added, all standing at the end; the coverage table agrees with its report. The packs go to documents in the order of
  their ids, and here all 12 went to the v0.3.0 specification: on this corpus the pass added material on an older version only.
* **Coverage.** Units quoted: 886 and 909 of 2,562 with the pass, 850 and 894 without; the rest were left by the reading budget,
  apart from the units answered empty and 2 withdrawn.
* **Withdrawals.** 2A withdraws a line of the summary of v1 that the changelog also states. Answers rested on it in runs 1 and 4,
  and both kept the withdrawal (`ok`). Run 5 quoted it with no answer resting on it, and run 2 never quoted it: not hit. 2B hit no
  run: run 5 quoted its line, and no answer rested on it.
* **The grading.** The answers went to the grader as files in the folder of the call, and a grade counts only if the call's own log
  shows the file of answers read to its end; all 8 were. The whole packet inline was cut by the CLI at 187 KB, and four runs in one
  call thought past the output limit with no grade; both attempts are kept. Each call of stage 1 thought to its output limit as
  well and gave the grade in the continuation the CLI asked for, and the CLI marks such a call `ERROR` though the grade is whole;
  one of them ended with no grade and was made again, and the empty call is kept.
  Runs 2 and 5 gave the same bytes at stages 1 and 2A, so each was graded twice: the facts stated current were the same both times
  (2 and 6), the share of correct statements was not (76.2% and 82.5%, 53.9% and 69.7%).
* **Cost.** With the pass 434 and 492 calls, 17.6 and 17.7 minutes, $0.56 and $0.58; without it 455 and 446 calls, 16.0 and 16.5
  minutes, $0.55 and $0.56; no call failed. With the stopped run ($0.10), $2.35 of the $6 cap.
* **The source of the files.** The manifest of these runs names one commit of the upstream repository for all five files, at paths
  that commit does not hold. The bytes are the upstream bytes and both sides read them under the same names, but the journals keep
  that wrong source in the identity of each document, and they are kept as they are. The manifest is to be corrected before the
  release.

### How far these numbers go

The tables are what was measured. What they do not show:

* **Sample size.** 45 to 121 statements were graded per side and stage. The 95% interval of a difference of two such shares is
  about 10 to 12 points either way: +10.6 on Haiku is [-1.8, +22.9]. One difference of the 18 clears it (DeepSeek series 1, 2A,
  K against T: +17.2, [+4.4, +30.0]), none after a correction for 18 comparisons. They are not independent either: the kernel's
  answers of stage 1 and 2A are the same text.
* **The naming rule is a label, not a test.** Its 7 points were fixed before the runs. T moved by 8.7 to 10.9 points between the
  two DeepSeek series, which differ only in the output limit, so "better than T" at +8.4 to +10.6 is within what T did from run
  to run (K moved by 2.1, L by 2.0 to 3.8).
* **A wider quote in series 1.** These runs refused only the exact span of a withdrawn quote. In DeepSeek series 1 a reader, refused,
  widened the withdrawn sentence by 15 bytes and the kernel stored it as a new record (entry 937 of the journal of `deepseek1-K`). No
  answer cited it, so the gradings stand. Since 0.1.6 a withdrawal closes the bytes (LIMITATIONS.md).
* **What stage 1 shows.** No source has been withdrawn yet, so the cascade and the journal play no part in it: a difference there
  comes from how the reading is organized, which can be built without the kernel. Nor did the cascade change K's answers in 2A,
  which are the same text as in stage 1: a difference there comes from what the other side changed.
* **Work done.** In stage 1 K made 326 model calls on Haiku against 127 for T and L, and 371 to 381 on DeepSeek against 185 to 202.
  The journal and the cascade cannot change stage 1, and section 2 shows the reading process alone is worth about 12 points. No
  side with an equal budget of calls was run: the kernel's effect on quality is not separated from the extra reading.
* **Model calls after a withdrawal.** The first withdrawal touched no answer of K (on Haiku, no record of it), which is why K made
  no call. In this case a side without the kernel could have learned the same by searching its answers for the withdrawn bytes,
  though a search finds a quotation, not a claim resting on a claim or a retelling; the runner gave it no such check. Of its calls on DeepSeek, most repeat pages marked incomplete in stage 1 and have nothing to do with the
  withdrawal:

  | Run, side | Calls after 2A | On the withdrawn page | Bringing the answer together | On other pages |
  |---|---|---|---|---|
  | Haiku, T | 6 | 4 | 2 | 0 |
  | DeepSeek 1, T | 62 | 3 | 7 | 52 |
  | DeepSeek 1, L | 65 | 10 | 7 | 48 |
  | DeepSeek 2, T | 55 | 6 | 10 | 39 |
  | DeepSeek 2, L | 40 | 4 | 7 | 29 |

  After 2B, the withdrawal that touched an answer, K made 7, 12 and 1 calls, T 8, 54 and 43, L 7, 52 and 34.

  In the runs of four makers, by the same script: all calls, then those on the withdrawn page, bringing the answer together and on
  other pages.

  | Run, side | After 2A | After 2B |
  |---|---|---|
  | 1, K | 5: 0, 5, 0 | 5: 4, 1, 0 |
  | 1, T | 13: 7, 2, 4 | 9: 5, 2, 2 |
  | 1, L | 24: 2, 6, 16 | 16: 2, 7, 7 |
  | 2, K | 0 | 1: 0, 1, 0 |
  | 2, T | 24: 6, 6, 12 | 10: 3, 3, 4 |
  | 2, L | 22: 4, 4, 14 | 8: 3, 2, 3 |

  Calls on the withdrawn page and on the answer, both withdrawals together: K 10 and 1, T 16 and 18, L 17 and 13. Those are the ones
  to compare. T's and L's other calls went to other pages, and in run 1 the difference on these is small.
* **Withdrawals.** The second withdrawal touched an answer of K once per run: three cases, on one corpus. T and L kept the
  withdrawals fully in 10 and 8 of 12 gradings and partly in the others.
* **The graders.** Each comparison has one grader and no human spot check; its two label orders differ by up to 20.3 points. The
  grading is blind by labels only: K's answers carry status notes that the neutralization does not remove. The gold file was
  written with Opus 5.5, which also grades the DeepSeek runs and took part in building YuCe. Fable 5.1 and Opus 5.5 come from the
  vendor of Claude Haiku 5.5.
* **Reproducing a run.** The journals check out against their receipts, but the link from these numbers to this code rests on
  our word: the `provenance.json` of a run names commits of the private development repository, which the public history does
  not hold, and the binaries of the runs are not the release binaries.

## 2. Circles against a shared queue (grader Fable 5.1, agents on Claude Haiku 5.5)

Both without a graph. Circles is the default of the v0.1 profile: readers work in rounds, roles are given per task.

| | Circles | Shared queue |
|---|---|---|
| Stage 1, share of correct statements | 92.7% | 80.6% (−12.1) |
| Version transitions named (of 13) | 11 | 11.5 |
| An outdated rule given as current | 0 | 0 |
| Wall time, cost | 61.7 min, $1.32 | 51.8 min, $1.41 |

Why circles answer better is not established; two hypotheses (more of the others' records in a reader's view, different
answer windows) were tested and not confirmed.

## 3. Quotes that can be found in their source

The share of an answer's quotes found byte for byte in the page it names, on the same corpus, with Claude Haiku 5.5.

| System | Quotes byte for byte in the named page |
|---|---|
| YuCe, default | 232 of 234 |
| GraphRAG, local search | 0 of 24 (names no pages) |
| Graphiti, 10 facts | 1 of 7 (6 retold outside the corpus) |
| LightRAG, hybrid | 10 of 30 (26 with whitespace normalized) |

These systems are built for another purpose and do not promise a byte-exact quote, so this is no verdict on them: it shows what the
kernel is for. A comparison of answers comes back with the graph work of a later version.

## 4. The kernel's limits, without a model

One campaign with `benchmarks/run_limits.py` on the kernel code of v0.1.4 (`crates/` tree `5ee0f927`), on a Windows laptop with
nothing else building, the machine 13 to 18% busy. Each point starts from an empty journal in a new process; clients are the
stock audit server over TCP with real tokens, the default profile, no artificial pauses; every journal is closed, reopened in a
new process and checked to reach the same roots. Memory is the peak resident size of the whole process.

| Records in the journal | Committing one quote, p50 / p95 | Reopening the journal (replay) | Peak memory |
|---|---|---|---|
| 1,000 | 3.4 / 3.9 ms | 0.05 s | 15 MiB |
| 5,000 | 12.7 / 15.2 ms | 0.63 s | 44 MiB |
| 10,000 | 25.3 / 39.7 ms | 2.2 s | 76 MiB |

These journals hold quotes and claims on them, in transactions of 32 records. Real journals have many more entries per record:
`audit-verify` takes 2.0 to 2.2 s on the recorded runs of about 3,000 records. The whole state is hashed at every entry, so the
time of a replay grows close to the square of its length.

| Agents at once, on a journal of 5,000 records | 3 | 8 | 16 | 32 |
|---|---|---|---|---|
| Tasks per second | 12.0 | 14.2 | 19.0 | 19.2 |

This is one run on one machine: tasks per second moved by about a quarter between runs here, and a build beside the campaign
halves them. To repeat it: `python benchmarks/run_limits.py --out <folder>`, which prints what it ran on and how busy the machine
was. Recommended for 0.1: runs of **a few thousand records** and up to **8 agents** at once. The published runs hold about
3,000 records. The cost of a commit and of a replay grows with the journal; more than 16 agents add little.

## Caveats

* One corpus, one or two runs per side and model, and graders that differ between comparisons (so the shares of section 1's two
  models and of section 2 are not comparable with each other; the differences within one comparison are).
* The side without the kernel is built by us. It is a careful substitute, not every possible one.
* The kernel checks bytes and registered dependencies, not meaning: its side once gave a current rule as replaced, on
  correct quotes, in every stage of the Haiku pair. See [LIMITATIONS.md](LIMITATIONS.md).
* Model outputs differ between runs; a new run will not repeat the answers byte for byte. The recorded journals do repeat:
  each one replays to its roots without a model (`sbgk audit-verify`).

## The recorded runs

The runs of section 1 are release assets of v0.1.0, the two runs on four makers of v0.1.6, the control run of 0.1.7 of v0.1.7 and
the runs of 0.2 of v0.2.0: one archive per run and per grading, each with a manifest of its files (sizes and SHA-256), and
`SHA256SUMS` over all of them (`SHA256SUMS-runs.txt` from v0.1.6 on).

| Archive | What it holds |
|---|---|
| `haiku-K`, `haiku-T`, `haiku-L` | the Haiku pair: the kernel's side, native Temporal, native LangGraph |
| `haiku-grading-fable` | its blind packets, the grader's prompts and replies, the tables |
| `deepseek1-K`, `-T`, `-L`, `deepseek1-grading-opus` | DeepSeek, series 1, and its grading |
| `deepseek2-K`, `-T`, `-L`, `deepseek2-grading-opus` | DeepSeek, series 2, and its grading |
| `makers1-K`, `-T`, `-L`, `makers1-grading-opus` | four makers, run 1 (v0.1.5), and its grading |
| `makers2-K`, `-T`, `-L`, `makers2-grading-opus` | four makers, run 2 (v0.1.6), its grading and the grader's control |
| `control017-K`, `control017-grading-opus` | the control run of 0.1.7 and its grading (v0.1.7) |
| `control02-run1-K`, `control02-run2-K`, `control02-grading-fable` | the control runs of 0.2 and their grading (v0.2.0) |
| `first02-run1-K`, `first02-run2-K` | the first runs of 0.2, made again after the fix; their four graded packets are in `control02-grading-fable` |

A run folder holds the journal (`arm_c/run.wal`), the calls and replies, the answers, the inputs (corpus copy, checklist,
withdrawal plan) and the summary. Left out: the agents' tokens (`arm_c/subjects.json`; replaying the journal needs none)
and the native Temporal history database (it held a local path; the Temporal side's outcome is in `arm_a.json`). Local
paths in metadata are replaced by placeholders (`<runs>/`, `<build>/`, `<home>/`), each such file listed in the manifest
with its original and new SHA-256; the journals keep their bytes. The T and L folders carry a copy of their K side's
journal: they reused it (`arm_c_reused.json`), they are not independent repeats of it. Each archive also carries, under
`LICENSES/`, the corpus's upstream `LICENSE` and `LICENSE-MIT`, its README with the attribution, and this project's NOTICE;
the manifest lists them apart from the run's own files.

To check a journal without a model: take the final receipt from the summary (`arm_c.phase3.receipt`: `audit_root`,
`engine_root` and `wal_head`, which binds the exact history, not only the end state) into a `receipt.json`, then
`sbgk audit-verify --wal arm_c/run.wal --expect receipt.json`. A receipt you trust comes from somewhere the archive's
writer cannot change; the one in the archive shows that the journal and its summary agree. The three kernel
journals verify: 817 entries and 3,058 records (Haiku), 947 and 2,719 (DeepSeek series 1), 903 and 2,650 (series 2).

The runs of sections 2 and 3 are summarized here; their records are not attached to 0.1.
