# Benchmarks

What was measured, on what, by whom, and with which caveats. Every comparison names its grader; numbers from different
graders are never put side by side.

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
  7 points higher (the spread of two identical runs), or when it keeps a withdrawal the other side breaks; "on par" within
  ±7; "kernel worse" when more than 7 points lower.
* **Runs.** One per side on Claude Haiku 5.5; two series per side on DeepSeek Flash.

## 1. The kernel against the same team without it

The side without the kernel is the same team with the same prompts and answer guidance, on its own orchestration: native
[Temporal](https://temporal.io/) (T) or native [LangGraph](https://www.langchain.com/langgraph) (L). The runner gives it
what a careful team would build: it checks every quote byte for byte, keeps the readers' notes, answers by map-reduce over
the pages and rebuilds its answer after a withdrawal. What it lacks is the kernel: registered `based_on` dependencies, the
cascade on revocation, a replayable journal and leased coordination. K is the kernel's side in the default v0.1 profile.

### Agents on Claude Haiku 5.5, grader Fable 5.1

| Stage | K | T | L | Named |
|---|---|---|---|---|
| 1: reading and answers, share of correct statements | 89.9% | 79.3% | 84.9% | K better than T (+10.6); on par with L (+5.0) |
| 2A: after the first withdrawal | 90.5% | 86.6% | 88.8% | on par |
| 2B: after the second withdrawal | 88.7% | 86.7% | 85.8% | on par |
| Withdrawal kept (2A, 2B) | yes | yes; once partly in 2B | yes | |
| An outdated rule given as current | 0 | 0 | 1 (2A) | |
| A current rule given as replaced | 1 control fact, in every stage | 0 | 0 | the kernel side's known error |
| Quotes byte for byte in the named page | 203 of 204 | 134 of 134 | 126 of 126 | not a difference: the runner checks both sides |
| Model calls to answer again after 2A | **0** | 6 | 6 | the kernel finds that the withdrawal touches no answer |
| Whole run: wall time, cost | 54.2 min, $1.37 | 23.3 min, $0.96 | 22.0 min, $0.96 | the kernel ×2.3–2.5 slower, ×1.4 the cost |

K ran on an earlier revision than T and L (the kernel side's code did not change between them); the cost of the Claude
models is the API-equivalent list price.

### Agents on DeepSeek Flash, grader Opus 5.5

All three sides on one revision; agents `deepseek-flash` (V4.1 Flash, thinking off).

Series 2 is the same with one change: an output limit of 32,000 tokens per call instead of 8,192 (series 1 cut one long
answer of L, its stage 1 RQ2 summary, at 8,192; series 2 cut none).

| Stage | Series | K | T | L | Named |
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
| Model calls to answer again after 2A | **0** and 0 | 62 and 55 | 65 and 40 |
| Wall time (series 1, series 2) | 15.0, 14.7 min | 11.8, 11.8 min | 12.9, 11.8 min |
| Cost (series 1, series 2) | $0.50, $0.48 | $0.32, $0.30 | $0.33, $0.30 |

The advantage of series 1 in stage 1 and 2A did not repeat in series 2; the kernel's side kept every withdrawal in both.
It took 1.2 to 1.3 times the wall time and 1.5 to 1.6 times the cost of the sides without it. The sides without the kernel
often wrote a closing line over its length limit, which the runner refuses (their pages are then marked incomplete); their
claims were kept (in series 1, 6 of about 2,000 were refused).

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

## 3. Against knowledge-graph systems (grader Gemini 4 Argon, stage 1)

The kernel without a graph (the v0.1 default), the kernel with its experimental graph builder, and three graph systems
built on the same corpus, all with Claude Haiku 5.5.

| System | Share of correct statements | Correct of graded | Quotes byte for byte in the named page | An outdated rule as current | Time, cost |
|---|---|---|---|---|---|
| YuCe, no graph (default) | 80.3% | 61 of 76 | 232 of 234 | 0 | 54 min, $1.40 |
| YuCe, with the graph (experimental) | 82.6% | 54.5 of 66 | 182 of 183 | 2–3 | 143 min, $4.36 |
| GraphRAG, local search | 86.7% | 13 of 15 | 0 of 24 (names no pages) | 0 | build 24 min, $0.72 |
| Graphiti, 10 facts | 81.1% | 17 of 21 | 1 of 7 (6 retold outside the corpus) | 2 | build 42 min, $1.09 |
| LightRAG, hybrid | 69.6% | 19.5 of 28 | 10 of 30 (26 with whitespace normalized) | 1 | build 51 min, $1.26 |

The graph systems give fewer statements, and most of their quotes are not found byte for byte in the page they name
(GraphRAG names none). The kernel's graph is off by default: its share is within the noise of the no-graph mode, but it knew fewer version transitions
than Graphiti (8 against 15 of 25) and cost three times as much.

## 4. The kernel's limits, without a model

One campaign on the release's kernel code (commit `599ad4eb`; v0.1.0 differs only in its version number and documents), on
the Windows laptop of the published runs with other applications open (89% of its memory in use at the start). Each
point starts from an empty journal in a new process; clients are the stock audit server over TCP with real tokens, the
v0.1 profile, no artificial pauses; every journal is closed, reopened in a new process and checked to reach the same roots.

| Records in the journal | Committing one quote, p50 / p95 | Reopening the journal (replay) | Writer memory |
|---|---|---|---|
| 1,000 | 4.6 / 4.9 ms | 0.14 s | 8.5 MiB |
| 5,000 | 20.2 / 26.1 ms | 3.2 s | 39.5 MiB |
| 10,000 | 40.9 / 69.9 ms | 13.0 s | 64 MiB |

| Agents at once, on a journal of 5,000 records | 3 | 8 | 16 | 32 |
|---|---|---|---|---|
| Tasks per second | 9.5 | 13.4 | 15.5 | 16.0 |

Recommended for 0.1: up to **10,000 records** in a run and up to **8 agents** at once. The published runs hold about
3,000 records. The cost of a commit and of a replay grows with the journal; more than 16 agents add little.

## Caveats

* One corpus, one or two runs per side and model, and graders that differ between comparisons (so the shares of section 1's two
  models and of sections 2 and 3 are not comparable with each other; the differences within one comparison are).
* The side without the kernel is built by us. It is a careful substitute, not every possible one; a substitute with the
  same dependencies, cascade and journal on a database was not built.
* The kernel checks bytes and registered dependencies, not meaning: its side once gave a current rule as replaced, on
  correct quotes, in every stage of the Haiku pair. See [LIMITATIONS.md](LIMITATIONS.md).
* Model outputs differ between runs; a new run will not repeat the answers byte for byte. The recorded journals do repeat:
  each one replays to its roots without a model (`sbgk audit-verify`).

## The recorded runs

The runs of section 1 are release assets of v0.1.0: one archive per run and per grading, each with a manifest of its files
(sizes and SHA-256), and `SHA256SUMS` over all of them.

| Archive | What it holds |
|---|---|
| `haiku-K`, `haiku-T`, `haiku-L` | the Haiku pair: the kernel's side, native Temporal, native LangGraph |
| `haiku-grading-fable` | its blind packets, the grader's prompts and replies, the tables |
| `deepseek1-K`, `-T`, `-L`, `deepseek1-grading-opus` | DeepSeek, series 1, and its grading |
| `deepseek2-K`, `-T`, `-L`, `deepseek2-grading-opus` | DeepSeek, series 2, and its grading |

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
