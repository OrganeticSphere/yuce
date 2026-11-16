# Checklist bacteria-under-flow (fixed before the run, 2026-11-16)

Corpus: `benchmarks/corpora/bacteria-under-flow`, three papers (B 2017, A 2019, C 2024), byte for byte as their files. The questions
are in `questions.json` and the withdrawal plan in `withdrawal.json`: 2A withdraws W1 (a clause of B), 2B withdraws W2 (a sentence
of A). The reference and its two addenda were fixed before the run. `benchmarks/PREREGISTRATION_CROSS_BIO.md` names them by SHA-256,
and they go to the graders after the run.

## Part I. From the journal, without a model

For each step, 2A and 2B:
- **must fall:** every record whose quotes overlap the withdrawn interval fell, and so did the link records the reference names
  for the step;
- **must stand:** no record fell whose quotes overlap an interval the reference says must stand, unless they also overlap the
  withdrawn interval. One such record is a failure of the step, and a failure of either step is a failure of the run;
- **collateral:** the records that rest both on the withdrawn interval and on what must stand. They fall, and are counted apart;
- **sent back:** the questions the kernel sends back to be answered again.

The condition of W2: whether any answer line of Q1–Q3 lost a ground at 2A. W2 counts toward the result "an answer fell and was
given again" only if none did; its mechanical checks above are reported either way.

The export: the standing claims whose quotes come from two or more papers, with the byte intervals of their quotes.

## Part II. Primary grading, against the reference, from the export

The case's researcher, an AI agent, grades the run's export files:
- **facts:** a fact counts when a standing record's quotes overlap its interval (or an alternative interval), and the grader
  confirms that the record states it;
- **links**, in two steps:
  - mechanical: a standing record whose quotes overlap at least one interval of every side of the link;
  - text: the grader checks that the record falls into no trap and, where the reference requires a conclusion, states it;
- **traps:** each trap the answers fall into, counted;
- the rule of the scoring addendum for the link that compares the thresholds.

## Part III. Secondary grading, blind

Gemini 4 Argon through the Antigravity CLI, one call per packet, using no tool. The grader sees the answers labelled by phase, the
corpus and the reference, and nothing else of the run. It grades each statement of each answer `correct`, `distorted`,
`unsupported` or `trap`, and names the trap. This grading never changes the primary score.
