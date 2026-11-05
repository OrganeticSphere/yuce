# What the 0.1.5 run will measure, fixed before it runs

This file is part of the tag `v0.1.5`, which is published before the run starts: the tag's date and the times in the run's
`provenance.json` show the order. `provenance.json` holds the SHA-256 of this file and of every runner source. Whatever the run shows
is published with it, including results against the kernel. It replaces `PREREGISTRATION_0.1.4.md`, whose run was not started; the
differences are listed below.

## The run

One run of the three sides of section 1 of BENCHMARKS.md, from the public tag: its source, its release binary, its runner. Unlike the published runs, the team is made of different
models: a team of one model checks the mechanism, and what the kernel is for is agents of different makers working on one record.

| | |
|---|---|
| Sides | K (team with the kernel), T (same team on Temporal), L (same team on LangGraph) |
| Team | four readers of four makers, the same model in the same seat on every side: `deepseek-flash` with thinking off, Claude Haiku 5.5, GPT-5.6 Luna through Codex, and Gemini 3.8 Flash through the Antigravity CLI, at medium effort where the transport has one. The answers of the sides without the kernel are led by `deepseek-flash`, as is the checker. Temperature is 0 where the transport sets it |
| Corpus | `benchmarks/corpora/mcp-spec-2026-07-28`, the 22 pages of the published runs |
| Withdrawals | the plan of the published runs, fixed before any of them: 2A a quote in a peripheral page, 2B a quote in the changelog, the same bytes on every side, withdrawn whether or not a side quotes them. It is in `withdrawal.json` of each archive |
| Spending cap | $6 per side, on the seats with a price per call: DeepSeek, and Claude at the API-equivalent cost its subscription reports. GPT and Gemini run on subscriptions with no price per call: their calls and tokens are published. Stage 1 is not made equal: the sides read as they read in the published runs, and the spend per stage is published |
| Grading | blind, one grader for all three sides, answers shuffled, Claude Opus 5.5 in a clean session, with the rules of `grade_common.py` in the archive `deepseek1-grading-opus` of release v0.1.0, SHA-256 `50ee02287d2d183d4e631dc04ad2019590e8b1baace38b1fa37394b91e3ecc7d`, unchanged |

A run with changed tracked files does not count. The archive leaves out `arm_a_temporal.db`, which holds a local path, and `arm_c/subjects.json`, which holds the run's tokens.

## Changed against the published runs

A closing line over its length limit is cut with a visible mark, no longer refused. That refusal marked 7 to 13 of 44 partial answers incomplete on the sides without the
kernel, and most of their calls after a withdrawal went to doing those again. The team is new, as above, with four readers instead of three, and a circle still takes as many sections as there are readers: four. Nothing else in the sides' behaviour changes. So the spread of the published series is a guide for this run, not a measure of it, and its calls are not comparable with the published ones.

## Changed against the pre-registration of 0.1.4

* The GPT seat is named: GPT-5.6 Luna. Gemini Flash is a fourth reader, no longer the fallback of that seat, and there is no fallback: if a seat's limits end during the run, the run says so, and its failed calls stay visible in it.
* The runner of `v0.1.4` could not start the side on Temporal with a Codex or an Antigravity seat, and refused the money brake beside an Antigravity seat. Both are fixed in this tag; nothing else in the runner changed.
* `benchmarks/revision_outcomes.py` now finds a quote that partly overlaps the withdrawn text, which outcome 3 would have counted as collateral, and counts a reader's stored quotes from the journal, as outcome 5 asks, apart from its other records.
* A short check with real models on two pages and all three sides found the defects of the runner before this tag. Its data is not part of the run and is not used.

## Primary outcomes

Fixed before the run. 2A is a control: if no answer rests on its quote, that stage shows the cost of finding this out, and only 2B shows a revision.

1. **Graph level.** After each withdrawal, the share of claims the kernel reports as grounded that rest on a withdrawn quote. Expected: 0, by construction. Any other value is a defect of the kernel, not a result, and it stops the release of the numbers until it is explained. Read from the journal, no model. K only.
2. **Text level.** On each side and stage, the grader's `withdrawal` verdict (`ok`, `partly`, `failed`, `not applicable`) and the facts it marks `stated current` that the plan withdrew, paraphrase included. This is a measured number and it can be above zero on every side, K included: the kernel controls what an answer may rest on, not the words a model writes. To show what the grader catches, two planted lines per stage, each restating the withdrawn content as current in other words, go into a copy of one side's answer in a separate packet, and the share it finds is published. There is one grader: its misses are a limit of this outcome.
3. **Collateral.** On each side and withdrawal, the quotes the answers of the stage before cited, the withdrawal did not touch, and the answers after it no longer cite. Counted by `benchmarks/revision_outcomes.py`, no model. An answer may drop a quote and say the same, so this counts what a revision did not keep, not a loss of truth.
4. **Cost of the revision.** On each side and withdrawal, by the same script: model calls, split into the withdrawn page, the assembly of the answer, and other pages; tokens for each model apart, as each model cuts text its own way and their tokens do not add up; and the bytes of prompts and replies, the one size common to all of them.
5. **By model.** On K, for each reader and its model: lines sent, quotes stored, quotes refused by reason. The same script. These numbers describe this corpus and this run, not the models.

## Secondary outcomes

Blind checklist points per stage, with the caveat of section 1 of BENCHMARKS.md. Version transitions named. Wall time and cost.

## What will not be claimed

This is one run with two withdrawals and one grader: two events per side for outcomes 2 and 3, which is an anecdote. No gain in answer quality from it, and no statement that a side is better on an outcome where the difference is inside the spread of the published series.
