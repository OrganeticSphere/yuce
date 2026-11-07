# What the 0.1.7 control run will measure, fixed before it runs

This file is in the branch `release-017` of the public repository, pushed before the run starts: the commit's date and the times in the run's
`provenance.json` show the order. `provenance.json` holds the SHA-256 of this file and of every runner source. Unlike the runs before it, this one comes before the
tag: the tag `v0.1.7` follows it, on the same `crates` tree. A defect the run finds is fixed first, and the run is made again from the new tree. Whatever the run shows
is published with it, including results against the kernel.

## Why this run

In run 2 of four makers, the kernel kept the second withdrawal partly in both label orders: its answer dropped a conclusion that another page supports. The graph was right: the
claim stood on a quote of that page and was shown to the model. One row of the answer had merged that quote with the withdrawn one, so the row fell by the all-quotes
rule, and the request for a repair did not name it. The model wrote the whole answer again, most of it copies of rows it was told to keep. The request is fixed in this
tree. A check on recorded prompts, one model, six calls, showed the row restored; it did not show other models, several fallen rows, or the grader's verdict. This run does.

## The run

One run of side K of section 1 of BENCHMARKS.md, from that branch: its source, the binary its release workflow builds, its runner. T and L are not run again.

| | |
|---|---|
| Sides | K (team with the kernel) is run. T and L are the answers of run 2 of four makers, from the tag v0.1.6: they use no kernel, and nothing in this tree changes them |
| Team | as in run 2: four readers of four makers, the same model in the same seat: `deepseek-flash` with thinking off, Claude Haiku 5.5, GPT-5.6 Luna through Codex, and Gemini 3.8 Flash through the Antigravity CLI, at medium effort where the transport has one |
| Corpus | `benchmarks/corpora/mcp-spec-2026-07-28`, the 22 pages of the published runs |
| Withdrawals | the plan of the published runs: 2A a quote in a peripheral page, 2B a quote in the changelog, the same bytes, withdrawn whether or not the side quotes them. It is in `withdrawal.json` of the archive |
| Spending cap | $6, on the seats with a price per call: DeepSeek, and Claude at the API-equivalent cost its subscription reports. GPT and Gemini run on subscriptions with no price per call: their calls and tokens are published |
| Grading | blind, one grader for all three sides in one pass, answers shuffled, Claude Opus 5.5 in a clean session, with the rules of `grade_common.py` in the archive `deepseek1-grading-opus` of release v0.1.0, SHA-256 `50ee02287d2d183d4e631dc04ad2019590e8b1baace38b1fa37394b91e3ecc7d`, unchanged. T and L are graded again with the new K, so that the three sides have one grading; the published grading of run 2 stands as it is |

A run with changed tracked files does not count. The archive leaves out `arm_c/subjects.json`, which holds the run's tokens.

## Changed against the pre-registration of 0.1.6

* A repair after a withdrawal names each row that fell by its id, with the quotes under it that stand. The row's own text stays out. The answer it repairs keeps its other rows, a repair takes a few lines, and a line that copies a kept row is left out and counted.
* Only side K is run, and it comes before the tag, as above.
* The runner does not change. Team, corpus, withdrawals, spending cap and grading rules are those of 0.1.6.
* The rest of this tree does not reach the run: `--docs`, the cut of files that are not Markdown and the neutral words in the prompt apply to supplied documents, and the search near a quote gives the same decisions. The tasks of a pinned corpus are those of 0.1.6, apart from the repair.

## Primary outcomes

Fixed before the run.

1. **Graph level.** After each withdrawal, the share of claims the kernel reports as grounded that rest on a quote overlapping the withdrawn text, and the quotes overlapping it stored after the withdrawal. Expected: 0 and 0. Any other value is a defect of the kernel, not a result, and it stops the tag.
2. **Text level.** The grader's `withdrawal` verdict for K at 2A and 2B, in both label orders, and the facts it marks `stated current` that the plan withdrew, paraphrase included. Expected: `ok`, or `not applicable` where no answer rests on the quote. This is a measured number. A `partly` is published as it came, with its cause. As in 0.1.6, two planted lines per stage, each restating the withdrawn content as current in other words, go into a copy of one side's answer in a separate packet, and the share the grader finds is published. There is one grader: its misses are a limit of this outcome.
3. **The repair.** At each withdrawal that touched an answer: the rows that fell, the lines the model sent and the limit it had, the copies left out, the lines refused, and the answer's rows before and after. From the journal, no model. Expected: a few lines and no row lost that a standing quote supports.
4. **Repeats.** Claims in K's answers, with and without repeats, case and spacing aside, at 2A and 2B.
5. **Collateral and cost.** The quotes the answers of the stage before cited, the withdrawal did not touch, and the answers after it no longer cite; model calls, split into the withdrawn page, the assembly of the answer, and other pages; tokens for each model apart and bytes. By `benchmarks/revision_outcomes.py`, no model.

## Secondary outcomes

Blind checklist points per stage for the three sides, with the caveat of section 1 of BENCHMARKS.md. Wall time and cost.

## What the tag waits for

The run ends, its journal verifies, outcome 1 is 0 and 0, and no defect of the kernel is found in outcomes 2 to 4. A `partly` whose cause is not in the kernel does not hold the tag back, and is published as it came.

## What will not be claimed

This is one run with two withdrawals and one grader, two events for outcomes 2 and 3: an anecdote. It can show that the request works on this team and this corpus, not how often. No gain in answer quality from it, and no comparison of K with T and L beyond what section 1 of BENCHMARKS.md already allows: K is a new run, T and L are not.
