# Preregistration: the gap pass of 0.2 on a second corpus (A2A), 0.2.1

Written 2026-11-13, before any run on the corpus. Fixed here: the question, the corpus, the pair, what is measured and what would
count against the gap pass.

## Question

The gap pass of 0.2 was built and measured on one corpus, the MCP specification: on run 1 of the release it used all 12 of its
packs, covered 94 units and added 111 records. Does it work the same way on a corpus it was not built on?

## Corpus and reference

- `benchmarks/corpora/a2a-spec-v1.0.1`: the A2A specification of v0.2.5, v0.3.0 and v1.0.1, the v1.0.1 changelog and the summary of
  v1, 380,731 bytes in five files, pinned by tag, commit and bytes.
- Oracle: `benchmarks/corpora/gold/a2a-spec-v1.0.1-stale-facts.json`, 14 facts that ended and 2 controls that still hold, judged
  against v1.0.1.
- The blind checklist and the withdrawal plan are fixed with this file and ship in each run's archive. The withdrawal plan:
  - 2A withdraws a peripheral line of the summary of v1, which the changelog also states;
  - 2B withdraws the one changelog item that states the removal of the `stateTransitionHistory` capability.

## The pair

- Only the kernel's side, with the flags of the runs of 0.2 (`--freeze-arm-a`).
- Three readers on `deepseek-flash`, thinking off, temperature 0.
- One factor changes: the gap pass, on (at most 12 packs of 8 units) or off.
- Two runs on each side. The sides run one after the other, alternating, on one binary and one tree.
- Budget: at most $3 per run, $6 for the four.

## What is measured

1. **The pass itself**, on the side with it:
   - packs used, units covered, records added and how many of them stand;
   - the coverage table (`sbgk audit-read coverage`): what each read unit came to, and whether its totals equal the report of the
     pass.
2. **Coverage**, both sides: read units quoted, units left without a quote.
3. **The answers**, graded blind by Gemini 4 Argon through Antigravity on the checklist:
   - stale-current errors on the 14 facts;
   - false-superseded errors on the 2 controls;
   - statement grades;
   - withdrawal discipline at 2A and 2B.
4. **Cost and time**, per run.

## What would count against the gap pass

- Its records do not stand: refused, or falling without a withdrawal.
- The coverage table and the report of the pass disagree.
- The side with the pass makes more stale-current or false-superseded errors than the side without, on both of its runs.

Two runs a side make a check, not a measure with bounds: a difference within the spread of the two runs of a side is reported as no
difference.
