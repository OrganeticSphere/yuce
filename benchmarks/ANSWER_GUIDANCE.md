# Common answer guidance

The canonical UTF-8 asset is `crates/sbgk-core/src/audit/answer_guidance.json` (format
`r2r-common-answer-guidance/1`). Rust embeds this asset and Python reads the same file from the source checkout. Both render
the identical `COMMON ANSWER GUIDANCE` block in their answer prompts, including when C's temporal retrieval option is off.
The block covers chronology and incomplete coverage. Claim and done instructions ask for text of at most 200 characters; the
existing 240-character validation bound is unchanged. Native output schemas and their citation mechanisms remain distinct.

Arm A's notes, direct, map, tree merge and final reduce prompts show the question id and text without the private `about` search
topics. Actual source text is preserved, including an `ABOUT:` line in a source. The notes stub receives its test topics through
call-local context metadata, which is not sent to real models and cannot leak between concurrent questions.

C still supplies its actual record window, accepted links, later candidates, stale warnings and open questions. The statement
that records are ordered by report date appears only when that retrieval policy is enabled. A tree merge does not assert that
its first input is chronologically earlier merely because it came first.

This policy applies to the normal C SUMMARIZE interface and all seven A answer template sites. Reader/builder task instructions
and native response schemas remain specific to their interfaces. Historical runs retain their original saved prompts and
results; changing instructions does not revalidate old scores or establish the quality, cost or speed of a new pair.
