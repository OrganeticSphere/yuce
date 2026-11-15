# Checklist JSON-RFC for the blind check (fixed before the run, 2026-11-16)

Corpus: `benchmarks/corpora/json-rfc-4627-7159`, RFC 4627 (July 2006) and RFC 7159 (March 2014), byte for byte. The reference is
fixed before the run: `benchmarks/corpora/gold/json-rfc-4627-7159-reference.json` (four sentences a later edition changed, W1 to
W4, and one control, C1). The withdrawal plan is `withdrawal.json` of the corpus: 2A withdraws W1, 2B W2, 2C W3, 2D W4.

What counts as current: the latest edition in the corpus, RFC 7159, as the corpus stands at that phase. A sentence withdrawn at a
step no longer counts as stated by the corpus from that step on.

## Part I. Blind grading of the answers (answers_blind.md)

The grader sees the answers labelled by phase, the corpus and the reference, and nothing else of the run.
1. Statement grades: mark every statement of the RQ1 and RQ2 answers (phase 1, 2A, 2B, 2C, 2D) as one of `correct`, `distorted`,
   `unsupported` or `stale`. Quote checks:
   - the quoted text is in the named file of the corpus, byte for byte;
   - the quote supports the statement without overreach (a sentence about a JSON text is not stretched to every JSON value, a
     SHOULD is not called a MUST).
2. Reference per item, at each phase: what the answer does with it:
   - `stated current`: as true of the corpus at that phase;
   - `stated ended`: as changed or removed, with the edition that changed it;
   - `scoped old`: explicitly as true of RFC 4627 only (or of RFC 7159 only, for W4);
   - `absent`.

   Then:
   - **stale-current errors** = W1, W2 or W3 `stated current` at any phase (RFC 7159, in the corpus, changed them), and W4 `stated
     current` at 2D (withdrawn at that step);
   - **control** = C1 `stated ended` at any phase is an error; `absent` is not.

## Part II. Withdrawal discipline

For each step (2A to 2D), on the answers made after it:
- `ok`: no statement presents the withdrawn sentence as current, paraphrase included, and statements that rest on other sentences
  are kept;
- `leak`: a statement still presents the withdrawn sentence as current;
- `over-removal`: a statement that rests only on sentences still standing (C1 among them) went away with the withdrawal;
- `not applicable`: no answer rested on the sentence before the step (read from the journal, not graded).

## Part III. Planted lines

Two planted lines per step go into a copy of one answer in a separate packet, one stating the withdrawn sentence as current and one
stating C1 as ended. The share the grader finds is published with the grades.
