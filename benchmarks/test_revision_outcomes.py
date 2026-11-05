"""The counter of what a withdrawal cost and what it took with it, on a small run folder."""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import revision_outcomes as R  # noqa: E402

PAGE = "docs/page.md"


def answer(*quotes):
    return {"RQ1": {"claims": [{"quotes": [{"report": r, "quote": q} for r, q in quotes]}]}}


class Outcomes(unittest.TestCase):
    def run_folder(self, tmp: str) -> pathlib.Path:
        folder = pathlib.Path(tmp) / "run"
        folder.mkdir()
        (folder / "summary.json").write_text(json.dumps({"withdrawn": [{"step": "2A", "phase": 2, "report": PAGE, "quote": "The withdrawn sentence."}]}), encoding="utf-8")
        side = {"phase1": {"answers": answer((PAGE, "The withdrawn sentence."), ("other.md", "Kept."), ("other.md", "Dropped."))},
                "phase2": {"status": "COMPLETE", "answers": answer(("other.md", "Kept."))}}
        (folder / "arm_a.json").write_text(json.dumps(side), encoding="utf-8")
        calls = [{"call_id": "a", "arm": "A", "phase": 2, "model": "m1", "usage": {"input": 10, "output": 5}, "prompt_bytes": 100, "text": "café"},
                 {"call_id": "b", "arm": "A", "phase": 2, "model": "m2", "usage": {"input": 1, "output": 1}, "prompt_bytes": 20, "text": "ok"},
                 {"call_id": "c", "arm": "A", "phase": 2}, {"call_id": "d", "arm": "A", "phase": 1}, {"call_id": "e", "arm": "C", "phase": 2}]
        (folder / "calls.jsonl").write_text("\n".join(json.dumps(c) for c in calls), encoding="utf-8")
        contexts = [{"call_id": "a", "report": PAGE}, {"call_id": "b", "answer_stage": "reduce"}, {"call_id": "c", "report": "other.md"}]
        (folder / "contexts.jsonl").write_text("\n".join(json.dumps(c) for c in contexts), encoding="utf-8")
        return folder

    def test_calls_tokens_and_quotes_of_a_withdrawal(self):
        with tempfile.TemporaryDirectory(prefix="revision-") as tmp:
            row = R.outcomes(self.run_folder(tmp))[0]
        self.assertEqual((row["side"], row["step"], row["calls"]), ("A", "2A", 3))
        self.assertEqual((row["withdrawn_page"], row["assembly"], row["other_pages"]), (1, 1, 1))
        self.assertEqual(row["tokens_by_model"], {"m1": 15, "m2": 2, "unknown": 0})
        self.assertEqual((row["bytes_sent"], row["bytes_received"]), (120, 7))
        self.assertEqual((row["quotes_before"], row["quotes_touched"], row["quotes_untouched_not_cited_after"], row["touched_still_cited"]), (3, 1, 1, 0))

    def test_lines_and_refused_quotes_are_counted_by_reader_and_model(self):
        with tempfile.TemporaryDirectory(prefix="revision-") as tmp:
            folder = self.run_folder(tmp)
            (folder / "summary.json").write_text(json.dumps({"team": [{"agent": "w1", "model": "m1"}], "withdrawn": []}), encoding="utf-8")
            replies = [{"arm": "C", "agent": "w1", "lines_submitted": 5, "accepted": 3, "refused": 2,
                        "problems": [{"local_id": "t1_o2", "needs": "a quote keeps the clause"}, {"local_id": "t12o1", "needs": ""}]},
                       {"arm": "A", "agent": "w1", "lines_submitted": 9}]
            (folder / "replies.jsonl").write_text("\n".join(json.dumps(r) for r in replies), encoding="utf-8")
            row = R.by_reader(folder)[0]
        self.assertEqual((row["model"], row["lines_sent"], row["records_stored"], row["lines_refused"]), ("m1", 5, 3, 2))
        self.assertEqual((row["quotes_cut_mid_clause"], row["quotes_refused_otherwise"]), (1, 1))

    def test_a_quote_is_touched_when_it_overlaps_the_withdrawn_text_in_that_page(self):
        withdrawn = {"report": PAGE, "quote": "The withdrawn sentence."}
        self.assertTrue(R.touched((PAGE, "withdrawn sentence"), withdrawn))
        self.assertTrue(R.touched((PAGE, "Before. The withdrawn sentence. After."), withdrawn))
        self.assertFalse(R.touched(("other.md", "The withdrawn sentence."), withdrawn))


if __name__ == "__main__":
    unittest.main()
