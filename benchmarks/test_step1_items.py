"""The runner's side of item-wise acceptance (the consilium of 10A-17, Gemini's plan step 1): the repair of an answer the kernel
stored except some lines, and the partial delivery of a summary whose repairs are used up."""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402


class ItemWiseRepair(unittest.TestCase):
    def test_only_the_lines_not_stored_are_asked_for(self):
        refusal = {"status": "REPAIR_REQUIRED", "repair_scope": "rejected_items_only", "failed_index": 2, "not_stored": ["t1_o2", "t1_c2"],
                   "refused": [{"index": 2, "local_id": "t1_o2", "error": {"code": "QUOTE_NOT_FOUND_IN_BYTES"}}],
                   "excluded": [{"index": 3, "local_id": "t1_c2", "rests_on": "t1_o2"}]}
        text = P.repair_prompt("PROMPT", refusal, "lines", '{"kind":"observe"}', [])
        self.assertIn("YOUR ANSWER WAS STORED EXCEPT SOME LINES", text)
        self.assertIn("Send only the lines of not_stored", text)
        self.assertNotIn("PARTLY REFUSED", text, "not the builder's repair of refused operations")


class PartialSummary(unittest.TestCase):
    task = {"kind": "SUMMARIZE", "local_id_prefix": "t9_", "key": "rq:RQ1", "task_id": "TS9-x"}

    def test_a_summary_with_stored_lines_is_delivered_partial(self):
        [done] = P.fallback(self.task, {"t9_c2", "t9_c1"})
        self.assertEqual((done["outcome"], done["answer_ids"]), ("answered", ["t9_c1", "t9_c2"]))
        self.assertTrue(done["text"].startswith("Partial answer: 2 lines"))
        self.assertLessEqual(len(done["text"]), 240)

    def test_a_summary_with_nothing_stored_stays_unknown(self):
        [done] = P.fallback(self.task, set())
        self.assertEqual((done["outcome"], done["answer_ids"]), ("unknown", []))
        self.assertEqual(P.fallback({"kind": "EXTEND"}, {"t1_o1"}), [])


if __name__ == "__main__":
    unittest.main()
