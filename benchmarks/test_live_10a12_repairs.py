"""DeepSeek check run 10A-12 (2026-10-23, revision a5f0432, Sonnet builder). Each summary of 40 claims had one faulty claim; the
kernel refused it whole ("nothing was stored ... send the whole answer again") and the repair added the prefix rule ("send only the
corrected line and the lines after it"): DeepSeek sent 7 and 10 claims again. Three sections over the line bound lost every line:
told only to merge, DeepSeek wrote 34, 45 and 36 lines again."""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402


class WholeAnswer(unittest.TestCase):
    def refusal(self):
        return {"status": "REPAIR_REQUIRED", "failed_index": 0, "task_id": "TS1",
                "error": {"code": "BAD_FIELD", "field": "lines", "message": "nothing was stored: correct these lines and send the whole "
                                                                            "answer again",
                          "expected_by_kernel": {"lines": [{"line": 1, "local_id": "t1_c2", "needs": "text of 1..240 characters"}]}}}

    def test_a_summary_refused_whole_is_sent_again_whole(self):
        previous = "\n".join('{"kind":"claim","local_id":"t1_c%d","text":"x"}' % i for i in range(1, 41))
        prompt = P.repair_prompt("TASK SUMMARIZE", self.refusal(), "lines", previous, [])
        self.assertIn("t1_c40", prompt, "the whole previous answer is shown to be sent again")
        self.assertIn("Send the whole answer again", prompt)
        self.assertIn("every other line unchanged", prompt)
        self.assertNotIn("before the failed index were accepted", prompt, "no prefix rule: nothing was stored")

    def test_the_prefix_rule_stays_for_a_line_refused_inside_an_answer(self):
        refusal = {"status": "REPAIR_REQUIRED", "failed_index": 3, "error": {"code": "BAD_FIELD", "field": "exact_quote", "message": "no",
                                                                             "expected_by_kernel": None}}
        prompt = P.repair_prompt("TASK", refusal, "lines", '{"kind":"observe","local_id":"t1_o1"}', [])
        self.assertIn("before the failed index were accepted", prompt)


class LineBound(unittest.TestCase):
    def test_an_answer_over_the_bound_may_leave_out_the_least_important_records(self):
        refusal = {"status": "REPAIR_REQUIRED", "failed_index": 0,
                   "error": {"code": "BAD_FIELD", "message": "34 lines, at most 32 per answer: nothing was stored; send the whole answer "
                                                              "again, at most 32 lines", "expected_by_kernel": {"max_lines": 32}}}
        prompt = P.repair_prompt("TASK EXTEND", refusal, "lines", "", [])
        self.assertIn("leave out the least important records", prompt)
        self.assertIn("more than 32 and nothing is stored again", prompt)
        self.assertNotIn("rather than leaving any out", prompt)


if __name__ == "__main__":
    unittest.main()
