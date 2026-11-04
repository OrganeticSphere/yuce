"""DeepSeek check run 10A-11 (2026-10-23, revision 89366d4): after a withdrawal both summaries wrote 54 and 72 lines over a bound of
48, the repair showed them their answer, and they sent the same lines four times: both questions ended unknown. An answer over
the line bound is no longer shown again; the repair names the bound and asks to merge."""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402


class LineBound(unittest.TestCase):
    def test_an_answer_over_the_line_bound_is_not_shown_again(self):
        refusal = {"status": "REPAIR_REQUIRED", "failed_index": 0,
                   "error": {"code": "BAD_FIELD", "message": "54 lines, at most 48 per answer: nothing was stored; send the whole answer "
                                                              "again, at most 48 lines", "expected_by_kernel": {"max_lines": 48}}}
        previous = "\n".join('{"kind":"claim","local_id":"t1_c%d","text":"x"}' % i for i in range(54))
        prompt = P.repair_prompt("TASK SUMMARIZE", refusal, "lines", previous, [])
        self.assertNotIn("t1_c53", prompt, "the over-long answer is not shown")
        self.assertIn("at most 48 lines", prompt)
        self.assertIn("merge related records", prompt)

    def test_other_refusals_still_show_the_previous_answer(self):
        refusal = {"status": "REPAIR_REQUIRED", "failed_index": 1, "error": {"code": "QUOTE_NOT_FOUND_IN_BYTES", "message": "no"}}
        prompt = P.repair_prompt("TASK", refusal, "lines", '{"kind":"observe","local_id":"t1_o1"}', [])
        self.assertIn("t1_o1", prompt)


if __name__ == "__main__":
    unittest.main()
