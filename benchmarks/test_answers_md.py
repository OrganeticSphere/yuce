"""The blind answers (`answers_md`): a notice of the kernel is written once per answer, however many of its claims carry it."""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from sbgk_bench import pilot_ac as P  # noqa: E402

NOTICE = ("@43c0295c55860496 stale_suspect: its evidence dated up to 2017-04-12 stands; its later evidence dated 2019-06-06 was "
          "withdrawn. Do not present the earlier state as current. superseded_by=[]")


def claim(text: str, warned: bool) -> dict:
    out = {"id": "@x", "kind": "claim", "stance": "reported", "as_of": 20170412,
           "quotes": [{"report": "b.md", "quote": "a threshold of 11 mPa"}], "text": text}
    if warned:
        out.update(authored_text=text, temporal_warnings=[NOTICE], text=f"{NOTICE} Historical statement: {text}")
    return out


class AnswersMarkdown(unittest.TestCase):
    def setUp(self):
        self.saved = P.QUESTIONS
        P.QUESTIONS = [{"id": "Q1", "text": "What limits colonisation?"}]

    def tearDown(self):
        P.QUESTIONS = self.saved

    def test_a_notice_is_written_once_per_answer_and_each_claim_keeps_its_own_words(self):
        c = {"phase1": {"answers": {"Q1": {"outcome": "answered", "claims": [claim("B starts no biofilm above 11 mPa.", True),
                                                                               claim("B used five channels.", True),
                                                                               claim("C used four regimes.", False)]}}}}
        md, _ = P.answers_md({"mode": "frozen"}, c)
        self.assertEqual(md.count(" stale_suspect:"), 1)
        self.assertIn("- (kernel notices @43c0295c55860496) Historical statement: B starts no biofilm above 11 mPa.", md)
        self.assertIn("- (kernel notices @43c0295c55860496) Historical statement: B used five channels.", md)
        self.assertIn("- C used four regimes.", md)


if __name__ == "__main__":
    unittest.main()
