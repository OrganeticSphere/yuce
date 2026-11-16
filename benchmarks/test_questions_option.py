"""A corpus's own research questions (`run_pilot_ac.py --questions`): the file is checked before any work, and a run on the stub
team answers each of its questions, gives them to the kernel and records them in its snapshot. Needs the kernel binary; no
provider is called.

Run: python -m unittest discover -s benchmarks -p "test_*.py"
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_pilot_ac as R  # noqa: E402
from sbgk_bench import pilot_ac as P  # noqa: E402
from test_build_scope import corpus  # noqa: E402

THREE = [{"id": "Q1", "text": "What limits the old check of each rule?", "about": ["rule", "check"]},
         {"id": "Q2", "text": "Which limitations remain open?", "about": ["limitation"], "stances": ["open"]},
         {"id": "Q3", "text": "What was removed?", "about": ["removed"]}]


class QuestionsOption(unittest.TestCase):
    def setUp(self):
        self.saved = {k: v for k, v in vars(P).items() if k.isupper()}
        P.ARM_A_MODE, P.PAIRS_ONLY, P.LINK_CHECKER = "team", False, True
        P.DYNAMIC_ROLES, P.BUILD_BACKLOG, P.CHECKER_MODEL = True, 1, P.StubModel()
        P.CIRCLES, P.WAVE_SECTIONS = True, 3

    def tearDown(self):
        vars(P).update(self.saved)

    def check(self, questions) -> list[dict]:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "questions.json"
            path.write_text(json.dumps(questions) if not isinstance(questions, str) else questions, encoding="utf-8")
            return R.questions_from(path)

    def test_a_file_of_questions_is_checked_before_any_work(self):
        self.assertEqual(self.check(THREE), THREE)
        bad = {"not a list": {"id": "Q1"}, "no question": [], "nine": [dict(THREE[0], id=f"Q{i}") for i in range(9)],
               "no topics": [{"id": "Q1", "text": "t"}], "empty topics": [dict(THREE[0], about=[])],
               "a blank topic": [dict(THREE[0], about=["rule", " "])], "an unknown field": [dict(THREE[0], hint="x")],
               "a repeated id": [THREE[0], dict(THREE[1], id="Q1")], "an id with a space": [dict(THREE[0], id="Q 1")],
               "no text": [dict(THREE[0], text=" ")], "stances not a list": [dict(THREE[1], stances="open")], "not JSON": "[{"}
        for why, questions in bad.items():
            with self.assertRaises(ValueError, msg=why):
                self.check(questions)

    def test_a_run_answers_each_question_of_the_file_and_records_them(self):
        P.BUILD_SCOPE, P.ARM_A_FROZEN = "none", True
        P.QUESTIONS = THREE
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest, docs = corpus(root)
            paths = sorted(docs)
            plan = {"steps": [{"name": "2A", "report": paths[0], "candidates": [{"anchor": "rule 0", "quote": "The old check of rule 0 was removed."}]}]}
            s = R.run(manifest, root / "repo", paths, root / "out", P.StubModel(), 3, plan, phase_timeout_s=120, max_calls=400,
                      team=[P.StubModel(), P.StubModel(), P.StubModel()])
            given = json.loads((root / "out" / "arm_c" / "questions.json").read_text(encoding="utf-8"))
            snapshot = json.loads((root / "out" / "inputs" / "snapshot.json").read_text(encoding="utf-8"))
        for phase in ("phase1", "phase2"):
            self.assertEqual(s["arm_c"][phase]["receipt"]["status"], "TERMINAL", phase)
            self.assertEqual(sorted(s["arm_c"][phase]["answers"]), ["Q1", "Q2", "Q3"], phase)
            self.assertEqual(sorted(s["arm_c"][phase]["receipt"]["answered"] + s["arm_c"][phase]["receipt"]["not_answered"]),
                             ["Q1", "Q2", "Q3"], phase)
        self.assertEqual([q["id"] for q in given], ["Q1", "Q2", "Q3"], "the kernel was given the file's questions")
        self.assertEqual(given[1]["about"], ["limitation"])
        self.assertEqual(snapshot["questions"], THREE, "the run's snapshot records them")


if __name__ == "__main__":
    unittest.main()
