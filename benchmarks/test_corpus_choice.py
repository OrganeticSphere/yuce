"""A corpus other than the pilot's six reports brings its own withdrawal plan and checklist (registry R18, the chain corpus)."""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402
import run_pilot_ac as R  # noqa: E402


class CorpusChoice(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.dir.name)
        self.reports = self.root / "reports.txt"
        self.reports.write_text("# chain\ndocs/reports/a.md\n\ndocs/reports/b.md\n", encoding="utf-8")
        self.plan = self.root / "plan.json"
        self.plan.write_text(json.dumps({"steps": [{"name": "2A", "report": "docs/reports/a.md", "candidates": []}]}), encoding="utf-8")
        self.checklist = self.root / "checklist.md"
        self.checklist.write_text("# chain checklist\n", encoding="utf-8")

    def tearDown(self):
        self.dir.cleanup()

    def test_without_the_closed_layer_a_run_without_reports_names_what_to_give(self):
        # the first pilot's six reports are private (sbgk_bench.closed): their absence is one message, never a missing corpus
        def absent(feature=None):
            if feature is not None:
                raise P.ClosedLayerMissing(P.closed_missing(feature))
        with mock.patch.object(P, "closed_layer", side_effect=absent):
            for withdraw in (None, {"quote": "q", "report": "docs/reports/a.md"}):
                with self.assertRaisesRegex(ValueError, r"needs the closed layer .* give the corpus by --reports with its "
                                                        r"--checklist and --withdrawal-plan"):
                    R.corpus_choice(None, None, None, withdraw)
            self.assertEqual(R.corpus_choice(self.reports, self.plan, self.checklist, None)[0], ["docs/reports/a.md", "docs/reports/b.md"])

    def test_a_corpus_file_brings_its_plan_and_checklist(self):
        reports, plan, checklist = R.corpus_choice(self.reports, self.plan, self.checklist, None)
        self.assertEqual(reports, ["docs/reports/a.md", "docs/reports/b.md"])
        self.assertEqual(plan["steps"][0]["name"], "2A")
        self.assertEqual(checklist, "# chain checklist\n")

    def test_a_corpus_file_without_its_own_checklist_or_plan_is_refused(self):
        for plan, checklist in ((self.plan, None), (None, self.checklist), (None, None)):
            with self.assertRaises(ValueError):
                R.corpus_choice(self.reports, plan, checklist, None)

    def test_a_plan_or_checklist_without_a_corpus_file_is_refused(self):
        with self.assertRaises(ValueError):
            R.corpus_choice(None, self.plan, None, None)
        with self.assertRaises(ValueError):
            R.corpus_choice(None, None, self.checklist, None)

    def test_two_withdrawals_or_a_repeated_report_are_refused(self):
        with self.assertRaises(ValueError):
            R.corpus_choice(self.reports, self.plan, self.checklist, {"quote": "q"})
        self.reports.write_text("docs/reports/a.md\ndocs/reports/a.md\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            R.corpus_choice(self.reports, self.plan, self.checklist, None)


if __name__ == "__main__":
    unittest.main()
