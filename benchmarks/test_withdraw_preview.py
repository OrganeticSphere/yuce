"""`run_pilot_ac.py --withdraw-preview`: before each planned withdrawal the owner asks audit_withdraw_preview, which writes nothing;
the run keeps the answer, and what the withdrawal then makes fall is what the preview said."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_pilot_ac as R  # noqa: E402
from sbgk_bench import pilot_ac as P  # noqa: E402
from test_questions_option import THREE, corpus  # noqa: E402


class WithdrawPreview(unittest.TestCase):
    def setUp(self):
        # the settings of the corpus runs (as test_questions_option)
        self.saved = {k: v for k, v in vars(P).items() if k.isupper()}
        P.ARM_A_MODE, P.PAIRS_ONLY, P.LINK_CHECKER = "team", False, True
        P.DYNAMIC_ROLES, P.BUILD_BACKLOG, P.CHECKER_MODEL = True, 1, P.StubModel()
        P.CIRCLES, P.WAVE_SECTIONS = True, 3

    def tearDown(self):
        vars(P).update(self.saved)

    def test_the_preview_of_each_withdrawal_is_kept_and_names_what_then_fell(self):
        P.BUILD_SCOPE, P.ARM_A_FROZEN, P.QUESTIONS, P.WITHDRAW_PREVIEW = "none", True, THREE, True
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest, docs = corpus(root)
            paths = sorted(docs)
            plan = {"steps": [{"name": "2A", "report": paths[0], "candidates": [{"anchor": "rule 0", "quote": "The old check of rule 0 was removed."}]}]}
            s = R.run(manifest, root / "repo", paths, root / "out", P.StubModel(), 3, plan, phase_timeout_s=120, max_calls=400,
                      team=[P.StubModel(), P.StubModel(), P.StubModel()])
            full = json.loads((root / "out" / "arm_c.json").read_text(encoding="utf-8"))
        previews = full.get("withdraw_preview") or []
        self.assertEqual([(p["step"], p["status"], p["written"]) for p in previews], [("2A", "PREVIEW", False)], previews)
        self.assertGreater(previews[0]["fell"], 0, "the stub's readers quoted the withdrawn sentence, so the preview names records")
        self.assertTrue(all(r.get("status") == "REVOKED" for r in s["arm_c"]["revoke"]), "the withdrawal itself is written after it")

if __name__ == "__main__":
    unittest.main()
