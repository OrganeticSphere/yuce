"""The address layer: the runner's flag rules and the stub builder's placement."""
import json
import pathlib
import subprocess
import sys
import unittest

from sbgk_bench import pilot_ac as P

RUNNER = pathlib.Path(__file__).with_name("run_pilot_ac.py")


class Flags(unittest.TestCase):
    def test_declared_summaries_and_pairs_per_function_need_the_layer(self):
        for extra, flag in (
            (["--evolution-cards", "--evolution-pairing", "lexical", "--change-summary-documents", "x.json"], "--change-summary-documents"),
            (["--evolution-pairs-per-function", "2"], "--evolution-pairs-per-function"),
        ):
            r = subprocess.run([sys.executable, "-X", "utf8", str(RUNNER), "--model", "stub", *extra], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0, extra)
            self.assertIn(f"{flag} requires --concept-functions", r.stdout + r.stderr, extra)


class Stub(unittest.TestCase):
    @staticmethod
    def ops(card: dict) -> list[dict]:
        return [json.loads(line) for line in P.StubModel._builder("TASK BUILD\nCARD:\n" + json.dumps(card)).splitlines() if line.strip()]

    def test_the_stub_names_a_function_only_when_the_card_shows_known_functions(self):
        card = {"records": [{"id": "@o1", "kind": "observe", "terms": ["valve"]}], "candidates": {}, "max_ops": 8}
        proposals = [o for o in self.ops(card) if o["op"] == "propose_concept"]
        self.assertTrue(proposals and all("function" not in o for o in proposals), proposals)
        card["known_functions"] = []
        self.assertEqual([o["function"] for o in self.ops(card) if o["op"] == "propose_concept"], ["valve"])
        card["known_functions"] = [{"function": "cooling", "concepts": 2, "examples": ["pump"]}]
        self.assertEqual([o["function"] for o in self.ops(card) if o["op"] == "propose_concept"], ["cooling"])


if __name__ == "__main__":
    unittest.main()
