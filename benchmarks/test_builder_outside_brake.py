"""The owner, 2026-10-23: a DeepSeek swarm with a Sonnet builder. The money brake bounds the paid swarm's calls only: a model it does
not bill reserves and settles nothing, a billed one as before. In-process fakes only."""
from __future__ import annotations

import pathlib
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402


class Fake:
    def __init__(self, name, billed, cost):
        self.name, self.billed, self.cost = name, billed, cost

    def estimate(self, prompt):
        return 0.5

    def complete(self, prompt):
        return "[]", {}, self.cost


class BrakeScope(unittest.TestCase):
    def test_an_unbilled_builder_leaves_the_brake_alone(self):
        log = P.Log()
        log.budget = P.Budget(1.0)
        log.invoke(Fake("sonnet-builder", False, 0.9), "card", call_id="B1-C1-0", arm="C", role="BUILDER", phase=1)
        self.assertEqual(log.budget.state()["spent_usd_estimate"], 0.0)
        log.invoke(Fake("deepseek", True, 0.2), "task", call_id="C1-T1-0", arm="C", role="EXTEND", phase=1)
        self.assertEqual(log.budget.state()["spent_usd_estimate"], 0.2)
        self.assertEqual(log.budget.state()["reserved_usd"], 0.0)

    def test_the_claude_adapter_says_whether_the_brake_counts_it(self):
        self.assertTrue(P.ClaudeCliModel(exe="x").billed)
        m = P.ClaudeCliModel(exe="x", billed=False)
        self.assertFalse(m.billed)
        self.assertFalse(m.config["counted_by_brake"])


if __name__ == "__main__":
    unittest.main()
