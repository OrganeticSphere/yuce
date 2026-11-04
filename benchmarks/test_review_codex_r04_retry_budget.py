"""Codex's review of 06a578c, R04: the Claude adapter's retries and the money brake. An attempt without a reported cost vanished behind
a known later one ([unknown, 0.02] settled 0.02), and one call's reservation did not bound several billed attempts (two of 0.30
settled 0.60 under a cap of 0.35). Now every retry reserves its own estimate first, and any unknown attempt makes the call's cost
unknown, which the brake settles at the whole reservation. In-process fakes only: no Claude Code, no money."""
from __future__ import annotations

import json
import pathlib
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402

OK_USAGE = {"modelUsage": {P.CLAUDE_MODEL: {"costBasis": "list"}}, "usage": {"input_tokens": 1, "output_tokens": 1}, "stop_reason": "end_turn"}


def attempt(cost, ok):
    """One `claude -p` process: a JSON result with or without total_cost_usd, or no JSON at all (cost None and not ok)."""
    if cost is None and not ok:
        return SimpleNamespace(stdout="", stderr="API overloaded (529)", returncode=1)
    d = {"is_error": not ok, "result": "OK" if ok else "API overloaded (529)", **(OK_USAGE if ok else {})}
    if cost is not None:
        d["total_cost_usd"] = cost
    return SimpleNamespace(stdout=json.dumps(d), stderr="", returncode=0 if ok else 1)


class RetryBudget(unittest.TestCase):
    def run_call(self, attempts, cap):
        runs = iter(attempts)
        log = P.Log()
        log.budget = P.Budget(cap)
        model = P.ClaudeCliModel(exe="claude")
        with mock.patch.object(P.subprocess, "run", side_effect=lambda *a, **k: next(runs)), mock.patch.object(P.time, "sleep"):
            c = log.invoke(model, "x", call_id="C1-T1-0", arm="C", role="EXTEND", phase=1)
        return c, log, model.estimate("x")

    def test_an_unknown_attempt_makes_the_call_unknown_and_keeps_both_reservations(self):
        c, log, est = self.run_call([attempt(None, False), attempt(0.02, True)], cap=1.0)
        self.assertTrue(c.ok)
        self.assertIsNone(c.cost_usd, "the unknown first attempt does not vanish behind the known second")
        state = log.budget.state()
        self.assertEqual(state["unknown_cost_calls"], 1)
        self.assertAlmostEqual(state["spent_usd_estimate"], 2 * est, places=6)
        self.assertEqual(state["reserved_usd"], 0.0)
        self.assertEqual((c.usage["attempts"], c.usage["known_cost_usd"], c.usage["unknown_cost_attempts"]), (2, 0.02, 1))

    def test_a_retry_the_brake_cannot_reserve_is_not_sent(self):
        c, log, est = self.run_call([attempt(0.30, False), attempt(0.30, True)], cap=0.35)
        self.assertFalse(c.ok)
        self.assertIn("no reserve for attempt 2", c.error)
        self.assertEqual(c.cost_usd, 0.30, "the failed attempt's known cost is settled")
        self.assertLessEqual(log.budget.state()["spent_usd_estimate"], 0.35)
        self.assertTrue(log.stopped.startswith("BUDGET_CAP"))

    def test_known_attempts_settle_their_sum(self):
        c, log, est = self.run_call([attempt(0.10, False), attempt(0.02, True)], cap=1.0)
        self.assertTrue(c.ok)
        self.assertAlmostEqual(c.cost_usd, 0.12, places=6)
        state = log.budget.state()
        self.assertAlmostEqual(state["spent_usd_estimate"], 0.12, places=6)
        self.assertEqual((state["reserved_usd"], state["unknown_cost_calls"]), (0.0, 0))

    def test_an_unbilled_builder_retries_without_the_brake(self):
        runs = iter([attempt(0.30, False), attempt(0.30, True)])
        log = P.Log()
        log.budget = P.Budget(0.35)
        model = P.ClaudeCliModel(exe="claude", billed=False)
        with mock.patch.object(P.subprocess, "run", side_effect=lambda *a, **k: next(runs)), mock.patch.object(P.time, "sleep"):
            c = log.invoke(model, "x", call_id="B1-C1-0", arm="C", role="BUILDER", phase=1)
        self.assertTrue(c.ok)
        self.assertEqual(log.budget.state()["spent_usd_estimate"], 0.0)
        self.assertIsNone(log.stopped)


if __name__ == "__main__":
    unittest.main()
