"""Claude Haiku 5.5 as the swarm in place of DeepSeek: the brake reserves a call at the model's own prices."""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402


class HaikuRates(unittest.TestCase):
    def test_the_brake_reserves_a_haiku_call_at_haiku_prices(self):
        prompt = "x" * 10_000
        haiku, sonnet = P.ClaudeCliModel(model=P.CLAUDE_HAIKU), P.ClaudeCliModel()
        self.assertAlmostEqual(haiku.estimate(prompt), (10_000 * 0.10 + P.CLAUDE_RESERVED_OUTPUT * 0.50) / 1e6)
        self.assertAlmostEqual(sonnet.estimate(prompt), (10_000 * 2.00 + P.CLAUDE_RESERVED_OUTPUT * 10.00) / 1e6)
        self.assertIn(P.CLAUDE_HAIKU, haiku.config["rates"])

    def test_a_model_without_list_prices_is_refused(self):
        with self.assertRaises(ValueError):
            P.ClaudeCliModel(model="claude-unknown")


if __name__ == "__main__":
    unittest.main()
