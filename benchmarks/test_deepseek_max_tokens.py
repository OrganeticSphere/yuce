"""--deepseek-max-tokens: the output budget of one DeepSeek call is an option of the run (default 8192, as every run before it), read
when each DeepSeek agent is made, and recorded in the model's config. Offline: no provider is called."""
from __future__ import annotations

import contextlib
import io
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402
import run_pilot_ac as R  # noqa: E402


class DeepSeekMaxTokens(unittest.TestCase):
    def test_the_default_stays_8192_and_the_option_reaches_every_new_agent(self):
        self.assertEqual(P.DEEPSEEK_MAX_TOKENS, 8192)
        m = P.DeepSeekModel(key="offline")
        self.assertEqual((m.max_tokens, m.config["max_tokens"]), (8192, 8192))
        with mock.patch.object(P, "DEEPSEEK_MAX_TOKENS", 32000):
            m = P.DeepSeekModel(key="offline")
            self.assertEqual((m.max_tokens, m.config["max_tokens"]), (32000, 32000))
            self.assertEqual(P.DeepSeekModel(max_tokens=16, key="offline").max_tokens, 16)  # the control call keeps its own budget

    def main(self, *args: str) -> tuple[int | str | None, int]:
        argv = ["pilot", "--manifest", "m", "--repo", "r", *args]
        seen = {}

        def stop_at_run(*_a, **_k):
            seen["max_tokens"] = P.DEEPSEEK_MAX_TOKENS
            raise SystemExit("stopped before the run")

        with mock.patch.dict(P.__dict__), mock.patch.object(sys, "argv", argv), mock.patch.object(R.C, "BIN", pathlib.Path(__file__)), \
                mock.patch.object(R, "corpus_choice", side_effect=stop_at_run), \
                contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as stop:
                R.main()
        return stop.exception.code, seen.get("max_tokens")

    def test_the_option_sets_the_budget_before_any_work_and_refuses_a_value_out_of_range(self):
        self.assertEqual(self.main(), ("stopped before the run", 8192))
        self.assertEqual(self.main("--deepseek-max-tokens", "32000"), ("stopped before the run", 32000))
        for bad in ("0", "-1", "393217"):
            with self.subTest(value=bad):
                self.assertEqual(self.main("--deepseek-max-tokens", bad), ("--deepseek-max-tokens must be 1..393216", None))


if __name__ == "__main__":
    unittest.main()
