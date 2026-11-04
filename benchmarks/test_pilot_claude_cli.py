"""The Claude Code adapter of the pilot (Sonnet 5.5 on the owner's Max plan): one tool-less session per task in an empty directory,
without the enclosing session's environment; usage and the API-equivalent cost from Claude Code's result; another model is an error,
a rate limit is retried. A faked subprocess only: nothing is sent."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P


def result(text="ok", *, model=P.CLAUDE_MODEL, error=False, cost=0.0123, turns=1):
    return json.dumps({"type": "result", "is_error": error, "result": text, "total_cost_usd": cost, "stop_reason": "end_turn", "num_turns": turns,
                       "usage": {"input_tokens": 5, "cache_creation_input_tokens": 700, "cache_read_input_tokens": 300, "output_tokens": 40},
                       "modelUsage": {model: {"thinkingTokens": 0, "costBasis": "list"}}})


class ClaudeCliAdapter(unittest.TestCase):
    def run_with(self, *outputs):
        seen = []

        def fake(cmd, **kw):
            seen.append({"cmd": cmd, **kw})
            return subprocess.CompletedProcess(cmd, 0, stdout=outputs[len(seen) - 1], stderr="")

        with mock.patch.object(P.subprocess, "run", side_effect=fake), mock.patch.object(P.time, "sleep"), \
             mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": "host", "CLAUDECODE": "1", "PATH": os.environ.get("PATH", "")}):
            out = P.ClaudeCliModel(exe="claude.exe").complete("TASK")
        return out, seen

    def test_one_tool_less_session_without_the_host_environment(self):
        (text, usage, cost), seen = self.run_with(result('{"kind":"done"}'))
        self.assertEqual((text, cost), ('{"kind":"done"}', 0.0123))
        self.assertEqual((usage["input"], usage["cache_hit"], usage["cache_write"], usage["output"]), (1005, 300, 700, 40))
        cmd, kw = seen[0]["cmd"], seen[0]
        self.assertEqual(cmd[cmd.index("--model") + 1], "claude-sonnet-5-5")
        self.assertEqual(cmd[cmd.index("--tools") + 1], "")
        self.assertEqual(cmd[cmd.index("--system-prompt") + 1], P.CLAUDE_SYSTEM)
        self.assertIn("--strict-mcp-config", cmd)
        self.assertIn("--no-session-persistence", cmd)
        self.assertEqual(kw["input"], "TASK")
        self.assertEqual([k for k in kw["env"] if k.startswith("CLAUDE")], ["CLAUDE_CODE_MAX_OUTPUT_TOKENS"],
                         "the child signs in with its own login; only the output bound the brake reserved is set")
        self.assertFalse(pathlib.Path(kw["cwd"]).exists(), "the empty working directory is removed")

    def test_another_model_is_an_error(self):
        with self.assertRaisesRegex(RuntimeError, "not claude-sonnet-5-5"):
            self.run_with(result(model="claude-haiku-5-5"))

    def test_a_rate_limit_is_retried_and_a_login_error_is_not(self):
        (text, _, _), seen = self.run_with(result("API Error: 429 rate limit reached", error=True), result("fine"))
        self.assertEqual((text, len(seen)), ("fine", 2))
        with self.assertRaisesRegex(RuntimeError, "OAuth"):
            self.run_with(result("Failed to authenticate: OAuth session expired", error=True))

    def test_an_output_overrun_fails_the_call_at_once_as_an_agent_failure(self):
        # live run MCPctl_none_r2: a summary's repair ran past the reserved output, and the run stopped on MODEL_ERROR;
        # claude-reviewer's RV-01 of 87b54b2b: a retry inside the call made the task's fate depend on how fast the model overran
        over = result("API Error: Claude's response exceeded the 32000 output token maximum. To configure this behavior, set the "
                      "CLAUDE_CODE_MAX_OUTPUT_TOKENS environment variable.", error=True)
        with self.assertRaisesRegex(P.CallFailed, f"^{P.OUTPUT_OVERRUN}: API Error") as cm:
            self.run_with(over)  # one output only: a retry would find none
        self.assertAlmostEqual(cm.exception.cost_usd, 0.0123, msg="the overrun attempt was billed and counts")
        failed = SimpleNamespace(ok=False, error=f"CallFailed: {cm.exception}")
        self.assertTrue(P.agent_failed(failed), "its task is released and given out again, as a timed-out one")
        self.assertFalse(P.model_refused(failed) or P.model_timed_out(failed))

    def test_an_answer_resumed_past_the_output_maximum_is_an_overrun_not_its_last_turn(self):
        # live run MCPsbase_r1: Claude Code resumed a summary past the reserved output and its result held the last turn only, the
        # lines from the 32nd on; a probe with a 400-token bound gave 16 of 60 lines in 3 turns
        with self.assertRaisesRegex(P.CallFailed, f"^{P.OUTPUT_OVERRUN}: the answer ran past .* resumed in 3 turns") as cm:
            self.run_with(result("L45\nL46", turns=3))  # one output only: a retry would find none
        self.assertAlmostEqual(cm.exception.cost_usd, 0.0123, msg="the resumed turns were billed and count")
        self.assertTrue(P.agent_failed(SimpleNamespace(ok=False, error=f"CallFailed: {cm.exception}")))
        (text, _, _), _ = self.run_with(result("L01\nL02", turns=1))
        self.assertEqual(text, "L01\nL02", "an answer in one turn is the answer")

    def test_the_reservation_bounds_a_call(self):
        m = P.ClaudeCliModel(exe="claude.exe")
        self.assertAlmostEqual(m.estimate("ab"), (2 * 2.00 + P.CLAUDE_RESERVED_OUTPUT * 10.00) / 1e6)


if __name__ == "__main__":
    unittest.main()
