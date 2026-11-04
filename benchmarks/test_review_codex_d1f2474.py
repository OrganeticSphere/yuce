"""Codex's review of d1f2474 (2026-10-23, cut short by his usage limit; his probes in results/work/codex_review_d1f2474_20261023):
the Claude adapter keeps the child on the subscription login and bounds its output as reserved, counts a retried attempt's cost,
reads the API's refusal stop and its max_tokens cut; a builder submission lost after the stop gets a card outcome. Fakes only."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402


def reply(text="[]", *, stop="end_turn", cost=0.02, error=False):
    return json.dumps({"type": "result", "is_error": error, "result": text, "total_cost_usd": cost, "stop_reason": stop,
                       "usage": {"input_tokens": 1, "output_tokens": 5}, "modelUsage": {P.CLAUDE_MODEL: {"costBasis": "list"}}})


def run_adapter(*outputs, env=None):
    seen = []

    def fake(cmd, **kw):
        seen.append(kw)
        return subprocess.CompletedProcess(cmd, 0, stdout=outputs[len(seen) - 1], stderr="")

    with mock.patch.object(P.subprocess, "run", side_effect=fake), mock.patch.object(P.time, "sleep"), \
         mock.patch.dict(os.environ, env or {}, clear=False):
        out = P.ClaudeCliModel(exe="claude.exe").complete("TASK")
    return out, seen


class Adapter(unittest.TestCase):
    def test_the_child_uses_the_subscription_login_and_the_reserved_output_bound(self):
        _, seen = run_adapter(reply(), env={"ANTHROPIC_API_KEY": "fixture", "ANTHROPIC_AUTH_TOKEN": "fixture", "ANTHROPIC_BASE_URL": "https://x"})
        env = seen[0]["env"]
        self.assertFalse({"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"} & set(env), "an API key would bill the API")
        self.assertEqual(env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"], str(P.CLAUDE_RESERVED_OUTPUT))

    def test_a_retried_attempts_cost_counts(self):
        (_, _, cost), seen = run_adapter(reply("API Error: 529 overloaded", error=True, cost=0.10), reply("[]", cost=0.02))
        self.assertEqual(len(seen), 2)
        self.assertAlmostEqual(cost, 0.12)

    def test_the_refusal_stop_is_a_model_refusal(self):
        with self.assertRaisesRegex(RuntimeError, f"^{P.MODEL_REFUSED}"):
            run_adapter(reply("I can't help with that.", stop="refusal"))

    def test_a_max_tokens_stop_is_a_cut_answer(self):
        self.assertTrue(P.was_cut(SimpleNamespace(usage={"finish_reason": "max_tokens"})))
        self.assertTrue(P.was_cut(SimpleNamespace(usage={"finish_reason": "length"})))
        self.assertFalse(P.was_cut(SimpleNamespace(usage={"finish_reason": "end_turn"})))


class BuilderAckUnknown(unittest.TestCase):
    def test_a_lost_builder_submission_gets_a_card_outcome(self):
        stop = threading.Event()

        class Wire:
            def call(self, tool, **kw):
                if tool == "audit_next_card":
                    return {"status": "CARD", "card_id": "C1", "records": [{"id": "@r"}], "max_ops": 8, "prompt": "card"}
                raise TimeoutError("fixture: operation receipt lost after stop")

            def close(self):
                pass

        def call_model(model, prompt, **kw):
            stop.set()
            return P.Call(**kw, prompt_chars=1, text='{"op":"map_term","record":"@r","term":"t","concept":"c"}', model="fake")

        log = P.Log()
        with mock.patch.object(P, "call_model", side_effect=call_model):
            P.guarded_worker(lambda: P.c_builder(SimpleNamespace(connect=lambda a: Wire()), SimpleNamespace(), log, [1], stop), log, stop,
                             arm="C", agent="gb")
        outcomes = [(e.get("card"), e["outcome"]) for e in log.events]
        self.assertIn(("C1", "ACK_UNKNOWN"), outcomes)
        self.assertIsNone(log.stopped)


if __name__ == "__main__":
    unittest.main()
