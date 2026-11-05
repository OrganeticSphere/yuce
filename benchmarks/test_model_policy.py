"""The model of each call: the model as configured, an answer call under the answer deadline. No external model is invoked."""
from __future__ import annotations

import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402
from sbgk_bench.model_policy import ANSWER_ROLES, PlainPolicy, RunHook  # noqa: E402


def plain():
    """A plain run (another test's run_pilot_ac.main may have set a hook)."""
    return mock.patch.object(P, "RUN_HOOK", RunHook())


class Plain(unittest.TestCase):
    def test_a_call_runs_on_the_model_itself(self):
        model = P.AgyModel("flash-high", timeout_s=240)
        chosen, meta = PlainPolicy().select(model, "C", "BUILD", 1, {"card_id": "c"}, 900)
        self.assertIs(chosen, model)
        self.assertEqual(meta, {"model_family": "agy:flash"})

    def test_an_answer_call_gets_the_answer_deadline(self):
        for role in ANSWER_ROLES:
            with self.subTest(role=role):
                model = P.AgyModel("flash-high", timeout_s=240)
                chosen, _ = PlainPolicy().select(model, "A", role, 1, {"rq_id": "RQ1"}, 900)
                self.assertEqual((chosen.name, chosen.timeout_s, model.timeout_s), ("flash-high", 900, 240))
        sonnet = P.make_model("sonnet")
        chosen, _ = PlainPolicy().select(sonnet, "C", "SUMMARIZE", 1, {"key": "rq:RQ1"}, 900)
        self.assertEqual((chosen.name, chosen.effort, chosen.timeout_s), (P.CLAUDE_MODEL, sonnet.effort, 900))

    def test_a_model_without_for_role_is_used_as_it_is(self):
        model = P.StubModel()
        chosen, meta = PlainPolicy().select(model, "A", "LEAD", 1, {}, 900)
        self.assertIs(chosen, model)
        self.assertEqual(meta["model_family"], model.name)

    def test_the_next_call_of_a_card_goes_to_the_same_model(self):
        self.assertEqual(tuple(PlainPolicy().after_call("C", "BUILD", 1, {"card_id": "c"}, reply={"status": "REPAIR_REQUIRED"})), ())
        with plain():
            log = P.Log()
            log.after_call("C", "BUILD", 1, {"card_id": "c"}, reply={"status": "REPAIR_REQUIRED"})
            self.assertEqual(log.preview_model(P.AgyModel("flash-high"), "C", "BUILD", 1, {"card_id": "c"}).name, "flash-high")
        self.assertEqual(log.events, [])

    def test_a_policy_adds_fields_to_a_calls_record_and_events_to_the_log(self):
        class Noting(PlainPolicy):
            def select(self, model, arm, role, phase, context, answer_timeout_s):
                return model, {"model_family": "family", "noted": 1}

            def after_call(self, arm, role, phase, context, call=None, reply=None):
                return [{"outcome": "NOTED"}]

        class Hook(RunHook):
            def policy(self):
                return Noting()

        def fake(model, prompt, **kw):
            return P.Call(**kw, prompt_chars=len(prompt), model=model.name, text="ok")

        with mock.patch.object(P, "RUN_HOOK", Hook()), mock.patch.object(P, "call_model", side_effect=fake):
            log = P.Log()
            log.invoke(P.AgyModel("flash-high"), "p", call_id="one", arm="C", role="BUILD", phase=1)
            record = log.result()["calls"][0]
        self.assertEqual((record["model_family"], record["noted"]), ("family", 1))
        self.assertNotIn("extra", record)
        self.assertEqual(log.events[-1]["outcome"], "NOTED")


class AnswerRetry(unittest.TestCase):
    def test_timeout_retry_keeps_both_calls_and_uses_the_same_prompt(self):
        calls = []

        def fake(model, prompt, **kw):
            calls.append((model.name, prompt, kw["call_id"]))
            second = len(calls) > 1
            return P.Call(**kw, prompt_chars=len(prompt), model=model.name, ok=second, text="complete" if second else "partial",
                          error=None if second else "AGY_TIMEOUT: fixture")

        with plain(), mock.patch.object(P, "call_model", side_effect=fake):
            log = P.Log()
            result = P.invoke_answer(log, P.AgyModel("flash-high"), "original bytes", call_id="a", arm="A", role="LEAD", phase=1,
                                     context={"rq_id": "RQ1"})
        self.assertTrue(result.ok)
        self.assertEqual(calls, [("flash-high", "original bytes", "a"), ("flash-high", "original bytes", "a-timeout-retry-1")])
        self.assertEqual(len(log.calls), 2)
        self.assertEqual(log.calls[0].text, "partial")

    def test_retry_stops_at_call_cap_and_does_not_retry_other_errors(self):
        for error, limit in (("AGY_TIMEOUT: fixture", 1), ("AGY_TIMEOUT: fixture", 5), ("MODEL_FAILED: fixture", 5)):
            def fake(model, prompt, **kw):
                return P.Call(**kw, prompt_chars=len(prompt), model=model.name, ok=False, error=error)

            with mock.patch.object(P, "call_model", side_effect=fake):
                log = P.Log(max_calls=limit)
                P.invoke_answer(log, P.AgyModel("flash-medium"), "p", call_id="a", arm="A", role="UPDATE", phase=2)
            self.assertEqual(len(log.calls), 1 if limit == 1 or error.startswith("MODEL_FAILED") else 2)
            if limit == 1:
                self.assertIn("CALL_CAP", log.stopped)


if __name__ == "__main__":
    unittest.main()
