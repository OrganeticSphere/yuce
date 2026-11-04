"""Instruction parity at actual prompt constructors; model/provider transport is intercepted or a deterministic stub."""
from __future__ import annotations

import concurrent.futures
import pathlib
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import answer_guidance as G, answer_map_reduce as M, pilot_ac as P


class FakeLog:
    calls = []
    stopped = None

    def active(self):
        return True

    def event(self, **unused):
        pass


class NoModel:
    name = "transport-must-be-intercepted"

    def complete(self, prompt):
        raise AssertionError("a model call escaped the prompt capture")


class EqualAnswerPrompts(unittest.TestCase):
    def test_all_a_templates_and_withdrawals_share_bytes_without_topic_hints(self):
        q = {"id": "RQ1", "text": "What do these sources establish?", "about": ["ABOUT_ONLY_SENTINEL"]}
        docs = {"r.md": "A source sentence."}
        withdrawal = {"report": "r.md", "quote": docs["r.md"]}
        prompts = []

        def capture(log, model, prompt, *args, **kw):
            prompts.append(prompt)
            return {"complete": True, "claims": [{"id": "a1", "text": "A finding.",
                    "quotes": [{"report": "r.md", "quote": docs["r.md"]}]}], "unsettled": None}

        def note_capture(log, model, prompt, **kw):
            prompts.append(prompt)
            return P.Call(call_id=kw["call_id"], arm=kw["arm"], role=kw["role"], phase=kw["phase"],
                          prompt_chars=len(prompt), text="A note.", model="intercepted")

        with mock.patch.object(P, "QUESTIONS", [q]), mock.patch.object(P, "read_notes", return_value=['- [r.md] "A source sentence."']), \
             mock.patch.object(P, "invoke_answer", side_effect=note_capture), mock.patch.object(P, "single_answer", side_effect=capture), \
             mock.patch.object(P, "ARM_A_ANSWER", "direct"):
            P.run_arm_a(NoModel(), docs, withdrawal, workers=1, timeout_s=30)
            P.answer_phases(FakeLog(), NoModel(), docs, withdrawal, P.single_corpus(docs), "Native schema rules.",
                            {"phase1": {"answers": {}}}, time.monotonic(), 30, None, name="probe", role="LEAD")
            _, part = M.partial(FakeLog(), NoModel(), docs, [], q, 1, "Native schema rules.", "probe", "LEAD", {}, None, "r.md")
            M.partial(FakeLog(), NoModel(), docs, [withdrawal], q, 2, P.TEAM_RULES, "probe", "UPDATE", {}, {"r.md": []}, "r.md")
            with mock.patch.object(P, "ARM_A_REDUCE", "tree"):
                M.reduce(FakeLog(), NoModel(), docs, [], q, 1, "probe", "LEAD", {}, [part] * 4, [])
            with mock.patch.object(P, "ARM_A_REDUCE", "single"):
                M.reduce(FakeLog(), NoModel(), docs, [withdrawal], q, 2, "probe", "UPDATE", {}, [part], [])
        self.assertEqual(len(prompts), 10)
        for prompt in prompts:
            self.assertNotIn("ABOUT_ONLY_SENTINEL", prompt)
            self.assertNotIn("\nABOUT:", prompt)
            self.assertEqual(prompt.count(G.TEXT), 1)
            start = prompt.index("COMMON ANSWER GUIDANCE:")
            self.assertEqual(prompt[start:start + len(G.TEXT)].encode("utf-8"), G.TEXT.encode("utf-8"))
            self.assertNotIn("the first part comes from earlier reports", prompt)
        self.assertIn('"text":"<at most 200 characters>"', P.SINGLE_RULES)
        self.assertIn('"text":"<at most 200 characters: what the reports do not settle>"', P.SINGLE_RULES)
        self.assertEqual(P.SINGLE_TEXT_CHARS, 240, "the validator bound is unchanged")

    def test_about_in_source_bytes_is_kept(self):
        source = "ABOUT: source-owned text, not a question hint."
        q = {"id": "RQ1", "text": "What does it say?", "about": ["PRIVATE_QUESTION_TOPIC"]}
        prompts = []

        def capture(log, model, prompt, *args, **kw):
            prompts.append(prompt)
            return {"complete": True, "claims": [], "unsettled": None}

        with mock.patch.object(P, "QUESTIONS", [q]), mock.patch.object(P, "ARM_A_ANSWER", "direct"), \
             mock.patch.object(P, "single_answer", side_effect=capture):
            P.answer_phases(FakeLog(), NoModel(), {"r.md": source}, {}, P.single_corpus({"r.md": source}), P.SINGLE_RULES,
                            {"phase1": {"answers": {}}}, time.monotonic(), 30, None, name="probe", role="LEAD")
        self.assertIn(source, prompts[0])
        self.assertNotIn("PRIVATE_QUESTION_TOPIC", prompts[0])

    def test_concurrent_stub_questions_are_call_local_and_reset_afterward(self):
        barrier = threading.Barrier(2)

        class Parallel(P.StubModel):
            def complete(self, prompt):
                barrier.wait(timeout=5)
                return super().complete(prompt)

        stub = Parallel()
        prompt = 'ARM A SUMMARY RQ: A question.\nNOTES:\n- [r.md] "alpha finding"\n- [r.md] "beta finding"'

        def run(topic):
            return P.Log().invoke(stub, prompt, call_id=topic, arm="A", role="SUMMARIZE", phase=1, context={"stub_about": [topic]})

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            a, b = list(pool.map(run, ["alpha", "beta"]))
        self.assertIn("alpha finding", a.text)
        self.assertNotIn("beta finding", a.text)
        self.assertIn("beta finding", b.text)
        self.assertNotIn("alpha finding", b.text)
        self.assertEqual(P._stub_about.get(), ())
        unset = P.Log().invoke(P.StubModel(), prompt, call_id="no-topics", arm="A", role="SUMMARIZE", phase=1)
        self.assertTrue(unset.ok)
        self.assertTrue(unset.text.startswith("unknown:"))

    def test_stub_context_is_reset_after_failure(self):
        class Failing(P.StubModel):
            def complete(self, prompt):
                raise RuntimeError("offline fixture failure")

        call = P.Log().invoke(Failing(), "prompt", call_id="fail", arm="A", role="SUMMARIZE", phase=1, context={"stub_about": ["alpha"]})
        self.assertFalse(call.ok)
        self.assertEqual(P._stub_about.get(), ())

    def test_real_model_interface_gets_only_prompt_without_stub_metadata(self):
        seen = []

        class ProviderFixture:
            name = "offline-provider-interface-fixture"

            def complete(self, prompt):
                seen.append(prompt)
                return "unknown", {}, 0.0

        call = P.Log().invoke(ProviderFixture(), "Unchanged prompt.", call_id="provider", arm="A", role="SUMMARIZE", phase=1,
                             context={"stub_about": ["MUST_NOT_REACH_MODEL"]})
        self.assertTrue(call.ok)
        self.assertEqual(seen, ["Unchanged prompt."])
        self.assertEqual(P._stub_about.get(), ())


if __name__ == "__main__":
    unittest.main()
