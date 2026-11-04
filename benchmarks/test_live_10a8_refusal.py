"""Live run 10A-8 (Sonnet 5.5): the builder's answer leaked its reasoning as text, the repair prompt sent it back, Sonnet's safeguards
declined that call and the one refusal stopped the run. A refusal now closes its task or card and the run goes on; repair prompts
and format refusals carry only JSON lines; each run records what ran. In-process fakes only."""
from __future__ import annotations

import json
import pathlib
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_pilot_ac as R  # noqa: E402
from sbgk_bench import pilot_ac as P  # noqa: E402

REFUSED = f"{P.MODEL_REFUSED}: API Error: Sonnet 5.5's safeguards flagged this message"


class Worker(unittest.TestCase):
    def run_worker(self, kind: str, answers: list):
        stop, sent = threading.Event(), []

        class Wire:
            def __init__(self):
                self.given = False

            def call(self, tool, **kw):
                if tool == "audit_acquire":
                    if self.given:
                        stop.set()
                        return {"status": "WAIT"}
                    self.given = True
                    return {"status": "DIRECTIVE", "kind": kind, "task_id": "T1", "key": "k1", "prompt": "task", "max_lines": 8,
                            "local_id_prefix": "t1_"}
                sent.append((tool, kw))
                if tool == "audit_submit":
                    if kind == "VERIFY_LINK" and not kw["lines"]:
                        return {"status": "REPAIR_REQUIRED", "failed_index": 0, "error": {"code": "MISSING_FIELD"}}
                    return {"status": "COMMITTED", "accepted_locals": {}}
                return {"status": "RELEASED"}

            def close(self):
                pass

        calls = iter(answers)

        def call_model(model, prompt, **kw):
            text, error = next(calls)
            return P.Call(**kw, prompt_chars=len(prompt), text=text or "", ok=error is None, error=error, model="fake")

        log = P.Log()
        with mock.patch.object(P, "call_model", side_effect=call_model):
            P.c_worker(SimpleNamespace(connect=lambda a: Wire()), "w1", SimpleNamespace(), log, [1], stop)
        return log, sent

    def test_a_refused_reading_task_closes_honestly_and_the_run_goes_on(self):
        log, sent = self.run_worker("EXTEND", [(None, REFUSED)])
        self.assertIsNone(log.stopped)
        self.assertEqual([e["outcome"] for e in log.events if e.get("task")], ["MODEL_REFUSED", "COMMITTED"])
        self.assertEqual(sent, [("audit_submit", {"task_id": "T1", "lines": []})])
        self.assertTrue(log.events[-1]["abandoned"])

    def test_a_refused_repair_after_a_format_refusal_is_no_parse_failure(self):
        log, sent = self.run_worker("EXTEND", [("<think>reasoning</think>", None), (None, REFUSED)])
        self.assertIsNone(log.stopped, "not PARSE_FAILURE: the model declined, it did not fail the format")
        self.assertEqual(log.events[-1]["outcome"], "COMMITTED")

    def test_a_refused_link_check_counts_as_a_failed_lease(self):
        log, sent = self.run_worker("VERIFY_LINK", [(None, REFUSED)])
        self.assertIsNone(log.stopped)
        self.assertEqual([t for t, _ in sent], ["audit_submit", "audit_release"], "an empty answer is refused, then the lease is given back")

    def test_another_model_error_still_stops_the_run(self):
        log, _ = self.run_worker("EXTEND", [(None, "RuntimeError: Claude Code failed (1): Not logged in")])
        self.assertTrue(log.stopped.startswith("MODEL_ERROR"))


class Builder(unittest.TestCase):
    def test_a_refused_card_is_closed_empty(self):
        stop, sent = threading.Event(), []

        class Wire:
            def __init__(self):
                self.cards = 0

            def call(self, tool, **kw):
                if tool == "audit_next_card":
                    self.cards += 1
                    if self.cards > 1:
                        stop.set()
                        return {"status": "IDLE"}
                    return {"status": "CARD", "card_id": "C1", "records": [{"id": "@r"}], "max_ops": 8, "prompt": "card"}
                sent.append((tool, kw))
                return {"status": "CARD_DONE"}

            def close(self):
                pass

        log = P.Log()
        with mock.patch.object(P, "call_model", side_effect=lambda m, p, **kw: P.Call(**kw, prompt_chars=1, ok=False, error=REFUSED, model="fake")):
            P.c_builder(SimpleNamespace(connect=lambda a: Wire()), SimpleNamespace(), log, [1], stop)
        self.assertIsNone(log.stopped)
        self.assertEqual(sent, [("audit_submit_ops", {"card_id": "C1", "ops": []})])
        self.assertEqual([e["outcome"] for e in log.events], ["CARD_ASSIGNED", "MODEL_REFUSED", "CARD_SUBMITTED", "CARD_DONE"])


class EchoOnlyJson(unittest.TestCase):
    def test_leaked_reasoning_is_not_sent_back(self):
        text = '{"op":"link"}\nCorrection: the line above is void.\n<think>Need to output only valid lines.</think>\n{"op":"map_term"}'
        lines, refusal, _ = P.submission_lines(text, allow_empty=True)
        self.assertNotIn("think", json.dumps(refusal))
        prompt = P.repair_prompt("TASK", refusal, "operations", text)
        self.assertNotIn("think", prompt)
        self.assertNotIn("Correction", prompt)
        self.assertIn('{"op":"map_term"}', prompt)

    def test_the_adapter_names_a_refusal(self):
        out = json.dumps({"is_error": True, "result": "API Error: Sonnet 5.5's safeguards flagged this message (https://...)"})
        with mock.patch.object(P.subprocess, "run", return_value=SimpleNamespace(stdout=out, stderr="", returncode=1)):
            with self.assertRaisesRegex(RuntimeError, f"^{P.MODEL_REFUSED}"):
                P.ClaudeCliModel(exe="claude.exe").complete("x")


class PartlyRefused(unittest.TestCase):
    def test_the_builder_is_told_how_to_drop_a_refused_operation(self):
        # live run 10A-9: the builder explained in a sentence before [] and failed the format
        prompt = P.repair_prompt("CARD", {"status": "REPAIR_REQUIRED", "refused": [{"index": 0}]}, "operations", '{"op":"link"}')
        self.assertIn("reply exactly [] with no words", prompt)


class Provenance(unittest.TestCase):
    def test_a_run_records_its_revision_and_binary(self):
        p = R.provenance()
        if (pathlib.Path(__file__).resolve().parents[1] / ".git").exists():
            self.assertRegex(p["git_head"] or "", r"^[0-9a-f]{40}$")
        else:  # a source archive without git (git archive, a release tarball): the run records no revision, it invents none
            self.assertIsNone(p["git_head"])
        self.assertIn("changed_tracked_files", p)
        # the closed layer's sources join the runner's when the package is installed
        closed = {name for name in p["runner_sha256"] if name.startswith("sbgk_bench/closed/")}
        self.assertEqual(set(p["runner_sha256"]) - closed, {"run_pilot_ac.py", "sbgk_bench/pilot_ac.py"})
        self.assertEqual(bool(closed), P.closed_layer() is not None)


if __name__ == "__main__":
    unittest.main()
