"""A review card whose every answer the kernel refuses is a failed attempt of the agent (Tobi rerun, 17.11.2026: at temperature 0 the
run Cn_r1 got one ontology review card 53 times and its circle never ended). With --agent-attempts the runner releases the leased
card as failed after its repairs, so the kernel's limit can give it up; without the option nothing changes. No model is called."""
import json
import pathlib
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from sbgk_bench import pilot_ac as P  # noqa: E402

CARD = {"card_id": "R1-1-review", "kind": "ONTOLOGY_REVIEW_CARD", "records": [], "neighbors": [], "candidates": {},
        "prompt": "An explicit review is required.", "ontology_revision": {"hints": [{"kind": "possible_catchall", "concept": "@c"}]}}
REFUSED = {"status": "REPAIR_REQUIRED", "accepted": 0, "error": {"code": "BAD_FIELD", "message": "name already reserved"}, "refused": [],
           "results": []}


def run(card: dict, attempts: int | None, *, circles: bool = True, empty_reply: dict | None = None,
        release_reply: dict | None = None) -> tuple[object, list[tuple[str, dict]]]:
    """build_card on one card whose every model answer the kernel refuses; `empty_reply` answers the runner's [] (refused too by
    default), `release_reply` answers audit_release. Returns build_card's result and the kernel tools called."""
    tools = []

    def fake(model, prompt, **kw):
        return P.Call(**kw, prompt_chars=len(prompt), model=model.name, ok=True,
                      text=json.dumps({"op": "revise_concept", "concept": "@c", "action": "narrow", "basis": ["@o"]}))

    def rpc_call(tool, **kw):
        tools.append((tool, kw))
        if tool == "audit_renew":
            return {"status": "RENEWED"}
        if tool == "audit_release":
            return release_reply or {"status": "RELEASED"}
        if tool == "audit_submit" and kw.get("lines") == [] and empty_reply is not None:
            return empty_reply
        return REFUSED

    context = {"circle": 1, "circle_phase": "BUILD"} if circles else {}
    with mock.patch.object(P, "RUN_HOOK", P.RunHook()), mock.patch.object(P, "CIRCLES", circles), mock.patch.object(P, "WHOLE_READER", False), \
            mock.patch.object(P, "PAIRS_ONLY", False), mock.patch.object(P, "AGENT_ATTEMPTS", attempts), \
            mock.patch.object(P, "call_model", side_effect=fake):
        done = P.build_card(SimpleNamespace(call=rpc_call), card, P.AgyModel("flash-low"), P.Log(), 1, threading.Event(), agent="w2",
                            task_id="TB7", circle_context=context)
    return done, tools


def releases(tools):
    return [kw for tool, kw in tools if tool == "audit_release"]


class ReviewCardGiveUp(unittest.TestCase):
    def test_a_refused_review_card_is_released_as_a_failed_attempt(self):
        done, tools = run(CARD, 4)
        self.assertEqual(releases(tools), [{"task_id": "TB7", "timed_out": True}])
        self.assertIsNone(done)  # like a timeout: the worker does not release the task a second time

    def test_a_refused_revision_card_is_released_as_a_failed_attempt(self):
        done, tools = run(dict(CARD, kind="REVISION_CARD"), 4)
        self.assertEqual(releases(tools), [{"task_id": "TB7", "timed_out": True}])
        self.assertIsNone(done)

    def test_without_circles_the_card_is_released_as_failed_too(self):
        done, tools = run(CARD, 4, circles=False)
        self.assertEqual(releases(tools), [{"task_id": "TB7", "timed_out": True}])
        self.assertIsNone(done)

    def test_a_stale_lease_counts_once_and_is_not_released_again(self):
        done, tools = run(CARD, 4, release_reply={"status": "STALE_TASK", "task_id": "TB7"})
        self.assertEqual(len(releases(tools)), 1)
        self.assertIsNone(done)

    def test_a_release_the_kernel_did_not_record_stops_the_run(self):
        with self.assertRaises(RuntimeError):
            run(CARD, 4, release_reply={"status": "error", "code": "RING_CHECKPOINT_REFUSED"})

    def test_an_empty_answer_on_a_stale_task_is_no_failed_attempt(self):
        done, tools = run(CARD, 4, empty_reply={"status": "STALE_TASK", "task_id": "TB7"})
        self.assertFalse(releases(tools))
        self.assertIs(done, False)

    def test_without_agent_attempts_nothing_changes(self):
        done, tools = run(CARD, None)
        self.assertFalse(releases(tools))
        self.assertIs(done, False)

    def test_an_ordinary_record_card_is_not_released_as_failed(self):
        done, tools = run(dict(CARD, kind="RECORD_CARD", records=[{"id": "@r", "author": "w1", "kind": "claim"}]), 4)
        self.assertFalse(releases(tools))
        self.assertIs(done, False)


if __name__ == "__main__":
    unittest.main()
