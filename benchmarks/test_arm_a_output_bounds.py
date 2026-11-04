"""Offline regressions from MCPT_7b54977_r1: a failed repair is not a fresh full-answer task."""
from __future__ import annotations

import json
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import answer_guidance as G, answer_map_reduce as M, pilot_ac as P


DOCS = {"r.md": "The port is 9090. Client experimental features. Server experimental features."}
DONE = {"kind": "done", "text": "Coverage is limited to the supplied notes."}


def claim(local="a1", quote="The port is 9090.", text="The port is 9090."):
    return {"kind": "claim", "local_id": local, "text": text, "quotes": [{"report": "r.md", "exact_quote": quote}]}


def lines(*rows):
    return "\n".join(json.dumps(r) for r in rows)


class Sequence:
    name = "offline-answer-sequence"

    def __init__(self, *results):
        self.results, self.prompts = list(results), []

    def complete(self, prompt):
        self.prompts.append(prompt)
        if not self.results:
            raise AssertionError("unexpected extra call")
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result, {"finish_reason": "stop"}, 0.0


class AnswerBounds(unittest.TestCase):
    def answer(self, model, **kw):
        log = P.Log(max_calls=100)
        with mock.patch.object(P, "SUMMARY_REPAIRS", kw.pop("repairs", 2)):
            out = P.single_answer(log, model, P.single_corpus(DOCS) + P.SINGLE_RULES, DOCS, [],
                                  phase=1, rq="RQ1", role="LEAD", stop_on_model_error=False,
                                  repair_context=P.single_corpus(DOCS) + "\nQUESTION RQ1: What is shown?", **kw)
        return out, log

    def test_overrun_is_not_repeated_as_timeout_and_validated_lines_survive(self):
        m = Sequence(lines(claim(), claim("a2", "experimental features"), DONE),
                     P.CallFailed(P.OUTPUT_OVERRUN + ": resumed in 2 turns; last turn only", 0.0))
        out, log = self.answer(m)
        self.assertEqual([c["id"] for c in out["claims"]], ["a1"])
        self.assertEqual(out["outcome"], "answered")
        self.assertFalse(out["complete"])
        self.assertIn(P.OUTPUT_OVERRUN, out["error"])
        self.assertEqual(len(log.calls), 2)
        self.assertFalse(any("timeout-retry" in c.call_id for c in log.calls))
        self.assertTrue(all(p.count(G.TEXT) == 1 for p in m.prompts))
        repair = m.prompts[1]
        self.assertNotIn('"local_id": "a1"', repair.split("YOUR PREVIOUS ANSWER:")[1])
        self.assertIn('"local_id": "a2"', repair.split("YOUR PREVIOUS ANSWER:")[1])
        self.assertIn("at most 1 claim lines", repair)
        self.assertNotIn("At most 40 claim lines", repair)

    def test_first_call_overrun_is_unknown_incomplete_not_a_native_retry_request(self):
        out, log = self.answer(Sequence(P.CallFailed(P.OUTPUT_OVERRUN + ": result unavailable", 0.0)))
        self.assertEqual((out["outcome"], out["claims"], out["complete"]), ("unknown", [], False))
        self.assertEqual(len(log.calls), 1)
        self.assertIsNone(log.stopped)

    def test_timeout_still_has_its_visible_bounded_retry(self):
        out, log = self.answer(Sequence(TimeoutError("synthetic deadline"), lines(claim(), DONE)))
        self.assertTrue(out["complete"])
        self.assertTrue(log.calls[1].call_id.endswith("-timeout-retry-1"))
        self.assertEqual(log.calls[0].prompt_sha256, log.calls[1].prompt_sha256)

    def test_ambiguous_quote_can_be_omitted_without_empty_response_loop(self):
        m = Sequence(lines(claim(), claim("a2", "experimental features"), DONE), lines(DONE))
        out, _ = self.answer(m)
        self.assertTrue(out["complete"], "done closes the local protocol, not a semantic coverage acceptance")
        self.assertEqual([c["id"] for c in out["claims"]], ["a1"])
        self.assertIn("Do not reconstruct unseen source text", m.prompts[1])
        self.assertIn("Always send one done line", m.prompts[1])

    def test_repair_cannot_add_new_ids_and_done_is_required_again(self):
        m = Sequence(lines(claim(), claim("a2", "experimental features"), DONE),
                     lines(claim("extra", "The port is 9090."), DONE),
                     lines(claim("extra", "The port is 9090."), DONE))
        out, _ = self.answer(m, repairs=2)
        self.assertFalse(out["complete"])
        self.assertEqual([c["id"] for c in out["claims"]], ["a1"])
        self.assertTrue(any("refused local_id" in r["why"] for r in out["refused_at_end"]))
        out, _ = self.answer(Sequence(lines(claim(), claim("a2", "experimental features"), DONE),
                                     lines(claim("a2", "Client experimental features."))), repairs=1)
        self.assertFalse(out["complete"], "an old done line must not hide a missing repair done")

    def test_map_enforces_eight_claims_in_the_validator(self):
        out, _ = self.answer(Sequence(lines(*(claim(f"a{i}") for i in range(9)), DONE)), max_claims=8, repairs=0)
        self.assertEqual(out["claims"], [])
        self.assertFalse(out["complete"])
        self.assertIn("at most 8 claim lines", out["refused_at_end"][0]["why"])
        new, refused, _ = P.check_single([claim(f"a{i}") for i in range(9)], DOCS, [], {}, max_claims=8)
        self.assertEqual((len(new), len(refused)), (8, 1))

    def test_oversized_json_is_not_accepted_or_echoed_into_repair(self):
        huge = lines(claim(quote=DOCS["r.md"]), {"kind": "done", "text": "x" * 200}) + " " * 6000
        m = Sequence(huge, lines(claim(), DONE))
        out, _ = self.answer(m, max_response_chars=5000)
        self.assertTrue(out["complete"])
        self.assertNotIn(huge, m.prompts[1])
        self.assertIn("(cut at the output limit)", m.prompts[1])
        self.assertIn("at most 5000 characters", m.prompts[0])
        self.assertIn("at most 5000 characters", m.prompts[1])

    def test_truncated_valid_json_does_not_contribute_claims(self):
        m = Sequence(lines(claim(), DONE), lines(DONE))
        original = P.check_answer
        def cut_first(c, **kw):
            if c.call_id.endswith("-0"):
                c.usage["finish_reason"] = "max_tokens"
            return original(c, **kw)
        with mock.patch.object(P, "check_answer", side_effect=cut_first):
            out, _ = self.answer(m)
        self.assertEqual(out["claims"], [])
        self.assertTrue(out["complete"])

    def test_claim_text_validator_remains_240_while_common_target_is_200(self):
        new, refused, _ = P.check_single([claim(text="x" * 240), claim("a2", text="x" * 241)], DOCS, [], {})
        self.assertEqual((len(new), len(refused)), (1, 1))
        self.assertEqual(G.TARGET_CLAIM_CHARACTERS, 200)

    def test_map_passes_limits_and_original_notes_but_no_new_source_to_repair(self):
        notes = {"r.md": ['- [r.md] "experimental features"']}
        m = Sequence(lines(claim("a2", "experimental features"), DONE), lines(DONE))
        log = P.Log(max_calls=100)
        row, part = M.partial(log, m, DOCS, [], {"id": "RQ1", "text": "What is shown?"}, 1,
                              P.TEAM_RULES, "w1", "LEAD", {}, notes, "r.md")
        self.assertEqual(row["status"], "COMPLETE")
        self.assertEqual(part["claims"], [])
        for prompt in m.prompts:
            self.assertEqual(prompt.count(G.TEXT), 1)
            self.assertIn("at most 5000 characters", prompt)
            self.assertNotIn("Client experimental features.", prompt)
        self.assertIn("at most 8 claim lines", m.prompts[0])
        self.assertIn("at most 1 claim lines", m.prompts[1])


if __name__ == "__main__":
    unittest.main()
