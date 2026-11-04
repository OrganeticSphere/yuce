"""Offline checks of the pilot A vs C runner (no server, no model calls).

Run: python -m unittest discover -s benchmarks -p "test_*.py"
"""
from __future__ import annotations

import json
import pathlib
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from sbgk_bench import pilot_ac as P  # noqa: E402

R1 = "# Classifier MVP\nDiffering validator versions -> warning only.\nSame canonical/hash remains a candidate only.\n\n# Limits\nVersion negotiation is future work.\n"
# a synthetic withdrawal plan of two steps, the shape of a corpus' --withdrawal-plan
TWO_STEPS = {"steps": [{"name": "2A", "report": "r.md", "candidates": [{"anchor": "alpha", "quote": "alpha line"}]},
                       {"name": "2B", "report": "r.md", "candidates": [{"anchor": "beta", "quote": "beta line"}]}]}


class Sections(unittest.TestCase):
    def test_cut_at_headings_within_the_bound_and_contiguous(self):
        secs = P.sections(R1, 80)
        n = len(R1.encode())
        self.assertGreaterEqual(len(secs), 2)
        self.assertEqual((secs[0][0], secs[-1][1]), (0, n))
        self.assertTrue(all(b - a <= 80 for a, b in secs))
        self.assertTrue(all(x[1] == y[0] for x, y in zip(secs, secs[1:])))
        self.assertEqual("".join(P.section_text(R1, x) for x in secs), R1)

    def test_a_long_section_splits_on_char_boundaries(self):
        text = "# T\n" + "é" * 100 + "\n"
        secs = P.sections(text, 64)
        self.assertEqual("".join(P.section_text(text, s) for s in secs), text)


class Answers(unittest.TestCase):
    def test_json_lines_are_read_and_broken_ones_counted(self):
        lines, broken = P.parse_lines('```json\n{"kind": "observe"}\nnot json\n{"kind": broken\n[1]\n```')
        self.assertEqual((lines, broken), ([{"kind": "observe"}], 1))

    def test_fallbacks_are_honest_and_link_checks_have_none(self):
        self.assertEqual(P.fallback({"kind": "EXTEND"}), [])
        done = P.fallback({"kind": "SUMMARIZE", "key": "rq:RQ2", "task_id": "T5-x", "local_id_prefix": "t5_"})[0]
        self.assertEqual((done["rq_id"], done["directive_id"], done["outcome"], done["answer_ids"]), ("RQ2", "T5-x", "unknown", []))
        self.assertIsNone(P.fallback({"kind": "VERIFY_LINK"}))

    def test_the_brakes_stop_a_stuck_key_and_a_call_cap(self):
        log = P.Log(max_calls=3)
        for _ in range(P.MAX_RELEASES):
            log.released("verify:@ab")
        self.assertTrue(log.stopped.startswith("STUCK"))
        log = P.Log(max_calls=2)
        for i in range(2):
            log.add(P.Call(call_id=str(i), arm="C", role="EXTEND", phase=1, prompt_chars=1))
        self.assertTrue(log.stopped.startswith("CALL_CAP"))

    def test_unknown_cost_is_not_zero(self):
        calls = [{"cost_usd": None, "usage": {}, "ok": True, "prompt_chars": 5, "latency_s": 0.1},
                 {"cost_usd": 0.002, "usage": {"input": 10, "output": 3}, "ok": True, "prompt_chars": 7, "latency_s": 0.2}]
        c = P.cost_of(calls)
        self.assertEqual((c["cost_usd_known"], c["cost_unknown_calls"], c["input_tokens"]), (0.002, 1, 10))


class Stub(unittest.TestCase):
    def test_extend_quotes_whole_unique_lines_of_its_section(self):
        prompt = ("Answer with at most 24 JSON lines; every local_id starts with t3_.\n\nTASK EXTEND: ...\nSECTION doc_id=\"d_1\" (bytes 0..99):\n<<<\n"
                  + R1 + "\n>>>")
        lines, _ = P.parse_lines(P.StubModel().complete(prompt)[0])
        self.assertEqual([x["kind"] for x in lines], ["observe", "claim", "observe", "claim"])
        self.assertTrue(all(x["local_id"].startswith("t3_") for x in lines))
        self.assertIn(lines[0]["exact_quote"], R1)


class Team(unittest.TestCase):
    def test_the_lead_gets_every_report_path_and_a_short_name_is_refused(self):
        # live run S2: the notes named their reports short and the lead, never shown the paths, had every claim refused
        docs = {"docs/reports/a.md": "The gate is now blocking for every version mismatch.\n", "docs/reports/b.md": "Nothing else.\n"}
        corpus = P.team_corpus(['- [a] "The gate is now blocking for every version mismatch." - frozen'], docs)
        self.assertTrue(all(f"  {path}\n" in corpus for path in docs), corpus)
        claim = {"kind": "claim", "local_id": "a1", "text": "The gate blocks.",
                 "quotes": [{"report": "a", "exact_quote": "The gate is now blocking for every version mismatch."}]}
        new, refused, _ = P.check_single([claim], docs, [], {})
        self.assertEqual((new, refused[0]["why"][:14]), ({}, "unknown report"))
        claim["quotes"][0]["report"] = "docs/reports/a.md"
        new, refused, _ = P.check_single([claim], docs, [], {})
        self.assertEqual((list(new), refused), (["a1"], []))


class WholeRestate(unittest.TestCase):
    def test_restatements_sent_as_an_array_without_kind_are_kept_on_their_remaining_quotes_only(self):
        # live run S1.3: the agent restated three rows as one JSON array without "kind", and the runner dropped all three
        text = ('[{"local_id": "a5", "rq_id": "RQ1", "text": "One run had one failure.", "based_on": ["o12", "o16"]}, '
                '{"local_id": "a6", "text": "Rests on a withdrawn quote.", "based_on": ["o12", "o9"]}]')

        class Model:
            name = "fixed"

            def complete(self, prompt):
                return text, {}, 0.0

        whole = {"graph_lines": [{"kind": "observe", "local_id": n, "doc_id": "d", "exact_quote": n} for n in ("o12", "o16", "o9")]}
        lost = [{"agent_id": "a5", "text": "t", "remaining": ["o12", "o16"]}, {"agent_id": "a6", "text": "t", "remaining": ["o12"]}]
        out = P.whole_restate(Model(), P.Log(), 2, whole, "RQ1", lost)
        self.assertEqual([(v["local_id"], v["kind"], v["based_on"]) for v in out], [("a5", "answer", ["o12", "o16"])])

    def test_a_restatement_may_rest_on_another_observe_that_stands_but_not_on_a_withdrawn_one(self):
        # replicate S1.3-R1: restated on its remaining quotes only, a supersession lost the newer state its other observes held
        text = ('{"kind": "answer", "local_id": "a6", "text": "Newer state.", "based_on": ["o12", "o16"]}\n'
                '{"kind": "answer", "local_id": "a7", "text": "On withdrawn text.", "based_on": ["o12", "o9"]}')

        class Model:
            name = "fixed"

            def complete(self, prompt):
                assert "YOUR OTHER OBSERVES THAT STAND:" in prompt and '"o16"' in prompt.split("YOUR OTHER OBSERVES")[1], prompt
                return text, {}, 0.0

        whole = {"graph_lines": [{"kind": "observe", "local_id": n, "doc_id": "d", "exact_quote": n} for n in ("o12", "o16", "o9")],
                 "locals": {"o12": "@" + "1" * 16, "o16": "@" + "2" * 16, "o9": "@" + "3" * 16}, "revoked": ["@" + "3" * 16]}
        lost = [{"agent_id": "a6", "text": "t", "remaining": ["o12"]}, {"agent_id": "a7", "text": "t", "remaining": ["o12"]}]
        out = P.whole_restate(Model(), P.Log(), 3, whole, "RQ1", lost)
        self.assertEqual([(v["local_id"], v["based_on"]) for v in out], [("a6", ["o12", "o16"])])


class SingleAnswer(unittest.TestCase):
    """Codex's review of S1, C01/C02: an answer without its done line, one cut at the output limit and one with a prose line all
    ended COMPLETE."""

    DOCS = {"r.md": "Alpha holds."}
    CLAIM = json.dumps({"kind": "claim", "local_id": "a1", "text": "Alpha holds.", "quotes": [{"report": "r.md", "exact_quote": "Alpha holds."}]})
    DONE = json.dumps({"kind": "done", "text": "Nothing else is established."})

    class Model:
        name = "fixed"

        def __init__(self, *answers):
            self.answers, self.prompts = list(answers), []

        def complete(self, prompt):
            self.prompts.append(prompt)
            text, finish = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
            return text, {"finish_reason": finish}, 0.0

    def phase1(self, *answers):
        model = self.Model(*answers)
        res = P.run_arm_single(model, self.DOCS, {}, timeout_s=60)
        return res["phase1"], model

    def test_a_valid_answer_is_complete(self):
        ph, model = self.phase1((self.CLAIM + "\n" + self.DONE, "stop"))
        self.assertEqual((ph["status"], len(model.prompts), ph["answers"]["RQ1"]["complete"]), ("COMPLETE", len(P.QUESTIONS), True))

    def test_no_done_line_after_every_repair_is_incomplete(self):
        ph, _ = self.phase1((self.CLAIM, "stop"))
        self.assertEqual((ph["status"], ph["answers"]["RQ1"]["complete"], ph["answers"]["RQ1"]["repairs"]), ("INCOMPLETE", False, P.SUMMARY_REPAIRS))

    def test_a_cut_answer_keeps_nothing_and_is_asked_for_again(self):
        ph, model = self.phase1((self.CLAIM + "\n" + self.DONE, "max_tokens"), (self.CLAIM + "\n" + self.DONE, "stop"))
        self.assertEqual((ph["answers"]["RQ1"]["repairs"], ph["answers"]["RQ1"]["complete"]), (1, True))
        self.assertIn("Nothing of your previous answer was kept", model.prompts[1])
        self.assertNotIn(self.DONE, model.prompts[1].split("YOUR PREVIOUS ANSWER:", 1)[1])

    def test_a_prose_line_refuses_the_whole_answer(self):
        ph, _ = self.phase1(("Here is my answer.\n" + self.CLAIM + "\n" + self.DONE, "stop"))
        self.assertEqual((ph["status"], ph["answers"]["RQ1"]["claims"]), ("INCOMPLETE", []))


class DeepSeek(unittest.TestCase):
    def test_usage_is_priced_from_the_provider_tokens_and_the_key_never_shows(self):
        reply = {"id": "r1", "model": "deepseek-flash", "choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}],
                 "usage": {"prompt_tokens": 1000, "completion_tokens": 100, "prompt_cache_hit_tokens": 400, "prompt_cache_miss_tokens": 600}}
        m = P.DeepSeekModel(key="sk-test-not-real")
        with mock.patch.object(P, "deepseek_request", return_value=reply) as req, mock.patch.object(P, "deepseek_price_factor", return_value=1.0):
            text, usage, cost = m.complete("hello")
        self.assertEqual((text, usage["input"], usage["output"], usage["cache_hit"]), ("OK", 1000, 100, 400))
        r = P.DEEPSEEK_RATES
        self.assertAlmostEqual(cost, (600 * r[0] + 400 * r[1] + 100 * r[2]) / 1e6)
        self.assertEqual(req.call_args.args[2]["messages"], [{"role": "user", "content": "hello"}], "one fresh call, no history")
        self.assertEqual(req.call_args.args[2]["thinking"], {"type": "disabled"}, "the answer gets the output budget, not the reasoning")
        self.assertNotIn("sk-test", repr(m))
        with mock.patch.object(P, "deepseek_request", return_value=reply), mock.patch.object(P, "deepseek_price_factor", return_value=0.5):
            self.assertAlmostEqual(m.complete("hello")[2], (600 * r[0] + 400 * r[1] + 100 * r[2]) / 2e6, msg="off-peak is half")

    def test_peak_hours_are_weekday_utc_windows_and_every_other_time_is_off_peak(self):
        import calendar
        at = lambda s: calendar.timegm(time.strptime(s, "%Y-%m-%d %H:%M"))  # noqa: E731
        # Thursday 2026-10-22: live run 10A-4 at 18:57 UTC was off-peak
        self.assertEqual([P.deepseek_price_factor(at(f"2026-10-22 {h}")) for h in ("00:59", "01:00", "03:59", "04:00", "06:00", "09:59", "10:00", "18:57")],
                         [0.5, 1.0, 1.0, 0.5, 1.0, 1.0, 0.5, 0.5])
        self.assertEqual(P.deepseek_price_factor(at("2026-10-24 02:00")), 0.5, "a Saturday is off-peak all day")
        # a peak window that opens during a call's life is priced in (Codex's static review of 6384733)
        m = P.DeepSeekModel(key="k")
        with mock.patch.object(P.time, "time", return_value=at("2026-10-22 00:55")):
            self.assertAlmostEqual(m.estimate("x" * 10), (10 * P.DEEPSEEK_RATES[0] + m.max_tokens * P.DEEPSEEK_RATES[2]) / 1e6)
        with mock.patch.object(P.time, "time", return_value=at("2026-10-22 18:57")):
            self.assertAlmostEqual(m.estimate("x" * 10), (10 * P.DEEPSEEK_RATES[0] + m.max_tokens * P.DEEPSEEK_RATES[2]) / 2e6)

    def test_a_network_outage_is_retried_before_the_call_fails(self):
        import urllib.error
        reply = {"choices": [{"message": {"content": "ok"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}}
        outage = [urllib.error.URLError("getaddrinfo failed")] * 3 + [reply]
        with mock.patch.object(P, "deepseek_request", side_effect=outage) as req, mock.patch.object(P.time, "sleep") as pause:
            self.assertEqual(P.DeepSeekModel(key="k").complete("p")[0], "ok")
        self.assertEqual((req.call_count, [c.args[0] for c in pause.call_args_list]), (4, [2, 4, 8]))

    def test_no_usage_means_unknown_cost(self):
        reply = {"choices": [{"message": {"content": "x"}}]}
        with mock.patch.object(P, "deepseek_request", return_value=reply):
            self.assertIsNone(P.DeepSeekModel(key="k").complete("p")[2])


class CodexBuilder(unittest.TestCase):
    def test_one_session_per_task_text_from_the_last_message_and_unknown_cost(self):
        import json as _json
        import subprocess
        events = [{"type": "thread.started"}, {"type": "item.completed", "item": {"type": "agent_message", "text": '{"op":"map_term"}'}},
                  {"type": "turn.completed", "usage": {"input_tokens": 900, "cached_input_tokens": 700, "output_tokens": 12}}]
        done = subprocess.CompletedProcess([], 0, stdout="\n".join(_json.dumps(e) for e in events), stderr="")
        with mock.patch.object(P.subprocess, "run", return_value=done) as run:
            text, usage, cost = P.CodexModel("gpt-5.6-sol", workdir=pathlib.Path(tempfile.mkdtemp())).complete("card")
        self.assertEqual((text, usage["input"], usage["cache_hit"], usage["output"], cost), ('{"op":"map_term"}', 900, 700, 12, None))
        args, kwargs = run.call_args
        self.assertIn("read-only", args[0])
        self.assertTrue(kwargs["input"].endswith("card"), "the task comes on stdin")


class MoneyBrake(unittest.TestCase):
    def test_a_call_reserves_its_bound_and_unknown_cost_keeps_it(self):
        b = P.Budget(0.01)
        self.assertTrue(b.reserve(0.006))
        self.assertFalse(b.reserve(0.006), "two upper bounds do not fit under the cap")
        b.settle(0.006, 0.001)
        self.assertTrue(b.reserve(0.006))
        b.settle(0.006, None)
        self.assertEqual(b.state()["unknown_cost_calls"], 1)
        self.assertAlmostEqual(b.state()["spent_usd_estimate"], 0.007)

    def test_the_log_stops_before_a_call_the_budget_cannot_cover(self):
        class Costly:
            name = "costly"

            def estimate(self, prompt):
                return 1.0

            def complete(self, prompt):
                return "x", {}, 1.0

        log = P.Log()
        log.budget = P.Budget(1.5)
        self.assertIsNotNone(log.invoke(Costly(), "p", call_id="1", arm="C", role="EXTEND", phase=1))
        self.assertIsNone(log.invoke(Costly(), "p", call_id="2", arm="C", role="EXTEND", phase=1))
        self.assertTrue(log.stopped.startswith("BUDGET_CAP"))


class ObserveMapping(unittest.TestCase):
    def test_accepted_records_are_mapped_by_local_id_not_by_position(self):
        log = P.Log()
        lines = [{"kind": "observe", "local_id": "a", "exact_quote": "quote A", "doc_id": "d"},
                 {"kind": "observe", "local_id": "b", "exact_quote": "quote B", "doc_id": "d"}]
        # the dispatcher dropped the resent line `a`: only `b` was accepted in this attempt
        P.note_observes(log, lines, {"accepted": ["@b"], "accepted_locals": {"b": "@b"}})
        self.assertEqual(log.observes, {"@b": {"quote": "quote B", "doc_id": "d"}})


class Run10Corrections(unittest.TestCase):
    """Codex review c78060e (F02, F06) and Gemini's checklist v2."""

    def test_broken_lines_come_back_for_a_repair_instead_of_being_dropped(self):
        r = P.broken_refusal('{"kind": "observe", "local_id": "o1"}\n{"kind": "claim", "text": "cut off\n')
        self.assertEqual((r["status"], r["failed_index"], r["local"]), ("REPAIR_REQUIRED", 0, True))
        self.assertEqual(r["error"]["lines"], ['{"kind": "claim", "text": "cut off'])

    def test_an_answer_cut_at_the_output_limit_is_asked_again_shorter_without_itself(self):
        # live run 10A-2: summaries of 70+ lines ran into 8192 output tokens three times and were lost
        text = '{"kind": "claim", "local_id": "c1"}\n{"kind": "claim", "local_id": "c2"}\n{"kind": "claim", "text": "cut'
        call = P.Call(call_id="x", arm="C", role="SUMMARIZE", phase=1, prompt_chars=1, text=text, usage={"finish_reason": "length"})
        self.assertTrue(P.was_cut(call))
        r = P.broken_refusal(text, P.was_cut(call), 40)
        self.assertEqual(r["error"]["code"], "OUTPUT_LIMIT")
        self.assertIn("after 2 complete lines", r["error"]["message"])
        self.assertIn("at most 40 lines", r["error"]["message"])
        again = P.repair_prompt("TASK", r, "lines", text)
        self.assertTrue(again.startswith("TASK\n\n"))
        self.assertNotIn("cut", again.split("NOT ACCEPTED")[0], "the cut answer is not shown again")
        # Codex's review of 4381fe7, finding 1: after an accepted prefix the repair keeps its local references
        kept = P.repair_prompt("TASK", r, "lines", text, [{"local_id": "t1_o1", "record_id": "@durable"}])
        self.assertIn('"record_id": "@durable"', kept)
        self.assertNotIn('"text": "cut', kept)

    def test_a_deep_relation_keeps_every_quote_and_leaf_claim(self):
        # Codex's review of 4381fe7, finding 2: a chain of five nested relations lost quotes and leaves at depth 3
        recs = {}
        for i in range(6):
            recs[f"@o{i}"] = {"id": f"{i}" * 64, "short": f"@o{i}", "kind": "observe", "quote": f"quote number {i} here", "doc_id": "d", "based_on": []}
            recs[f"@c{i}"] = {"id": f"c{i}", "short": f"@c{i}", "kind": "claim", "text": f"Claim {i}.", "based_on": [f"@o{i}"]}
        recs["@r0"] = {"id": "r0", "short": "@r0", "kind": "relation", "ends": ["@c1", "qualifies", "@c0"], "based_on": ["@o1"]}
        for i in range(1, 5):
            recs[f"@r{i}"] = {"id": f"r{i}", "short": f"@r{i}", "kind": "relation", "ends": [f"@c{i + 1}", "qualifies", f"@r{i - 1}"], "based_on": [f"@o{i + 1}"]}

        class Own:
            def call(self, tool, record):
                return recs[record]

        doc = " ".join(f"quote number {i} here" for i in range(6))
        claim = P.c_answers(Own(), {"outcomes": {"RQ1": {"outcome": "answered", "answer_ids": ["@r4"]}}}, {"r.md": doc}, {"d": "r.md"})["RQ1"]["claims"][0]
        self.assertEqual(sorted(q["short"] for q in claim["quotes"]), [f"@o{i}" for i in range(6)])
        for i in range(6):
            self.assertIn(f"Claim {i}.", claim["text"])

    def test_an_answer_claim_is_told_the_replaced_states_its_quotes_hold_and_every_claim_keeps_its_status(self):
        # registry R34a, Codex's check of bc7cf23: the kernel's answer_status reaches the reader of the answer. Codex review of
        # 40f97e0: it names the evidence under the claim; the text is not called superseded or historical for it
        pair = [{"earlier": "@e", "earlier_date": "2026-07-29", "later": "@l", "later_date": ""}]
        recs = {
            "@a": {"short": "@a", "kind": "claim", "text": "The port is 8080.", "based_on": ["@o"],
                   "answer_status": {"temporal_status": "CITES_REPLACED", "replaced": pair, "earlier_and_later": []}},
            "@b": {"short": "@b", "kind": "claim", "text": "The port is 9090.", "based_on": ["@o"],
                   "answer_status": {"temporal_status": "LATEST_KNOWN", "replaced": [], "earlier_and_later": []}},
            "@c": {"short": "@c", "kind": "claim", "text": "Legacy run.", "based_on": ["@o"]},
            "@d": {"short": "@d", "kind": "claim", "text": "The port went from 8080 to 9090.", "based_on": ["@o"],
                   "answer_status": {"temporal_status": "CITES_EARLIER_AND_LATER", "replaced": [], "earlier_and_later": pair}},
            "@f": {"short": "@f", "kind": "claim", "text": "The port was 8080.", "based_on": ["@o"],
                   "temporal_warnings": ["CURRENT_UNCERTAIN: @l was withdrawn."],
                   "answer_status": {"temporal_status": "CURRENT_UNCERTAIN", "replaced": [], "earlier_and_later": []}},
            "@o": {"id": "o" * 64, "short": "@o", "kind": "observe", "quote": "port", "doc_id": "d", "based_on": []},
            "@e": {"short": "@e", "kind": "claim", "text": "The port is 8080.", "based_on": ["@o"]},
            "@l": {"short": "@l", "kind": "claim", "text": "The port is 9090.", "based_on": ["@o"]},
        }

        class Own:
            def call(self, tool, record):
                return recs[record]

        receipt = {"outcomes": {"RQ1": {"outcome": "answered", "answer_ids": ["@a", "@b", "@c", "@d", "@f"]}}}
        old, new, legacy, both, uncertain = P.c_answers(Own(), receipt, {"r.md": "the port text"}, {"d": "r.md"})["RQ1"]["claims"]
        self.assertEqual(old["text"], 'CITES A REPLACED STATE: one of its quotes grounds @e stating "The port is 8080." (latest report date 2026-07-29), '
                                      'a state that @l stating "The port is 9090." (latest report date unknown) replaced; it may state the earlier state. '
                                      'Statement: The port is 8080.')
        self.assertEqual((old["authored_text"], old["temporal_status"]), ("The port is 8080.", "CITES_REPLACED"))
        self.assertEqual(both["text"], 'CITES EARLIER AND LATER: its quotes ground both @e stating "The port is 8080." (latest report date 2026-07-29) '
                                       'and the state that replaced it, @l stating "The port is 9090." (latest report date unknown). '
                                       'Statement: The port went from 8080 to 9090.')
        for claim in (old, both):
            self.assertNotIn("SUPERSEDED", claim["text"])
            self.assertNotIn("Historical statement", claim["text"])
        # R30's withdrawn later evidence keeps its historical label
        self.assertEqual(uncertain["text"], "CURRENT_UNCERTAIN: @l was withdrawn. Historical statement: The port was 8080.")
        self.assertEqual((new["text"], new["temporal_status"]), ("The port is 9090.", "LATEST_KNOWN"))
        self.assertNotIn("temporal_warnings", new)
        self.assertEqual(set(legacy) & {"temporal_status", "temporal_warnings", "authored_text"}, set(), "a kernel without it: as before")

    def test_an_answer_keeps_its_kind_stance_date_and_what_stays_unsettled(self):
        recs = {
            "@c": {"short": "@c", "kind": "claim", "text": "The gate was blocking.", "stance": "superseded", "body": {"as_of": 20260810},
                   "based_on": ["@o"]},
            "@o": {"id": "o" * 64, "short": "@o", "kind": "observe", "quote": "gate blocking", "doc_id": "d", "based_on": []},
            "@r": {"short": "@r", "kind": "relation", "ends": ["@c", "supersedes", "@c2"], "based_on": ["@c", "@c2"]},
            "@c2": {"short": "@c2", "kind": "claim", "text": "The gate warns only.", "stance": "reported", "based_on": ["@o"]},
            "@d": {"short": "@d", "kind": "done", "body": {"text": "The final SHA is not in the corpus."}},
        }

        class Own:
            def call(self, tool, record):
                return recs[record]

        receipt = {"outcomes": {"RQ1": {"outcome": "answered", "done": "@d", "answer_ids": ["@c", "@o", "@r"]}}}
        ans = P.c_answers(Own(), receipt, {"r.md": "the gate blocking text"}, {"d": "r.md"})["RQ1"]
        self.assertEqual([c["kind"] for c in ans["claims"]], ["claim", "observe", "relation"])
        self.assertEqual((ans["claims"][0]["stance"], ans["claims"][0]["as_of"]), ("superseded", 20260810))
        self.assertEqual(ans["claims"][1]["text"], "gate blocking", "an observe answers with its own quote")
        self.assertIn("-- supersedes ->", ans["claims"][2]["text"])
        self.assertEqual(ans["unsettled"], "The final SHA is not in the corpus.")
        md, _ = P.answers_md({}, {"phase1": {"answers": {"RQ1": ans}}})
        self.assertIn("[stance: superseded; as of: 20260810]", md)
        self.assertIn("Not settled: The final SHA is not in the corpus.", md)

    def test_the_reports_each_answer_cites_are_counted(self):
        report, second = "docs/reports/first.md", "docs/reports/second.md"
        a = {"calls": [], "events": [], "phase1": {"answers": {"RQ1": f"- [{report}] \"x\" - y"}}}
        c = {"calls": [], "events": [], "phase1": {"answers": {"RQ1": {"claims": [{"quotes": [{"report": report}, {"report": second}]}]}}}}
        # one definition for both arms: a report counts when its bytes hold a quote the answer cites (Codex review d7d9a49, D09)
        docs = {report: "the line x quoted here and more", second: "another report with the second quote inside", "other.md": "none"}
        a = {"calls": [], "events": [], "phase1": {"answers": {"RQ1": f'- [{report}] "the line x quoted here" - y'}}}
        c = {"calls": [], "events": [], "phase1": {"answers": {"RQ1": {"claims": [{"quotes": [{"quote": "the line x quoted here"},
                                                                                         {"quote": "with the second quote"}]}]}}}}
        m = P.measures(a, c, docs)["reports_cited"]
        self.assertEqual((m["of"], m["A"]["phase1"]["RQ1"], m["C"]["phase1"]["RQ1"]), (3, 1, 2))
        # Codex's review of 4381fe7, finding 3: the same quoted bytes count the same for both arms, short or long
        docs = {"one.md": "a short quote and a much longer quoted sentence"}
        for quote in ("short quote", "a much longer quoted sentence"):
            a_cov = P.reports_quoted(f'- [one.md] "{quote}"', docs)
            c_cov = P.reports_quoted({"claims": [{"quotes": [{"quote": quote}]}]}, docs)
            self.assertEqual(a_cov, c_cov, quote)


class Run10aDeadline(unittest.TestCase):
    """Live run 10A: the phase deadline came during a kernel call and the whole run crashed."""

    def test_a_late_answer_to_a_timed_out_call_is_skipped(self):
        a, b = socket.socketpair()
        try:
            rpc = object.__new__(P.Rpc)
            rpc.timeout_s, rpc.deadline, rpc._closed, rpc.s, rpc._buffer, rpc.n = 5.0, None, False, a, b"", 1
            b.sendall(b'{"jsonrpc": "2.0", "id": 1, "result": "late"}\n{"jsonrpc": "2.0", "id": 2, "result": "this one"}\n')
            self.assertEqual(rpc._rpc("tools/call", {})["result"], "this one")
        finally:
            a.close()
            b.close()

    def test_a_deadline_during_the_terminal_call_is_a_timeout_not_a_crash(self):
        class Own:
            def set_deadline(self, deadline):
                pass

            def call(self, tool):
                time.sleep(0.05)
                raise TimeoutError("RPC absolute deadline expired")

        self.assertEqual(P.c_until_terminal(Own(), P.Log(), 0.01)["status"], "TIMEOUT")

    def test_a_kernel_busy_past_one_poll_is_asked_again_and_a_silent_one_fails(self):
        # live run MCPsfun_r1: the kernel answered an acquire after 112 s at the last circle's FINAL, and the owner's one timed-out
        # poll failed the run
        class Own:
            def __init__(self, timeouts):
                self.timeouts = timeouts

            def set_deadline(self, deadline):
                pass

            def call(self, tool):
                if self.timeouts:
                    self.timeouts -= 1
                    raise TimeoutError("timed out")
                return {"status": "TERMINAL"}

        log = P.Log()
        self.assertEqual(P.c_until_terminal(Own(P.KERNEL_SLOW_POLLS - 1), log, 30.0)["status"], "TERMINAL")
        self.assertEqual([e["polls"] for e in log.events if e.get("kind") == "KERNEL_SLOW"], list(range(1, P.KERNEL_SLOW_POLLS)))
        with self.assertRaises(TimeoutError):
            P.c_until_terminal(Own(P.KERNEL_SLOW_POLLS), P.Log(), 30.0)

    def test_a_busy_kernel_after_the_phase_deadline_does_not_crash_the_arm(self):
        # Codex's analysis of 831bbac, A2: the status call right after a TIMEOUT could still raise
        class Rpc:
            def __init__(self, agent):
                self.agent = agent

            def set_deadline(self, deadline):
                pass

            def call(self, tool, **args):
                if tool == "audit_acquire":
                    return {"status": "WAIT"}
                if tool == "audit_next_card":
                    return {"status": "IDLE"}
                if tool == "audit_terminal_receipt":
                    time.sleep(0.35)  # the kernel holds the call past the phase deadline (0.3 s)
                raise TimeoutError("the kernel is busy")

            def close(self):
                pass

        class Kernel:
            def __init__(self, *args, **kwargs):
                self.hello = {"status": "listening"}

            def connect(self, agent):
                return Rpc(agent)

            def stop(self):
                pass

        with tempfile.TemporaryDirectory() as d, mock.patch.object(P, "Kernel", Kernel), mock.patch.object(P, "source_document_paths", return_value={}):
            manifest = pathlib.Path(d) / "manifest.json"
            manifest.write_text("{}", encoding="utf-8")
            res = P.run_arm_c(P.StubModel(), P.StubModel(), pathlib.Path(d) / "c", manifest, pathlib.Path(d), [], {}, TWO_STEPS,
                              workers=1, timeout_s=0.3)
        self.assertEqual(res["phase1"]["receipt"]["status"], "TIMEOUT")
        self.assertEqual(res["phase1"]["status"]["status"], "UNAVAILABLE", "the status the kernel could not give is recorded")

    def test_an_agent_wait_records_why_the_kernel_had_no_task(self):
        # 02.11.2026: the idle time of a circles run is explained by the kernel's own reason, not guessed from status samples
        stop = threading.Event()
        answers = [
            {"status": "WAIT", "message": "waiting for every ring reader at the shift barrier", "waited_ms": 1500},
            {"status": "WAIT", "open_work": 3, "leases": 2, "builder_caught_up": False, "waited_ms": 2000},
        ]

        class Rpc:
            def call(self, tool, **args):
                answer = answers.pop(0)
                if not answers:
                    stop.set()
                return answer

            def close(self):
                pass

        log = P.Log()
        with mock.patch.object(P, "CIRCLES", True):
            P.c_worker(types.SimpleNamespace(connect=lambda agent: Rpc()), "w1", P.StubModel(), log, [1], stop)
        waits = [e for e in log.events if e.get("kind") == "IDLE_WAIT" and e.get("reason") == "acquire"]
        self.assertEqual(waits[0]["kernel_message"], "waiting for every ring reader at the shift barrier")
        self.assertEqual(waits[0]["kernel_waited_ms"], 1500)
        self.assertEqual((waits[1]["kernel_open_work"], waits[1]["kernel_leases"], waits[1]["kernel_builder_caught_up"]), (3, 2, False))
        self.assertNotIn("kernel_message", waits[1])

    def test_a_refused_close_of_an_empty_card_stops_visibly_instead_of_looping(self):
        # Codex's analysis of 831bbac, A3
        stop, calls = threading.Event(), []

        class Rpc:
            def call(self, tool, **args):
                calls.append(tool)
                if tool == "audit_next_card":
                    return {"status": "CARD", "card_id": "C1", "prompt": "p", "records": [], "candidates": {}, "max_ops": 8}
                return {"status": "error", "code": "CHECKPOINT_REFUSED"}

            def close(self):
                pass

        log = P.Log()
        P.c_builder(types.SimpleNamespace(connect=lambda agent: Rpc()), P.StubModel(), log, [1], stop)
        self.assertEqual(calls, ["audit_next_card", "audit_submit_ops"])
        self.assertTrue(log.stopped.startswith("EMPTY_CARD_REFUSED"), log.stopped)

    def test_a_nested_relation_is_exported_with_its_inner_ends_and_all_their_quotes(self):
        # Codex review d7d9a49, D08
        recs = {
            "@o1": {"id": "1" * 64, "short": "@o1", "kind": "observe", "quote": "first quote here", "doc_id": "d", "based_on": []},
            "@o2": {"id": "2" * 64, "short": "@o2", "kind": "observe", "quote": "second quote here", "doc_id": "d", "based_on": []},
            "@o3": {"id": "3" * 64, "short": "@o3", "kind": "observe", "quote": "third quote here", "doc_id": "d", "based_on": []},
            "@c1": {"short": "@c1", "kind": "claim", "text": "Old rule.", "based_on": ["@o1"]},
            "@c2": {"short": "@c2", "kind": "claim", "text": "New rule.", "based_on": ["@o2"]},
            "@c3": {"short": "@c3", "kind": "claim", "text": "Staging only.", "based_on": ["@o3"]},
            "@r1": {"short": "@r1", "kind": "relation", "ends": ["@c2", "supersedes", "@c1"], "based_on": ["@c2", "@c1"]},
            "@r2": {"short": "@r2", "kind": "relation", "ends": ["@c3", "qualifies", "@r1"], "based_on": ["@c3", "@r1"]},
        }

        class Own:
            def call(self, tool, record):
                return recs[record]

        receipt = {"outcomes": {"RQ1": {"outcome": "answered", "answer_ids": ["@r2"]}}}
        ans = P.c_answers(Own(), receipt, {"r.md": "first quote here, second quote here, third quote here"}, {"d": "r.md"})["RQ1"]
        claim = ans["claims"][0]
        self.assertEqual(claim["text"], "Staging only. -- qualifies -> New rule. -- supersedes -> Old rule.")
        self.assertEqual(sorted(q["short"] for q in claim["quotes"]), ["@o1", "@o2", "@o3"])

    def test_a_phase_deadline_must_be_finite(self):
        # Codex review d7d9a49, D10: inf or NaN would switch the deadline off
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        import run_pilot_ac as R
        for bad in (float("inf"), float("nan"), 0.0, -1.0):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                R.run(pathlib.Path("m"), pathlib.Path("r"), [], pathlib.Path("never-created"), P.StubModel(), 1, None, phase_timeout_s=bad)

    def test_a_model_call_in_flight_at_the_stop_is_waited_for(self):
        # live run 10B: a strong builder's call of up to 85 s was cut at the deadline and the whole run failed
        log, stop = P.Log(), threading.Event()
        log.in_flight["B1-card-0"] = {"role": "BUILDER"}

        def call():
            time.sleep(0.3)
            log.in_flight.clear()

        t = threading.Thread(target=call)
        t.start()
        with mock.patch.object(P, "SHUTDOWN_TIMEOUT_S", 0.05), mock.patch.object(P, "CALL_DRAIN_S", 5.0):
            P.finish_threads([t], log, stop)
        self.assertFalse(t.is_alive())
        with mock.patch.object(P, "SHUTDOWN_TIMEOUT_S", 0.05), mock.patch.object(P, "CALL_DRAIN_S", 5.0), \
             mock.patch.object(P, "ACQUIRE_WAIT_MS", 50), mock.patch.object(P, "RPC_TIMEOUT_S", 0.05):
            idle = threading.Thread(target=time.sleep, args=(0.3,))
            idle.start()
            with self.assertRaises(RuntimeError, msg="a thread with no call in flight gets the wait of one kernel call only"):
                P.finish_threads([idle], P.Log(), threading.Event())
            idle.join()

    def test_a_reader_queued_behind_the_kernel_at_the_stop_is_waited_for(self):
        # claude-reviewer's RV-01 of 84d7e6b4: a reader inside a kernel call longer than the 10 s shutdown wait failed the phase
        with mock.patch.object(P, "SHUTDOWN_TIMEOUT_S", 0.05), mock.patch.object(P, "ACQUIRE_WAIT_MS", 50), \
             mock.patch.object(P, "RPC_TIMEOUT_S", 1.0):
            queued = threading.Thread(target=time.sleep, args=(0.3,))
            queued.start()
            P.finish_threads([queued], P.Log(), threading.Event())
        self.assertFalse(queued.is_alive())


class Withdrawal(unittest.TestCase):
    def test_2b_takes_the_first_candidate_an_answer_rests_on(self):
        step = {"name": "2B", "report": "r.md", "candidates": [{"anchor": "alpha", "quote": "alpha line"}, {"anchor": "beta", "quote": "beta line"}]}
        observes = {"@1": {"doc_id": "d", "quote": "alpha line"}, "@2": {"doc_id": "d", "quote": "the beta line here"}}
        answers = {"RQ1": {"claims": [{"quotes": [{"short": "@2"}]}]}}
        cand, hit, reason = P.choose_candidate(step, observes, answers, {"d": "r.md"})
        self.assertEqual((cand["anchor"], hit, reason), ("beta", ["@2"], "an answer rests on it"))
        cand, hit, reason = P.choose_candidate(step, observes, {}, {"d": "r.md"})
        self.assertEqual((cand["anchor"], hit), ("alpha", ["@1"]))



if __name__ == "__main__":
    unittest.main()
