"""The steps of a retraction plan: a whole step withdraws every byte of one report, an all step every candidate in the same phase,
each in its own report, and any step may carry the message arm A is told in place of the withdrawn text. Arm C writes one
withdrawal per text, with its byte span, and with --withdraw-preview previews every text of a step before the step's first
withdrawal; arm A hears the messages and never the withdrawn text, may say which of its conclusions they affect, and with
--arm-a-no-withdrawn-check (which a plan with messages requires) keeps a quote that overlaps withdrawn text. A refusal of the
model's safeguards closes one task of arm A and the arm goes on; a declined update leaves the answer it updated for the next step.
The kernel runs need the kernel binary; no provider is called."""

from __future__ import annotations

import json
import pathlib
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_pilot_ac as R  # noqa: E402
from sbgk_bench import pilot_ac as P  # noqa: E402
from test_questions_option import THREE, corpus  # noqa: E402

# the corpus of test_build_scope (corpus() writes the same texts): two findings a page
DOCS = {f"reports/scope_{i}.md": f"# Rule {i}\nA known limitation remains for version rule {i}.\nThe old check of rule {i} was removed.\n"
        for i in range(6)}
RETRACTED = "The paper of rule 0 was retracted by its journal."
CITING = "Two sentences of the other reports cite the retracted paper."


def plan(paths: list[str], messages: bool = True) -> dict:
    """2A withdraws all of the first report; 2B withdraws a sentence in each of the next two, in one phase."""
    whole = {"name": "2A", "report": paths[0], "whole": True}
    every = {"name": "2B", "all": True, "candidates": [
        {"report": paths[1], "anchor": "rule 1", "quote": "The old check of rule 1 was removed."},
        {"report": paths[2], "anchor": "rule 2", "quote": "A known limitation remains for version rule 2."}]}
    if messages:
        whole["message"], every["message"] = RETRACTED, CITING
    return {"steps": [whole, every]}


def declined() -> P.CallFailed:
    return P.CallFailed(f"{P.MODEL_REFUSED}: API Error: the model's safeguards flagged this message", 0.0)


class Lead(P.StubModel):
    """The team's lead: the stub's answers, and when an update asks what the notices affect, one such line before them; a repair
    leaves the refused claims out, as a model told why would. It keeps every prompt it is given."""

    def __init__(self):
        self.prompts: list[str] = []

    def complete(self, prompt: str):
        self.prompts.append(prompt)
        if prompt.startswith("ARM A ANSWER REPAIR"):
            return json.dumps({"kind": "done", "text": "The refused claims are left out."}), {}, 0.0
        text, usage, cost = super().complete(prompt)
        if prompt.startswith("ARM A TEAM") and '"kind":"affected"' in prompt:
            rq = re.search(r"^QUESTION (\S+):", prompt, re.M).group(1)
            text = json.dumps({"kind": "affected", "text": f"My answer to {rq} rested on the retracted paper."}) + "\n" + text
        return text, usage, cost


class DecliningLead(Lead):
    """The lead, whose safeguards decline its update of one question at 2A, before it gives a line."""

    def __init__(self, rq: str):
        super().__init__()
        self.rq = rq

    def complete(self, prompt: str):
        if (prompt.startswith("ARM A TEAM") and f"\nQUESTION {self.rq}:" in prompt and "YOUR ANSWER BEFORE" in prompt
                and CITING not in prompt):
            self.prompts.append(prompt)
            raise declined()
        return super().complete(prompt)


class Declining(P.StubModel):
    """A member of the team whose safeguards decline the sections of one report (`report`) and the first answer to one question
    (`question`); `error` fails every section with another error instead."""

    def __init__(self, report: str | None = None, question: str | None = None, error: str | None = None):
        self.report, self.question, self.error = report, question, error

    def complete(self, prompt: str):
        if prompt.startswith("ARM A WORKER") and self.error:
            raise RuntimeError(self.error)
        if prompt.startswith("ARM A WORKER") and self.report and f"SECTION OF {self.report}:" in prompt:
            raise declined()
        if self.question and prompt.startswith("ARM A TEAM") and f"\nQUESTION {self.question}:" in prompt and "YOUR ANSWER BEFORE" not in prompt:
            raise declined()
        return super().complete(prompt)


def told(prompt: str) -> str:
    """The part of an update prompt that tells the withdrawals: after the question, before the answer it gave."""
    return prompt.split("\nQUESTION ", 1)[1].split("\n", 1)[1].split("YOUR ANSWER BEFORE THE WITHDRAWAL", 1)[0]


def before(prompt: str) -> str:
    """The answer an update prompt shows as the one before the withdrawal."""
    return prompt.split("YOUR ANSWER BEFORE THE WITHDRAWAL:\n", 1)[1].split("\nAnswer again", 1)[0]


def quoted(answers: dict, report: str) -> bool:
    return any(q["report"] == report for a in answers.values() for cl in a.get("claims") or [] for q in cl.get("quotes") or [])


class Steps(unittest.TestCase):
    def setUp(self):
        self.saved = {k: v for k, v in vars(P).items() if k.isupper()}

    def tearDown(self):
        vars(P).update(self.saved)

    def team(self, *members, withdraw=None) -> dict:
        return P.run_arm_team(list(members), DOCS, plan(sorted(DOCS)) if withdraw is None else withdraw, timeout_s=60)

    def kernel_run(self, withdraw, *, docs: dict[str, str] | None = None, team: list | None = None) -> tuple[dict, dict, dict, dict]:
        """A stub run of both arms in real kernel circles (the settings of test_questions_option): the summary, arm C, arm A and the
        texts of the run."""
        P.ARM_A_MODE, P.PAIRS_ONLY, P.LINK_CHECKER = "team", False, True
        P.DYNAMIC_ROLES, P.BUILD_BACKLOG, P.CHECKER_MODEL = True, 1, P.StubModel()
        P.CIRCLES, P.WAVE_SECTIONS = True, 3
        P.BUILD_SCOPE, P.QUESTIONS, P.WITHDRAW_PREVIEW = "none", THREE, True
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest, docs = corpus(root, docs)
            s = R.run(manifest, root / "repo", sorted(docs), root / "out", P.StubModel(), 3, withdraw(sorted(docs)), phase_timeout_s=120,
                      max_calls=600, team=team or [P.StubModel(), P.StubModel(), P.StubModel()])
            c = json.loads((root / "out" / "arm_c.json").read_text(encoding="utf-8"))
            a = json.loads((root / "out" / "arm_a.json").read_text(encoding="utf-8"))
        return s, c, a, docs

    def test_arm_c_withdraws_each_text_on_its_own_and_previews_a_step_at_its_start(self):
        P.ARM_A_WITHDRAWN_CHECK = False  # a plan with messages requires it
        lead = Lead()
        s, c, a, docs = self.kernel_run(plan, team=[lead, P.StubModel(), P.StubModel()])
        paths = sorted(docs)
        whole = docs[paths[0]]
        # one withdrawal, one journal frame, per text: the whole report, then each candidate of 2B in its own report
        self.assertEqual([(w["step"], w["phase"], w["report"], w["reason"]) for w in c["withdrawals"]],
                         [("2A", 2, paths[0], P.WHOLE_REASON), ("2B", 3, paths[1], P.ALL_REASON), ("2B", 3, paths[2], P.ALL_REASON)])
        self.assertEqual((c["withdrawals"][0]["quote"], c["withdrawals"][0]["anchor"]), (whole, "# Rule 0"))
        self.assertTrue(c["withdrawals"][0]["observes"], "every observe of the whole report is the step's")
        self.assertEqual([r["status"] for r in c["revoke"]], ["REVOKED"] * 3, c["revoke"])
        # each withdrawal names its bytes, the whole report's all of them
        first, second = (docs[t["report"]].index(t["quote"]) for t in plan(paths)["steps"][1]["candidates"])
        self.assertEqual([w["quote_span"] for w in c["withdrawals"]],
                         [[0, len(whole.encode("utf-8"))], [first, first + len("The old check of rule 1 was removed.")],
                          [second, second + len("A known limitation remains for version rule 2.")]])
        # one preview per text, every one of a step taken before the step's first withdrawal: both of 2B at the same point
        previews = c["withdraw_preview"]
        self.assertEqual([(p["step"], p["report"], p["status"], p["written"], p["describes"]) for p in previews],
                         [("2A", paths[0], "PREVIEW", False, P.PREVIEW_STATE), ("2B", paths[1], "PREVIEW", False, P.PREVIEW_STATE),
                          ("2B", paths[2], "PREVIEW", False, P.PREVIEW_STATE)])
        self.assertEqual([p["quote_span"] for p in previews], [w["quote_span"] for w in c["withdrawals"]])
        self.assertEqual((previews[1]["since"], previews[2]["since"]), (c["revoke"][1]["since"], c["revoke"][1]["since"]))
        self.assertGreater(c["revoke"][2]["since"], c["revoke"][1]["since"], "2B's second text withdrawn after its first")
        self.assertGreater(previews[0]["fell"], 0)
        self.assertEqual(previews[0]["fell"], c["revoke"][0]["fell"], "the preview named what the withdrawal then made fall")
        # compared per step: what the step's withdrawals made fall together, beside the rows its previews named
        self.assertEqual(c["phase3"]["fell"], c["revoke"][1]["fell"] + c["revoke"][2]["fell"])
        self.assertEqual(c["phase3"]["previewed"], {"rows": c["phase3"]["fell"], "describes": P.PREVIEW_STATE})
        # everything on the whole report fell: the answers rested on it before and on none of it after
        self.assertTrue(quoted(c["phase1"]["answers"], paths[0]))
        for phase in ("phase2", "phase3"):
            self.assertEqual(c[phase]["receipt"]["status"], "TERMINAL", phase)
            self.assertFalse(quoted(c[phase]["answers"], paths[0]), phase)
        self.assertEqual((c["phase2"]["step"], c["phase3"]["step"]), ("2A", "2B"))
        # arm A: one phase per step, its texts grouped from arm C's withdrawals; each update hears every message so far, in order
        self.assertEqual((a["phase2"]["step"], a["phase3"]["step"]), ("2A", "2B"))
        third = [p for p in lead.prompts if p.startswith("ARM A TEAM") and CITING in p]
        self.assertTrue(third and all(0 <= p.index(RETRACTED) < p.index(CITING) for p in third))
        self.assertEqual(sorted(a["phase3"]["affected"]), [q["id"] for q in THREE])
        self.assertTrue(quoted(a["phase2"]["answers"], paths[0]), "without the check arm A may still rest on the retracted report")
        self.assertIs(s["strong_reader"]["arm_a_withdrawn_check"], False, "the run records the setting")

    def test_a_whole_report_with_crlf_and_a_bom_is_withdrawn_byte_for_byte(self):
        P.ARM_A_FROZEN = True
        docs = dict(DOCS)
        retracted = sorted(docs)[0]
        docs[retracted] = "﻿# Rule 0\r\nA known limitation remains for version rule 0.\r\nThe old check of rule 0 was removed.\r\n"
        s, c, _, docs = self.kernel_run(lambda paths: {"steps": [{"name": "2A", "report": paths[0], "whole": True}]}, docs=docs)
        entry = c["withdrawals"][0]
        self.assertEqual((entry["quote"], entry["anchor"]), (docs[retracted], "﻿# Rule 0"))
        self.assertEqual(entry["quote_span"], [0, len(docs[retracted].encode("utf-8"))], "the BOM's three bytes and every CR are in it")
        self.assertEqual([r["status"] for r in c["revoke"]], ["REVOKED"], c["revoke"])
        self.assertEqual(c["phase2"]["receipt"]["status"], "TERMINAL")
        self.assertTrue(quoted(c["phase1"]["answers"], retracted))
        self.assertFalse(quoted(c["phase2"]["answers"], retracted))
        self.assertIs(s["strong_reader"]["arm_a_withdrawn_check"], True)

    def test_arm_a_hears_the_messages_and_never_the_withdrawn_text(self):
        lead = Lead()
        a = self.team(lead, P.StubModel())
        paths = sorted(DOCS)
        quotes = [c["quote"] for c in plan(paths)["steps"][1]["candidates"]]
        updates = [p for p in lead.prompts if p.startswith("ARM A TEAM") and "YOUR ANSWER BEFORE THE WITHDRAWAL" in p]
        self.assertEqual(len(updates), 2 * len(P.QUESTIONS), "each question once in each phase")
        for prompt in updates:
            self.assertIn(f"NOTICE: {RETRACTED}\n", told(prompt))
            self.assertFalse(any(q in told(prompt) for q in quotes), "a candidate's text is not told")
        self.assertEqual(sum(CITING in p for p in updates), len(P.QUESTIONS), "the second notice from its own phase on")
        self.assertFalse([p for p in lead.prompts if "WITHDRAWN QUOTE" in p])
        # the updates and their repairs (phase 1 read the report before its retraction, as arm C did)
        later = [p for p in lead.prompts if f"NOTICE: {RETRACTED}" in p]
        self.assertGreater(len(later), len(updates), "the repairs carry the notices too")
        for prompt in later:
            self.assertNotIn(DOCS[paths[0]], prompt, "the retracted report's text is never sent with a notice")
        self.assertEqual((a["phase2"]["step"], a["phase3"]["step"]), ("2A", "2B"))
        self.assertIsNone(a["stopped"])

    def test_the_conclusions_a_notice_affects_are_recorded_and_refused_nowhere(self):
        a = self.team(Lead(), P.StubModel())
        self.assertNotIn("affected", a["phase1"])
        for phase in ("phase2", "phase3"):
            self.assertEqual(a[phase]["affected"], {q["id"]: [f"My answer to {q['id']} rested on the retracted paper."] for q in P.QUESTIONS})
            for ans in a[phase]["answers"].values():
                self.assertFalse([r for r in ans["refused_at_end"] if r.get("kind") == "affected"], ans["refused_at_end"])
        # an affected line where none was asked is refused as before
        _, refused, _ = P.check_single([{"kind": "affected", "text": "x"}], DOCS, [], {})
        self.assertEqual([r["kind"] for r in refused], ["affected"])

    def test_without_the_withdrawn_check_a_quote_on_withdrawn_text_is_kept(self):
        retracted = sorted(DOCS)[0]
        line = "The old check of rule 0 was removed."
        claim = {"kind": "claim", "local_id": "a1", "text": "t", "quotes": [{"report": retracted, "exact_quote": line}]}
        withdrawn = [{"report": retracted, "quote": DOCS[retracted]}]
        _, refused, _ = P.check_single([claim], DOCS, withdrawn, {})
        self.assertIn("rests on withdrawn text", refused[0]["why"])
        a = self.team(Lead())
        self.assertTrue(quoted(a["phase1"]["answers"], retracted))
        self.assertFalse(quoted(a["phase2"]["answers"], retracted), "by default a quote on withdrawn text is refused")
        P.ARM_A_WITHDRAWN_CHECK = False
        new, refused, _ = P.check_single([claim], DOCS, withdrawn, {})
        self.assertEqual((list(new), refused), (["a1"], []))
        bad = dict(claim, quotes=[{"report": retracted, "exact_quote": "not in the report"}])
        self.assertIn("not found", P.check_single([bad], DOCS, withdrawn, {})[1][0]["why"], "its bytes are still checked")
        a = self.team(Lead())
        self.assertTrue(quoted(a["phase2"]["answers"], retracted), "kept: the withdrawn span is not checked")
        self.assertEqual([a[p]["status"] for p in ("phase2", "phase3")], ["COMPLETE", "COMPLETE"])

    def test_a_declined_update_leaves_the_answer_it_updated_for_the_next_step(self):
        rq = P.QUESTIONS[0]["id"]
        lead = DecliningLead(rq)
        a = self.team(lead)
        declined_update = a["phase2"]["answers"][rq]
        self.assertEqual((declined_update["claims"], declined_update["model_refused"]), ([], True), "the phase keeps the declined answer")
        self.assertEqual(a["phase2"]["status"], "INCOMPLETE")
        third = [p for p in lead.prompts if p.startswith("ARM A TEAM") and f"\nQUESTION {rq}:" in p and CITING in p]
        self.assertEqual(len(third), 1)
        shown = before(third[0])
        self.assertNotEqual(shown, "(no claims)")
        self.assertEqual([json.loads(ln)["local_id"] for ln in shown.splitlines()], [cl["id"] for cl in a["phase1"]["answers"][rq]["claims"]],
                         "2B updates the answer of phase 1, the last one given")
        other = P.QUESTIONS[1]["id"]
        shown_other = before(next(p for p in lead.prompts if p.startswith("ARM A TEAM") and f"\nQUESTION {other}:" in p and CITING in p))
        self.assertEqual([json.loads(ln)["local_id"] for ln in shown_other.splitlines()], [cl["id"] for cl in a["phase2"]["answers"][other]["claims"]],
                         "an answered update is the one the next step updates")

    def test_a_plan_without_messages_tells_each_withdrawn_text_as_before(self):
        lead = Lead()
        paths = sorted(DOCS)
        self.team(lead, withdraw=plan(paths, messages=False))
        third = [p for p in lead.prompts if p.startswith("ARM A TEAM") and "YOUR ANSWER BEFORE" in p and "rule 2" in told(p)]
        self.assertEqual(len(third), len(P.QUESTIONS))
        self.assertEqual(told(third[0]).count("WITHDRAWN QUOTE: "), 3, "the whole report and both texts of 2B")
        self.assertNotIn('"kind":"affected"', third[0])

    def test_a_plan_is_checked_before_any_work(self):
        P.ARM_A_MODE = "team"
        paths = sorted(DOCS)
        # a plan with messages: arm A is not told the withdrawn text, so the runner may not refuse its quotes of that text
        with self.assertRaisesRegex(ValueError, "needs --arm-a-no-withdrawn-check: arm A is not told the withdrawn text"):
            R.check_withdrawal(plan(paths), DOCS)
        R.check_withdrawal(plan(paths, messages=False), DOCS)
        P.ARM_A_FROZEN = True
        R.check_withdrawal(plan(paths), DOCS)
        P.ARM_A_FROZEN, P.ARM_A_WITHDRAWN_CHECK = False, False
        R.check_withdrawal(plan(paths), DOCS)
        unknown = plan(paths)
        unknown["steps"][0]["report"] = "reports/missing.md"
        with self.assertRaisesRegex(ValueError, "whole step names a selected report"):
            R.check_withdrawal(unknown, DOCS)
        elsewhere = plan(paths)
        elsewhere["steps"][1]["candidates"][1]["report"] = paths[3]
        with self.assertRaisesRegex(ValueError, "each candidate of an all step"):
            R.check_withdrawal(elsewhere, DOCS)
        empty = plan(paths)
        empty["steps"][1]["candidates"] = []
        with self.assertRaisesRegex(ValueError, "at least one candidate"):
            R.check_withdrawal(empty, DOCS)
        # the kernel closes every occurrence of a withdrawn text: a sentence an all step names occurs once in its report
        twice = dict(DOCS)
        twice[paths[1]] += "The old check of rule 1 was removed.\n"
        with self.assertRaisesRegex(ValueError, "occurs exactly once"):
            R.check_withdrawal(plan(paths), twice)
        # arm A finds a step's texts by its name
        same = plan(paths)
        same["steps"][1]["name"] = "2A"
        with self.assertRaisesRegex(ValueError, "names must be unique"):
            R.check_withdrawal(same, DOCS)
        # the map-reduce answer and the notes arm build their prompts from the withdrawn text: a message cannot be told there
        P.ARM_A_ANSWER = "map-reduce"
        with self.assertRaisesRegex(ValueError, "message"):
            R.check_withdrawal(plan(paths), DOCS)
        R.check_withdrawal(plan(paths, messages=False), DOCS)
        P.ARM_A_ANSWER, P.ARM_A_MODE = "direct", "notes"
        with self.assertRaisesRegex(ValueError, "message"):
            R.check_withdrawal(plan(paths), DOCS)

    def test_a_refusal_in_the_team_closes_its_task_and_the_arm_goes_on(self):
        rq, declined_report = P.QUESTIONS[0]["id"], sorted(DOCS)[1]
        a = self.team(Declining(report=declined_report, question=rq))
        self.assertIsNone(a["stopped"])
        refused = [e for e in a["events"] if e.get("outcome") == "MODEL_REFUSED"]
        self.assertEqual([e["report"] for e in refused if e.get("kind") == "WORKER"], [declined_report])
        self.assertFalse(quoted(a["phase1"]["answers"], declined_report), "a declined section gives no notes")
        self.assertTrue(quoted(a["phase1"]["answers"], sorted(DOCS)[2]), "the other sections were read")
        self.assertEqual([e["rq_id"] for e in refused if e.get("kind") == "LEAD"], [rq])
        first = a["phase1"]["answers"][rq]
        self.assertEqual((first["claims"], first["complete"], first["model_refused"]), ([], False, True))
        self.assertEqual(a["phase1"]["status"], "INCOMPLETE")
        self.assertIn("MODEL_REFUSED", a["phase1"]["reason"])
        self.assertEqual(sorted(a["phase1"]["answers"]), sorted(q["id"] for q in P.QUESTIONS), "the next question went on")
        self.assertEqual((a["phase2"]["step"], a["phase3"]["step"]), ("2A", "2B"), "and the withdrawals")

    def test_the_outcome_counter_takes_a_step_of_two_texts_as_one_phase(self):
        import revision_outcomes as O
        paths = sorted(DOCS)
        texts = plan(paths)["steps"][1]["candidates"]
        other = (paths[3], "The old check of rule 3 was removed.")

        def answer(*quotes):
            return {"RQ1": {"claims": [{"quotes": [{"report": r, "quote": q} for r, q in quotes]}]}}

        with tempfile.TemporaryDirectory() as tmp:
            folder = pathlib.Path(tmp)
            (folder / "summary.json").write_text(json.dumps({"withdrawn": [dict(t, step="2B", phase=2) for t in texts]}), encoding="utf-8")
            side = {"phase1": {"answers": answer(*((t["report"], t["quote"]) for t in texts), other)},
                    "phase2": {"status": "COMPLETE", "answers": answer(other)}}
            (folder / "arm_a.json").write_text(json.dumps(side), encoding="utf-8")
            calls = [{"call_id": "a", "arm": "A", "phase": 2}, {"call_id": "b", "arm": "A", "phase": 2}]
            (folder / "calls.jsonl").write_text("\n".join(json.dumps(c) for c in calls), encoding="utf-8")
            (folder / "contexts.jsonl").write_text(json.dumps({"call_id": "a", "report": paths[2]}), encoding="utf-8")
            rows = O.outcomes(folder)
        self.assertEqual([(r["step"], r["texts"], r["calls"], r["withdrawn_page"], r["other_pages"]) for r in rows], [("2B", 2, 2, 1, 1)])
        self.assertEqual((rows[0]["quotes_before"], rows[0]["quotes_touched"], rows[0]["quotes_untouched_not_cited_after"]), (3, 2, 0))

    def test_another_model_error_still_stops_the_team_arm(self):
        a = self.team(Declining(error="Not logged in"))
        self.assertTrue(a["stopped"].startswith("MODEL_ERROR"), a["stopped"])

    def test_fable_is_an_alias_of_the_claude_cli(self):
        model = P.make_model("fable", "high")
        self.assertEqual((type(model), model.name, model.effort, model.timeout_s), (P.ClaudeCliModel, P.CLAUDE_FABLE, "high", 1200.0))
        self.assertEqual(P.CLAUDE_FABLE, "claude-fable-5-2")
        self.assertEqual(P.make_model("fable", timeout_s=60.0).timeout_s, 60.0)


if __name__ == "__main__":
    unittest.main()
