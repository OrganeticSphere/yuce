"""The control runs: arm C without the graph builder (`--build-scope none`) or with links off (`concepts`), on
the stub team in real kernel circles. Needs the kernel binary; no provider is called."""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_pilot_ac as R  # noqa: E402
from sbgk_bench import pilot_ac as P  # noqa: E402
from sbgk_bench import common as C  # noqa: E402


def corpus(root: pathlib.Path, docs: dict[str, str] | None = None) -> tuple[pathlib.Path, dict[str, str]]:
    # two findings a page, so a reader writes two claims it can relate
    docs = docs or {f"reports/scope_{i}.md": f"# Rule {i}\nA known limitation remains for version rule {i}.\nThe old check of rule {i} was removed.\n"
                    for i in range(6)}
    entries = []
    for path, text in docs.items():
        dest = root / "repo" / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        raw = text.encode("utf-8")
        dest.write_bytes(raw)
        entries.append({"path": path, "extension": ".md", "corpus_role": "markdown_document_candidate", "size_bytes": len(raw),
                        "raw_sha256": hashlib.sha256(raw).hexdigest(), "references": {"commit_candidates": [], "pull_request_candidates": []}})
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"format": "r2r.tobi_corpus_metadata_manifest.v1", "entries": entries,
                                    "source": {"origin_recorded": "https://example.invalid/scope.git", "commit": "1" * 40, "repository": "local"}}),
                        encoding="utf-8")
    return manifest, docs


class RelatingStub(P.StubModel):
    """A reader that also relates its first two claims (Codex review of 8023910, SCOPE-01): in a control profile the kernel must
    refuse the relation line; on the repair it drops it, as a model told why would."""

    def complete(self, prompt: str):
        text, usage, cost = super().complete(prompt)
        lines = [json.loads(x) for x in text.splitlines() if x.strip().startswith("{")]
        if prompt.startswith("FIX THESE ANSWER LINES"):
            return "\n".join(json.dumps(x) for x in lines if x.get("kind") != "relation"), usage, cost
        prefix = re.search(r"every local_id starts with (\S+?)\.", prompt)
        claims = [x for x in lines if x.get("kind") == "claim"]
        if "TASK EXTEND" in prompt and prefix and len(claims) >= 2:
            lines.append({"kind": "relation", "local_id": f"{prefix.group(1)}r9", "from": claims[1]["local_id"], "rel": "supports",
                          "to": claims[0]["local_id"], "based_on": claims[0]["based_on"] + claims[1]["based_on"]})
        return "\n".join(json.dumps(x) for x in lines), usage, cost


class StubbornReader(P.StubModel):
    """A reader whose first answer to a section adds a quote the section does not hold, and whose every repair sends that quote
    again: its repairs run out and the reading closes on the lines the kernel stored."""

    def __init__(self):
        self.answered: set[str] = set()

    @staticmethod
    def repaired(bad: str) -> str:
        return bad

    def complete(self, prompt: str):
        if "TASK EXTEND" not in prompt or "TASK RELATE" in prompt or '"answer_done"' in prompt:
            return super().complete(prompt)
        doc = re.search(r'SECTION doc_id="([^"]+)"', prompt).group(1)
        p = re.search(r"every local_id starts with (\S+?)\.", prompt).group(1)
        bad = json.dumps({"kind": "observe", "local_id": f"{p}o9", "doc_id": doc, "exact_quote": "Nothing like this is written here.", "terms": ["x"]})
        if p in self.answered:
            return self.repaired(bad), {}, 0.0
        self.answered.add(p)
        text, usage, cost = super().complete(prompt)
        return text + "\n" + bad, usage, cost


class OnceWrongReader(StubbornReader):
    """A reader whose one repair of a section leaves the wrong quote out: one repair a reading."""

    @staticmethod
    def repaired(bad: str) -> str:
        return "[]"


class OverrunningSummarizer(P.StubModel):
    """A team whose first summary of each question runs past the output bound (live run MCPctl_none_r2)."""

    overran: set[str] = set()

    def complete(self, prompt: str):
        rq = re.search(r'"rq_id":"([^"]+)"', prompt)
        if "TASK SUMMARIZE research question" in prompt and rq and rq.group(1) not in self.overran:
            self.overran.add(rq.group(1))
            raise P.CallFailed(f"{P.OUTPUT_OVERRUN}: API Error: Claude's response exceeded the 32000 output token maximum.", 0.0)
        return super().complete(prompt)


class OverrunningRelater(P.StubModel):
    """A reader whose RELATE turns run past the output bound: each turn ends as timed out, its reading stays stored."""

    def complete(self, prompt: str):
        if "TASK RELATE" in prompt:
            raise P.CallFailed(f"{P.OUTPUT_OVERRUN}: API Error: Claude's response exceeded the 32000 output token maximum.", 0.0)
        return super().complete(prompt)


class StubbornOverrunningRelater(StubbornReader):
    """A reader whose repairs run out, and whose RELATE turn after the closed reading runs past the output bound."""

    def complete(self, prompt: str):
        if "TASK RELATE" in prompt:
            raise P.CallFailed(f"{P.OUTPUT_OVERRUN}: API Error: Claude's response exceeded the 32000 output token maximum.", 0.0)
        return super().complete(prompt)


@unittest.skipUnless(C.BIN.exists(), "the kernel binary is not built")
class BuildScope(unittest.TestCase):
    def setUp(self):
        self.saved = {k: v for k, v in vars(P).items() if k.isupper()}
        P.ARM_A_MODE, P.PAIRS_ONLY, P.LINK_CHECKER = "team", False, True
        P.DYNAMIC_ROLES, P.BUILD_BACKLOG, P.CHECKER_MODEL = True, 1, P.StubModel()
        P.CIRCLES, P.WAVE_SECTIONS = True, 3

    def tearDown(self):
        vars(P).update(self.saved)

    def run_c(self, scope: str, model=P.StubModel, docs: dict[str, str] | None = None) -> dict:
        P.BUILD_SCOPE = scope
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest, docs = corpus(root, docs)
            team = [model(), model(), model()]
            return P.run_arm_c(team[0], team[0], root / "work", manifest, root / "repo", list(docs), docs, {"steps": []}, workers=3,
                               timeout_s=120, max_calls=200, team=team, builder_card=None if scope in ("none", "hints") else {"max_records": 16})

    def test_without_the_builder_the_run_ends_terminal_and_says_so(self):
        r = self.run_c("none")
        receipt, st = r["phase1"]["receipt"], r["phase1"]["status"]
        self.assertEqual((receipt["status"], receipt.get("build_scope")), ("TERMINAL", "none"), receipt)
        roles = {c["role"] for c in r["calls"]}
        self.assertNotIn("BUILD", roles)
        self.assertNotIn("VERIFY_LINK", roles)
        self.assertIn("EXTEND", roles)
        self.assertEqual(st["build_scope"], "none")
        self.assertEqual((st["builder"]["cards"], st["links"]), (0, {"proposed": 0, "accepted": 0, "rejected": 0}), st)
        self.assertEqual(st["builder_cursor"], st["records"], "no builder to wait for: the cursor is the head")
        self.assertTrue(all(a["outcome"] for a in r["phase1"]["answers"].values()), r["phase1"]["answers"])
        # the window of a control run spans more reports than a concept-narrowed one: every question still gets its answer
        self.assertEqual(st["completion"]["unresolved"], [], st["completion"])

    def test_with_links_off_the_builder_names_concepts_and_makes_no_link(self):
        r = self.run_c("concepts")
        receipt, st = r["phase1"]["receipt"], r["phase1"]["status"]
        self.assertEqual((receipt["status"], receipt.get("build_scope")), ("TERMINAL", "concepts"), receipt)
        roles = {c["role"] for c in r["calls"]}
        self.assertIn("BUILD", roles)
        self.assertNotIn("VERIFY_LINK", roles)
        self.assertEqual(st["build_scope"], "concepts")
        self.assertGreater(st["builder"]["concepts_proposed"], 0, st)
        self.assertEqual((st["builder"]["links_proposed"], st["links"]), (0, {"proposed": 0, "accepted": 0, "rejected": 0}), st)
        self.assertEqual((st["builder_cursor"], st["open_builder_cards"]), (st["records"], 0), st)
        self.assertEqual(st["completion"]["unresolved"], [], st["completion"])


    def test_a_readers_relation_is_refused_in_both_control_scopes_and_no_link_is_made(self):
        # Codex review of 8023910, SCOPE-01: the full run stores the same relation as a link to check, the control runs do not
        full = self.run_c("full", RelatingStub)
        self.assertGreater(full["phase1"]["status"]["links"]["proposed"] + full["phase1"]["status"]["links"]["accepted"]
                           + full["phase1"]["status"]["links"]["rejected"], 0, "the relation is a link in an ordinary run")
        for scope in ("none", "concepts"):
            r = self.run_c(scope, RelatingStub)
            st = r["phase1"]["status"]
            self.assertEqual(r["phase1"]["receipt"]["status"], "TERMINAL", r["phase1"]["receipt"])
            self.assertEqual(st["links"], {"proposed": 0, "accepted": 0, "rejected": 0}, (scope, st["links"]))
            self.assertNotIn("VERIFY_LINK", {c["role"] for c in r["calls"]}, scope)
            written = [c for c in r["calls"] if c["role"] == "EXTEND" and '"kind": "relation"' in (c.get("text") or "")]
            self.assertTrue(written, f"{scope}: the readers did write relation lines")
            self.assertGreater(st["dispatch"]["repairs"], 0, f"{scope}: and the kernel refused them for repair")

    def test_without_the_builder_and_without_circles_the_run_starts_and_ends_terminal(self):
        # Codex review of 8023910, SCOPE-02: without dynamic roles the runner named a builder subject the kernel refuses
        P.DYNAMIC_ROLES, P.CIRCLES, P.WAVE_SECTIONS = False, False, None
        r = self.run_c("none")
        self.assertEqual((r["phase1"]["receipt"]["status"], r["phase1"]["receipt"].get("build_scope")), ("TERMINAL", "none"))
        self.assertNotIn("BUILD", {c["role"] for c in r["calls"]})


class Flags(unittest.TestCase):
    def refused(self, *flags: str) -> str:
        saved = {k: v for k, v in vars(P).items() if k.isupper()}
        try:
            with mock.patch.object(sys, "argv", ["run_pilot_ac.py", "--model", "stub", *flags]):
                with self.assertRaises(SystemExit) as stop:
                    R.main()
            return str(stop.exception)
        finally:
            vars(P).update(saved)

    def test_a_control_scope_refuses_what_makes_links(self):
        self.assertIn("--evolution-cards", self.refused("--build-scope", "concepts", "--evolution-cards"))
        self.assertIn("--builder-max-links", self.refused("--build-scope", "none", "--builder-max-links", "4"))

    def test_without_a_builder_its_card_settings_are_refused(self):
        self.assertIn("--builder-max-records", self.refused("--build-scope", "none", "--builder-max-records", "16"))


@unittest.skipUnless(C.BIN.exists(), "the kernel binary is not built")
class StrongGraph(unittest.TestCase):
    setUp, tearDown, run_c = BuildScope.setUp, BuildScope.tearDown, BuildScope.run_c

    def test_the_strongest_graph_pairs_by_words_and_links_the_change_on_a_packed_card(self):
        # the lexical pairing run: pairs from the claims' own words on dated reports, cards of up to four pairs; the stub
        # links the first pair of a card and the checker confirms it
        P.GRAPH_QUALITY = {"temporal_summary": True, "evolution_cards": True, "evolution_pairing": "lexical", "evolution_pairs_per_card": 4}
        r = self.run_c("full", docs=DATED)
        receipt, st = r["phase1"]["receipt"], r["phase1"]["status"]
        self.assertEqual(receipt["status"], "TERMINAL", receipt)
        self.assertEqual(st["graph_quality"]["config"]["evolution_pairing"], "lexical", st["graph_quality"])
        self.assertGreater(st["graph_quality"]["evolution"]["cards_issued"], 0, st["graph_quality"])
        self.assertEqual(st["graph_quality"]["evolution"]["pairs_without_a_taker"], 0, st["graph_quality"])
        self.assertGreater(st["links"]["accepted"], 0, st["links"])

    def test_a_graph_option_the_kernel_did_not_take_stops_the_run_before_any_model_call(self):
        P.GRAPH_QUALITY = {"no_such_option": "on"}  # a flag the server does not know: it refuses to start and names it
        with self.assertRaisesRegex(RuntimeError, "no.such.option"):
            self.run_c("full")



# three dated reports, two of them about one feature that a later version ends
DATED = {
    "reports/batching.md": "+++\ndate = \"2025-01-01\"\n+++\n# Batching\nA known limitation: the legacy batching window stays unsupported for streams.\n"
                           "The batching warning fires after ten seconds of idle streams.\n",
    "reports/logging.md": "+++\ndate = \"2025-06-01\"\n+++\n# Logging\nA known limitation: audit trails rotate their syslog files daily.\n"
                          "The syslog warning lists every dropped severity record.\n",
    "reports/batching_v2.md": "+++\ndate = \"2026-01-01\"\n+++\n# Batching removal\nThe legacy batching window was removed from every stream server.\n"
                              "The batching warning for idle streams was removed as well.\n",
}


@unittest.skipUnless(C.BIN.exists(), "the kernel binary is not built")
class Hints(unittest.TestCase):
    setUp, tearDown, run_c = BuildScope.setUp, BuildScope.tearDown, BuildScope.run_c

    def test_with_hints_a_reading_task_relates_its_claims_to_other_report_dates_and_the_run_ends(self):
        # the hint profile: no builder; a stored reading answer gets one more turn with the claims of other report
        # dates that share its words, and the stub writes the change on both quotes
        r = self.run_c("hints", docs=DATED)
        receipt, st = r["phase1"]["receipt"], r["phase1"]["status"]
        self.assertEqual((receipt["status"], receipt.get("build_scope")), ("TERMINAL", "hints"), receipt)
        roles = {c["role"] for c in r["calls"]}
        self.assertNotIn("BUILD", roles)
        self.assertNotIn("VERIFY_LINK", roles)
        self.assertGreater(st["dispatch"]["relate_turns"], 0, st["dispatch"])
        self.assertTrue(any(c["call_id"].endswith("-r0") for c in r["calls"]), [c["call_id"] for c in r["calls"]])
        self.assertEqual((st["links"], st["completion"]["unresolved"]), ({"proposed": 0, "accepted": 0, "rejected": 0}, []), st)

    def test_a_reading_whose_repairs_run_out_still_takes_its_relate_turn(self):
        # the hints pre-flight of 8d771feb: such a reading closed on its stored lines after the RELATE loop, and the turn the kernel
        # opened was released unasked (2 turns of 12)
        r = self.run_c("hints", model=StubbornReader, docs=DATED)
        receipt, st = r["phase1"]["receipt"], r["phase1"]["status"]
        self.assertEqual(receipt["status"], "TERMINAL", receipt)
        ids = [c["call_id"] for c in r["calls"]]
        self.assertTrue(any(c["role"] == "EXTEND" and c["call_id"].endswith("-1") for c in r["calls"]), ids)
        self.assertGreater(st["dispatch"]["relate_turns"], 0, st["dispatch"])
        self.assertEqual(sum(1 for i in ids if i.endswith("-r0")), st["dispatch"]["relate_turns"], ids)
        self.assertEqual(st["completion"]["unresolved"], [], st["completion"])

    def test_a_relate_turn_keeps_the_readings_repairs_in_the_task_event(self):
        # claude-reviewer's RV-01 of d8ab1a74: the turn wrote its repairs over the reading's, and a hints run would have shown almost
        # no reading repairs beside an honest count in none
        def readings(scope, model):
            return [e for e in self.run_c(scope, model=model, docs=DATED)["events"] if e.get("kind") == "EXTEND" and "abandoned" in e]

        for model in (OnceWrongReader, StubbornReader):
            none, hints = readings("none", model), readings("hints", model)
            want = {e["repairs"] for e in none}
            self.assertEqual(len(want), 1, none)
            self.assertGreater(min(want), 0, none)
            self.assertEqual({e["repairs"] for e in hints}, want, (model.__name__, hints))
            self.assertTrue(any("relate_repairs" in e for e in hints), (model.__name__, hints))
            if model is OnceWrongReader:
                self.assertEqual(want, {1})

    def test_a_reading_whose_relate_turn_timed_out_counts_as_committed(self):
        # a RELATE_TIMED_OUT event had no `abandoned`, and measures() left the stored reading out of every count
        r = self.run_c("hints", model=OverrunningRelater, docs=DATED)
        timed = [e for e in r["events"] if e.get("outcome") == "RELATE_TIMED_OUT"]
        self.assertGreater(len(timed), 0, [e.get("outcome") for e in r["events"]])
        self.assertTrue(all(e["abandoned"] is False and e["error"] is None and "repairs" in e for e in timed), timed)
        tasks = P.measures({"events": [], "calls": []}, {"events": r["events"], "calls": r["calls"]})["swarm_tasks"]
        self.assertGreaterEqual(tasks["committed"], len(timed), tasks)
        self.assertFalse({e["key"] for e in timed} & set(tasks["abandoned"]), tasks)

    def test_a_timed_out_relate_turn_after_a_closed_reading_keeps_the_readings_refusal(self):
        # claude-reviewer's note 1 on 055fd50: the event wrote error=None, and the code was missing from swarm_tasks.refusals
        r = self.run_c("hints", model=StubbornOverrunningRelater, docs=DATED)
        timed = [e for e in r["events"] if e.get("outcome") == "RELATE_TIMED_OUT"]
        self.assertGreater(len(timed), 0, [e.get("outcome") for e in r["events"]])
        self.assertTrue(all(e["abandoned"] is True and e["error"] for e in timed), timed)
        tasks = P.measures({"events": [], "calls": []}, {"events": r["events"], "calls": r["calls"]})["swarm_tasks"]
        self.assertLessEqual({e["error"] for e in timed}, set(tasks["refusals"]), tasks)


@unittest.skipUnless(C.BIN.exists(), "the kernel binary is not built")
class OutputOverrun(unittest.TestCase):
    setUp, tearDown, run_c = BuildScope.setUp, BuildScope.tearDown, BuildScope.run_c

    def test_a_summary_that_runs_past_the_output_bound_is_given_out_again_and_answered(self):
        # claude-reviewer's RV-01 of 87b54b2b: the task is released at once, whatever the time the model took to overrun
        plain = {k: a["outcome"] for k, a in self.run_c("none")["phase1"]["answers"].items()}
        OverrunningSummarizer.overran = set()
        r = self.run_c("none", model=OverrunningSummarizer)
        receipt, st = r["phase1"]["receipt"], r["phase1"]["status"]
        self.assertEqual(receipt["status"], "TERMINAL", receipt)
        over = [e for e in r["events"] if e.get("outcome") == "AGENT_OUTPUT_OVERRUN"]
        self.assertEqual(len(over), len(OverrunningSummarizer.overran), over)
        self.assertGreater(len(over), 0)
        self.assertFalse([e for e in r["events"] if e.get("outcome") == "MODEL_REFUSED"])
        self.assertEqual({k: a["outcome"] for k, a in r["phase1"]["answers"].items()}, plain, "each question ends as without the overrun")
        self.assertEqual(st["completion"]["unresolved"], [], st["completion"])


if __name__ == "__main__":
    unittest.main()
