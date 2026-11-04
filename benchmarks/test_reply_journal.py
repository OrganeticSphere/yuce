"""Every reply to a swarm submission is journaled (replies.jsonl), the refusal of a task's last attempt too: the store's WAL holds no
line a dispatcher rule refused (the B1 side session's check of 10A-13), and a task given up in 10A-13 showed only an error code."""
from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402
import run_pilot_ac as R  # noqa: E402


class ReplyJournal(unittest.TestCase):
    def test_a_dispatcher_refusal_is_journaled_with_its_rule_and_line(self):
        seen = []
        log = P.Log(evidence=lambda kind, value: seen.append((kind, value)))
        refusal = {"status": "REPAIR_REQUIRED", "task_id": "T6", "failed_index": 9, "repair_scope": "accepted_prefix",
                   "accepted": ["@a", "@b"], "error": {"code": "NO_EVIDENCE", "field": "based_on", "message": "a claim names only identifiers"},
                   "problems": [{"line": 9, "local_id": "t6_c1", "missing_identifiers": ["#130"], "needs": "a claim names only identifiers"}]}
        self.assertIs(log.reply(refusal, task="T6", kind="EXTEND", call_id="C1-T6-2", lines_submitted=12), refusal)
        kind, value = seen[0]
        self.assertEqual(kind, "reply")
        self.assertEqual((value["code"], value["failed_index"], value["accepted"], value["repair_scope"]), ("NO_EVIDENCE", 9, 2, "accepted_prefix"))
        self.assertEqual(value["problems"][0]["rules"], ["missing_identifiers"])
        self.assertEqual(value["call_id"], "C1-T6-2")
        self.assertEqual(value["reply"], refusal, "the whole reply, not an index of it (Codex's review of deb7fe2, RJ-01)")
        self.assertEqual(len(value["reply_sha256"]), 64)

    def test_a_format_refusal_keeps_its_broken_lines_and_a_long_reply_is_marked(self):
        seen = []
        log = P.Log(evidence=lambda kind, value: seen.append(value))
        broken = {"status": "REPAIR_REQUIRED", "failed_index": 0, "local": True,
                  "error": {"code": "BROKEN_JSON_LINE", "message": "these did not parse", "lines": ['{"kind":"observe"']}}
        log.reply(broken, task="T1")
        self.assertEqual(seen[0]["reply"]["error"]["lines"], ['{"kind":"observe"'])
        huge = {"status": "REPAIR_REQUIRED", "error": {"code": "X", "message": "m"}, "pad": "x" * (P.REPLY_MAX_CHARS + 10)}
        log.reply(huge, task="T2")
        self.assertIsNone(seen[1]["reply"])
        self.assertEqual(len(seen[1]["reply_prefix"]), P.REPLY_MAX_CHARS)
        self.assertGreater(seen[1]["reply_chars"], P.REPLY_MAX_CHARS)

    def test_a_whole_summary_refusal_lists_its_lines(self):
        seen = []
        log = P.Log(evidence=lambda kind, value: seen.append(value))
        refusal = {"status": "REPAIR_REQUIRED", "failed_index": 0, "repair_scope": "whole_answer",
                   "error": {"code": "BAD_FIELD", "field": "lines", "message": "nothing was stored",
                             "expected_by_kernel": {"lines": [{"line": 33, "local_id": "t1_c34", "needs": "text of 1..240 characters"}]}}}
        log.reply(refusal, task="TS1")
        self.assertEqual(seen[0]["problems"][0]["local_id"], "t1_c34")

    def test_graph_shape_counts_mapped_records_and_concepts_across_reports(self):
        a, b, c = "a" * 64, "b" * 64, "c" * 64
        frames = [
            {"payload": {"actor": "w1", "command": {"kind": "submit", "directive": "T1", "lines": [
                {"kind": "observe", "local_id": "t1_o1", "doc_id": "dA"}, {"kind": "observe", "local_id": "t1_o2", "doc_id": "dB"},
                {"kind": "claim", "local_id": "t1_c1", "based_on": ["t1_o1", "t1_o2"]}]},
                "outcome": {"result": {"accepted": ["@" + a[:16], "@" + b[:16], "@" + c[:16]]}}}},
            {"payload": {"actor": "builder", "command": {"kind": "batch", "operations": [
                {"kind": "propose_concept", "name": "gate"}, {"kind": "map_term", "record": a, "concept": "k1"},
                {"kind": "map_term", "record": c, "concept": "k1"}, {"kind": "map_term", "record": b, "concept": "k2"}]},
                "outcome": {"result": {"accepted_operations": 3, "results": [{"id": "k1"}, {}, {}]}}}},
        ]
        with tempfile.TemporaryDirectory() as d:
            wal = pathlib.Path(d) / "run.wal"
            wal.write_text("".join(__import__("json").dumps(f) + "\n" for f in frames), encoding="utf-8")
            g = P.graph_shape(wal)
        self.assertEqual((g["records"], g["records_with_concept"], g["concepts_used"]), (3, 2, 1), "the refused 4th operation is not counted")
        self.assertEqual(g["concepts_across_reports"], 1, "the claim reaches dA and dB through its local quotes")
        self.assertEqual(g["largest_concepts"][0], {"records": 2, "name": "gate"})

    def test_the_evidence_sink_has_a_file_for_replies(self):
        with tempfile.TemporaryDirectory() as d:
            ev = R.Evidence(pathlib.Path(d))
            ev("reply", {"status": "COMMITTED"})
            self.assertEqual(len((pathlib.Path(d) / "replies.jsonl").read_text(encoding="utf-8").splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
