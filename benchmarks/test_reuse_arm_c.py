"""--reuse-arm-c: a run takes the finished arm C of an earlier run on the same inputs and runs only arm A
(arm C of MCPpair2_r1 finished every phase, arm A lost its withdrawals to a runner defect). No model, pilot or provider is executed."""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_pilot_ac as R  # noqa: E402
from sbgk_bench import pilot_ac as P  # noqa: E402


def shape(wal: pathlib.Path):
    """A stand-in for graph_shape: its current concepts come from the snapshot beside arm C, as the real one's do."""
    snapshot = wal.parent.parent / "ontology_evolution.json"
    return {"wal": wal.read_bytes().decode(), "concepts": snapshot.read_text(encoding="utf-8") if snapshot.exists() else None}


CORPUS = {"manifest_sha256": "m" * 64, "reports": ["a.md", "b.md"], "source_bytes": {"a.md": {"size_bytes": 1}}, "section_bytes": 6000,
          "questions": [{"id": "RQ1"}]}
WITHDRAW = {"steps": [{"name": "2A", "report": "a.md", "candidates": [{"anchor": "x", "quote": "x y"}]}]}


def earlier(root: pathlib.Path, *, status="FINISHED", corpus=None, withdraw=None, stopped=None, snapshot=None, exported=False) -> pathlib.Path:
    src = root / "earlier"
    (src / "arm_c").mkdir(parents=True)
    (src / "arm_c" / "run.wal").write_bytes(b"wal bytes")
    (src / "status.json").write_text(json.dumps({"status": status, "corpus": corpus or CORPUS}), encoding="utf-8")
    (src / "withdrawal.json").write_text(json.dumps(withdraw or WITHDRAW), encoding="utf-8")
    ontology = {"ontology_evolution": {"status": "EXPORTED", "path": "ontology_evolution.json"}} if exported else {}
    (src / "arm_c.json").write_text(json.dumps({"arm": "C", "stopped": stopped, "calls": [], "events": [], **ontology}), encoding="utf-8")
    if snapshot is not None:
        (src / "ontology_evolution.json").write_text(snapshot, encoding="utf-8")
    (src / "provenance.json").write_text(json.dumps({"git_head": "2c2f517"}), encoding="utf-8")
    (src / "summary.json").write_text(json.dumps({"spend": {"budget": {"C": {"spent_usd_estimate": 4.18}}}, "measures": {"circles": {"n": 21}}}),
                                      encoding="utf-8")
    (src / "circles.json").write_text("{}", encoding="utf-8")
    return src


@mock.patch.object(P, "graph_shape", side_effect=shape)
class ReuseArmC(unittest.TestCase):
    def test_a_finished_arm_c_on_the_same_inputs_is_taken_as_it_ended(self, _shape):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src, out = earlier(root), root / "out"
            out.mkdir()
            c, reused = R.reuse_arm_c(src, out, CORPUS, WITHDRAW)
            self.assertEqual(c["arm"], "C")
            self.assertEqual((out / "arm_c" / "run.wal").read_bytes(), b"wal bytes", "the WAL the graph is read from")
            self.assertTrue((out / "arm_c.json").is_file() and (out / "circles.json").is_file())
            self.assertEqual(reused["spend_c"], {"spent_usd_estimate": 4.18})
            self.assertEqual(reused["circles"], {"n": 21})
            record = json.loads((out / "arm_c_reused.json").read_text(encoding="utf-8"))
            self.assertEqual((record["from"], record["provenance"]["git_head"]), (src.name, "2c2f517"))
            self.assertEqual(len(record["arm_c_sha256"]), 64)

    def test_other_inputs_an_unfinished_run_or_a_stopped_arm_c_are_refused(self, _shape):
        cases = {"other corpus": dict(corpus=dict(CORPUS, reports=["a.md"])),
                 "other questions": dict(corpus=dict(CORPUS, questions=[{"id": "RQ9"}])),
                 "other withdrawal": dict(withdraw={"steps": []}),
                 "unfinished": dict(status="RUNNING"),
                 "stopped": dict(stopped="CALL_CAP: total=3000"),
                 "a declared ontology snapshot missing": dict(exported=True)}
        for name, kw in cases.items():
            with tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                src, out = earlier(root, **kw), root / "out"
                out.mkdir()
                with self.assertRaises(ValueError, msg=name):
                    R.reuse_arm_c(src, out, CORPUS, WITHDRAW)
                self.assertFalse((out / "arm_c").exists(), f"{name}: nothing copied")

    def test_the_ontology_snapshot_goes_with_arm_c_and_the_graph_measure_stays(self, _shape):
        # Codex review of 4abec7e, REUSE-01: graph_shape takes the current concepts from ontology_evolution.json beside arm C
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src, out = earlier(root, snapshot='{"current": "Current concept"}', exported=True), root / "out"
            out.mkdir()
            _, reused = R.reuse_arm_c(src, out, CORPUS, WITHDRAW)
            self.assertEqual((out / "ontology_evolution.json").read_text(encoding="utf-8"), '{"current": "Current concept"}')
            self.assertEqual(len(reused["ontology_evolution_sha256"]), 64)
            self.assertEqual(shape(out / "arm_c" / "run.wal"), shape(src / "arm_c" / "run.wal"))
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src, out = earlier(root), root / "out"
            out.mkdir()
            _, reused = R.reuse_arm_c(src, out, CORPUS, WITHDRAW)
            self.assertIsNone(reused["ontology_evolution_sha256"], "no snapshot in the source: none in the copy")
            self.assertFalse((out / "ontology_evolution.json").exists())


if __name__ == "__main__":
    unittest.main()
