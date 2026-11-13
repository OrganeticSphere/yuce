"""The A2A specification corpus (benchmarks/corpora/a2a-spec-v1.0.1): its bytes, its manifest, its document order and its
oracle of stale facts.

Run: python -m unittest discover -s benchmarks -p "test_*.py"
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from sbgk_bench import pilot_ac as P  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent / "corpora" / "a2a-spec-v1.0.1"
GOLD = ROOT.parent / "gold" / "a2a-spec-v1.0.1-stale-facts.json"
RELEASES = ("v0.2.5", "v0.3.0", "v1.0.1")


class A2aCorpus(unittest.TestCase):
    def setUp(self):
        self.raw_manifest = (ROOT / "manifest.json").read_bytes()
        self.manifest = json.loads(self.raw_manifest)
        self.entries = self.manifest["entries"]

    def test_every_file_is_the_pinned_upstream_bytes_of_its_release(self):
        source = self.manifest["source"]
        self.assertEqual(source["commit"], "3303592588e388e62e0f69f701af531d2f4e3991")
        self.assertEqual(sorted(source["releases"]), list(RELEASES))
        self.assertEqual(len(self.entries), 5)
        for e in self.entries:
            raw = (ROOT / e["path"]).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (e["size_bytes"], e["raw_sha256"]), e["path"])
            # the upstream git blob id: a checkout that converted line endings would change it
            self.assertEqual(hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest(), e["upstream_git_blob"], e["path"])
            # the corpus path is the release and the upstream path, and the entry names the commit of that release
            up = e["upstream"]
            self.assertEqual(e["path"], f'{up["tag"]}/{up["path"]}')
            self.assertEqual((up["tag"], up["commit"], e["date"]), (e["version"], source["releases"][e["version"]]["commit"],
                                                                     source["releases"][e["version"]]["date"]))
        self.assertEqual(sum(e["size_bytes"] for e in self.entries), 380731)
        self.assertTrue((ROOT / "LICENSE").read_text(encoding="utf-8").lstrip().startswith("Apache License"))

    def test_the_reports_and_the_document_order_follow_the_releases(self):
        reports = (ROOT / "reports.txt").read_text(encoding="utf-8").split()
        self.assertEqual(reports, [e["path"] for e in self.entries])
        self.assertEqual([e["version"] for e in self.entries], sorted(e["version"] for e in self.entries))
        docs = {p: (ROOT / p).read_bytes().decode("utf-8") for p in reports}
        by_id = P.source_document_paths(self.raw_manifest, docs)
        order = json.loads((ROOT / "document_order.json").read_text(encoding="utf-8"))
        self.assertEqual([by_id[d] for d in order], reports, "the kernel's document ids in release order")

    def test_every_stale_fact_quotes_where_it_held_and_where_it_ended(self):
        gold = json.loads(GOLD.read_text(encoding="utf-8"))
        self.assertEqual((gold["corpus"], gold["as_of"]), ("a2a-spec-v1.0.1", "v1.0.1"))
        texts = {e["path"]: (ROOT / e["path"]).read_text(encoding="utf-8") for e in self.entries}
        version = lambda path: path.split("/")[0]  # noqa: E731
        for f in gold["facts"]:
            self.assertIn(f["status"], ("removed", "replaced", "changed"), f["id"])
            for side in ("old", "new"):
                self.assertIn(f[side]["quote"], texts[f[side]["file"]], (f["id"], side))
            self.assertIn(version(f["old"]["file"]), f["held_in"], f["id"])
            self.assertTrue(all(v < f["since"] for v in f["held_in"]), f["id"])
            self.assertTrue(version(f["new"]["file"]) >= f["since"] or version(f["new"]["file"]) == "v1.0.1", f["id"])
        for c in gold["controls"]:
            for side in ("old", "still"):
                self.assertIn(c[side]["quote"], texts[c[side]["file"]], (c["id"], side))
            self.assertEqual(version(c["still"]["file"]), gold["as_of"], c["id"])
        self.assertEqual((len(gold["facts"]), len(gold["controls"])), (14, 2))


if __name__ == "__main__":
    unittest.main()
