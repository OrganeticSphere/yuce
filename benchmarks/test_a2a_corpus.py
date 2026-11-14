"""The A2A specification corpus (benchmarks/corpora/a2a-spec-v1.0.1): its bytes, its manifest, its document order and its
oracle of stale facts.

Run: python -m unittest discover -s benchmarks -p "test_*.py"
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from sbgk_bench import pilot_ac as P  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
PREFIX = "benchmarks/corpora/a2a-spec-v1.0.1/"
ROOT = REPO / PREFIX
GOLD = ROOT.parent / "gold" / "a2a-spec-v1.0.1-stale-facts.json"
RELEASES = ("v0.2.5", "v0.3.0", "v1.0.1")


class A2aCorpus(unittest.TestCase):
    def setUp(self):
        self.raw_manifest = (ROOT / "manifest.json").read_bytes()
        self.manifest = json.loads(self.raw_manifest)
        self.entries = self.manifest["entries"]

    def test_every_file_is_the_pinned_upstream_bytes_of_its_release(self):
        source = self.manifest["source"]
        # the kernel's document identity names this repository, a commit of it and the path from its root (0.2.1, A2A-01): the
        # three releases share one upstream path, so no upstream commit holds the corpus
        self.assertEqual((source["origin_recorded"], source["repository"]), ("https://github.com/OrganeticSphere/yuce.git",
                                                                             "OrganeticSphere/yuce"))
        self.assertRegex(source["commit"], r"^[0-9a-f]{40}$")
        upstream = source["upstream"]
        self.assertEqual((upstream["repository"], upstream["releases"]["v1.0.1"]["commit"]),
                         ("a2aproject/A2A", "3303592588e388e62e0f69f701af531d2f4e3991"))
        self.assertEqual(sorted(upstream["releases"]), list(RELEASES))
        self.assertEqual(len(self.entries), 5)
        for e in self.entries:
            raw = (REPO / e["path"]).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (e["size_bytes"], e["raw_sha256"]), e["path"])
            # the upstream git blob id: a checkout that converted line endings would change it
            self.assertEqual(hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest(), e["upstream_git_blob"], e["path"])
            # the path is this corpus's folder, the release and the upstream path; the entry names the commit of that release
            up = e["upstream"]
            self.assertEqual(e["path"], f'{PREFIX}{up["tag"]}/{up["path"]}')
            self.assertEqual((up["tag"], up["commit"], e["date"]), (e["version"], upstream["releases"][e["version"]]["commit"],
                                                                     upstream["releases"][e["version"]]["date"]))
        self.assertEqual(sum(e["size_bytes"] for e in self.entries), 380731)
        self.assertTrue((ROOT / "LICENSE").read_text(encoding="utf-8").lstrip().startswith("Apache License"))

    def test_the_pinned_commit_holds_every_file_where_its_history_is_at_hand(self):
        # in a clone of OrganeticSphere/yuce the pinned commit is in the history: every path there is the upstream blob. Elsewhere
        # (an exported snapshot, the private development repository) the commit is not at hand and the check is skipped.
        commit = self.manifest["source"]["commit"]
        try:
            at_hand = subprocess.run(["git", "-C", str(REPO), "cat-file", "-e", f"{commit}^{{commit}}"], capture_output=True).returncode == 0
        except OSError:
            at_hand = False
        if not at_hand:
            self.skipTest("the pinned commit is not in this checkout's history")
        for e in self.entries:
            blob = subprocess.run(["git", "-C", str(REPO), "rev-parse", f"{commit}:{e['path']}"], capture_output=True, text=True)
            self.assertEqual((blob.returncode, blob.stdout.strip()), (0, e["upstream_git_blob"]), e["path"])

    def test_the_reports_and_the_document_order_follow_the_releases(self):
        reports = (ROOT / "reports.txt").read_text(encoding="utf-8").split()
        self.assertEqual(reports, [e["path"] for e in self.entries])
        self.assertEqual([e["version"] for e in self.entries], sorted(e["version"] for e in self.entries))
        docs = {p: (REPO / p).read_bytes().decode("utf-8") for p in reports}
        by_id = P.source_document_paths(self.raw_manifest, docs)
        order = json.loads((ROOT / "document_order.json").read_text(encoding="utf-8"))
        self.assertEqual([by_id[d] for d in order], reports, "the kernel's document ids in release order")

    def test_every_stale_fact_quotes_where_it_held_and_where_it_ended(self):
        gold = json.loads(GOLD.read_text(encoding="utf-8"))
        self.assertEqual((gold["corpus"], gold["as_of"]), ("a2a-spec-v1.0.1", "v1.0.1"))
        # the oracle names a file by its path inside the corpus folder
        texts = {e["path"][len(PREFIX):]: (REPO / e["path"]).read_text(encoding="utf-8") for e in self.entries}
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


if __name__ == "__main__":
    unittest.main()
