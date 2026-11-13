"""The MCP specification corpus (benchmarks/corpora/mcp-spec-2026-07-28): its bytes, its manifest and its document order.

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

ROOT = pathlib.Path(__file__).resolve().parent / "corpora" / "mcp-spec-2026-07-28"


class McpCorpus(unittest.TestCase):
    def setUp(self):
        self.raw_manifest = (ROOT / "manifest.json").read_bytes()
        self.manifest = json.loads(self.raw_manifest)
        self.entries = self.manifest["entries"]

    def test_every_file_is_the_pinned_upstream_bytes(self):
        self.assertEqual(self.manifest["source"]["commit"], "5f5440bb26a62e2cf3440b92da5a667efa03b267")
        self.assertEqual(len(self.entries), 22)
        for e in self.entries:
            raw = (ROOT / e["path"]).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (e["size_bytes"], e["raw_sha256"]), e["path"])
            # the upstream git blob id: a checkout that converted line endings would change it
            self.assertEqual(hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest(), e["upstream_git_blob"], e["path"])
            # the path is the upstream repository-relative path, so repo@commit:path names the file itself
            self.assertTrue(e["path"].startswith(f"docs/specification/{e['version']}/") and e["extension"] == ".mdx", e["path"])
        self.assertEqual(sum(e["size_bytes"] for e in self.entries), 293854)

    def test_the_reports_and_the_document_order_follow_the_versions(self):
        reports = (ROOT / "reports.txt").read_text(encoding="utf-8").split()
        self.assertEqual(reports, [e["path"] for e in self.entries])
        self.assertEqual([e["version"] for e in self.entries], sorted(e["version"] for e in self.entries))
        # the pages have no date front matter: the manifest dates each one by its release, so pages of one release are not
        # earlier or later than each other (run smoke2: undated, 13 of 25 evolution pairs were two pages of 2026-07-28)
        self.assertEqual([e["date"] for e in self.entries], [e["version"] for e in self.entries])
        docs = {p: (ROOT / p).read_bytes().decode("utf-8") for p in reports}
        by_id = P.source_document_paths(self.raw_manifest, docs)
        order = json.loads((ROOT / "document_order.json").read_text(encoding="utf-8"))
        self.assertEqual([by_id[d] for d in order], reports, "the kernel's document ids in version order")

    def texts(self):
        return {e["path"]: (ROOT / e["path"]).read_text(encoding="utf-8") for e in self.entries}

    def test_the_transitions_catalog_quotes_its_changelogs_and_relates_earlier_events(self):
        gold = json.loads((ROOT.parent / "gold" / "mcp-spec-2026-07-28-transitions.json").read_text(encoding="utf-8"))
        events, texts = gold["events"], self.texts()
        sources = "".join(texts[p] for p in sorted(texts) if p.endswith(("changelog.mdx", "deprecated.mdx")))
        items = sum(len([line for line in texts[f"docs/specification/{v}/changelog.mdx"].splitlines()
                         if line[:1].isdigit() or line.startswith("- ")]) for v in ("2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"))
        self.assertEqual(len(events), items, "one event per changelog item")
        ids = [e["id"] for e in events]
        kinds = {e["id"]: e["kind"] for e in events}
        for e in events:
            self.assertIn(e["quote"], texts[e["file"]], e["id"])
            self.assertIn(e["kind"], gold["kinds"], e["id"])
            self.assertTrue(all(x in ids and ids.index(x) < ids.index(e["id"]) for x in e["related_earlier"]), e["id"])
            # a clarified event has no mechanism of its own: never the earlier end of a link (the rule of 2026-11-13)
            self.assertTrue(all(kinds[x] != "clarified" for x in e["related_earlier"]), e["id"])
            if e["basis"] == "decided":
                self.assertIn(e["decision"]["quote"], sources, e["id"])
            if e["basis"] == "corrected":
                self.assertIn(e["correction"]["quote"], texts[e["correction"]["file"]], e["id"])

    def test_every_stale_fact_quotes_where_it_held_and_where_it_ended(self):
        gold = json.loads((ROOT.parent / "gold" / "mcp-spec-2026-07-28-stale-facts.json").read_text(encoding="utf-8"))
        events = {e["id"]: e for e in json.loads((ROOT.parent / "gold" / "mcp-spec-2026-07-28-transitions.json")
                                                  .read_text(encoding="utf-8"))["events"]}
        texts = self.texts()
        for f in gold["facts"]:
            self.assertIn(f["status"], ("removed", "replaced", "changed", "deprecated"), f["id"])
            for side in ("old", "new"):
                self.assertIn(f[side]["quote"], texts[f[side]["file"]], (f["id"], side))
            self.assertIn(f["old"]["file"].split("/")[2], f["held_in"], f["id"])
            self.assertTrue(f["ended_by"] and all(x in events and events[x]["version"] >= f["since"] for x in f["ended_by"]), f["id"])
            self.assertTrue(all(v < f["since"] for v in f["held_in"]), f["id"])
        for c in gold["controls"]:
            for side in ("old", "still"):
                self.assertIn(c[side]["quote"], texts[c[side]["file"]], (c["id"], side))
            self.assertEqual(c["still"]["file"].split("/")[2], gold["as_of"], c["id"])

    def test_both_license_texts_ship_with_the_corpus(self):
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text(encoding="utf-8"))
        self.assertIn("CC-BY-4.0", (ROOT / "LICENSE").read_text(encoding="utf-8"))
        self.assertTrue((ROOT / "LICENSE-MIT").read_text(encoding="utf-8").startswith("MIT License"))


if __name__ == "__main__":
    unittest.main()
