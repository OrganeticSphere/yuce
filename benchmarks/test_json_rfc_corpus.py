"""The JSON RFC corpus (benchmarks/corpora/json-rfc-4627-7159): its bytes, its manifest and document order, the sentences of its
reference, how the kernel cuts it into reading sections, and its withdrawal plan.

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
PREFIX = "benchmarks/corpora/json-rfc-4627-7159/"
ROOT = REPO / PREFIX
REFERENCE = ROOT.parent / "gold" / "json-rfc-4627-7159-reference.json"


def sections(text: str, max_bytes: int, headings: bool) -> list[tuple[int, int]]:
    """The kernel's rule for cutting a document into reading sections (crates/sbgk-core/src/audit/directives.rs `sections`,
    SECTION_RULE 2), for ASCII text: a `#` line outside a code fence opens a section in a Markdown file; a piece longer than
    `max_bytes` is cut after its last blank line (in plain text, else after its last line); short neighbours are packed."""
    max_bytes = max(max_bytes, 64)
    starts, at, fence = [0], 0, False
    for line in text.split("\n"):
        is_fence = line.lstrip().startswith(("```", "~~~"))
        if headings and at > 0 and not (fence or is_fence) and line.startswith("#"):
            starts.append(at)
        fence = fence != is_fence
        at += len(line) + 1
    starts.append(len(text))
    raw = []
    for a, b in zip(starts, starts[1:]):
        while b - a > max_bytes:
            piece = text[a:a + max_bytes]
            blank = piece.rfind("\n\n")
            if headings:
                end = blank + 2 if blank > 0 else None
            else:
                end = blank + 2 if blank >= 0 else (piece.rfind("\n") + 1 if "\n" in piece else None)
            cut = a + end if end is not None else a + max_bytes
            raw.append((a, cut))
            a = cut
        if b > a:
            raw.append((a, b))
    out: list[tuple[int, int]] = []
    for a, b in raw:
        if out and b - out[-1][0] <= max_bytes:
            out[-1] = (out[-1][0], b)
        else:
            out.append((a, b))
    return out


class JsonRfcCorpus(unittest.TestCase):
    def setUp(self):
        self.ref = json.loads(REFERENCE.read_text(encoding="utf-8"))
        self.files = {name: (ROOT / name.replace(".txt", ".md")).read_bytes() for name in self.ref["sources"]
                      if (ROOT / name.replace(".txt", ".md")).exists()}
        self.raw_manifest = (ROOT / "manifest.json").read_bytes()
        self.manifest = json.loads(self.raw_manifest)

    def test_both_files_are_the_rfc_editors_bytes(self):
        self.assertEqual(sorted(self.files), ["rfc4627.txt", "rfc7159.txt"], "RFC 8259 is named by the reference, not in the corpus")
        for name, raw in self.files.items():
            want = self.ref["sources"][name]
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (want["bytes"], want["sha256"]), name)
        self.assertEqual(sum(len(r) for r in self.files.values()), 43770)
        self.assertEqual(hashlib.sha256(REFERENCE.read_bytes()).hexdigest(), "7ebaf0a2710785d798e8230fad58e8585c78ae4c3afcde784160aa24331b041b",
                         "the reference is the file fixed before any run")

    def test_the_manifest_pins_both_files_to_a_commit_of_this_repository(self):
        source = self.manifest["source"]
        # the kernel's document identity names a repository, a commit of it and the path from its root; the RFC Editor's editions
        # are in no git repository, so the manifest names this one and the commit of it that holds the two files
        self.assertEqual((source["origin_recorded"], source["repository"]), ("https://github.com/OrganeticSphere/yuce.git",
                                                                             "OrganeticSphere/yuce"))
        self.assertRegex(source["commit"], r"^[0-9a-f]{40}$")
        entries = self.manifest["entries"]
        self.assertEqual([e["path"] for e in entries], [PREFIX + "rfc4627.md", PREFIX + "rfc7159.md"])
        for e in entries:
            raw, up = (REPO / e["path"]).read_bytes(), e["upstream"]
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (e["size_bytes"], e["raw_sha256"]), e["path"])
            want = self.ref["sources"][up["name"]]
            self.assertEqual((e["size_bytes"], e["raw_sha256"]), (want["bytes"], want["sha256"]), "the manifest names the reference's bytes")
            # the git blob id: a checkout that converted line endings would change it
            self.assertEqual(hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest(), e["git_blob"], e["path"])
            self.assertEqual((e["path"], up["url"]), (PREFIX + up["name"].replace(".txt", ".md"), "https://www.rfc-editor.org/rfc/" + up["name"]))
        self.assertEqual([(e["version"], e["date"]) for e in entries], [("RFC 4627", "2006-07-01"), ("RFC 7159", "2014-03-01")])

    def test_the_pinned_commit_holds_both_files_where_its_history_is_at_hand(self):
        # in a clone of OrganeticSphere/yuce the pinned commit is in the history: every path there is the file's blob. Elsewhere
        # (an exported snapshot, the private development repository) the commit is not at hand and the check is skipped.
        commit = self.manifest["source"]["commit"]
        try:
            at_hand = subprocess.run(["git", "-C", str(REPO), "cat-file", "-e", f"{commit}^{{commit}}"], capture_output=True).returncode == 0
        except OSError:
            at_hand = False
        if not at_hand:
            self.skipTest("the pinned commit is not in this checkout's history")
        for e in self.manifest["entries"]:
            blob = subprocess.run(["git", "-C", str(REPO), "rev-parse", f"{commit}:{e['path']}"], capture_output=True, text=True)
            self.assertEqual((blob.returncode, blob.stdout.strip()), (0, e["git_blob"]), e["path"])

    def test_the_reports_and_the_document_order_follow_publication(self):
        reports = (ROOT / "reports.txt").read_text(encoding="utf-8").split()
        self.assertEqual(reports, [e["path"] for e in self.manifest["entries"]])
        docs = {p: (REPO / p).read_bytes().decode("utf-8") for p in reports}
        by_id = P.source_document_paths(self.raw_manifest, docs)
        order = json.loads((ROOT / "document_order.json").read_text(encoding="utf-8"))
        self.assertEqual([by_id[d] for d in order], reports, "the kernel's document ids in publication order")

    def test_every_sentence_of_the_reference_is_at_its_offset_once(self):
        for s in self.ref["steps"]:
            raw, quote = self.files[s["file"]], s["quote"].encode("utf-8")
            self.assertEqual((raw.find(quote), raw.count(quote)), (s["byte"], s["occurrences"]), s["id"])
        # the control holds in every edition of the corpus
        c1 = next(s for s in self.ref["steps"] if s["id"] == "C1")["quote"].encode("utf-8")
        self.assertEqual([r.count(c1) for r in self.files.values()], [1, 1])

    def test_the_kernel_cuts_each_file_as_plain_text_and_no_sentence_crosses_a_section(self):
        for name, raw in self.files.items():
            text = raw.decode("ascii")
            md = sections(text, P.SECTION_BYTES, headings=True)
            self.assertEqual(md, sections(text, P.SECTION_BYTES, headings=False), f"{name}: the .md name changes how it is cut")
            self.assertEqual((md[0][0], md[-1][1]), (0, len(text)))
            for s in self.ref["steps"]:
                at = text.find(s["quote"])
                if at >= 0:
                    self.assertTrue(any(a <= at and at + len(s["quote"]) <= b for a, b in md), f"{s['id']} crosses a section in {name}")
        self.assertEqual([len(sections(r.decode("ascii"), P.SECTION_BYTES, True)) for r in self.files.values()], [3, 5])

    def test_the_withdrawal_plan_withdraws_w1_to_w4_in_order_and_never_the_control(self):
        plan = json.loads((ROOT / "withdrawal.json").read_text(encoding="utf-8"))
        reports = (ROOT / "reports.txt").read_text(encoding="utf-8").split()
        self.assertEqual(reports, [PREFIX + "rfc4627.md", PREFIX + "rfc7159.md"])
        withdrawn = [s for s in self.ref["steps"] if s["kind"] == "withdraw"]
        self.assertEqual([st["name"] for st in plan["steps"]], ["2A", "2B", "2C", "2D"])
        for st, s in zip(plan["steps"], withdrawn, strict=True):
            self.assertEqual((st["id"], st["report"]), (s["id"], PREFIX + s["file"].replace(".txt", ".md")))
            self.assertEqual(st["candidates"], [{"anchor": s["quote"], "quote": s["quote"]}])
            self.assertIn(st["report"], reports)
        c1 = next(s for s in self.ref["steps"] if s["id"] == "C1")["quote"]
        self.assertFalse(any(c1 in c["quote"] for st in plan["steps"] for c in st["candidates"]))


if __name__ == "__main__":
    unittest.main()
