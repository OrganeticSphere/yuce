"""The corpus bacteria-under-flow (benchmarks/corpora/bacteria-under-flow): its bytes and attribution headers, its manifest and
document order, both withdrawn passages inside one reading section of the kernel, its questions and its withdrawal plan. The reference is published after the
run; benchmarks/PREREGISTRATION_CROSS_BIO.md names it by SHA-256.

Run: python -m unittest discover -s benchmarks -p "test_*.py"
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from sbgk_bench import pilot_ac as P  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
PREFIX = "benchmarks/corpora/bacteria-under-flow/"
ROOT = REPO / PREFIX
FILES = {"B_thomen2017.md": (40998, "f350479e95368bbaca4bf25b2f841c8c100dbc88b3f8174c41f53b2141f26e23", "PMC5389662"),
         "A_rossy2019.md": (28794, "e86d281bf6f8a2b658f67dede19cfd8dee290c728f783a4bd24f26311ab90d01", "PMC6554397"),
         "C_hubert2024.md": (36828, "4de06f5bacdfb4bb155e018e00a5c0c2c2ea56e36ecd842acfa9a2e03e3f18dd", "PMC11263347")}
# the withdrawn passages at their byte offsets, as the reference fixed them before the run
WITHDRAWN = {"W1": ("B_thomen2017.md", 1639, 1712), "W2": ("A_rossy2019.md", 7544, 7641)}
TOPICS = {"Q1": ["coloni", "surface", "flow", "threshold"], "Q2": ["threshold", "flow", "compar"],
          "Q3": ["mechanical", "force", "growth", "flow", "measurement"]}


def sections(text: bytes, max_bytes: int, headings: bool) -> list[tuple[int, int]]:
    """The kernel's rule for cutting a document into reading sections (crates/sbgk-core/src/audit/directives.rs `sections`,
    SECTION_RULE 2), on bytes: a `#` line outside a code fence opens a section in a Markdown file; a piece longer than `max_bytes`
    is cut after its last blank line (in plain text, else after its last line); short neighbours are packed."""
    max_bytes = max(max_bytes, 64)
    starts, at, fence = [0], 0, False
    for line in text.split(b"\n"):
        is_fence = line.lstrip().startswith((b"```", b"~~~"))
        if headings and at > 0 and not (fence or is_fence) and line.startswith(b"#"):
            starts.append(at)
        fence = fence != is_fence
        at += len(line) + 1
    starts.append(len(text))
    raw = []
    for a, b in zip(starts, starts[1:]):
        while b - a > max_bytes:
            piece = text[a:a + max_bytes]
            blank = piece.rfind(b"\n\n")
            if headings:
                end = blank + 2 if blank > 0 else None
            else:
                end = blank + 2 if blank >= 0 else (piece.rfind(b"\n") + 1 if b"\n" in piece else None)
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


class CrossBioCorpus(unittest.TestCase):
    def setUp(self):
        self.files = {name: (ROOT / name).read_bytes() for name in FILES}
        self.plan = json.loads((ROOT / "withdrawal.json").read_text(encoding="utf-8"))
        self.raw_manifest = (ROOT / "manifest.json").read_bytes()
        self.manifest = json.loads(self.raw_manifest)

    def test_the_three_papers_are_their_pinned_bytes_with_their_attribution(self):
        for name, (size, sha, pmc) in FILES.items():
            raw = self.files[name]
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (size, sha), name)
            head = raw[:1200].decode("utf-8")
            self.assertTrue(head.startswith("# "), name)
            self.assertIn(pmc, head, name)
            self.assertIn("Creative Commons Attribution 4.0 International (CC BY 4.0)", head, name)
            self.assertIn("Changes:", head, name)
        self.assertEqual(sum(len(r) for r in self.files.values()), 106620)
        reports = (ROOT / "reports.txt").read_text(encoding="utf-8").split()
        self.assertEqual(reports, [PREFIX + n for n in FILES], "publication order: 2017, 2019, 2024")

    def test_the_manifest_pins_the_three_files_to_a_commit_of_this_repository(self):
        source = self.manifest["source"]
        # the kernel's document identity names a repository, a commit of it and the path from its root; the papers are in no git
        # repository, so the manifest names this one and the commit of it that holds the three files
        self.assertEqual((source["origin_recorded"], source["repository"]), ("https://github.com/OrganeticSphere/yuce.git",
                                                                             "OrganeticSphere/yuce"))
        self.assertRegex(source["commit"], r"^[0-9a-f]{40}$")
        entries = self.manifest["entries"]
        self.assertEqual([e["path"] for e in entries], [PREFIX + n for n in FILES])
        for e in entries:
            raw = (REPO / e["path"]).read_bytes()
            size, sha, pmc = FILES[e["path"][len(PREFIX):]]
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (e["size_bytes"], e["raw_sha256"]), e["path"])
            self.assertEqual((e["size_bytes"], e["raw_sha256"]), (size, sha), e["path"])
            # the git blob id: a checkout that converted line endings would change it
            self.assertEqual(hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest(), e["git_blob"], e["path"])
            self.assertEqual((e["upstream"]["pmcid"], e["upstream"]["licence"]), (pmc, "CC BY 4.0"), e["path"])
            self.assertEqual(e["upstream"]["url"], "https://doi.org/" + e["upstream"]["doi"])
        self.assertEqual([e["date"] for e in entries], ["2017-04-12", "2019-06-06", "2024-07-22"])

    def test_the_pinned_commit_holds_the_three_files_where_its_history_is_at_hand(self):
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

    def test_both_withdrawn_passages_are_at_their_offsets_once_inside_one_section(self):
        for st in self.plan["steps"]:
            name, a, b = WITHDRAWN[st["id"]]
            raw, quote = self.files[name], st["candidates"][0]["quote"].encode("utf-8")
            self.assertEqual((raw.find(quote), raw.count(quote), len(quote)), (a, 1, b - a), st["id"])
            cuts = sections(raw, P.SECTION_BYTES, headings=True)
            self.assertEqual((cuts[0][0], cuts[-1][1]), (0, len(raw)))
            self.assertEqual(sum(1 for s, e in cuts if s <= a and b <= e), 1, f"{st['id']} crosses a section")
        self.assertEqual([len(sections(self.files[n], P.SECTION_BYTES, True)) for n in FILES], [10, 7, 8])

    def test_the_questions_carry_only_topics_from_their_own_words(self):
        qs = json.loads((ROOT / "questions.json").read_text(encoding="utf-8"))
        self.assertEqual([q["id"] for q in qs], ["Q1", "Q2", "Q3"])
        for q in qs:
            self.assertEqual(set(q), {"id", "text", "about"})
            self.assertEqual(q["about"], TOPICS[q["id"]], q["id"])
            words = re.findall(r"[a-z]+", q["text"].lower())
            for topic in q["about"]:
                self.assertTrue(any(w.startswith(topic) for w in words), f"{q['id']}: '{topic}' is no stem of a word of the question")

    def test_the_plan_withdraws_w1_then_w2_and_both_are_applied(self):
        self.assertEqual([(st["name"], st["id"]) for st in self.plan["steps"]], [("2A", "W1"), ("2B", "W2")])
        for st in self.plan["steps"]:
            self.assertEqual(st["report"], PREFIX + WITHDRAWN[st["id"]][0])
            self.assertEqual(len(st["candidates"]), 1)
            self.assertEqual(st["candidates"][0]["anchor"], st["candidates"][0]["quote"])
        self.assertIn("both always", self.plan["rule"])


if __name__ == "__main__":
    unittest.main()
