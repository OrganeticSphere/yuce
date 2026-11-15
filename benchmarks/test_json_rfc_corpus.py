"""The JSON RFC corpus (benchmarks/corpora/json-rfc-4627-7159): its bytes, the sentences of its reference, how the kernel cuts it
into reading sections, and its withdrawal plan.

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

    def test_both_files_are_the_rfc_editors_bytes(self):
        self.assertEqual(sorted(self.files), ["rfc4627.txt", "rfc7159.txt"], "RFC 8259 is named by the reference, not in the corpus")
        for name, raw in self.files.items():
            want = self.ref["sources"][name]
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (want["bytes"], want["sha256"]), name)
        self.assertEqual(sum(len(r) for r in self.files.values()), 43770)
        self.assertEqual(hashlib.sha256(REFERENCE.read_bytes()).hexdigest(), "7ebaf0a2710785d798e8230fad58e8585c78ae4c3afcde784160aa24331b041b",
                         "the reference is the file fixed before any run")

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
