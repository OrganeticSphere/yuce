import unittest
from analysis_step0_reference_trace import Run, exact_pair, reference_v1
from sbgk_bench.pilot_ac import fallback


class ConsiliumMeasurements(unittest.TestCase):
    def test_summary_stance_and_later_reading_do_not_backfill_phase1_extraction(self):
        r = Run.__new__(Run)
        raw = b"A source quote long enough for the overlap."
        r.raw = {"d": raw}
        r.phase = 1
        r.observes = {"o": ("d", [(0, len(raw))])}
        r.claims = {"read": {"based": ["o"]}, "summary": {"based": ["o"]}, "later": {"based": ["o"]}}
        r.texts = {"read": {"stance": "reported"}, "summary": {"stance": "qualified"}, "later": {"stance": "superseded"}}
        r.origin = {"o": ("EXTEND", 1), "read": ("EXTEND", 1), "summary": ("SUMMARIZE", 1), "later": ("EXTEND", 2)}
        r.answers = {"RQ1": {"summary"}}
        row = r.trace({"id": "F-1", "rq": "RQ1A", "report": "d", "quotes": [raw.decode()]})
        self.assertTrue(row["claimed"])
        self.assertFalse(row["stance"])
        self.assertTrue(row["answered"])
        self.assertEqual(row["reading_claim_ids"], ["read"])

    def test_exact_pair_requires_relation_and_direction(self):
        item = {"expected_relation": "supersedes", "expected_direction": "1_to_0"}
        link = {"from": "new", "to": "old", "rel": "qualifies"}
        self.assertFalse(exact_pair(item, link, {"old"}, {"new"}))
        link["rel"] = "supersedes"
        self.assertTrue(exact_pair(item, link, {"old"}, {"new"}))
        link.update({"from": "old", "to": "new"})
        self.assertFalse(exact_pair(item, link, {"old"}, {"new"}))
        self.assertFalse(exact_pair({}, link, {"old"}, {"new"}))

    def test_denominator_amendment_preserves_the_original_and_unlinked_candidates(self):
        draft = {"items": [{"id": n, "rq": q, "confidence": "borderline"} for n, q in
                           [("F-7", "RQ1"), ("L-4", "RQ1"), ("E-2", "RQ1"), ("N6", "NEG"), ("X3", "X")]]}
        v1 = {r["id"]: r for r in reference_v1(draft)["items"]}
        self.assertEqual(draft["items"][0]["rq"], "RQ1")
        self.assertEqual(v1["F-7"]["rq"], "RQ1B")
        self.assertEqual((v1["L-4"]["rq"], v1["L-4"]["confidence"]), ("RQ1A", "firm"))
        self.assertEqual(v1["E-2"]["rq"], "EXCLUDED")
        self.assertEqual(v1["N6"]["rq"], "NEG")
        self.assertEqual(v1["X3"]["matrix_bucket"], "candidate_thematic_evolution_unlinked")

    def test_partial_fallback_unions_retained_and_new_rows(self):
        t = {"kind": "SUMMARIZE", "key": "rq:RQ1", "task_id": "TS2", "local_id_prefix": "t2_", "retained_answer_ids": ["@old"]}
        row = fallback(t, {"new"})[0]
        self.assertEqual(row["outcome"], "answered")
        self.assertEqual(row["answer_ids"], ["@old", "new"])


if __name__ == "__main__":
    unittest.main()
