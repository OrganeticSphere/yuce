"""Repair routing for actual dispatcher preflight and post-storage refusal shapes. No model or provider calls."""
import pathlib
import sys
import unittest

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P


class RepairScope(unittest.TestCase):
    def prompt(self,refusal):
        return P.repair_prompt("TASK SUMMARIZE",refusal,"lines",'{"kind":"claim","local_id":"c1","text":"gate"}',[])

    def test_wrong_done_question_is_a_whole_answer_retry(self):
        # The real dispatcher stored zero records, although its bad done line has index 1.
        r={"status":"REPAIR_REQUIRED","failed_index":1,"repair_scope":"whole_answer",
           "error":{"code":"BAD_FIELD","field":"rq_id","expected_by_kernel":{"rq_id":"RQ1"}}}
        p=self.prompt(r)
        self.assertIn("Send the whole answer again",p)
        self.assertNotIn("before the failed index were accepted",p)
        self.assertIn("correct the reported error",p)

    def test_missing_done_can_add_the_required_line_without_dropping_claims(self):
        r={"status":"REPAIR_REQUIRED","failed_index":1,"repair_scope":"whole_answer",
           "error":{"code":"MISSING_FIELD","field":"kind"}}
        self.assertIn("Add any required missing line",self.prompt(r))

    def test_the_legacy_whole_summary_preflight_still_retries_whole(self):
        r={"status":"REPAIR_REQUIRED","failed_index":0,"error":{"code":"BAD_FIELD","field":"lines",
           "expected_by_kernel":{"lines":[{"line":1,"needs":"shorten text"}]}}}
        self.assertIn("Send the whole answer again",self.prompt(r))

    def test_a_lines_list_at_a_nonzero_index_is_not_a_legacy_whole_preflight(self):
        r={"status":"REPAIR_REQUIRED","failed_index":3,"error":{"code":"BAD_FIELD","field":"lines",
           "expected_by_kernel":{"lines":[{"line":3,"needs":"fix"}]}}}
        self.assertIn("before the failed index were accepted",self.prompt(r))

    def test_explicit_post_storage_prefix_wins_over_a_lines_list(self):
        r={"status":"REPAIR_REQUIRED","failed_index":0,"repair_scope":"accepted_prefix","accepted":["@record"],
           "error":{"code":"BAD_FIELD","field":"lines","expected_by_kernel":{"lines":[]}}}
        self.assertIn("before the failed index were accepted",self.prompt(r))


if __name__=="__main__":
    unittest.main()
