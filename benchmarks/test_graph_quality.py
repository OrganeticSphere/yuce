import copy
import unittest
from sbgk_bench.graph_quality import inline_card

class Presentation(unittest.TestCase):
    def test_inline_is_record_specific_and_has_no_operation_lines(self):
        card={"candidates":{"unit":[{"id":"@a"},{"id":"@b"}]}}
        before=copy.deepcopy(card)
        out=inline_card(card,[{"op":"map_term","record":"@r1","term":"unit","concept":"@a"},{"op":"map_term","record":"@r2","term":"unit","concept":"@b"}])
        self.assertEqual(card,before)
        self.assertTrue(out["candidates"]["unit"][0]["fast_match"])
        self.assertEqual(out["candidates"]["unit"][0]["fast_match_records"],["@r1"])
        self.assertTrue(all("op" not in r for r in out["fast_matches"]))

if __name__=="__main__":unittest.main()
