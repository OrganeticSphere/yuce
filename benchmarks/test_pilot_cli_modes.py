"""CLI mode routing without a corpus run, process launch or provider call."""
import contextlib
import io
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_pilot_ac as R
from sbgk_bench import pilot_ac as P

class Modes(unittest.TestCase):
    def invoke(self, args, expected_mode=None, selftest=False):
        argv=["run_pilot_ac.py", "--manifest", "unused.json", "--repo", "unused", "--model", "stub", *args]
        modes=[]
        def run(*a, **kw):
            modes.append((P.ARM_A_MODE, P.ARM_A_ANSWER, len(kw.get("team") or [])))
            return {"measures": {}}
        with mock.patch.dict(P.__dict__, {"ARM_A_MODE":"notes", "WHOLE_READER":False, "PAIRS_ONLY":False, "LINK_CHECKER":False}), \
             mock.patch.object(sys,"argv",argv), mock.patch.object(R.C,"BIN",pathlib.Path(__file__)), \
             mock.patch.object(R,"corpus_choice",return_value=(["a.md"],{"steps":[]},{})), \
             mock.patch.object(R,"run",side_effect=run) as driver, \
             mock.patch.object(P,"make_model",side_effect=lambda *a,**kw:P.StubModel()) as models, \
             mock.patch.object(P,"call_model",side_effect=AssertionError("CLI preflight must not call a model")), \
             mock.patch.object(P,"Kernel",side_effect=AssertionError("CLI preflight must not launch a kernel")), \
             mock.patch.object(R,"selftest") as test, contextlib.redirect_stdout(io.StringIO()):
            if expected_mode is None:
                with self.assertRaises(SystemExit) as e:R.main()
                driver.assert_not_called();models.assert_not_called();test.assert_not_called()
                return str(e.exception)
            R.main()
            if selftest:
                test.assert_called_once();driver.assert_not_called();models.assert_not_called()
                self.assertEqual(P.ARM_A_MODE,expected_mode)
            else:
                driver.assert_called_once();self.assertEqual(modes[0][0],expected_mode)
                self.assertEqual(modes[0][1],"map-reduce" if "map-reduce" in args else "direct")
        return modes

    def test_map_reduce_reaches_driver_after_each_supported_mode_is_inferred(self):
        cases=[(["--team","stub"],"team",2),
               (["--team-models","stub,stub,stub"],"team",3),
               (["--team-models","stub,stub,stub","--dynamic-roles","--circles"],"team",3),
               (["--strong-reader","--workers","1"],"single",0)]
        for flags,mode,n in cases:
            with self.subTest(flags=flags):
                found=self.invoke([*flags,"--arm-a-answer","map-reduce"],mode)
                self.assertEqual(found[0][2],n)

    def test_map_reduce_rejects_notes_and_whole_before_model_or_run(self):
        for flags in ([],["--whole-reader","--workers","1"]):
            with self.subTest(flags=flags):
                msg=self.invoke([*flags,"--arm-a-answer","map-reduce"])
                self.assertIn("--team",msg);self.assertIn("--strong-reader",msg)
                self.assertNotIn("requires --arm-a ",msg)

    def test_direct_mode_routing_is_unchanged(self):
        for flags,mode in (([],"notes"),(["--team","stub"],"team"),
                           (["--strong-reader","--workers","1"],"single"),
                           (["--whole-reader","--workers","1"],"whole")):
            with self.subTest(flags=flags):self.invoke(flags,mode)

    def test_existing_conflicting_flags_still_refuse(self):
        msg=self.invoke(["--team-models","stub,stub","--strong-reader","--workers","1","--arm-a-answer","map-reduce"])
        self.assertIn("--team-models is separate",msg)

    def test_cli_selftest_route_also_passes_the_mode_gate(self):
        self.invoke(["--team-models","stub,stub,stub","--arm-a-answer","map-reduce","--selftest"],"team",selftest=True)

if __name__=="__main__":unittest.main()
