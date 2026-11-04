"""A run with arm A frozen makes the kernel's arm only. No model, pilot, or provider is executed."""
import json, pathlib, sys, tempfile, unittest
from types import SimpleNamespace
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import run_pilot_ac as R
from sbgk_bench import pilot_ac as P

class FreezeArmA(unittest.TestCase):
 def test_frozen_run_skips_arm_a_and_blinds_the_kernel_arm_alone(self):
  with tempfile.TemporaryDirectory() as folder:
   root=pathlib.Path(folder);(root/"one.md").write_text("A limitation remains.",encoding="utf-8");manifest=root/"manifest.json";manifest.write_text("{}")
   answer={"outcome":"answered","claims":[{"text":"A limitation remains.","quotes":[{"report":"one.md","quote":"A limitation remains."}]}]}
   arm={"calls":[],"events":[],"phase1":{"status":{"reading_done":True},"answers":{"RQ1":answer}}}
   with mock.patch.object(P,"CIRCLES",False),mock.patch.object(P,"ARM_A_FROZEN",True),mock.patch.object(P,"run_arm_c",return_value=arm),\
        mock.patch.object(P,"run_arm_a",side_effect=AssertionError("arm A ran")),mock.patch.object(P,"graph_shape",return_value={}):
    summary=R.run(manifest,root,["one.md"],root/"out",SimpleNamespace(name="dependency-only"),1,None)
   out=root/"out"
   self.assertEqual(json.loads((out/"arm_a.json").read_text())["mode"],"frozen")
   self.assertEqual(summary["arm_a"]["phase1"]["reason"],"ARM_A_FROZEN")
   self.assertEqual(summary["artifact_errors"],[])
   self.assertEqual(json.loads((out/"answers_key.json").read_text()),{"Variant 1":"C"})
   blind=(out/"answers_blind.md").read_text(encoding="utf-8")
   self.assertIn("A limitation remains.",blind);self.assertNotIn("Variant 2",blind)

 def test_frozen_arm_a_takes_no_arm_a_answer_mode(self):
  saved={k:v for k,v in vars(P).items() if k.isupper()}  # main sets module settings before it exits
  try:
   with mock.patch.object(sys,"argv",["run_pilot_ac.py","--freeze-arm-a","--arm-a-answer","map-reduce","--model","stub"]):
    with self.assertRaises(SystemExit) as stop:R.main()
  finally:
   vars(P).update(saved)
  self.assertIn("--freeze-arm-a",str(stop.exception))

if __name__=="__main__":
 unittest.main()
