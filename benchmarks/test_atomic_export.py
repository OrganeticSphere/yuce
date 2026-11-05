"""Atomic output of the run's files. No external model is invoked."""
import json, pathlib, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from sbgk_bench.atomic_output import write_text
import run_pilot_ac as R
class Export(unittest.TestCase):
 def test_atomic_windows_retry_publishes_complete_json(self):
  with tempfile.TemporaryDirectory() as folder:
   path=pathlib.Path(folder)/"a.json";path.write_text("old")
   original=pathlib.Path.replace;count=[0]
   def replace(src,dst):
    count[0]+=1
    if count[0]<3:raise PermissionError("sharing")
    return original(src,dst)
   with mock.patch.object(pathlib.Path,"replace",replace),mock.patch("sbgk_bench.atomic_output.time.sleep"):
    write_text(path,'{"complete":true}')
   self.assertEqual(json.loads(path.read_text()),{"complete":True});self.assertEqual(list(path.parent.glob("*.tmp")),[])
 def test_persistent_sharing_failure_retains_payload_and_primary_output_can_continue(self):
  with tempfile.TemporaryDirectory() as folder:
   path=pathlib.Path(folder)/"a.json";path.write_text("old")
   with mock.patch.object(pathlib.Path,"replace",side_effect=PermissionError("sharing")),mock.patch("sbgk_bench.atomic_output.time.sleep"):
    with self.assertRaises(PermissionError):write_text(path,"new complete payload")
   self.assertEqual(path.read_text(),"old");self.assertEqual(next(path.parent.glob("*.tmp")).read_text(),"new complete payload")
   with mock.patch.object(R,"write_circle_artifacts",side_effect=PermissionError("blocked")):
    metrics=R.safe_circle_artifacts(path.parent,{},stage="fixture")
   R.save_json(path.parent/"summary.json",{"arm_c":{"partial":True},"circles":metrics})
   self.assertTrue(json.loads((path.parent/"summary.json").read_text())["arm_c"]["partial"])

if __name__=="__main__":unittest.main()
