"""C1r offline regression checks. No model, pilot, or provider is executed."""
import json, pathlib, sys, tempfile, threading, unittest
from types import SimpleNamespace
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import run_pilot_ac as R
from sbgk_bench import pilot_ac as P
from sbgk_bench.circle_metrics import circle_metrics,anomaly_counts

class C1r(unittest.TestCase):
 def test_answers_share_the_900_second_deadline(self):
  for arm,role in (("A","LEAD"),("C","SUMMARIZE")):
   calls=[]
   def fake(model,prompt,**kw):
    calls.append((model.name,model.timeout_s))
    return P.Call(**kw,prompt_chars=len(prompt),model=model.name,ok=len(calls)>1,text="ok" if len(calls)>1 else None,error="AGY_TIMEOUT: fixture" if len(calls)==1 else None)
   with mock.patch.object(P,"RUN_HOOK",P.RunHook()),mock.patch.object(P,"call_model",side_effect=fake):
    log=P.Log()
    if arm=="A":P.invoke_answer(log,P.AgyModel("flash-medium"),"p",call_id="a",arm=arm,role=role,phase=1,context={"rq_id":"RQ1"})
    else:
     # C times out its lease and is reissued at the next synchronized shift, with a stable RQ key.
     for n in range(2):log.invoke(P.AgyModel("flash-medium"),"p",call_id=f"c{n}",arm=arm,role=role,phase=1,context={"key":"rq:RQ1","task_id":f"lease{n}"})
   self.assertEqual(calls,[("flash-medium",900),("flash-medium",900)])
 def test_graph_shape_sort_resolves_seed_names_and_keeps_unknown_explicit(self):
  with tempfile.TemporaryDirectory() as folder:
   root=pathlib.Path(folder);(root/"arm_c").mkdir();wal=root/"arm_c/run.wal"
   frames=[{"payload":{"actor":"builder","command":{"operations":[{"kind":"map_term","record":"a"*64,"concept":cid}]},"outcome":{"result":{"accepted_operations":1,"results":[{}]}}}} for cid in ("1"*64,"2"*64)]
   wal.write_text("\n".join(json.dumps(f) for f in frames),encoding="utf-8")
   result=P.graph_shape(wal);self.assertEqual(result["concept_names_unresolved"],2)
   (root/"ontology_evolution.json").write_text(json.dumps({"ontology":{"concepts":[{"id":"1"*64,"definition":{"name":"seed"}}]}}),encoding="utf-8")
   result=P.graph_shape(wal);self.assertEqual(result["concept_names_unresolved"],1)
   self.assertEqual(result["largest_concepts"][0]["name"],"seed")
 def test_artifact_errors_preserve_summary_and_allow_next_pair_arm(self):
  with tempfile.TemporaryDirectory() as folder:
   root=pathlib.Path(folder);(root/"one.md").write_text("A limitation remains.",encoding="utf-8");manifest=root/"manifest.json";manifest.write_text("{}")
   model=SimpleNamespace(name="dependency-only");arm={"calls":[],"events":[]};returned=[]
   with mock.patch.object(P,"CIRCLES",False),mock.patch.object(P,"ARM_A_MODE","default"),mock.patch.object(P,"run_arm_c",return_value=arm),mock.patch.object(P,"run_arm_a",return_value=arm),mock.patch.object(P,"measures",side_effect=[RuntimeError("measurement fixture"),{}]),mock.patch.object(P,"graph_shape",return_value={}),mock.patch.object(P,"answers_md",side_effect=ValueError("blind fixture")):
    for label in ("C1","C0"):
     out=root/label;returned.append(R.run(manifest,root,["one.md"],out,model,1,None))
     self.assertTrue((out/"summary.json").exists());self.assertEqual(json.loads((out/"status.json").read_text())["status"],"FINISHED")
   self.assertEqual([e["step"] for e in returned[0]["artifact_errors"]],["measures","blind_answers"])
   self.assertEqual([e["step"] for e in returned[1]["artifact_errors"]],["blind_answers"])
 def test_circle_metrics_count_cards_without_equating_submissions_to_proposals(self):
  events=[{"circle":1,"circle_phase":"BUILD","card":"c","ontology_anomaly":True,"operation_decisions":[{"op":"revise_concept","decision":"refused"}]}]
  result=anomaly_counts(events,1);self.assertEqual(result["distinct_hint_cards"],1);self.assertEqual(result["distinct_revision_proposals"],0);self.assertEqual(result["revise_submissions_by_decision"],{"refused":1})
  frames=[{"payload":{"outcome":{"result":{"results":[{"op":"ontology_review","review_id":"o","concept":"c","circle":1,"subject":"w2","decision":"keep","reason":"insufficient evidence","basis":["quote"]}]}}}}]
  result=circle_metrics(pathlib.Path("unused"),events,frames=frames);self.assertEqual(result["ontology_reviews"][0]["decision"],"keep")
 def test_empty_record_review_invokes_the_model_then_repairs(self):
  card={"card_id":"R1-1-review","kind":"ONTOLOGY_REVIEW_CARD","records":[],"neighbors":[],"candidates":{},"prompt":"An explicit review is required.","ontology_revision":{"hints":[{"kind":"possible_catchall","concept":"@c"}]}}
  op={"op":"keep","concept":"@c","basis":["@o"],"reason":"Insufficient evidence for a change."};calls=[];submissions=[]
  def fake(model,prompt,**kw):
   calls.append(model.name)
   return P.Call(**kw,prompt_chars=len(prompt),model=model.name,ok=True,text="[]" if len(calls)==1 else json.dumps(op))
  def rpc_call(tool,**kw):
   if tool=="audit_renew":return {"status":"RENEWED"}
   submissions.append(kw["lines"])
   return {"status":"REPAIR_REQUIRED","accepted":0,"error":{"code":"REVIEW_REQUIRED"},"refused":[],"results":[]} if len(submissions)==1 else {"status":"CARD_DONE","accepted":1,"results":[{"op":"keep"}]}
  with mock.patch.object(P,"RUN_HOOK",P.RunHook()),mock.patch.object(P,"CIRCLES",True),mock.patch.object(P,"WHOLE_READER",False),mock.patch.object(P,"PAIRS_ONLY",False),mock.patch.object(P,"call_model",side_effect=fake):
   log=P.Log();done=P.build_card(SimpleNamespace(call=rpc_call),card,P.AgyModel("flash-low"),log,1,threading.Event(),agent="w2",task_id="TB",circle_context={"circle":1,"circle_phase":"BUILD"})
  self.assertTrue(done);self.assertEqual(calls,["flash-low","flash-low"]);self.assertEqual(submissions,[[],[op]])
 def test_circle_render_failure_preserves_computed_metrics_and_other_files(self):
  with tempfile.TemporaryDirectory() as folder:
   root=pathlib.Path(folder);(root/"events.jsonl").write_text("")
   with mock.patch("sbgk_bench.circle_metrics.matrix_markdown",side_effect=ValueError("render fixture")):
    metrics=R.write_circle_artifacts(root,{},stage="arm_c_progress",telemetry={"frames":[]})
   self.assertEqual(metrics["export"]["artifact_errors"][0]["artifact"],"circle_model_matrix.md")
   self.assertTrue((root/"circle_acceptance.svg").exists());self.assertTrue((root/"circles.json").exists())
 def test_authenticated_telemetry_never_opens_live_wal(self):
  with tempfile.TemporaryDirectory() as folder:
   root=pathlib.Path(folder);(root/"events.jsonl").write_text("")
   with mock.patch("pathlib.Path.open",side_effect=PermissionError("writer owns WAL")):
    # Loading events also needs open: supply the event prefix directly.
    with mock.patch("sbgk_bench.circle_metrics.jsonl_prefix",return_value=iter(())):
     result=R.write_circle_artifacts(root,{},stage="arm_c_progress",telemetry={"frames":[],"through_sequence":7,"wal_head":"h"})
   self.assertEqual(result["input_source"]["kind"],"authenticated_committed_checkpoints")

if __name__=="__main__":unittest.main()
