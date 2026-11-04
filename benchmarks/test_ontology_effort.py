"""Ontology/effort/export dependency checks. No external model is invoked."""
import json, pathlib, sys, tempfile, threading, unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from sbgk_bench import pilot_ac as P
from sbgk_bench.phase_effort import EffortPolicy, parse_phase_effort
from sbgk_bench.atomic_output import write_text
import run_pilot_ac as R
SPEC="READ=medium,BUILD=low,VERIFY=medium,ANSWER=medium"
class Effort(unittest.TestCase):
 def test_strict_configuration(self):
  self.assertEqual(parse_phase_effort(SPEC)["BUILD"],"low")
  for spec in ("BUILD=low",SPEC+",BUILD=high",SPEC.replace("low","turbo"),SPEC.replace("READ","BAD")):
   with self.assertRaises(ValueError):parse_phase_effort(spec)
 def test_shared_card_ladder_changes_effort_without_changing_model_nature(self):
  policy=EffortPolicy(parse_phase_effort(SPEC));first=P.AgyModel("flash-high",timeout_s=240);second=P.AgyModel("argon-medium",timeout_s=240)
  card={"card_id":"C1","task_id":"lease1"}
  m,meta=policy.select(first,"C","BUILD",1,card,600);self.assertEqual(m.name,"flash-low");self.assertEqual(meta["model_family"],"agy:flash")
  policy.change("C","BUILD",1,card,"kernel_repair");policy.change("C","BUILD",1,card,"kernel_repair")
  m,_=policy.select(second,"C","BUILD",1,{"card_id":"C1","task_id":"lease2"},600);self.assertEqual(m.name,"argon-high")
  policy.change("C","BUILD",1,card,"timeout");m,_=policy.select(second,"C","BUILD",1,card,600);self.assertEqual(m.name,"argon-medium")
  m,_=policy.select(first,"C","BUILD",1,{"card_id":"C2"},600);self.assertEqual(m.name,"flash-low")
  m,_=policy.select(first,"A","LEAD",1,{"rq_id":"RQ1"},600);self.assertEqual(m.timeout_s,600);self.assertEqual(first.timeout_s,240)
 def test_log_timeout_is_recorded_and_ladder_survives_reassignment(self):
  def fake(model,prompt,**kw):return P.Call(**kw,prompt_chars=len(prompt),model=model.name,ok=False,error="AGY_TIMEOUT: fixture")
  with mock.patch.object(P,"PHASE_EFFORT",parse_phase_effort(SPEC)),mock.patch.object(P,"call_model",side_effect=fake):
   log=P.Log();log.adjust_effort("C","BUILD",1,{"card_id":"c"},"kernel_repair")
   c=log.invoke(P.AgyModel("flash-high"),"p",call_id="one",arm="C",role="BUILD",phase=1,context={"card_id":"c"})
   self.assertEqual(c.model,"flash-medium");self.assertEqual(c.effort,"medium")
   self.assertEqual(log.preview_model(P.AgyModel("argon-high"),"C","BUILD",1,{"card_id":"c"}).name,"argon-low")
   self.assertEqual(log.events[-1]["outcome"],"EFFORT_CHANGED")
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

class ProvisionalFlow(unittest.TestCase):
 def test_provisional_jev_suggestion_is_not_submitted_as_an_automatic_mapping(self):
  card={"records":[{"id":"@record","terms":["engine"]}],"candidates":{"engine":[{"id":"@1111111111111111","name":"engine","type":"Component","status":"provisional"}]},"ontology_revision":{"pending":[]}}
  card.update(status="CARD",card_id="C-suggestion",prompt="Build",max_ops=8)
  seen=[];sent=[]
  def fake(model,prompt,**kw):
   seen.append((kw["role"],prompt))
   return P.Call(**kw,prompt_chars=len(prompt),text="{}" if kw["role"]=="JEV" else "[]",model=model.name)
  class Wire:
   def call(self,tool,**kw):sent.append(kw["ops"]);return {"status":"CARD_DONE","results":[]}
  # a term selector sure of the provisional concept (the open hook of build_card; Jev's own rule is the closed layer's)
  selector=type("Selector",(),{"name":"jev","request":lambda self,c:({"questions":{}},{0:("@record","engine")}),
                               "ops":lambda self,a,i,c:[{"op":"map_term","record":"@record","term":"engine","concept":"@1111111111111111"}]})()
  with mock.patch.object(P,"call_model",side_effect=fake),mock.patch.object(P,"CIRCLES",True):
   log=P.Log();self.assertTrue(P.build_card(Wire(),card,type("Model",(),{"name":"builder"})(),log,1,threading.Event(),selector))
  self.assertEqual(sent,[[]]);prompt=next(p for role,p in seen if role=="BUILDER");self.assertIn("PROVISIONAL CONCEPT SUGGESTIONS",prompt);self.assertNotIn("ALREADY MAPPED",prompt)
  self.assertEqual(log.events[-1]["jev_provisional_suggestions"],1)

class AnswerRetry(unittest.TestCase):
 def test_timeout_retry_keeps_both_calls_and_uses_same_prompt_lower_effort(self):
  calls=[]
  def fake(model,prompt,**kw):
   calls.append((model.name,prompt,kw["call_id"]))
   return P.Call(**kw,prompt_chars=len(prompt),model=model.name,ok=len(calls)>1,text="complete" if len(calls)>1 else "partial",error=None if len(calls)>1 else "AGY_TIMEOUT: fixture")
  with mock.patch.object(P,"PHASE_EFFORT",parse_phase_effort(SPEC)),mock.patch.object(P,"call_model",side_effect=fake):
   log=P.Log();result=P.invoke_answer(log,P.AgyModel("flash-high"),"original bytes",call_id="a",arm="A",role="LEAD",phase=1,context={"rq_id":"RQ1"})
  self.assertTrue(result.ok);self.assertEqual([x[0] for x in calls],["flash-medium","flash-low"]);self.assertEqual([x[1] for x in calls],["original bytes"]*2);self.assertEqual([x[2] for x in calls],["a","a-timeout-retry-1"]);self.assertEqual(len(log.calls),2);self.assertEqual(log.calls[0].text,"partial")
 def test_retry_stops_at_call_cap_and_does_not_retry_other_errors(self):
  for error,limit in (("AGY_TIMEOUT: fixture",1),("AGY_TIMEOUT: fixture",5),("MODEL_FAILED: fixture",5)):
   def fake(model,prompt,**kw):return P.Call(**kw,prompt_chars=len(prompt),model=model.name,ok=False,error=error)
   with mock.patch.object(P,"call_model",side_effect=fake):
    log=P.Log(max_calls=limit);P.invoke_answer(log,P.AgyModel("flash-medium"),"p",call_id="a",arm="A",role="UPDATE",phase=2)
   self.assertEqual(len(log.calls),1 if limit==1 or error.startswith("MODEL_FAILED") else 2)
   if limit==1:self.assertIn("CALL_CAP",log.stopped)

if __name__=="__main__":unittest.main()
