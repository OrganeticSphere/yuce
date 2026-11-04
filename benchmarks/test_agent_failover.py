"""C0 retry and A map-reduce checks. Models are in-process stubs, never providers."""
import json,pathlib,sys,threading,time,unittest
from types import SimpleNamespace
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P
from sbgk_bench import answer_map_reduce as M
class Failover(unittest.TestCase):
 def test_transport_categories_and_fatal_configuration(self):
  for e in ('AGY_TIMEOUT: deadline','AGY_STREAM_ERROR: stdin: BrokenPipeError','BrokenPipeError: closed','agy did not return a successful text result: exit 1','AGY_ASKED_HUMAN: ask_question'):
   c=P.Call(call_id='x',arm='C',role='EXTEND',phase=1,prompt_chars=0,ok=False,error=e);self.assertTrue(P.agent_failed(c),e)
  self.assertFalse(P.agent_failed(P.Call(call_id='x',arm='C',role='EXTEND',phase=1,prompt_chars=0,ok=False,error='unknown model / no credential')))
  self.assertFalse(P.agent_failed(P.Call(call_id='x',arm='C',role='EXTEND',phase=1,prompt_chars=0,ok=True,error='AGY_TIMEOUT')))
 def test_c0_stream_failure_returns_lease_and_pauses_without_stop(self):
  rpc=mock.Mock();rpc.call.return_value={'status':'RELEASED'};log=P.Log();c=P.Call(call_id='x',arm='C',role='EXTEND',phase=1,prompt_chars=0,ok=False,error='AGY_STREAM_ERROR: stdin: BrokenPipeError',diagnostics={'stdout_prefix':'partial'})
  with mock.patch.multiple(P,CIRCLES=False,AGENT_ATTEMPTS=3),mock.patch.object(P.time,'sleep') as pause:
   self.assertTrue(P.report_agent_timeout(rpc,c,'TE1',log,agent='w1',phase=1,context={}))
   pause.assert_called_once_with(P.AGENT_RETRY_PAUSE_S)
  rpc.call.assert_called_once_with('audit_release',task_id='TE1',timed_out=True);self.assertIsNone(log.stopped);self.assertEqual(log.events[-1]['outcome'],'AGENT_STREAM_FAILURE');self.assertEqual(c.diagnostics['stdout_prefix'],'partial')
 def test_circle_stream_failure_uses_existing_exclusion_route_without_new_flag(self):
  rpc=mock.Mock();rpc.call.return_value={'status':'RELEASED'}
  with mock.patch.multiple(P,CIRCLES=True,AGENT_ATTEMPTS=None):self.assertTrue(P.report_agent_timeout(rpc,P.Call(call_id='x',arm='C',role='EXTEND',phase=1,prompt_chars=0,ok=False,error='AGY_STREAM_ERROR: closed'),'T',P.Log(),agent='w',phase=1,context={}))
  rpc.call.assert_called_once_with('audit_release',task_id='T',timed_out=True)
 def test_disabled_c0_failure_has_no_retry_rpc(self):
  rpc=mock.Mock()
  with mock.patch.multiple(P,CIRCLES=False,AGENT_ATTEMPTS=None):self.assertFalse(P.report_agent_timeout(rpc,P.Call(call_id='x',arm='C',role='EXTEND',phase=1,prompt_chars=0,ok=False,error='AGY_TIMEOUT'),'T',P.Log(),agent='w',phase=1,context={}))
  rpc.call.assert_not_called()
 def test_standalone_same_card_has_distinct_attempt_and_lower_effort(self):
  seen=[];rpc=mock.Mock();rpc.call.side_effect=lambda tool,**kw: {'status':'CARD_RETRY'} if tool=='audit_builder_failure' else {'status':'CARD_DONE'}
  def complete(model,prompt):
   seen.append(model.name)
   if len(seen)==1:raise P.AgyCallError('AGY_STREAM_ERROR: stdin: BrokenPipeError',{}, {'stdout_prefix':'partial builder'})
   return '[]',{},None
  log=P.Log();card={'card_id':'C1-2-unit','records':[{'author':'w1'}],'prompt':'make links'}
  with mock.patch.multiple(P,CIRCLES=False,AGENT_ATTEMPTS=3,PAIRS_ONLY=False,WHOLE_READER=False,AGENT_RETRY_PAUSE_S=0),mock.patch.object(P.AgyModel,'complete',complete):
   log.effort_policy.failure_ladder=True
   self.assertIsNone(P.build_card(rpc,dict(card,agent_attempt=1),P.AgyModel('flash-medium'),log,1,threading.Event()))
   self.assertTrue(P.build_card(rpc,dict(card,agent_attempt=2),P.AgyModel('flash-medium'),log,1,threading.Event()))
  self.assertEqual(seen,['flash-medium','flash-low']);self.assertEqual(len({c.call_id for c in log.calls}),2);self.assertIn('-agent2',log.calls[-1].call_id)
  self.assertEqual(log.calls[0].diagnostics['stdout_prefix'],'partial builder');self.assertIsNone(log.stopped)

 def test_standalone_physical_id_is_fresh_even_after_client_restart_before_failure_ack(self):
  rpc=mock.Mock();rpc.call.return_value={'status':'CARD_RETRY'};card={'card_id':'C1-2-unit','records':[{'author':'w1'}],'prompt':'card','agent_attempt':1};ids=[]
  model=SimpleNamespace(name='fixture',complete=lambda p: (_ for _ in ()).throw(TimeoutError('simulated timeout')))
  with mock.patch.multiple(P,CIRCLES=False,AGENT_ATTEMPTS=3,PAIRS_ONLY=False,WHOLE_READER=False,AGENT_RETRY_PAUSE_S=0):
   for _ in range(2):
    log=P.Log();self.assertIsNone(P.build_card(rpc,card,model,log,1,threading.Event()));ids.append(log.calls[0].call_id)
  self.assertEqual(len(set(ids)),2)

class TreeReduce(unittest.TestCase):
 docs={f'r{i}.md':f'Limitation number {i} remains open.' for i in range(1,7)}
 q={'id':'RQ1','text':'What limitations remain?','about':['limitation']}
 def invoke(self,model):
  log=P.Log();sink=[]
  with mock.patch.object(P,'ARM_A_REDUCE','tree'):
   a=M.answer(log,model,self.docs,[],self.q,1,P.SINGLE_RULES,'lead','LEAD',{},None,sink)
  return a,log
 def test_six_reports_merge_pairwise_in_report_order_then_reduce(self):
  prompts=[]
  class Model(P.StubModel):
   def complete(self,p):prompts.append(p);return super().complete(p)
  a,log=self.invoke(Model())
  merges=[p for p in prompts if p.startswith('ARM A ANSWER REDUCE (merge level')]
  self.assertTrue(a['complete'],a);self.assertEqual(len(merges),4);self.assertEqual(len(log.calls),6+4+1)
  self.assertIn('r1.md',merges[0]);self.assertIn('r2.md',merges[0]);self.assertNotIn('r3.md',merges[0])
  self.assertTrue(all(m['merged'] for m in a['map_reduce']['merges']));self.assertEqual(a['map_reduce']['reduce'],'tree')
 def test_failed_merge_passes_a_union_on_and_the_answer_survives(self):
  class Model(P.StubModel):
   def complete(self,p):
    if p.startswith('ARM A ANSWER REDUCE (merge level 1') and 'r1.md' in p:raise TimeoutError('simulated merge timeout')
    return super().complete(p)
  a,log=self.invoke(Model())
  self.assertIsNone(log.stopped);self.assertTrue(a['claims'])
  first=[m for m in a['map_reduce']['merges'] if m['reports']=='r1.md+r2.md'][0]
  self.assertFalse(first['merged']);self.assertTrue(first['error'])
 def test_final_reduction_failure_falls_back_to_the_union(self):
  class Model(P.StubModel):
   def complete(self,p):
    if p.startswith('ARM A ANSWER REDUCE\nPARTIAL'):raise TimeoutError('simulated final timeout')
    return super().complete(p)
  a,log=self.invoke(Model())
  self.assertIsNone(log.stopped);self.assertIn('union',a['reduce_fallback']);self.assertEqual(len({q['report'] for c in a['claims'] for q in c['quotes']}),6)

class MapReduce(unittest.TestCase):
 docs={'a.md':'A limitation remains open.\nExtra unused private detail.','b.md':'B future work remains open.'}
 q={'id':'RQ1','text':'What limitations remain?','about':['limitation','future']}
 def invoke(self,model=None,withdrawn=None,notes=None):
  log=P.Log();sink=[]
  a=M.answer(log,model or P.StubModel(),self.docs,withdrawn or [],self.q,1,P.TEAM_RULES if notes is not None else P.SINGLE_RULES,'lead','LEAD',{},notes,sink)
  return a,log,sink
 def test_reports_local_and_reduction_uses_partial_quotes_only(self):
  seen=[]
  class Model(P.StubModel):
   def complete(self,p):seen.append(p);return super().complete(p)
  notes={'a.md':['- [a.md] "A limitation remains open."'],'b.md':['- [b.md] "B future work remains open."']}
  a,log,sink=self.invoke(Model(),notes=notes)
  self.assertTrue(a['complete'],a);self.assertEqual(len(log.calls),3);self.assertEqual(len(sink),2)
  self.assertNotIn('b.md',seen[0]);self.assertNotIn('a.md',seen[1]);self.assertNotIn('Extra unused private detail.',seen[2])
  self.assertTrue(all(len(p['claims']) for p in json.loads(seen[2].split('PARTIAL ANSWERS:\n')[1].split('\nEND PARTIAL ANSWERS')[0])))
  self.assertTrue(all(row['calls']==1 and row['prompt_chars'] and row['wall_s']>=0 for row in sink))
 def test_withdrawn_quote_cannot_survive_maps_or_reduction(self):
  a,log,sink=self.invoke(withdrawn=[{'report':'a.md','quote':'A limitation remains open.'}])
  self.assertTrue(a['complete'],a);self.assertTrue(all(q['report']!='a.md' for c in a['claims'] for q in c['quotes']))
 def test_map_does_not_receive_another_reports_withdrawal(self):
  prompts=[]
  class Model(P.StubModel):
   def complete(self,p):prompts.append(p);return super().complete(p)
  self.invoke(Model(),withdrawn=[{'report':'a.md','quote':'A limitation remains open.'}])
  self.assertIn('WITHDRAWN QUOTE:',prompts[0]);self.assertNotIn('a.md',prompts[1]);self.assertNotIn('A limitation remains open.',prompts[1])
 def test_reducer_cannot_add_quote_it_was_not_given(self):
  class Model(P.StubModel):
   def complete(self,p):
    if p.startswith(('ARM A ANSWER REDUCE', 'ARM A ANSWER REPAIR')):
     return json.dumps({'kind':'claim','local_id':'new','text':'unsupported reduction','quotes':[{'report':'a.md','exact_quote':'Extra unused private detail.'}]})+'\n'+json.dumps({'kind':'done','text':'done'}),{},0
    return super().complete(p)
  a,log,sink=self.invoke(Model());self.assertFalse(a['complete']);self.assertEqual(a['claims'],[]);self.assertIn('not among',a['refused_at_end'][0]['why'])
 def test_failed_report_is_visible_and_does_not_stop_other_report(self):
  class Model(P.StubModel):
   def complete(self,p):
    if 'ANSWER_MAP:' in p and '=== REPORT a.md' in p:raise TimeoutError('simulated timeout')
    return super().complete(p)
  a,log,sink=self.invoke(Model());self.assertIsNone(log.stopped);self.assertFalse(a['complete']);self.assertEqual(a['partial_reports_missing'],['a.md']);self.assertEqual([r['status'] for r in sink],['INCOMPLETE','COMPLETE'])
 def test_repair_and_retry_use_same_answer_model_effort_and_deadline(self):
  seen=[]
  def complete(m,p):seen.append((m.name,m.timeout_s));return P.StubModel().complete(p)
  with mock.patch.object(P.AgyModel,'complete',complete),mock.patch.object(P,'ANSWER_TIMEOUT_S',900):
   a,log,_=self.invoke(P.AgyModel('flash-medium',timeout_s=240))
  self.assertTrue(a['complete'],a);self.assertEqual(seen,[('flash-medium',900)]*3)
 def test_call_cap_preserves_completed_partials_and_skips_remaining(self):
  log=P.Log(max_calls=1);sink=[]
  a=M.answer(log,P.StubModel(),self.docs,[],self.q,1,P.SINGLE_RULES,'lead','LEAD',{},None,sink)
  self.assertIsNone(a);self.assertEqual(log.started,1);self.assertEqual(sink[1]['status'],'NOT_ATTEMPTED');self.assertEqual(sink[0]['status'],'COMPLETE')
 def test_team_mode_integration_on_stub_and_flag_off(self):
  with mock.patch.object(P,'ARM_A_ANSWER','map-reduce'):
   a=P.run_arm_team([P.StubModel(),P.StubModel()],self.docs,{},timeout_s=30)
  self.assertEqual(a['phase1']['status'],'COMPLETE',a);self.assertEqual(len(a['phase1']['partials']),len(P.QUESTIONS))
  with mock.patch.object(P,'ARM_A_ANSWER','direct'):
   old=P.run_arm_team([P.StubModel()],self.docs,{},timeout_s=30)
  self.assertEqual(old['phase1']['status'],'COMPLETE',old);self.assertNotIn('partials',old['phase1']);self.assertNotIn('answer_strategy',old)
if __name__=='__main__':unittest.main()
