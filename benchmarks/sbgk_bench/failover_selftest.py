"""Explicit C0 failure imitation on a real local store. No provider process is invoked."""
import hashlib,json,pathlib,tempfile,threading

def run(output=None):
 from . import pilot_ac as P
 from unittest.mock import patch
 from run_pilot_ac import SYNTH
 class Fault(P.StubModel):
  def __init__(self,kind,exhaust=False):self.kind=kind;self.count=0;self.exhaust=exhaust;self.lock=threading.Lock()
  def complete(self,prompt):
   applies='TASK EXTEND' in prompt if self.kind=='reader' else prompt.startswith(('You are the graph builder','PAIR_CARD:'))
   if applies:
    with self.lock:self.count+=1;n=self.count
    if self.exhaust or n<=2:
     if n%2:raise TimeoutError('simulated AGY_TIMEOUT')
     raise P.AgyCallError('AGY_STREAM_ERROR: stdin: BrokenPipeError (simulated)',{}, {'stdout_prefix':'simulated partial progress','stderr_prefix':'simulated closed stdin'})
   if "TASK SUMMARIZE research question" in prompt:
    # This fixture verifies transport, not semantic audit quality. Its honest answer is unknown.
    lines=[json.loads(v) for v in self._summarize(prompt).splitlines()]
    done=next(v for v in lines if v["kind"]=="done");done.update(outcome="unknown",answer_ids=[],text="Offline transport fixture; no semantic answer attempted.")
    return json.dumps(done),{},0.0
   return super().complete(prompt)
 def scenario(root,exhaust):
  root.mkdir(parents=True,exist_ok=False);entries=[]
  for path,text in SYNTH.items():
   p=root/'repo'/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text,encoding='utf-8',newline='\n')
   entries.append({'path':path,'extension':'.md','corpus_role':'markdown_document_candidate','size_bytes':len(text.encode()),'raw_sha256':hashlib.sha256(text.encode()).hexdigest(),'references':{'commit_candidates':[],'pull_request_candidates':[]}})
  manifest=root/'manifest.json';manifest.write_text(json.dumps({'format':'r2r.tobi_corpus_metadata_manifest.v1','entries':entries,'source':{'origin_recorded':'https://example.invalid/offline.git','commit':'1'*40,'repository':'local'}}),encoding='utf-8')
  reader,builder=Fault('reader'),Fault('builder',exhaust)
  with patch.multiple(P,CIRCLES=False,DYNAMIC_ROLES=False,AGENT_ATTEMPTS=3 if not exhaust else 1,AGENT_RETRY_PAUSE_S=0,ARM_A_ANSWER='direct',ARM_A_MODE='single',PAIRS_ONLY=False,WHOLE_READER=False,LINK_CHECKER=True):
   result=P.run_arm_c(reader,builder,root/'kernel',manifest,root/'repo',list(SYNTH),SYNTH,{"steps":[]},workers=1,timeout_s=60)
  (root/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
  assert result['phase1']['receipt']['status']=='TERMINAL',result['phase1']
  calls=result['calls'];errors=[c for c in calls if not c['ok']]
  assert len({c['call_id'] for c in calls})==len(calls)
  assert any('TimeoutError' in (c['error'] or '') for c in errors)
  assert any('BrokenPipeError' in (c['error'] or '') for c in errors)
  assert any(c.get('diagnostics',{}).get('stdout_prefix') for c in errors)
  ledger=result['phase1']['receipt']['agent_failures']['work']
  if exhaust:
   assert any(k.startswith('build:') and v['unresolved'] for k,v in ledger.items()),ledger
  else:
   assert any(k.startswith('doc:') and v['failures']==2 for k,v in ledger.items()),ledger
   assert any(k.startswith('build:') and v['failures']==2 for k,v in ledger.items()),ledger
  return {'calls':len(calls),'failed_calls':len(errors),'terminal':True,'unresolved':[k for k,v in ledger.items() if v['unresolved']]}
 def execute(root):
  report={'selftest':'c0-failover','recovery':scenario(root/'recovery',False),'exhaustion':scenario(root/'exhaustion',True)}
  (root/'selftest.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report));return report
 if output:
  root=pathlib.Path(output);root.mkdir(parents=True,exist_ok=False);return execute(root)
 with tempfile.TemporaryDirectory(prefix='c0-failover-selftest-') as tmp:return execute(pathlib.Path(tmp))
if __name__=='__main__':
 import argparse
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',required=True);a=ap.parse_args();run(a.out)
