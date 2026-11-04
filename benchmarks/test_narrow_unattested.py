"""Export and CLI checks use synthetic ontologies and stubs only; never the grading key."""
import contextlib,hashlib,io,json,pathlib,sys,tempfile,unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P
from sbgk_bench.ontology_evolution import enrich
import run_pilot_ac as R
class Evolution(unittest.TestCase):
 def test_per_concept_provenance_current_mappings_and_kernel_reason(self):
  event={"op":"revise_concept","status":"confirmed","subject":"w2","proposer":"w1","initial_reviewer":"w2","proposal":"p","change":{"concept":"b","action":"narrow"},"result":{"into":[{"id":"n"}],"moves":[{"from":"b","to":"n","record":"r","term":"term"}]}}
  snap={"ontology":{"concepts":[{"id":"b","status":"narrowed","proposed_by":"base"},{"id":"n","status":"provisional","proposed_by":"w1"},{"id":"u","status":"unattested","proposed_by":"base","attestation_reason":{"mapping_count":0,"ontology_revision":4}}]},"seed_ids":["b","u"],"events":[event,{"op":"ontology_attestation","subject":"kernel","concept":"u","status":"unattested"}],"current_mappings":[{"concept":"b","record":"old","term":"old"},{"concept":"n","record":"r","term":"term"}]}
  got=enrich(snap,{"w1":{"model":"first","nature":"family"},"w2":{"model":"second","nature":"other"}})
  b,n,u=got["ontology"]["concepts"]
  self.assertEqual(b["evolution"]["mappings_moved_out"],1);self.assertEqual(b["evolution"]["mappings_on_narrowed_concept"],1)
  self.assertEqual(n["evolution"]["mappings_moved_in"],1);self.assertEqual(n["evolution"]["proposer_model"]["model"],"first")
  self.assertEqual(b["evolution"]["confirmers"][0]["agent_model"]["model"],"second")
  self.assertEqual(u["evolution"]["attestation_history"][0]["agent_model"]["nature"],"deterministic_kernel")
  self.assertEqual(u["evolution"]["unattested_reason"]["mapping_count"],0)
  self.assertEqual(got["unmapped_seed_summary"][0]["concept"],"u");self.assertEqual(b["evolution"]["proposer_model"]["nature"],"genesis_seed")
 def test_restored_concept_is_not_exported_as_currently_unattested(self):
  snap={"ontology":{"concepts":[{"id":"u","status":"provisional","attestation_reason":{"mapping_count":0}}]},"events":[],"current_mappings":[{"concept":"u"}],"seed_ids":["u"]}
  enrich(snap,{})
  self.assertIsNone(snap["ontology"]["concepts"][0]["evolution"]["unattested_reason"]);self.assertEqual(snap["unmapped_seed_summary"],[])
 def test_cli_flag_is_read_without_starting_work(self):
  seen=[]
  def run(*a,**kw):seen.append(P.UNATTESTED_AT_END);return {"measures":{}}
  with mock.patch.dict(P.__dict__,{"ARM_A_MODE":"notes"}),mock.patch.object(sys,"argv",["pilot","--manifest","m","--repo","r","--model","stub","--unattested-at-end"]),mock.patch.object(R.C,"BIN",pathlib.Path(__file__)),mock.patch.object(R,"corpus_choice",return_value=(["x"],{"steps":[]},{})),mock.patch.object(P,"make_model",return_value=P.StubModel()),mock.patch.object(R,"run",side_effect=run),contextlib.redirect_stdout(io.StringIO()):R.main()
  self.assertEqual(seen,[True])
 def test_real_store_stub_run_exports_unattested_without_revision_policy(self):
  self.assertTrue(R.C.BIN.is_file(),"isolated built kernel required")
  with tempfile.TemporaryDirectory(prefix="unattested-export-") as tmp:
   root=pathlib.Path(tmp);(root/"repo").mkdir();text="# Limits\nFuture work remains open.\n";doc=root/"repo/report.md";doc.write_text(text,encoding="utf-8",newline="\n")
   manifest=root/"manifest.json";manifest.write_text(json.dumps({"format":"r2r.tobi_corpus_metadata_manifest.v1","source":{"origin_recorded":"https://example.invalid/repo.git","commit":"1"*40,"repository":"local"},"entries":[{"path":"report.md","extension":".md","corpus_role":"markdown_document_candidate","size_bytes":len(text.encode()),"raw_sha256":hashlib.sha256(text.encode()).hexdigest(),"references":{"commit_candidates":[],"pull_request_candidates":[]}}]}),encoding="utf-8")
   base=P.json.loads((pathlib.Path(P.__file__).parents[2]/"crates/sbgk-core/src/audit/base_ontology.json").read_text());base["concepts"]=[{"type":"Component","name":"unused synthetic component","aliases":[]}];base["seed_status"]="provisional";ontology=root/"base.json";ontology.write_text(json.dumps(base),encoding="utf-8")
   with mock.patch.multiple(P,UNATTESTED_AT_END=True,ONTOLOGY_REVISIONS=False,ONTOLOGY_REVIEW=False,CIRCLES=False,DYNAMIC_ROLES=False,WHOLE_READER=False,LINK_CHECKER=False,PAIRS_ONLY=False,BASE_ONTOLOGY=str(ontology),QUESTIONS=[{"id":"RQ1","text":"What future work remains?","about":["future"]}],AGENT_ATTEMPTS=None):
    try:result=P.run_arm_c(P.StubModel(),P.StubModel(),root/"out/arm_c",manifest,root/"repo",["report.md"],{"report.md":text},{"steps":[]},workers=1,timeout_s=30)
    except Exception as exc:
     err=root/"out/arm_c/server.err"
     raise AssertionError(f"stub kernel failure: {err.read_text() if err.exists() else 'no stderr'}") from exc
   self.assertEqual(result["phase1"]["receipt"]["status"],"TERMINAL",result)
   snapshot=json.loads((root/"out/ontology_evolution.json").read_text(encoding="utf-8"));seed=next(c for c in snapshot["ontology"]["concepts"] if c["definition"]["name"]=="unused synthetic component")
   self.assertEqual(seed["status"],"unattested");self.assertEqual(seed["evolution"]["unattested_reason"]["mapping_count"],0)
   self.assertEqual(seed["evolution"]["attestation_history"][0]["agent_model"]["nature"],"deterministic_kernel")
if __name__=="__main__":unittest.main()
