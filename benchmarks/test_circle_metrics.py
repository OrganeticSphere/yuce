"""Circle acceptance and idle-time regressions on synthetic WALs only."""
import json
import pathlib
import sys
import tempfile
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench.circle_metrics import circle_metrics

class Metrics(unittest.TestCase):
    def test_nested_durable_outcome_and_idle_intervals_crossing_phase_boundary(self):
        def boundary(phase,t):
            return {"payload":{"command":{"checkpoint":{"key":"audit:circles","context":{
                "format":"r2r-circles/1","circle":1,"circle_phase":phase,"started_unix_ms":t,
                "snapshot":{"records":0,"concepts":0,"links_total":0,"links_accepted":0,"links_rejected":0,"concepts_across_reports":0}}}},
                "outcome":{"kind":"value","result":{"checkpointed":True}}}}
        frames=[boundary("READ",0),boundary("BUILD",2000),boundary("FINAL",4000)]
        events=[{"kind":"IDLE_WAIT","agent":"w1","start_unix_s":1.0,"end_unix_s":5.0},
                {"kind":"EXTEND","task":"t1","circle":1,"circle_phase":"READ","lines_offered":5,"lines_stored":4,
                 "repairs":1,"error":None,"abandoned":False}]
        with tempfile.TemporaryDirectory() as tmp:
            wal=pathlib.Path(tmp)/"test.wal"
            wal.write_text("\n".join(json.dumps(x) for x in frames),encoding="utf-8")
            rows=circle_metrics(wal,events)["rows"]
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["reading"]["acceptance"],0.8)
        self.assertEqual(rows[0]["idle_s_by_agent"],{"READ":{"w1":1.0},"BUILD":{"w1":2.0}})
    def test_refused_checkpoint_is_not_a_phase_and_missing_denominator_is_null(self):
        context={"format":"r2r-circles/1","circle":1,"circle_phase":"READ","started_unix_ms":0,"snapshot":{}}
        frames=[{"payload":{"command":{"checkpoint":{"key":"audit:circles","context":context}},
                            "outcome":{"kind":"value","result":{"checkpointed":False}}}}]
        with tempfile.TemporaryDirectory() as tmp:
            wal=pathlib.Path(tmp)/"test.wal"
            wal.write_text(json.dumps(frames[0]),encoding="utf-8")
            self.assertEqual(circle_metrics(wal,[])["rows"],[])
            frames[0]["payload"]["outcome"]["result"]["checkpointed"]=True
            wal.write_text(json.dumps(frames[0]),encoding="utf-8")
            row=circle_metrics(wal,[])["rows"][0]
        self.assertIsNone(row["reading"]["acceptance"])
        self.assertFalse(row["closed"])
        self.assertIsNone(row["build_s"])

class Matrix(unittest.TestCase):
    def test_partial_operations_keep_their_authors_and_jev_is_a_separate_executor(self):
        from sbgk_bench.agent_matrix import operation_decisions,matrices
        card={"records":[{"id":"@a","author":"w1"},{"id":"@b","author":"w2"}],"neighbors":[]}
        ops=[{"op":"link","from":"@a","to":"@b"},{"op":"map_term","record":"@b","term":"term","concept":"@c"}]
        reply={"status":"REPAIR_REQUIRED","accepted":1,"results":[{}],"refused":[{"index":0}]}
        decisions=operation_decisions(card,ops,reply,["BUILDER","JEV"])
        self.assertEqual([r["decision"] for r in decisions],["refused","accepted"])
        m=matrices([{"circle":1,"builder_model":"builder","operation_decisions":decisions}],{"w1":"A","w2":"B"},1)
        self.assertEqual(sum(r.get("refused",0) for r in m["builder_operations"]),2,"two endpoint authors are reported explicitly")
        self.assertTrue(any(r["executing_model"]=="Jev" and r["author_model"]=="B" and r["accepted"]==1 for r in m["builder_operations"]))
    def test_jev_same_different_unresolved_and_coverage_deduplicates_reissued_cards(self):
        from sbgk_bench.agent_matrix import jev_comparison,matrices
        card={"candidates":{"term":[{"id":"@c1","name":"one","aliases":["alias"]},{"id":"@c2","name":"two","aliases":[]}]}}
        chosen=[{"op":"map_term","record":"@r","term":"term","concept":"@c1"}]
        proposals=[{"op":"map_term","record":"@r","term":"term","concept":c} for c in ("alias","@c2","unknown")]
        rows=jev_comparison(card,chosen,proposals)
        self.assertEqual([r["agreement"] for r in rows],["same","different","unresolved"])
        e={"circle":1,"outcome":"JEV_COVERAGE","card":"C1","material_keys":[["@r","term"]],"eligible_keys":[["@r","term"]],"selected_keys":[["@r","term"]]}
        m=matrices([e,e,{"circle":1,"builder_model":"B","jev_comparison":rows}],{},1)
        self.assertEqual(m["jev_coverage"]["material_terms"],1)
        self.assertEqual(m["jev_coverage"]["share"],1)
        self.assertEqual(m["jev_agreement"][0]["different"],1)
    def test_wholly_refused_operations_are_not_counted_as_accepted(self):
        from sbgk_bench.agent_matrix import operation_decisions
        ops=[{"op":"map_term","record":"@a"}]*2
        rows=operation_decisions({"records":[],"neighbors":[]},ops,{"status":"REPAIR_REQUIRED","accepted":0,"failed_index":0})
        self.assertTrue(all(r["decision"]=="refused" for r in rows))
        rows=operation_decisions({"records":[],"neighbors":[]},ops,{"status":"STALE_TASK"})
        self.assertTrue(all(r["decision"]=="unknown" for r in rows))
    def test_model_timeout_records_the_member_without_stopping_the_log(self):
        from sbgk_bench import pilot_ac as P
        from unittest import mock
        rpc=mock.Mock();rpc.call.return_value={"status":"RELEASED"}
        log=P.Log()
        call=P.Call("late","C","BUILD",1,10,ok=False,error="TimeoutExpired: 540 seconds",model="fake")
        with mock.patch.object(P,"CIRCLES",True):
            self.assertTrue(P.report_agent_timeout(rpc,call,"TB1",log,agent="w1",phase=1,context={"circle":1,"sync_step":3}))
        rpc.call.assert_called_once_with("audit_release",task_id="TB1",timed_out=True)
        self.assertIsNone(log.stopped)
        self.assertEqual(log.events[0]["outcome"],"AGENT_TIMEOUT")

if __name__=="__main__":
    unittest.main()
