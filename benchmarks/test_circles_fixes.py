"""C1c runner regressions. CLI streams come from owned Python children; no provider is called."""
from __future__ import annotations
import dataclasses
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P
from sbgk_bench.agy_stream import human_request, CAPTURE_CHARS
from sbgk_bench.circle_metrics import builder_empty_counts
import run_pilot_ac as R

class Stream(unittest.TestCase):
    def fake_call(self, body, timeout=10):
        # Substitute just the executable of this call, retaining real stdin/stdout/thread/kill mechanics.
        launched=[]
        real_popen=subprocess.Popen
        prelude="import json,sys,time\nmessage=json.loads(sys.stdin.readline())\nassert 'Do not use any tool' in message['message']['content']\n"
        def spawn(cmd, **kw):
            self.assertNotIn("--dangerously-skip-permissions",cmd)
            self.assertEqual(cmd[-2:],["--mode","plan"])
            proc=real_popen([sys.executable,"-u","-c",prelude+body],**kw)
            launched.append(proc)
            return proc
        records=[]
        # the executable is substituted, so its name is a placeholder on every OS (a runner without agy on PATH, as on CI)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(P.subprocess,"Popen",side_effect=spawn), \
             mock.patch.dict(P.os.environ,{"AGY_BIN":"agy-fixture"}):
            model=P.AgyModel("stream-fixture",timeout_s=timeout,workdir=pathlib.Path(tmp))
            log=P.Log(evidence=lambda kind,record: records.append((kind,record)))
            call=log.invoke(model,"task",call_id="fixture",arm="C",role="BUILD",phase=1)
            self.assertEqual(list(pathlib.Path(tmp).iterdir()),[])
        self.assertEqual(len(launched),1,"no hidden retry")
        self.assertIsNotNone(launched[0].poll(),"the owned process has exited")
        self.assertEqual([r for kind,r in records if kind=="call"][0],P.call_record(call))
        return call,log

    def test_human_tool_is_killed_early_and_recorded_then_uses_circle_failover(self):
        body="""print(json.dumps({"event":"init","tools":["ask_question"]}),flush=True)
print(json.dumps({"event":"tool_call","name":"ask_question","arguments":{"question":"Continue?"}}),flush=True)
time.sleep(30)
"""
        call,log=self.fake_call(body,timeout=20)
        self.assertFalse(call.ok)
        self.assertIn("AGY_ASKED_HUMAN: ask_question",call.error)
        self.assertLess(call.latency_s,5,"waits neither for the 20 second deadline nor the question")
        self.assertIn('"event": "tool_call"',call.diagnostics["stdout_prefix"])
        rpc=mock.Mock();rpc.call.return_value={"status":"RELEASED"}
        with mock.patch.object(P,"CIRCLES",True):
            self.assertTrue(P.report_agent_timeout(rpc,call,"TB1",log,agent="w1",phase=1,context={"circle":1}))
        rpc.call.assert_called_once_with("audit_release",task_id="TB1",timed_out=True)
        self.assertIsNone(log.stopped)
        self.assertEqual(log.events[-1]["outcome"],"AGENT_HUMAN_REQUEST")

    def test_timeout_keeps_partial_text_and_events_in_call_journal(self):
        call,_=self.fake_call('print(json.dumps({"event":"text","text":"partial progress 玉策"}),flush=True)\ntime.sleep(30)\n',timeout=1)
        self.assertFalse(call.ok)
        self.assertIn("AGY_TIMEOUT",call.error)
        self.assertIn("partial progress",call.diagnostics["stdout_prefix"])
        self.assertLess(call.latency_s,5)
        self.assertFalse(call.usage["usage_complete"])
        self.assertIsNone(call.cost_usd)

    def test_capture_has_one_shared_character_limit(self):
        body='print(json.dumps({"event":"text","text":"x"*90000}),flush=True)\nsys.stderr.write("y"*10000);sys.stderr.flush()\ntime.sleep(30)\n'
        call,_=self.fake_call(body,timeout=1)
        diag=call.diagnostics
        self.assertTrue(diag["truncated"])
        self.assertEqual(len(diag["stdout_prefix"])+len(diag["stderr_prefix"]),CAPTURE_CHARS)
        self.assertEqual(diag["captured_chars"],CAPTURE_CHARS)
        self.assertGreater(diag["observed_chars"],CAPTURE_CHARS)

    def test_stderr_is_drained_without_deadlock_and_success_uses_actual_usage(self):
        body='sys.stderr.write("z"*100000);sys.stderr.flush()\nprint(json.dumps({"event":"result","result":{"status":"SUCCESS","response":"[]","usage":{"input_tokens":9,"output_tokens":2,"thinking_tokens":1}}}),flush=True)\n'
        call,_=self.fake_call(body)
        self.assertTrue(call.ok,call.error)
        self.assertEqual((call.text,call.usage["input"],call.usage["reasoning"]),("[]",9,1))

    def test_registry_and_plain_text_do_not_trigger_but_waits_and_tools_do(self):
        self.assertIsNone(human_request({"event":"init","tools":[{"name":"ask_permission"}]}))
        self.assertIsNone(human_request({"event":"text","text":"Use ask_question only if required."}))
        self.assertIsNone(human_request({"type":"system","subtype":"init","content":[{"type":"tool_use","name":"ask_question"}]}))
        self.assertEqual(human_request({"event":"message","content":[{"functionCall":{"name":"ask_followup_question"}}]}),"ask_followup_question")
        for name in ("ask_question","ask_permission","ask_custom_permission","AskUserQuestion","request_user_input"):
            with self.subTest(name=name):
                self.assertEqual(human_request({"event":"assistant","message":{"content":[{"type":"tool_use","name":name}]}}),name)
        self.assertEqual(human_request({"event":"tool_call","name":"future_tool","requires_approval":True}),"future_tool")
        self.assertEqual(human_request({"event":"permission_request","tool_name":"new_tool"}),"new_tool")

class Card(unittest.TestCase):
    def test_two_leases_of_one_card_have_distinct_call_ids(self):
        rpc=mock.Mock()
        rpc.call.side_effect=lambda tool,**kw: {"status":"RENEWED"} if tool=="audit_renew" else {"status":"CARD_DONE","results":[]}
        card={"card_id":"C1-2-same","records":[{"id":"@r","author":"w1","terms":["term"]}],"neighbors":[],"prompt":"card"}
        model=SimpleNamespace(name="mock-builder",complete=lambda prompt:("[]",{},None))
        with mock.patch.object(P,"CIRCLES",True),mock.patch.object(P,"PAIRS_ONLY",False),mock.patch.object(P,"WHOLE_READER",False),mock.patch.object(P,"RUN_HOOK",P.RunHook()):
            log=P.Log()
            for task in ("TB1","TB2"):
                self.assertTrue(P.build_card(rpc,card,model,log,1,threading.Event(),agent="w2",task_id=task,
                                             circle_context={"circle":1,"circle_phase":"BUILD"}))
        ids=[c.call_id for c in log.calls]
        self.assertEqual(len(ids),2)
        self.assertEqual(len(set(ids)),2)
        self.assertTrue(any("TB1" in cid for cid in ids) and any("TB2" in cid for cid in ids))
        self.assertEqual(log.in_flight,{})
        measured=P.measures({"calls":[],"events":[]},{"calls":[dataclasses.asdict(c) for c in log.calls],"events":log.events})
        self.assertEqual(measured["builder"]["cards"],2)
        self.assertEqual(measured["swarm_tasks"]["repairs"],0)
        self.assertNotIn("BUILD",measured["lines_stored"])
        ends=[e for e in log.events if e.get("model_invoked") is True]
        self.assertEqual(len(ends),2)
        self.assertTrue(all(e["explicit_empty"] and e["closed_without_operations"] for e in ends))
        self.assertEqual(P.AgyModel("mock").timeout_s,240)
        self.assertEqual((P.AGY_TIMEOUT_S,P.AGENT_TIMEOUT_S),(240,300))

    def test_the_run_hook_shapes_the_prompt_the_submission_and_the_last_event(self):
        prompts=[];submitted=[]
        rpc=mock.Mock()
        def call(tool,**kw):
            if tool=="audit_renew":return {"status":"RENEWED"}
            submitted.append(kw["lines"])
            return {"status":"CARD_DONE","results":[]}
        rpc.call.side_effect=call
        def complete(prompt):
            prompts.append(prompt)
            return "[]",{},None
        more={"op":"request"}
        class Hook(P.RunHook):
            def before(self,card,ctx):
                return ctx.render(card)+"\nMORE",{"noted":1}
            def after(self,card,operations,submit,ctx):
                return operations+[more],submit(operations+[more],lambda fields:fields.update(annotated=True)),None
        model=SimpleNamespace(name="mock-builder",complete=complete)
        card={"card_id":"C1-2-hook","records":[{"id":"@r","author":"w1","terms":["term"]}],"neighbors":[],"prompt":"card"}
        with mock.patch.object(P,"PAIRS_ONLY",False),mock.patch.object(P,"WHOLE_READER",False),mock.patch.object(P,"RUN_HOOK",Hook()):
            log=P.Log()
            self.assertTrue(P.build_card(rpc,card,model,log,1,threading.Event(),agent="w2",task_id="TB"))
        self.assertTrue(prompts[0].endswith("\nMORE"))
        self.assertEqual(submitted,[[more]])
        self.assertTrue(next(e for e in log.events if e.get("outcome")=="CARD_SUBMITTED")["annotated"])
        self.assertEqual(log.events[-1]["noted"],1)

    def test_a_card_stops_when_the_run_hook_says_so(self):
        rpc=mock.Mock()
        model=SimpleNamespace(name="mock-builder",complete=mock.Mock(side_effect=AssertionError("no builder call")))
        class Hook(P.RunHook):
            def before(self,card,ctx):
                return None
        card={"card_id":"C1-2-stop","records":[{"id":"@r","author":"w1","terms":["term"]}],"neighbors":[],"prompt":"card"}
        with mock.patch.object(P,"PAIRS_ONLY",False),mock.patch.object(P,"WHOLE_READER",False),mock.patch.object(P,"RUN_HOOK",Hook()):
            log=P.Log()
            self.assertFalse(P.build_card(rpc,card,model,log,1,threading.Event(),agent="w2",task_id="TB"))
        self.assertEqual(log.calls,[])

    def test_unknown_concept_repair_can_add_a_preceding_proposal(self):
        mapping={"op":"map_term","record":"@o","term":"topic","concept":"scoped topic"}
        proposal={"op":"propose_concept","type":"Component","name":"scoped topic","aliases":[],"basis":["@o"]}
        prompts=[]
        def complete(prompt):
            prompts.append(prompt)
            if len(prompts)==1:
                return json.dumps(mapping),{},None
            self.assertIn("propose_concept prerequisites BEFORE",prompt)
            self.assertIn("scoped topic",prompt)
            return json.dumps(proposal)+"\n"+json.dumps(mapping),{},None
        model=SimpleNamespace(name="repair-fixture",complete=complete)
        replies=[{"status":"REPAIR_REQUIRED","accepted":0,"results":[],"failed_index":0,
                  "error":{"code":"UNKNOWN_ENTITY","expected_by_kernel":{"unresolved_concept":"scoped topic","repair":"propose before map"}},
                  "refused":[{"index":0}],"proposed_concepts":{}},
                 {"status":"CARD_DONE","results":[{"op":"propose_concept"},{"op":"map_term"}],"accepted":2}]
        rpc=mock.Mock()
        rpc.call.side_effect=lambda tool,**kw: {"status":"RENEWED"} if tool=="audit_renew" else replies.pop(0)
        card={"card_id":"C0-2-repair","records":[{"id":"@o","author":"w1","terms":["topic"]}],"neighbors":[],"prompt":"card"}
        with mock.patch.object(P,"CIRCLES",True),mock.patch.object(P,"PAIRS_ONLY",False),mock.patch.object(P,"WHOLE_READER",False):
            self.assertTrue(P.build_card(rpc,card,model,P.Log(),1,threading.Event(),agent="w2",task_id="TB-repair",
                                         circle_context={"circle":1,"circle_phase":"BUILD"}))
        self.assertEqual(len(prompts),2)
        submits=[c.kwargs["lines"] for c in rpc.call.call_args_list if c.args[0]=="audit_submit"]
        self.assertEqual(submits,[[mapping],[proposal,mapping]])

    def test_empty_model_answers_are_separate_from_automatic_closes(self):
        base={"circle":2,"circle_phase":"BUILD","kind":"BUILD","builder_model":"flash"}
        events=[dict(base,outcome="CARD_ASSIGNED",task="T1"),dict(base,outcome="CARD_ASSIGNED",task="T2"),
                dict(base,outcome="CARD_DONE",model_invoked=True,explicit_empty=True,closed_without_operations=True),
                dict(base,outcome="CARD_DONE",model_invoked=True,explicit_empty=True,closed_without_operations=False),
                dict(base,outcome="CARD_DONE",model_invoked=False),
                dict(base,circle_phase="FINAL",outcome="CARD_DONE",model_invoked=True,explicit_empty=True)]
        c=builder_empty_counts(events,2)["flash"]
        self.assertEqual((c["assignments"],c["empty_model_answers"],c["closed_without_operations"],c["automatic_no_model_closes"]),(2,2,1,1))
        self.assertEqual(builder_empty_counts(events,2,"FINAL")["flash"]["empty_model_answers"],1)

class Artifacts(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);self.out=self.root/"out"
        (self.root/"report.md").write_text("A known limitation remains.\n",encoding="utf-8")
        self.manifest=self.root/"manifest.json";self.manifest.write_text("{}",encoding="utf-8")
        self.model=SimpleNamespace(name="mock-model")
        self.team=[self.model]*3

    def wal(self,work):
        work.mkdir(exist_ok=True)
        def b(phase,t):
            return {"payload":{"command":{"checkpoint":{"key":"audit:circles","context":{
                "format":"r2r-circles/1","circle":1,"circle_phase":phase,"started_unix_ms":t,"wave":{},"snapshot":{}}}},
                "outcome":{"result":{"checkpointed":True}}}}
        (work/"run.wal").write_text("\n".join(json.dumps(b(p,t)) for p,t in (("READ",0),("BUILD",1000)))+"\n",encoding="utf-8")

    def run_case(self,c,a):
        with mock.patch.object(P,"CIRCLES",True),mock.patch.object(P,"DYNAMIC_ROLES",True),mock.patch.object(P,"ARM_A_MODE","team"), \
             mock.patch.object(P,"run_arm_c",side_effect=c),mock.patch.object(P,"run_arm_team",side_effect=a), \
             mock.patch.object(P,"measures",return_value={}),mock.patch.object(P,"graph_shape",return_value={}), \
             mock.patch.object(P,"answers_md",return_value=("",{})),mock.patch.object(R,"provenance",return_value={}):
            return R.run(self.manifest,self.root,["report.md"],self.out,self.model,3,{"steps":[]},team=self.team)

    def exists(self):
        for name in ("circles.json","circle_acceptance.svg","circle_model_matrix.md"):
            self.assertTrue((self.out/name).is_file(),name)

    def c_result(self,*args,**kw):
        self.wal(args[2])
        return {"calls":[],"events":[],"stopped":"TIMEOUT: phase deadline expired",
                "phase1":{"receipt":{"status":"STOPPED"},"answers":{}}}

    def test_progress_snapshot_exists_while_arm_c_is_still_running(self):
        def c(*args,evidence,**kw):
            self.wal(args[2])
            evidence.circle_telemetry=lambda: {"format":"r2r-circle-telemetry/1","complete":True,
                "frames":[json.loads(line) for line in (args[2]/"run.wal").read_text().splitlines()]}
            evidence("event",{"arm":"C","status_sample":True})
            self.exists()
            m=json.loads((self.out/"circles.json").read_text())
            self.assertEqual(m["export"]["stage"],"arm_c_progress")
            self.assertEqual(len(m["rows"]),1)
            self.assertFalse(m["rows"][0]["closed"])
            return {"calls":[],"events":[]}
        self.run_case(c,lambda *a,**kw: {"calls":[],"events":[]})

    def test_phase_deadline_exports_before_arm_a_even_with_open_circle(self):
        def a(*args,**kw):
            self.exists()
            return {"calls":[],"events":[]}
        summary=self.run_case(self.c_result,a)
        self.exists()
        self.assertFalse(summary["measures"]["circles"]["rows"][0]["closed"])
        self.assertIn("TIMEOUT",json.loads((self.out/"arm_c.json").read_text())["stopped"])

    def test_later_interrupt_preserves_circle_artifacts_and_original_error(self):
        def a(*args,**kw):
            self.exists()
            raise KeyboardInterrupt("operator stopped A")
        with self.assertRaisesRegex(KeyboardInterrupt,"operator stopped A"):
            self.run_case(self.c_result,a)
        self.exists()
        metrics=json.loads((self.out/"circles.json").read_text())
        self.assertTrue(metrics["export"]["interrupted"])
        self.assertEqual(metrics["export"]["stage"],"arm_a")

    def test_c_interrupt_exports_durable_prefix_and_marks_torn_tail(self):
        def c(*args,evidence,**kw):
            work=args[2];self.wal(work)
            with (work/"run.wal").open("ab") as f:f.write(b'{"payload":')
            evidence("event",{"circle":1,"circle_phase":"BUILD","kind":"BUILD","builder_model":"flash",
                              "model_invoked":True,"explicit_empty":True,"outcome":"CARD_DONE","closed_without_operations":True})
            raise KeyboardInterrupt("operator stopped C")
        with self.assertRaisesRegex(KeyboardInterrupt,"operator stopped C"):
            self.run_case(c,mock.Mock())
        self.exists()
        m=json.loads((self.out/"circles.json").read_text())
        self.assertTrue(m["export"]["interrupted"])
        self.assertIn("incomplete trailing",m["source_warnings"][0])
        self.assertEqual(m["rows"][0]["builder_cards_by_model"]["flash"]["empty_model_answers"],1)

    def test_failure_before_wal_still_writes_explicitly_unavailable_artifacts(self):
        with self.assertRaisesRegex(RuntimeError,"kernel startup"):
            self.run_case(mock.Mock(side_effect=RuntimeError("kernel startup")),mock.Mock())
        self.exists()
        m=json.loads((self.out/"circles.json").read_text())
        self.assertEqual(m["rows"],[])
        self.assertTrue(any("not available" in w for w in m["source_warnings"]))


class Grader(unittest.TestCase):
    def test_default_is_argon_and_is_preserved_in_the_cli_result(self):
        import grade_agy_prompt as G
        result={"ok":True,"judge_model":"agy:"+G.DEFAULT_GRADER,"usage":{},"cost_usd":None}
        with mock.patch.object(sys,"argv",["grade","--prompt","public.md","--out","new-grading"]), \
             mock.patch.object(G,"grade",return_value=result) as grade,mock.patch("builtins.print") as printed:
            G.main()
        self.assertEqual(grade.call_args.args[1],"gemini-4-argon-medium")
        self.assertEqual(json.loads(printed.call_args.args[0])["judge_model"],"agy:gemini-4-argon-medium")

    def test_failed_grading_still_records_the_requested_model_without_retry(self):
        import grade_agy_prompt as G
        model=SimpleNamespace(name=G.DEFAULT_GRADER,config={"fixture":"no provider"},complete=mock.Mock(side_effect=P.AgyCallError("AGY_ASKED_HUMAN: ask_question",{})))
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(P,"AgyModel",return_value=model) as factory:
            root=pathlib.Path(tmp);prompt=root/"public.md";prompt.write_text("Grade this.",encoding="utf-8");out=root/"grade"
            with self.assertRaisesRegex(RuntimeError,"AGY_ASKED_HUMAN"):
                G.grade(prompt,G.DEFAULT_GRADER,out)
            status=json.loads((out/"status.json").read_text())
            call=json.loads((out/"call.json").read_text())
            self.assertEqual(status["judge_model"],"agy:gemini-4-argon-medium")
            self.assertEqual(call["judge_model"],status["judge_model"])
            self.assertFalse(call["ok"])
        factory.assert_called_once_with(G.DEFAULT_GRADER)
        model.complete.assert_called_once()


if __name__=="__main__":
    unittest.main()
