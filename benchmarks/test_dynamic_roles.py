"""Offline dynamic-role boundaries and Antigravity stream protocol. All subprocesses are mocked."""
from __future__ import annotations
import json
import io
import pathlib
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P
from sbgk_bench import blind_links as B

class Agy(unittest.TestCase):
    def run_fake(self, result, code=0):
        calls = []
        processes = []
        class Sink(io.BytesIO):
            def close(self):
                self.value = self.getvalue()
                super().close()
        def popen(cmd, **kw):
            self.assertEqual(list(pathlib.Path(kw["cwd"]).iterdir()), [])
            self.assertEqual(cmd[-2:], ["--mode", "plan"])
            self.assertNotIn("--dangerously-skip-permissions", cmd)
            calls.append((cmd, kw))
            proc=mock.Mock()
            proc.stdin=Sink()
            proc.stdout=io.BytesIO(json.dumps({"event":"result","result":result}).encode())
            proc.stderr=io.BytesIO(b"private not logged")
            proc.returncode=code
            proc.poll.return_value=code
            proc.wait.return_value=code
            processes.append(proc)
            return proc
        # the executable is substituted, so its name is a placeholder on every OS (a runner without agy on PATH, as on CI)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(P.subprocess, "Popen", side_effect=popen) as opened, \
                mock.patch.dict(P.os.environ, {"AGY_BIN": "agy-fixture"}):
            model = P.AgyModel("test-model", workdir=pathlib.Path(tmp))
            call = P.call_model(model, "input", call_id="unit", arm="C", role="BUILD", phase=1)
            self.assertEqual(opened.call_count, 1, "quota failure must not trigger hidden retries")
            sent = json.loads(processes[0].stdin.value.decode("utf-8"))
            self.assertEqual(sent["event"], "user")
            self.assertIn("Do not use any tool", sent["message"]["content"])
            self.assertEqual(list(pathlib.Path(tmp).iterdir()), [])
            return call
    def test_success_records_tokens_without_fabricating_a_price(self):
        call = self.run_fake({"status":"SUCCESS","response":"[]","usage":{"input_tokens":9,"output_tokens":2,"thinking_tokens":1}})
        self.assertTrue(call.ok)
        self.assertIsNone(call.cost_usd)
        self.assertEqual((call.usage["input"],call.usage["output"],call.usage["reasoning"]), (9,2,1))
        self.assertTrue(call.usage["usage_complete"])
    def test_failure_preserves_usage_and_never_retries(self):
        call = self.run_fake({"status":"FAILED","usage":{"input_tokens":4,"output_tokens":0,"thinking_tokens":0}}, code=1)
        self.assertFalse(call.ok)
        self.assertEqual(call.usage["input"],4)
        self.assertNotIn("private",call.error)
    def test_unknown_tokens_remain_explicitly_unknown(self):
        call = self.run_fake({"status":"SUCCESS","response":"[]","usage":{"input_tokens":True}})
        self.assertFalse(call.usage["usage_complete"])
        self.assertEqual(set(call.usage["unknown_token_fields"]), {"input_tokens","output_tokens","thinking_tokens"})
    def test_model_factory_never_silently_substitutes_stub(self):
        self.assertIsInstance(P.make_model("agy:exact-id"),P.AgyModel)
        with self.assertRaises(ValueError):
            P.make_model("unknown-spelling")

class Card(unittest.TestCase):
    def test_shared_handler_routes_both_modes_and_logs_the_card_model(self):
        for task in (None,"TB1-unit"):
            with self.subTest(task=task):
                rpc=mock.Mock()
                rpc.call.side_effect=lambda tool, **kw: ({"status":"RENEWED"} if tool=="audit_renew" else
                                                        {"status":"CARD_DONE","results":[{"op":"link","link":"@abc"}]})
                model=types.SimpleNamespace(name="specific-model",complete=lambda p: ("[]",{},None))
                log=P.Log()
                card={"card_id":"C0-2-unit","records":[{"author":"w1"}],"prompt":"make links"}
                with mock.patch.object(P,"PAIRS_ONLY",False),mock.patch.object(P,"WHOLE_READER",False):
                    self.assertTrue(P.build_card(rpc,card,model,log,1,threading.Event(),agent="w2",task_id=task))
                name,=rpc.call.call_args.args
                self.assertEqual(name,"audit_submit" if task else "audit_submit_ops")
                assigned=[x for x in log.events if x.get("outcome")=="CARD_ASSIGNED"]
                self.assertEqual(assigned[0]["builder_model"],"specific-model")
                self.assertEqual(assigned[0]["card_authors"],["w1"])
                self.assertTrue(any(x.get("operation_results") for x in log.events))

    def test_a_stale_build_lease_starts_no_model_call(self):
        rpc=mock.Mock()
        rpc.call.return_value={"status":"STALE_TASK"}
        model=mock.Mock(name="model")
        card={"card_id":"C0-2-unit","records":[{"author":"w1"}],"prompt":"card"}
        with mock.patch.object(P,"PAIRS_ONLY",False),mock.patch.object(P,"WHOLE_READER",False):
            self.assertFalse(P.build_card(rpc,card,model,P.Log(),1,threading.Event(),agent="w2",task_id="TB1"))
        model.complete.assert_not_called()

class Blind(unittest.TestCase):
    def test_sample_is_reproducible_distinct_bounded_and_key_stays_private(self):
        links=[{"id":f"{i:064x}","from":"a","to":"b","rel":"supports","status":"accepted","by":"private-actor"} for i in range(25)]
        recs={"a":{"status":"RECORD","kind":"claim","text":"Alpha claim","body":{"subject":"alpha"},"based_on":["o"]},
              "b":{"status":"RECORD","kind":"claim","text":"Beta claim","based_on":[]},
              "o":{"status":"RECORD","kind":"observe","quote":"Source alpha.","doc_id":"d","based_on":[]}}
        def call(tool,**kw):
            return {"status":"LINKS","links":links} if tool=="audit_links" else recs[kw["record"]]
        x=B.capture_links(call,{"d":"report.md"})
        self.assertEqual(x,B.capture_links(call,{"d":"report.md"}))
        self.assertEqual(len({z["id"] for z in x["links"]}),20)
        prompt,key=B.blinded_package({"secret-C1":x,"secret-C0":x},{"report.md":"Source alpha."})
        self.assertEqual(len(key["items"]),40)
        self.assertNotIn("secret-C1",prompt)
        self.assertNotIn("private-actor",prompt)
        self.assertNotIn(links[0]["id"],prompt)
        self.assertIn("Source alpha.",prompt)
        few=B.capture_links(call,{},size=50)
        self.assertEqual(few["size"],25)
    def test_missing_record_is_not_a_complete_snapshot(self):
        sample=B.capture_links(lambda tool,**kw: {"status":"LINKS","links":[{"id":"l","from":"a","to":"b"}]} if tool=="audit_links" else {"status":"error"}, {})
        self.assertEqual(sample["status"],"UNAVAILABLE")
        with self.assertRaises(ValueError):
            B.blinded_package({"x":sample},{})

class Package(unittest.TestCase):
    def test_public_packet_excludes_keys_and_rejects_a_different_revision(self):
        import hashlib
        import prepare_dynamic_comparison as Q
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            data=b"Source alpha.\r\n"
            meta={"source_bytes":{"report.md":{"raw_sha256":hashlib.sha256(data).hexdigest(),"size_bytes":len(data)}},
                  "reports":["report.md"]}
            for name in ("C1","C0"):
                run=root/name
                (run/"inputs/repo").mkdir(parents=True)
                (run/"arm_c").mkdir()
                (run/"inputs/repo/report.md").write_bytes(data)
                def write(path,value):
                    (run/path).write_text(json.dumps(value),encoding="utf-8")
                write("summary.json",{"provenance":{"git_head":"1"*40,"changed_tracked_files":[]},"corpus":meta,
                                      "team":["one","two","three"],"dynamic_roles":{"enabled":name=="C1"}})
                write("answers_key.json",{"Variant 1":"A","Variant 2":"C"})
                write("arm_c/questions.json",[{"id":"RQ1","text":"What is current?"}])
                (run/"checklist.md").write_text("Check sources.")
                write("arm_a.json",{"phase1":{"status":"COMPLETE","answers":{"RQ1":{"claims":[{"text":"Alpha","quotes":[]}]}}}})
                write("arm_c.json",{"events":[],"phase1":{"receipt":{"status":"TERMINAL"},"answers":{},
                      "link_sample":{"status":"CAPTURED","size":0,"population":0,"links":[],"records":{},"document_paths":{}}}})
            (root/"coverage.json").write_text('{"RQ1":["item"]}')
            prepared=Q.prepare(root/"C1",root/"C0",root/"coverage.json",root/"package")
            self.assertEqual(prepared["link_judge"],"agy:gemini-4-argon-medium")
            self.assertEqual(prepared["answer_judge"],prepared["link_judge"])
            self.assertFalse((root/"package/public/key.json").exists())
            self.assertTrue((root/"package/private/key.json").is_file())
            for path in (root/"package/public").iterdir():
                text=path.read_text()
                self.assertNotIn("dynamic_roles",text)
                self.assertNotIn("C1",text)
            altered=json.loads((root/"C0/summary.json").read_text())
            altered["provenance"]["git_head"]="2"*40
            (root/"C0/summary.json").write_text(json.dumps(altered))
            with self.assertRaisesRegex(ValueError,"same clean revision"):
                Q.prepare(root/"C1",root/"C0",root/"coverage.json",root/"bad")
            self.assertFalse((root/"bad").exists())

if __name__=="__main__":
    unittest.main()
