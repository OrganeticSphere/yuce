"""Runner dependency tests: call_model, sockets and subprocesses are mocked. No server or model runs."""
from __future__ import annotations

import hashlib
import io
import json
import pathlib
import socket
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402


def completed(unused_model, prompt, **fields):
    return P.Call(**fields, prompt_chars=len(prompt), text="{}", model="dependency-intercept")


class BudgetAndEvidence(unittest.TestCase):
    def test_parallel_reservation_precedes_call_and_never_exceeds_cap(self):
        seen = []
        log = P.Log(max_calls=1, evidence=lambda kind, record: seen.append((kind, record)))
        barrier = threading.Barrier(4)
        def worker(i):
            barrier.wait()
            log.invoke(SimpleNamespace(name="unused"), "source prompt", call_id=str(i), arm="C", role="EXTEND", phase=1)
        with mock.patch.object(P, "call_model", side_effect=completed) as dependency:
            threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(dependency.call_count, 1)
        self.assertEqual(log.started, 1)
        self.assertEqual([kind for kind, _ in seen], ["context", "call_started", "call"])
        self.assertEqual(seen[0][1]["prompt"], "source prompt")
        self.assertEqual(seen[1][1]["call_id"], seen[2][1]["call_id"])
        self.assertIsNone(seen[2][1]["cost_usd"])
        self.assertIn("CALL_CAP", log.stopped)

    def test_c_repair_cannot_start_after_cap(self):
        class Wire:
            def call(self, tool, **kwargs):
                if tool == "audit_acquire":
                    return {"status": "DIRECTIVE", "kind": "VERIFY_LINK", "prompt": "directive", "task_id": "T1", "key": "verify:L1"}
                if tool == "audit_submit":
                    return {"status": "REPAIR_REQUIRED", "failed_index": 0, "error": {"code": "BAD_FIELD"}}
                raise AssertionError(tool)
            def close(self):
                pass
        kernel, log = mock.Mock(), P.Log(max_calls=1)
        kernel.connect.return_value = Wire()
        with mock.patch.object(P, "call_model", side_effect=completed) as dependency:
            P.c_worker(kernel, "w1", SimpleNamespace(name="unused"), log, [1], threading.Event())
        self.assertEqual(dependency.call_count, 1)
        self.assertIn("CALL_CAP", log.stopped)

    def test_a_cap_covers_worker_summary_and_phase2(self):
        with mock.patch.object(P, "call_model", side_effect=completed) as dependency:
            result = P.run_arm_a(SimpleNamespace(name="unused"), {"a.md": "# Title\nsource\n"}, {"report": "a.md", "quote": "source"},
                                 workers=1, max_calls=1)
        self.assertEqual(dependency.call_count, 1)
        self.assertEqual(result["phase1"]["status"], "STOPPED")
        self.assertEqual(result["phase2"]["status"], "SKIPPED")
        with mock.patch.object(P, "PHASE2_MAX_CALLS", 1), mock.patch.object(P, "call_model", side_effect=completed) as dependency:
            result = P.run_arm_a(SimpleNamespace(name="unused"), {}, {"report": "a.md", "quote": "source"}, workers=1, max_calls=20)
        self.assertEqual(dependency.call_count, len(P.QUESTIONS) + 1)
        self.assertEqual(len([c for c in result["calls"] if c["phase"] == 2]), 1)
        self.assertEqual(result["phase2"]["status"], "STOPPED")

    def test_context_contains_the_actual_shared_notes_snapshot(self):
        records = []
        def answer(unused, prompt, **fields):
            return P.Call(**fields, prompt_chars=len(prompt), text='- [a.md] "source" - finding')
        with mock.patch.object(P, "call_model", side_effect=answer):
            result = P.run_arm_a(SimpleNamespace(name="unused"), {"a.md": "source", "b.md": "another"}, {}, workers=1,
                                 evidence=lambda kind, record: records.append((kind, record)))
        contexts = {r["call_id"]: r for kind, r in records if kind == "context"}
        workers = [c for c in result["calls"] if c["role"] == "WORKER"]
        self.assertEqual(contexts[workers[0]["call_id"]]["notes"], "")
        for call in result["calls"]:
            context = contexts[call["call_id"]]
            self.assertEqual(context["notes_sha256"], hashlib.sha256(context["notes"].encode()).hexdigest())
            self.assertEqual(call["context_rev"], context["notes_revision"])
            self.assertEqual(call["prompt_sha256"], hashlib.sha256(context["prompt"].encode()).hexdigest())
        self.assertIn("source", contexts[workers[1]["call_id"]]["notes"])

    def test_distinct_report_paths_never_share_call_identity(self):
        with mock.patch.object(P, "call_model", side_effect=completed):
            result = P.run_arm_a(SimpleNamespace(name="unused"), {"one/report.md": "one", "two/report.md": "two"}, {}, workers=1)
        ids = [call["call_id"] for call in result["calls"] if call["role"] == "WORKER"]
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2)

    def test_sink_failure_prevents_dispatch(self):
        def broken(kind, record):
            raise OSError("evidence unavailable")
        log = P.Log(evidence=broken)
        with mock.patch.object(P, "call_model") as dependency, self.assertRaises(OSError):
            log.invoke(SimpleNamespace(name="unused"), "prompt", call_id="one", arm="C", role="EXTEND", phase=1)
        dependency.assert_not_called()
        self.assertIn("EVIDENCE_ERROR", log.stopped)

    def test_worker_exception_is_recorded_and_stops_the_run(self):
        log, stop, saved = P.Log(), threading.Event(), []
        log.evidence = lambda kind, record: saved.append((kind, record))
        def broken():
            raise RuntimeError("dependency failed")
        P.guarded_worker(broken, log, stop, arm="C", agent="w1")
        self.assertTrue(stop.is_set())
        self.assertIn("WORKER_ERROR", log.stopped)
        self.assertEqual(saved[0][0], "event")

    def test_unfinished_call_does_not_appear_as_a_successful_result(self):
        log = P.Log()
        log.in_flight["pending"] = {"call_id": "pending"}
        with self.assertRaisesRegex(RuntimeError, "unfinished"):
            log.result()


class WireAndPreservation(unittest.TestCase):
    def test_existing_directory_and_wal_are_never_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp)
            wal = work / "run.wal"
            wal.write_bytes(b"frozen evidence")
            with mock.patch.object(P.subprocess, "Popen") as launch, self.assertRaises(FileExistsError):
                P.Kernel(work, work / "manifest", work, ["a.md"], "run", 1)
            launch.assert_not_called()
            self.assertEqual(wal.read_bytes(), b"frozen evidence")
            self.assertEqual(sorted(p.name for p in work.iterdir()), ["run.wal"])

    def test_rpc_connect_and_read_are_bounded_and_close_is_idempotent(self):
        wire = mock.Mock()
        wire.recv.side_effect = [b'{"id":1,"result":{}}\n', socket.timeout("silent peer")]
        with mock.patch.object(P.socket, "create_connection", return_value=wire) as connect:
            rpc = P.Rpc(1234, "not-a-real-token", timeout_s=0.2)
            self.assertEqual(connect.call_args.kwargs["timeout"], 0.2)
            with self.assertRaises(socket.timeout):
                rpc.call("audit_status")
            rpc.close()
            rpc.close()
        self.assertEqual(wire.close.call_count, 1)
        self.assertTrue(all(call.args[0] <= 0.2 for call in wire.settimeout.call_args_list))

    def test_rpc_deadline_covers_a_peer_that_keeps_trickling_bytes(self):
        wire = mock.Mock()
        wire.recv.return_value = b'{"id":1,"result":{}}\n'
        with mock.patch.object(P.socket, "create_connection", return_value=wire):
            rpc = P.Rpc(1234, "unused", timeout_s=0.2)
        wire.recv.side_effect = [b"{", b'"', b"i", b"d"]
        with mock.patch.object(P.time, "monotonic", side_effect=[10.0, 10.0, 10.01, 10.09, 10.17, 10.25]):
            with self.assertRaisesRegex(TimeoutError, "absolute deadline"):
                rpc.call("audit_status")
        self.assertEqual(wire.recv.call_count, 4)  # handshake plus three partial reads
        rpc.close()

    def test_rpc_frame_has_a_hard_byte_limit(self):
        wire = mock.Mock()
        wire.recv.return_value = b'{"id":1,"result":{}}\n'
        with mock.patch.object(P.socket, "create_connection", return_value=wire):
            rpc = P.Rpc(1234, "unused")
        wire.recv.return_value = b"x" * 17
        with mock.patch.object(P, "MAX_RPC_RESPONSE_BYTES", 16), self.assertRaisesRegex(RuntimeError, "byte limit"):
            rpc.call("audit_status")
        rpc.close()

    def test_startup_timeout_reaps_its_reader_without_launching_a_process(self):
        blocked = threading.Event()
        class Pipe:
            def readline(self):
                blocked.wait(1)
                return ""
            def close(self):
                pass
        proc = SimpleNamespace(stdout=Pipe(), poll=lambda: None, kill=lambda: blocked.set(), wait=lambda timeout: None)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(P.subprocess, "Popen", return_value=proc):
            with self.assertRaisesRegex(TimeoutError, "startup"):
                P.Kernel(pathlib.Path(tmp) / "new", pathlib.Path(tmp) / "manifest", pathlib.Path(tmp), ["a.md"], "run", 1, startup_timeout_s=0.01)
        self.assertTrue(blocked.is_set())
        self.assertFalse(any(t.name == "audit-startup-reader" and t.is_alive() for t in threading.enumerate()))

    def test_builder_accepts_the_actual_idle_wire_status(self):
        stop = threading.Event()
        class Wire:
            def call(self, tool, **kwargs):
                self_tool = tool
                if self_tool != "audit_next_card":
                    raise AssertionError(tool)
                stop.set()
                return {"status": "IDLE", "caught_up": True}
            def close(self):
                pass
        kernel = mock.Mock()
        kernel.connect.return_value = Wire()
        with mock.patch.object(P, "call_model") as dependency:
            P.c_builder(kernel, SimpleNamespace(name="unused"), P.Log(), [1], stop)
        dependency.assert_not_called()


class ProvenanceAndOutcomes(unittest.TestCase):
    def test_repair_has_previous_output_and_accepted_local_mapping(self):
        previous = '{"kind":"observe","local_id":"t1_source","exact_quote":"source"}'
        accepted = [{"local_id": "t1_source", "record_id": "@abcd", "record": {"kind": "observe"}}]
        prompt = P.repair_prompt("directive", {"failed_index": 1, "accepted": ["@abcd"]}, "lines", previous, accepted)
        self.assertIn(previous, prompt)
        self.assertIn('"local_id": "t1_source"', prompt)
        self.assertIn('"record_id": "@abcd"', prompt)

    def test_document_ids_bind_identical_quotes_to_the_correct_path(self):
        quote = "A shared exact quote."
        raw = quote.encode()
        metadata = {"source": {"origin_recorded": "https://example.invalid/r.git", "commit": "A" * 40},
                    "entries": [{"path": path, "raw_sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)} for path in ("a.md", "b.md")]}
        docs = {"a.md": quote, "b.md": quote}
        paths = P.source_document_paths(json.dumps(metadata).encode(), docs)
        second_id = next(identity for identity, path in paths.items() if path == "b.md")
        wire = mock.Mock()
        wire.call.side_effect = [{"short": "@claim", "text": "finding", "based_on": ["@observe"]},
                                 {"kind": "observe", "id": "full", "short": "@observe", "quote": quote, "doc_id": second_id}]
        result = P.c_answers(wire, {"outcomes": {"RQ1": {"outcome": "answered", "answer_ids": ["@claim"]}}}, docs, paths)
        self.assertEqual(result["RQ1"]["claims"][0]["quotes"][0]["report"], "b.md")
        first_id = next(identity for identity, path in paths.items() if path == "a.md")
        observes = {"one": {"doc_id": first_id, "quote": quote}, "two": {"doc_id": second_id, "quote": quote}}
        self.assertEqual(P.withdrawal_hits(observes, {"report": "b.md", "quote": quote}, paths), ["two"])

    def test_missing_source_identity_is_not_guessed_from_quote(self):
        wire = mock.Mock()
        wire.call.side_effect = [{"based_on": ["ob"]}, {"kind": "observe", "quote": "same", "id": "x", "short": "@x", "doc_id": "missing"}]
        with self.assertRaisesRegex(ValueError, "bound source"):
            P.c_answers(wire, {"outcomes": {"RQ1": {"answer_ids": ["cl"]}}}, {"a.md": "same", "b.md": "same"})

    def test_skipped_phase_is_na_and_error_events_do_not_break_measures(self):
        arms = {"calls": [], "events": [], "phase2": P.skipped_phase("NO_TARGET")}
        c = dict(arms, events=[{"outcome": "ERROR", "card": "C1", "error": "WORKER_ERROR"}])
        measures = P.measures(arms, c)
        self.assertIsNone(measures["phase2"]["C"]["calls"])
        self.assertIsNone(measures["phase2"]["C"]["cost_usd_known"])
        self.assertEqual(measures["phase2"]["C"]["reason"], "NO_TARGET")
        self.assertEqual(len(measures["worker_errors"]), 1)


if __name__ == "__main__":
    unittest.main()
