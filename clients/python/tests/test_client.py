"""The client against a real `sbgk audit-serve`, and against a small socket for what a real server does not do on demand.

The real server needs the binary: `cargo build --release`, or SBGK_BIN with its path. Without it those tests are skipped, unless CI is set.
"""
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

import yuce  # noqa: E402
from yuce import client as C  # noqa: E402

REPO = HERE.parents[2]
CORPUS = REPO / "benchmarks" / "corpora" / "mcp-spec-2026-07-28"
PAGE = "docs/specification/2024-11-05/basic/lifecycle.mdx"
QUOTE = "The initialization phase **MUST** be the first interaction between client and server."
TEAM = ("reader-1", "reader-2", "reader-3")


def binary() -> pathlib.Path | None:
    if os.environ.get("SBGK_BIN"):
        return pathlib.Path(os.environ["SBGK_BIN"])
    target = pathlib.Path(os.environ.get("CARGO_TARGET_DIR") or REPO / "target")
    for name in ("sbgk.exe", "sbgk"):
        if (target / "release" / name).is_file():
            return target / "release" / name
    return None


class Version(unittest.TestCase):
    def test_the_package_has_the_version_of_the_workspace(self):
        workspace = re.search(r'^version = "(.+)"', (REPO / "Cargo.toml").read_text(encoding="utf-8"), re.M).group(1)
        project = re.search(r'^version = "(.+)"', (HERE.parent / "pyproject.toml").read_text(encoding="utf-8"), re.M).group(1)
        self.assertEqual((yuce.__version__, project), (workspace, workspace))


class License(unittest.TestCase):
    def test_the_package_carries_the_license_of_the_repository(self):
        self.assertEqual((HERE.parent / "LICENSE").read_text(encoding="utf-8"), (REPO / "LICENSE").read_text(encoding="utf-8"))


class Lines(unittest.TestCase):
    def test_the_lines_have_the_shape_of_the_schema(self):
        schema = json.loads((REPO / "crates/sbgk-core/src/audit/schema.json").read_text(encoding="utf-8"))
        shapes = {shape["properties"]["kind"]["const"]: shape for shape in schema["oneOf"]}
        for line in (yuce.observe("o1", "d", "q", terms=["t"]), yuce.claim("c1", "text", "s", ["o1"], as_of="2026-11-05")):
            shape = shapes[line["kind"]]
            self.assertLessEqual(set(shape["required"]), set(line))
            self.assertLessEqual(set(line), set(shape["properties"]))


class Scripted:
    """A server that answers `initialize`, then writes what `script(request)` gives for each request, as raw bytes."""

    def __init__(self, script):
        self.script, self.listener = script, socket.create_server(("127.0.0.1", 0))
        self.address = f"127.0.0.1:{self.listener.getsockname()[1]}"
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        connection, _ = self.listener.accept()
        with connection, connection.makefile("rb") as requests:
            for line in requests:
                request = json.loads(line)
                if request["method"] == "initialize":
                    answer = {"id": request["id"], "result": {"subject": {"role": "swarm", "id": "r"}}}
                    connection.sendall((json.dumps(answer) + "\n").encode())
                else:
                    connection.sendall(self.script(request))

    def close(self):
        self.listener.close()


class Wire(unittest.TestCase):
    def agent(self, script, **options):
        server = Scripted(script)
        self.addCleanup(server.close)
        agent = yuce.Client(server.address, "token", **options)
        self.addCleanup(agent.close)
        return agent

    @staticmethod
    def reply(request, **fields):
        return (json.dumps({"id": request["id"], **fields}) + "\n").encode()

    def test_a_late_answer_is_skipped(self):
        def script(request):
            late = json.dumps({"id": request["id"] - 1, "result": {"structuredContent": {"status": "LATE"}}}) + "\n"
            return late.encode() + self.reply(request, result={"structuredContent": {"status": "NOW"}})
        self.assertEqual(self.agent(script).call("audit_status"), {"status": "NOW"})

    def test_an_answer_in_two_pieces_and_a_long_one_are_read(self):
        text = "x" * 200_000
        self.assertEqual(self.agent(lambda r: self.reply(r, result={"structuredContent": {"text": text}})).call("t")["text"], text)

    def test_an_answer_for_another_call_ends_the_connection(self):
        agent = self.agent(lambda r: (json.dumps({"id": r["id"] + 5, "result": {}}) + "\n").encode())
        with self.assertRaises(yuce.ConnectionClosed):
            agent.ping()
        with self.assertRaises(yuce.ConnectionClosed):
            agent.ping()

    def test_what_is_not_json_ends_the_connection(self):
        with self.assertRaises(yuce.ConnectionClosed):
            self.agent(lambda r: b"not json\n").ping()

    def test_an_error_without_an_id_is_an_error(self):
        with self.assertRaises(yuce.RpcError) as caught:
            self.agent(lambda r: b'{"id":null,"error":{"code":-32700,"message":"parse error"}}\n').ping()
        self.assertEqual(caught.exception.code, -32700)

    def test_a_server_that_stays_silent_is_a_timeout_and_the_late_answer_does_not_leak(self):
        calls = []

        def script(request):
            calls.append(request)
            if len(calls) == 1:
                return b""
            first = json.dumps({"id": calls[0]["id"], "result": {"structuredContent": {"status": "OLD"}}}) + "\n"
            return first.encode() + self.reply(request, result={"structuredContent": {"status": "NEW"}})
        agent = self.agent(script, timeout_s=0.3)
        with self.assertRaises(TimeoutError):
            agent.call("audit_status")
        self.assertEqual(agent.call("audit_status"), {"status": "NEW"})

    def test_too_long_an_answer_ends_the_connection(self):
        original, C.MAX_RESPONSE_BYTES = C.MAX_RESPONSE_BYTES, 1000
        self.addCleanup(setattr, C, "MAX_RESPONSE_BYTES", original)
        with self.assertRaises(yuce.ConnectionClosed):
            self.agent(lambda r: b"x" * 5000).ping()

    def test_a_closed_client_says_so_and_closes_twice(self):
        agent = self.agent(lambda r: self.reply(r, result={}))
        agent.close()
        agent.close()
        with self.assertRaises(yuce.ConnectionClosed):
            agent.ping()

    def test_bad_arguments_are_refused_before_any_call(self):
        agent = self.agent(lambda r: self.reply(r, result={}))
        with self.assertRaises(ValueError):
            agent.acquire(max_wait_ms=C.MAX_WAIT_MS + 1)
        with self.assertRaises(ValueError):
            yuce.Client("no-port", "token")
        with self.assertRaises(ValueError):
            yuce.Client("127.0.0.1:1", "token", timeout_s=0)


@unittest.skipIf(binary() is None and not os.environ.get("CI"), "no sbgk binary")
class RealServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = pathlib.Path(tempfile.mkdtemp(prefix="yuce_client_"))
        cls.addClassCleanup(shutil.rmtree, cls.work, ignore_errors=True)
        cls.tokens = {who: f"{who}-local-test-token" for who in (*TEAM, "owner")}
        subjects = [{"id": who, "role": "owner" if who == "owner" else "swarm", "token": token} for who, token in cls.tokens.items()]
        (cls.work / "subjects.json").write_text(json.dumps({"subjects": subjects}), encoding="utf-8")
        (cls.work / "questions.json").write_text(json.dumps([{"id": "q1", "text": "How does a connection start?", "about": ["initialization"]}]),
                                                 encoding="utf-8")
        (cls.work / "select.txt").write_text(PAGE + "\n", encoding="utf-8")
        cls.process = subprocess.Popen(
            [str(binary()), "audit-serve", "--listen", "127.0.0.1:0", "--wal", str(cls.work / "run.wal"), "--subjects", str(cls.work / "subjects.json"),
             "--questions", str(cls.work / "questions.json"), "--manifest", str(CORPUS / "manifest.json"), "--repo", str(CORPUS),
             "--select", str(cls.work / "select.txt"), "--run-id", "client-test"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
        cls.addClassCleanup(cls.process.wait)
        cls.addClassCleanup(cls.process.kill)
        cls.address = f"127.0.0.1:{json.loads(cls.process.stdout.readline())['port']}"

    def connect(self, who):
        agent = yuce.Client(self.address, self.tokens[who])
        self.addCleanup(agent.close)
        return agent

    def test_a_reader_quotes_and_the_owner_withdraws_the_quote(self):
        team = {who: self.connect(who) for who in TEAM}
        owner = self.connect("owner")
        task = next(t for t in (team[who].acquire() for who in TEAM) if t.get("kind") == "EXTEND")
        self.assertEqual(task["status"], "DIRECTIVE")
        p = task["local_id_prefix"]
        reader = team[next(who for who in TEAM if who[-1] == p[1])]
        doc = task["key"].split(":", 1)[1].split("#", 1)[0]

        wrong = reader.submit(task["task_id"], [yuce.observe(p + "o1", doc, QUOTE.replace("first", "forst"))])
        self.assertEqual((wrong["status"], wrong["error"]["code"]), ("REPAIR_REQUIRED", "QUOTE_NOT_FOUND_IN_BYTES"))
        self.assertEqual(owner.status()["records"], 0)

        lines = [yuce.observe(p + "o1", doc, QUOTE, terms=["initialization"]),
                 yuce.claim(p + "c1", "Initialization comes first.", "initialization", [p + "o1"])]
        done = reader.submit(task["task_id"], lines)
        self.assertEqual(done["status"], "COMMITTED")
        quote, claim = done["accepted_locals"][p + "o1"], done["accepted_locals"][p + "c1"]
        self.assertTrue(owner.record(claim)["grounded"])

        owner.revoke(quote)
        self.assertFalse(owner.record(claim)["grounded"])
        self.assertEqual(owner.call("audit_status")["records"], owner.status()["records"])

    def test_who_the_server_says_this_is(self):
        agent = self.connect("reader-1")
        self.assertEqual(agent.subject, {"role": "swarm", "id": "reader-1"})
        self.assertEqual(agent.server["name"], "sbgk-audit")
        self.assertTrue(agent.instructions)
        agent.ping()

    def test_the_role_decides_the_tools(self):
        reader, owner = self.connect("reader-2"), self.connect("owner")
        self.assertEqual({t["name"] for t in reader.tools()}, {"audit_acquire", "audit_submit", "audit_renew", "audit_release"})
        self.assertIn("audit_revoke", {t["name"] for t in owner.tools()})
        with self.assertRaises(yuce.RpcError) as caught:
            reader.status()
        self.assertEqual(caught.exception.code, yuce.FORBIDDEN)

    def test_a_token_the_server_does_not_know_is_refused(self):
        with self.assertRaises(yuce.RpcError) as caught:
            yuce.Client(self.address, "a-token-nobody-has-here")
        self.assertEqual(caught.exception.code, yuce.UNAUTHORIZED)

    def test_every_method_names_a_tool_of_the_server(self):
        source = (HERE.parent / "src/yuce/client.py").read_text(encoding="utf-8")
        named = set(re.findall(r'self\.call\("(audit_[a-z_]+)"', source))
        served = set(re.findall(r'"(audit_[a-z_]+)"', (REPO / "crates/sbgk-cli/src/audit_mcp.rs").read_text(encoding="utf-8")))
        self.assertEqual(named - served, set())
        self.assertEqual({t for t in served if t in {"audit_" + n for n in ("acquire", "submit", "renew", "release", "next_card", "submit_ops",
                                                                            "builder_failure", "status", "links", "link_status", "concept_status",
                                                                            "record", "revoke", "terminal_receipt", "close")}} - named, set())


if __name__ == "__main__":
    unittest.main()
