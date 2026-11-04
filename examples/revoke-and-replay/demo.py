"""No-LLM demo of the YuCe audit server: a team of three readers and an owner on one page of the MCP specification.

The script plays the agents itself (no model, no API key) against the real `sbgk audit-serve` in its default v0.1 profile:

1. a reader quotes the page with one byte changed: the kernel refuses the line and stores no record;
2. the reader quotes two sentences byte for byte and records one claim on each quote: all four are accepted with receipt ids;
3. the owner revokes the first quote: the claim on it loses its registered support, the claim on the other quote keeps it;
4. the server is stopped and started again on the same journal: the replay reaches the same audit and engine roots, with
   the same two claim states;
5. a copy of the journal with one letter of the claim changed is refused on start (hash mismatch), and the original
   journal is left as it was;
6. without the server, `sbgk audit-verify` replays the journal and finds the state of the receipt saved before the stop
   (roots and chain head), and refuses the edited copy.

With --report FILE it also writes what the kernel answered at each step (the section it handed the reader, each line's receipt
or refusal, the claim states, the roots, both verify results) as JSON for inspector.html, which only displays that file.

With --html FILE it writes inspector.html with that report inside, a page that opens with its data.

usage: python demo.py [--bin path/to/sbgk] [--keep] [--report report.json] [--html inspector_report.html]
It exits 0 when every step behaves as described, 1 otherwise. Standard library only."""
import argparse
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
CORPUS = REPO / "benchmarks" / "corpora" / "mcp-spec-2026-07-28"
PAGE = "docs/specification/2024-11-05/basic/lifecycle.mdx"
QUOTE = "The initialization phase **MUST** be the first interaction between client and server."
QUOTE2 = "The client **MUST** initiate this phase by sending an `initialize` request containing:"
CLAIM = "Initialization must be the first client-server interaction."
TEAM = ("reader-1", "reader-2", "reader-3")


def find_binary(given: str | None) -> pathlib.Path:
    if given:
        return pathlib.Path(given)
    target = pathlib.Path(os.environ.get("CARGO_TARGET_DIR") or REPO / "target")  # where `cargo build` puts it
    for name in ("sbgk.exe", "sbgk"):
        candidate = (target if target.is_absolute() else REPO / target) / "release" / name
        if candidate.is_file():
            return candidate
    found = shutil.which("sbgk") or shutil.which("yuce")
    if found:
        return pathlib.Path(found)
    sys.exit("no sbgk binary: build it with `cargo build --release` or pass --bin")


class Agent:
    """One authenticated connection to audit-serve (newline-delimited JSON-RPC over TCP)."""

    def __init__(self, port: int, token: str):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=30)
        self.reader = self.sock.makefile("rb")
        self.n = 0
        reply = self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "auth_token": token})
        if "error" in reply:
            raise RuntimeError(f"the server refused the subject: {reply['error']}")

    def rpc(self, method: str, params: dict) -> dict:
        self.n += 1
        self.sock.sendall((json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}) + "\n").encode("utf-8"))
        return json.loads(self.reader.readline())

    def call(self, tool: str, **arguments) -> dict:
        reply = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        return reply["error"] if "error" in reply else reply["result"]["structuredContent"]

    def close(self) -> None:
        self.sock.close()


class Server:
    def __init__(self, binary: pathlib.Path, work: pathlib.Path, fresh: bool, wal: str = "demo.wal"):
        args = [str(binary), "audit-serve", "--listen", "127.0.0.1:0", "--wal", str(work / wal),
                "--subjects", str(work / "subjects.json"), "--questions", str(work / "questions.json")]
        if fresh:
            args += ["--manifest", str(CORPUS / "manifest.json"), "--repo", str(CORPUS), "--select", str(work / "select.txt"),
                     "--run-id", "no-llm-demo"]
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        first = self.proc.stdout.readline()
        if not first:
            self.proc.wait()
            raise RuntimeError(f"audit-serve did not start: {self.proc.stderr.read()}")
        self.hello = json.loads(first)
        self.port = self.hello["port"]

    def stop(self) -> None:
        self.proc.kill()
        self.proc.wait()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bin", help="path to the sbgk (or yuce) binary")
    ap.add_argument("--keep", action="store_true", help="keep the work folder with the journal")
    ap.add_argument("--report", type=pathlib.Path, help="write the kernel's answers at each step as JSON (for inspector.html)")
    ap.add_argument("--html", type=pathlib.Path, help="write inspector.html with that report inside it: a page that opens with its data")
    a = ap.parse_args()
    binary = find_binary(a.bin)
    work = pathlib.Path(tempfile.mkdtemp(prefix="yuce_demo_"))
    tokens = {who: f"{who}-local-demo-token" for who in (*TEAM, "owner")}
    (work / "subjects.json").write_text(json.dumps({"subjects": [
        {"id": who, "role": "owner" if who == "owner" else "swarm", "token": token} for who, token in tokens.items()]}), encoding="utf-8")
    (work / "questions.json").write_text(json.dumps([{"id": "q1", "text": "How does an MCP connection start?", "about": ["initialization"]}]),
                                         encoding="utf-8")
    (work / "select.txt").write_text(PAGE + "\n", encoding="utf-8")
    print(f"YuCe no-LLM demo: three readers and an owner on {PAGE}\n  binary {binary}\n  journal {work / 'demo.wal'}")
    good = True
    started = time.monotonic()
    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, encoding="utf-8").stdout.strip()
    report = {"format": "yuce-no-llm-demo-report/1", "made_by": "examples/revoke-and-replay/demo.py", "binary_version": version,
              "page": PAGE, "question": "How does an MCP connection start?", "steps": []}

    def step(n: int, text: str, ok: bool) -> bool:
        report["steps"].append({"n": n, "text": text, "ok": bool(ok)})
        print(f"  [{'ok' if ok else 'FAILED'}] {n}. {text}")
        return ok
    server = Server(binary, work, fresh=True)
    try:
        team = {who: Agent(server.port, tokens[who]) for who in TEAM}
        owner = Agent(server.port, tokens["owner"])
        task = next(t for t in (team[who].call("audit_acquire") for who in TEAM) if t.get("kind") == "EXTEND")
        p = task["local_id_prefix"]
        reader = team[next(who for who in TEAM if who[-1] == p[1])]
        doc = task["key"].split(":", 1)[1].split("#", 1)[0]
        print(f"  the kernel leased a section of the page to a reader: task {task['task_id']}, {task['kind']}")
        report["task"] = {k: task.get(k) for k in ("task_id", "kind", "key", "circle_phase")} | {"doc_id": doc}
        report["directive"] = task["prompt"]  # the whole directive the reader got, the section's bytes inside it

        altered = QUOTE.replace("first", "forst")  # one byte: i -> o
        bad = reader.call("audit_submit", task_id=task["task_id"], lines=[
            {"kind": "observe", "local_id": p + "o1", "doc_id": doc, "exact_quote": altered, "terms": ["initialization"]}])
        why = bad.get("error") or {}
        stored = owner.call("audit_status").get("records")
        report["altered"] = {"quote": altered, "original": QUOTE, "reply_status": bad.get("status"), "code": why.get("code"),
                             "message": why.get("message"), "records_stored": stored}
        good &= step(1, f"one byte changed in the quote -> {bad.get('status')} ({why.get('code')}: {why.get('message')}); "
                        f"records stored: {stored}", bad.get("status") == "REPAIR_REQUIRED" and why.get("code") == "QUOTE_NOT_FOUND_IN_BYTES"
                     and stored == 0)

        lines = [{"kind": "observe", "local_id": p + "o1", "doc_id": doc, "exact_quote": QUOTE, "terms": ["initialization"]},
                 {"kind": "claim", "local_id": p + "c1", "text": CLAIM, "subject": "initialization", "stance": "reported",
                  "based_on": [p + "o1"]},
                 {"kind": "observe", "local_id": p + "o2", "doc_id": doc, "exact_quote": QUOTE2, "terms": ["initialization"]},
                 {"kind": "claim", "local_id": p + "c2", "text": "The client starts initialization with an initialize request.",
                  "subject": "initialization", "stance": "reported", "based_on": [p + "o2"]}]
        done = reader.call("audit_submit", task_id=task["task_id"], lines=lines)
        ids = done.get("accepted_locals") or {}
        good &= step(2, f"two byte-exact quotes and one claim on each -> {done.get('status')}, receipts {ids}",
                     done.get("status") == "COMMITTED" and len(ids) == 4)
        observe, claim, other = ids.get(p + "o1"), ids.get(p + "c1"), ids.get(p + "c2")
        report["submitted"] = {"lines": lines, "reply_status": done.get("status"), "receipts": ids}

        def grounded() -> tuple:
            return owner.call("audit_record", record=claim).get("grounded"), owner.call("audit_record", record=other).get("grounded")

        before = grounded()
        revoked = owner.call("audit_revoke", record=observe)
        after = grounded()
        report["claims"] = [{"local_id": p + "c1", "record": claim, "text": CLAIM, "based_on": observe, "quote": QUOTE,
                             "grounded_before_revoke": before[0], "grounded_after_revoke": after[0]},
                            {"local_id": p + "c2", "record": other, "text": lines[3]["text"], "based_on": ids.get(p + "o2"),
                             "quote": QUOTE2, "grounded_before_revoke": before[1], "grounded_after_revoke": after[1]}]
        report["revoke"] = {"record": observe, "reply": revoked}
        good &= step(3, f"the owner revokes the first quote -> {revoked.get('status')}; grounded (claim on it, claim on the "
                        f"other quote): {before} before, {after} after",
                     revoked.get("status") == "REVOKED" and before == (True, True) and after == (False, True))

        root = owner.call("audit_status")
        for agent in (*team.values(), owner):
            agent.close()
    finally:
        server.stop()

    server = Server(binary, work, fresh=False)
    try:
        replayed = server.hello.get("audit", {})
        owner = Agent(server.port, tokens["owner"])
        again = grounded()
        status = owner.call("audit_status")
        same = all(status.get(k) == root.get(k) for k in ("audit_root", "engine_root")) and replayed.get("audit_root") == root.get("audit_root")
        good &= step(4, f"stopped and started again on the same journal -> resumed={replayed.get('resumed')}, "
                        f"audit and engine roots equal after replay: {same}, grounded: {again}",
                     bool(replayed.get("resumed")) and same and again == (False, True))
        print(f"     audit root {str(root.get('audit_root'))[:16]}..., engine root {str(root.get('engine_root'))[:16]}...")
        keys = ("audit_root", "engine_root", "wal_head", "records")
        report["before_stop"] = {k: root.get(k) for k in keys}
        report["after_restart"] = {k: status.get(k) for k in keys} | {"resumed": replayed.get("resumed"),
                                                                       "grounded": list(again) if again else None}
        owner.close()
    finally:
        server.stop()

    journal = (work / "demo.wal").read_bytes()
    at = journal.find(CLAIM.encode("utf-8"))
    edited = bytearray(journal)
    edited[at + len("Initialization ")] = ord("M")  # "must" -> "Must": one byte, still valid JSON
    (work / "edited.wal").write_bytes(bytes(edited))
    try:
        Server(binary, work, fresh=False, wal="edited.wal").stop()
        refusal = "the server started"
    except RuntimeError as e:
        refusal = str(e)
    untouched = (work / "demo.wal").read_bytes() == journal
    report["edited_copy"] = {"change": "one byte of the first claim's text: 'must' -> 'Must' (still valid JSON)",
                             "byte_offset": at + len("Initialization ") if at >= 0 else None, "refusal": refusal,
                             "original_unchanged": untouched}
    good &= step(5, f"a copy of the journal with one letter of the claim changed -> "
                    f"{'refused: hash mismatch' if 'hash mismatch' in refusal else refusal}; original journal unchanged: {untouched}",
                 at >= 0 and "hash mismatch" in refusal and untouched)

    # the receipt an owner keeps where the journal's writer cannot change it (a protected commit, a CI artifact)
    (work / "receipt.json").write_text(json.dumps({k: root.get(k) for k in ("audit_root", "engine_root", "wal_head")}), encoding="utf-8")

    def verify(wal: str) -> dict:
        out = subprocess.run([str(binary), "audit-verify", "--wal", str(work / wal), "--expect", str(work / "receipt.json")],
                             capture_output=True, text=True, encoding="utf-8")
        return json.loads(out.stdout or "{}") | {"exit": out.returncode}

    kept, copy = verify("demo.wal"), verify("edited.wal")
    report["receipt"] = json.loads((work / "receipt.json").read_text(encoding="utf-8"))
    report["verify"] = {"journal": kept, "edited_copy": copy}
    found = kept.get("expected", {}).get("found_after_entries")
    good &= step(6, f"checked without the server against the receipt saved before the stop -> journal {kept.get('status')} "
                    f"(the receipt's state after {found} of {kept.get('entries')} entries, {kept.get('records')} records), "
                    f"edited copy {copy.get('status')} (exit {copy.get('exit')})",
                 kept.get("status") == "VERIFIED" and kept["exit"] == 0 and found is not None
                 and copy.get("status") == "REFUSED" and copy["exit"] == 1)
    seconds = time.monotonic() - started
    print(f"All steps behaved as described ({seconds:.1f} s)." if good else "Some step did not behave as described.")
    if a.report or a.html:
        report |= {"all_ok": bool(good), "seconds": round(seconds, 1), "repeat": [
            "cargo build --release", "python examples/revoke-and-replay/demo.py --keep --report report.json",
            "sbgk audit-verify --wal <work folder>/demo.wal --expect <work folder>/receipt.json"]}
        here = str(work)

        def local(v):  # the temporary work folder (it holds the user's name on most systems) is written as <work folder>
            if isinstance(v, dict):
                return {k: local(x) for k, x in v.items()}
            if isinstance(v, list):
                return [local(x) for x in v]
            return v.replace(here.replace("\\", "\\\\"), "<work folder>").replace(here, "<work folder>") if isinstance(v, str) else v

        text = json.dumps(local(report), ensure_ascii=False, indent=1)
        if a.report:
            a.report.write_text(text + chr(10), encoding="utf-8")
            print(f"  report for inspector.html: {a.report}")
        if a.html:
            empty = '<script type="application/json" id="yuce-report"></script>'
            page = (HERE / "inspector.html").read_text(encoding="utf-8")
            # no "<" in the block (each is written as the JSON escape u003c, the same string): nothing in a report can close it or
            # open a tag, "<!--" included
            filled = page.replace(empty, empty.replace("></", ">" + text.replace("<", chr(92) + "u003c") + "</"), 1)
            a.html.write_text(filled, encoding="utf-8")
            print(f"  inspector page with this report: {a.html}")
    if a.keep:
        print(f"  work folder kept: {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
