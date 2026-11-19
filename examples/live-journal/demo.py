"""No-LLM demo for YuCe Live: a recorded run of three readers and an owner, played back as one page.

The script plays the agents itself (no model, no API key) against the real `sbgk audit-serve`:
1. three readers each read one of three short documents about refunds and hand in quotes and claims;
2. the owner seals, three answers to three questions are handed in, the owner seals again;
3. the owner withdraws one sentence of the 2023 policy: the claims and answers that rested on it fall, and the kernel sends
   the three questions back to be answered;
4. the readers answer again from what still stands, and the owner seals.
Then make_page.py turns the journal into one HTML page and compares it with the kernel at every frame, and check_states.mjs runs
the page's own script on the kernel's states at every frame (when Node.js is on the PATH).

usage: python demo.py --html live_journal.html [--bin path/to/sbgk] [--keep] [--states states.json]
It exits 0 when every step behaves as described and the page is written, 1 otherwise. Python 3.10+, standard library only."""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from make_page import find_binary  # noqa: E402

DOCS = {
    "refund-policy-2025.md": "# Refund policy 2025\n\n## Payment\n\nApproved refunds are paid within 14 days of approval.\n"
                             "The money goes back to the original payment method.\n\n## Approval\n\n"
                             "Refunds above 500 need the approval of a manager before payment.\n\n## Proof\n\n"
                             "We accept a receipt or an order number as proof of purchase.\n",
    "refund-policy-2023.md": "# Refund policy 2023\n\n## Payment\n\nRefunds are paid only against the original receipt, within 30 days.\n\n"
                             "## Exceptions\n\nGift cards are not refunded.\n",
    "support-handbook.md": "# Support handbook\n\n## Form\n\nThe refund form asks for the order number first.\n"
                           "A request is filed through the support form, not by e-mail.\n\n## Timing\n\n"
                           "Support answers a refund request within 2 working days.\n",
}
TEAM = ("agent-a", "agent-b", "agent-c")
QUESTIONS = [{"id": "Q1", "text": "How long does a refund take?", "about": ["refund-time"]},
             {"id": "Q2", "text": "Who approves a refund above 500?", "about": ["approval"]},
             {"id": "Q3", "text": "Is a receipt needed for a refund?", "about": ["receipt"]}]
# what the reader of each document quotes, the terms of the quote, and the claims on it
READ = {
    "Refund policy 2025": [
        ("Approved refunds are paid within 14 days of approval.", ["refund-time"], ["A refund is paid within 14 days of approval."]),
        ("The money goes back to the original payment method.", ["payment-method"], ["The money goes back to the original payment method."]),
        ("Refunds above 500 need the approval of a manager before payment.", ["approval"], ["A refund above 500 needs the approval of a manager."]),
        ("We accept a receipt or an order number as proof of purchase.", ["receipt"], ["A receipt or an order number is accepted as proof of purchase."])],
    "Refund policy 2023": [
        ("Refunds are paid only against the original receipt, within 30 days.", ["receipt", "refund-time"],
         ["A refund needs the original receipt.", "A refund is paid within 30 days."]),
        ("Gift cards are not refunded.", ["exceptions"], ["Gift cards are not refunded."])],
    "Support handbook": [
        ("The refund form asks for the order number first.", ["form"], ["The refund form asks for the order number first."]),
        ("A request is filed through the support form, not by e-mail.", ["form"], ["A refund request is filed through the support form."]),
        ("Support answers a refund request within 2 working days.", ["refund-time"], ["Support answers a refund request within 2 working days."])],
}
WITHDRAWN = "Refunds are paid only against the original receipt, within 30 days."
ANSWER = {
    "Q1": [("A refund is paid within 14 days of approval; the 2023 policy said within 30 days.",
            ["Approved refunds are paid within 14 days of approval.", WITHDRAWN])],
    "Q2": [("A manager approves a refund above 500, before payment.", ["Refunds above 500 need the approval of a manager before payment."])],
    "Q3": [("Yes: the 2023 policy needs the original receipt; the 2025 policy accepts a receipt or an order number.",
            [WITHDRAWN, "We accept a receipt or an order number as proof of purchase."])],
}
AGAIN = {
    "Q1": [("A refund is paid within 14 days of approval.", ["Approved refunds are paid within 14 days of approval."])],
    "Q2": [("A manager approves a refund above 500, before payment.", ["Refunds above 500 need the approval of a manager before payment."])],
    "Q3": [("A receipt or an order number is accepted as proof of purchase.", ["We accept a receipt or an order number as proof of purchase."])],
}


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


def setup(work: pathlib.Path) -> dict:
    (work / "repo" / "docs").mkdir(parents=True)
    entries = []
    for name, text in DOCS.items():
        data = text.encode("utf-8")
        (work / "repo" / "docs" / name).write_bytes(data)
        entries.append({"path": f"docs/{name}", "extension": ".md", "corpus_role": "markdown_document_candidate", "size_bytes": len(data),
                        "raw_sha256": hashlib.sha256(data).hexdigest(), "references": {"commit_candidates": [], "pull_request_candidates": []}})
    (work / "manifest.json").write_text(json.dumps({"format": "r2r.tobi_corpus_metadata_manifest.v1", "entries": entries, "source": {
        "origin_recorded": "https://example.invalid/refunds.git", "commit": "1" * 40, "repository": "local"}}), encoding="utf-8")
    (work / "select.txt").write_text("".join(f"docs/{n}\n" for n in DOCS), encoding="utf-8")
    tokens = {who: f"{who}-local-demo-token" for who in (*TEAM, "owner")}
    (work / "subjects.json").write_text(json.dumps({"subjects": [
        {"id": who, "role": "owner" if who == "owner" else "swarm", "token": t} for who, t in tokens.items()]}), encoding="utf-8")
    (work / "questions.json").write_text(json.dumps(QUESTIONS), encoding="utf-8")
    return tokens


def step(text: str, ok: bool) -> bool:
    print(f"  [{'ok' if ok else 'FAILED'}] {text}")
    return ok


def play(binary: pathlib.Path, work: pathlib.Path, tokens: dict, stage=None) -> bool:
    """The scripted run against `sbgk audit-serve`, the journal in work/run.wal. `stage(name)` is called after each part of the
    run, while the server still holds the journal, and once more as "stopped" after the server is gone; watch_demo.py looks at
    the watched page there. Returns whether every step behaved as described."""
    stage = stage or (lambda name: True)
    proc = subprocess.Popen([str(binary), "audit-serve", "--profile", "custom", "--build-scope", "none", "--listen", "127.0.0.1:0",
                             "--wal", str(work / "run.wal"), "--subjects", str(work / "subjects.json"), "--questions", str(work / "questions.json"),
                             "--manifest", str(work / "manifest.json"), "--repo", str(work / "repo"), "--select", str(work / "select.txt"),
                             "--run-id", "refund-demo"], stdout=subprocess.PIPE, stderr=open(work / "server.err", "w"), text=True,
                            encoding="utf-8")
    good = True
    try:
        first = proc.stdout.readline()
        if not first:
            raise RuntimeError(f"audit-serve did not start: {(work / 'server.err').read_text(encoding='utf-8')[:600]}")
        threading.Thread(target=proc.stdout.read, daemon=True).start()  # the server's later lines never block it
        port = json.loads(first)["port"]
        team = {who: Agent(port, tokens[who]) for who in TEAM}
        owner = Agent(port, tokens["owner"])
        titles, quote_ids = {}, {}

        def extend(who, t):
            p, doc = t["local_id_prefix"], t["key"].split(":", 1)[1].split("#", 1)[0]
            title = t["prompt"].split("<<<\n", 1)[1].splitlines()[0].lstrip("# ").strip()
            titles[doc] = title
            lines = []
            for i, (q, terms, claims) in enumerate(READ[title], 1):
                lines.append({"kind": "observe", "local_id": f"{p}o{i}", "doc_id": doc, "exact_quote": q, "terms": terms})
                lines += [{"kind": "claim", "local_id": f"{p}c{i}_{j}", "text": c, "subject": "refund", "stance": "reported",
                           "based_on": [f"{p}o{i}"]} for j, c in enumerate(claims, 1)]
            r = team[who].call("audit_submit", task_id=t["task_id"], lines=lines)
            for i, (q, _, _) in enumerate(READ[title], 1):
                quote_ids[q] = (r.get("accepted_locals") or {}).get(f"{p}o{i}")
            return step(f"{who} reads {title}: {r.get('status')}", r.get("status") == "COMMITTED")

        def summarize(who, t, answers):
            p, rq = t["local_id_prefix"], t["key"].split(":", 1)[1]
            plan = list(answers[rq])
            # an answer rests on every document whose quotes its window shows (the kernel's coverage rule for a summary)
            window = t["prompt"].split("RECORDS:\n", 1)[1].split("\nACCEPTED LINKS", 1)[0]
            used = {quote_ids[q] for _, qs in plan for q in qs}
            shown = {}
            for m in re.finditer(r'^  (@[0-9a-f]+) observe by [^:]+: \[([^\]]+)\] "(.*)"$', window, re.M):
                shown.setdefault(m.group(2), []).append((m.group(1), m.group(3)))
            for doc, obs in shown.items():
                if not any(o in used for o, _ in obs):
                    plan.append((f"The {titles[doc].lower()} says: {obs[0][1]}", [obs[0][1]]))
            lines = [{"kind": "claim", "local_id": f"{p}c{j}", "text": text, "subject": "refund", "stance": "reported",
                      "based_on": [quote_ids[q] for q in qs]} for j, (text, qs) in enumerate(plan, 1)]
            lines.append({"kind": "done", "local_id": f"{p}d1", "rq_id": rq, "directive_id": t["task_id"], "outcome": "answered",
                          "answer_ids": [f"{p}c{j}" for j in range(1, len(plan) + 1)], "text": "Only the three documents of this demo were read."})
            r = team[who].call("audit_submit", task_id=t["task_id"], lines=lines)
            return step(f"{who} answers {rq}: {r.get('status')}", r.get("status") == "COMMITTED")

        def round_(kind, answers=None):
            ok = True
            for who in TEAM:
                t = team[who].call("audit_acquire")
                if t.get("kind") != kind:
                    return step(f"{who} expected a {kind} task, got {t.get('kind') or t.get('status')}", False)
                ok &= extend(who, t) if kind == "EXTEND" else summarize(who, t, answers)
            return ok

        good &= round_("EXTEND")
        good &= stage("read")
        good &= step("the owner seals", owner.call("audit_seal").get("status") == "SEALED")
        good &= round_("SUMMARIZE", ANSWER)
        good &= step("the owner seals", owner.call("audit_seal").get("status") == "SEALED")
        good &= stage("answered")
        doc2023 = next(d for d, title in titles.items() if title == "Refund policy 2023")
        gone = owner.call("audit_withdraw_text", doc_id=doc2023, exact_quote=WITHDRAWN)
        fallen = owner.call("audit_fallen", since=gone.get("since", 0))
        again = fallen.get("questions_to_answer_again")
        good &= step(f"the owner withdraws a sentence of the 2023 policy: {gone.get('status')}, {gone.get('fell')} records fell, "
                     f"to answer again {again}", gone.get("status") == "REVOKED" and gone.get("fell") == 8 and again == ["Q1", "Q2", "Q3"])
        good &= stage("withdrawn")
        good &= round_("SUMMARIZE", AGAIN)
        good &= step("the owner seals", owner.call("audit_seal").get("status") == "SEALED")
        good &= stage("answered again")
        for agent in (*team.values(), owner):
            agent.close()
    except (RuntimeError, KeyError, StopIteration, OSError, ValueError) as e:
        good = step(f"the run stopped: {type(e).__name__}: {e}", False)
    finally:
        proc.kill()
        proc.wait()
    return good and stage("stopped")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--html", required=True, type=pathlib.Path, help="the page to write")
    ap.add_argument("--bin", help="path to the sbgk (or yuce) binary")
    ap.add_argument("--keep", action="store_true", help="keep the work folder with the journal and the documents")
    ap.add_argument("--states", type=pathlib.Path, help="also write the kernel's states at every frame here, for check_states.mjs")
    a = ap.parse_args()
    binary = find_binary(a.bin)
    work = pathlib.Path(tempfile.mkdtemp(prefix="yuce_live_demo_"))
    tokens = setup(work)
    states = a.states or work / "states.json"
    print(f"YuCe Live demo: three readers and an owner on three refund documents\n  binary {binary}\n  journal {work / 'run.wal'}")
    good = play(binary, work, tokens)
    if good:
        out = subprocess.run([sys.executable, str(HERE / "make_page.py"), "--wal", str(work / "run.wal"), "--out", str(a.html),
                              "--docs", str(work / "repo"), "--bin", str(binary), "--check", "all", "--coverage", "all",
                              "--states", str(states),
                              "--note", "A scripted demo: three agents and an owner, played by a script, with no model. The documents are made up."],
                             capture_output=True, text=True, encoding="utf-8")
        made = json.loads(out.stdout) if out.returncode == 0 else {}
        good &= step(f"make_page: {made.get('status') or out.stderr.strip()[:400]}, {made.get('frames')} frames, page equal to "
                     f"audit-prov --upto at {made.get('checked_frames')} frames, quotes shown in their documents: {made.get('docs_shown')}",
                     made.get("status") == "WRITTEN" and made.get("checked_frames") == made.get("frames", -1) + 1 and made.get("docs_shown"))
        node = shutil.which("node")
        if good and node:
            out = subprocess.run([node, str(HERE / "check_states.mjs"), str(a.html), str(states)], capture_output=True, text=True,
                                 encoding="utf-8")
            good &= step(f"the page's own script on the kernel's states: {out.stdout.strip().splitlines()[-1] if out.stdout.strip() else out.stderr.strip()[:300]}",
                         out.returncode == 0)
        elif good:
            print("  [skipped] no Node.js on the PATH: the page's own script was not run on the kernel's states")
    if a.keep:
        print(f"  work folder kept: {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    print(f"{'OK' if good else 'FAILED'}: open {a.html} in a browser" if good else "FAILED")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
