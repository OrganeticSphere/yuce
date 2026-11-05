"""The kernel's limits without a model: the campaign behind section 4 of BENCHMARKS.md, for anyone to repeat.

Part one, journal size. Each point starts from nothing in a new process (crates/sbgk-core/examples/limits.rs): a journal of N records
on a fixed synthetic corpus, half quotes and half claims. 32 single quotes are timed on top of it, one durable transaction each, and
the journal is then opened in another new process, which must reach the same roots and leave the file as it was.

Part two, clients at once. A stock audit-serve in its default profile over TCP with real tokens and no artificial pauses, starting
from a journal of 5,000 records: the clients close the 97 reading tasks and the summary until the run is TERMINAL, and the closed
journal is opened in a new process, which must reach the roots of the terminal receipt.

Part three, real journals, with --journals: the time `audit-verify` takes on each file given. Synthetic journals hold nothing but
quotes and claims on them, and are lighter per record than those of real runs, so this row is the one to read for a real run.

The OS file cache is not controlled and the machine is not reserved: the numbers describe one run on one machine, and the script
prints what it ran on, with how busy the machine was during each case: a build running beside it halves the tasks per second, so
it warns above 30%. Memory is the peak resident size of the whole process, sampled from outside. It fits no slope and sets no target.

usage: python benchmarks/run_limits.py --out DIR [--bin sbgk] [--driver limits] [--records 1000 5000 10000] [--agents 3 8 16 32]
                                       [--journals a.wal b.wal]
Build first: cargo build --release -p sbgk-cli --bin sbgk -p sbgk-core --example limits
It exits 0 when every case ends with its checks passed, 1 otherwise, and keeps what it wrote. Standard library only."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import pathlib
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

REPO = pathlib.Path(__file__).resolve().parent.parent
CASE_LIMIT_S = 1800
MEMORY_LIMIT_BYTES = 3 * 2 ** 30
BUSY_PERCENT = 30
START_RECORDS = 5000
TASKS_PER_RUN = 97


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: pathlib.Path, value) -> None:
    path.write_text(json.dumps(value, indent=1) + "\n", encoding="utf-8")


def stats(samples: list[float]) -> dict:
    """The sample at sorted index ceil((n-1) * q), as the storage side does."""
    if not samples:
        return {"n": 0}
    a = sorted(samples)

    def q(x: float) -> float:
        return a[math.ceil((len(a) - 1) * x)]

    return {"n": len(a), "p50_ms": q(0.5), "p95_ms": q(0.95), "min_ms": a[0], "max_ms": a[-1]}


def peak_memory(pid: int, handle: int | None) -> int | None:
    """The peak resident bytes of a live process so far: Windows and Linux only, None elsewhere."""
    if sys.platform == "win32" and handle is not None:
        class Counters(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_ulong), ("faults", ctypes.c_ulong)] + [(n, ctypes.c_size_t) for n in (
                "peak_ws", "ws", "peak_paged", "paged", "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile", "private")]
        c = Counters()
        c.cb = ctypes.sizeof(c)
        info = ctypes.windll.psapi.GetProcessMemoryInfo
        info.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
        return c.peak_ws if info(handle, ctypes.byref(c), c.cb) else None
    try:
        found = re.search(r"VmHWM:\s+(\d+) kB", pathlib.Path(f"/proc/{pid}/status").read_text(encoding="ascii"))
        return int(found.group(1)) * 1024 if found else None
    except OSError:
        return None


def cpu_times() -> tuple[int, int] | None:
    """Idle and total processor time of the machine so far: Windows and Linux only, None elsewhere."""
    if sys.platform == "win32":
        idle, kernel, user = ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong()
        ok = ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user))
        return (idle.value, kernel.value + user.value) if ok else None
    try:
        fields = [int(x) for x in pathlib.Path("/proc/stat").read_text(encoding="ascii").splitlines()[0].split()[1:]]
        return fields[3] + fields[4], sum(fields)
    except (OSError, ValueError, IndexError):
        return None


class HostLoad:
    """How busy the machine is while a case runs, every process counted."""

    def __enter__(self):
        self.start, self.started = cpu_times(), time.monotonic()
        return self

    def __exit__(self, *_):
        end = cpu_times()
        self.percent = None
        if self.start and end and end[1] > self.start[1]:
            self.percent = round(100 * (1 - (end[0] - self.start[0]) / (end[1] - self.start[1])), 1)
        if self.percent is not None and self.percent > BUSY_PERCENT:
            print(f"  WARNING: the machine was {self.percent}% busy during this case: the numbers are not for publication", flush=True)


class Watched:
    """A subprocess whose peak memory is sampled while it lives; over the memory limit it is stopped."""

    def __init__(self, args: list, **popen):
        self.proc = subprocess.Popen([str(a) for a in args], **popen)
        self.peak, self.over_limit, self.done = None, False, threading.Event()
        self.thread = threading.Thread(target=self.sample, daemon=True)
        self.thread.start()

    def sample(self) -> None:
        handle = getattr(self.proc, "_handle", None)
        while not self.done.wait(0.1):
            if self.proc.poll() is not None:
                return
            seen = peak_memory(self.proc.pid, int(handle) if handle is not None else None)
            if seen is not None:
                self.peak = max(self.peak or 0, seen)
                if seen > MEMORY_LIMIT_BYTES:
                    self.over_limit = True
                    self.proc.kill()
                    return

    def wait(self, timeout: float) -> int:
        code = self.proc.wait(timeout=timeout)
        self.done.set()
        self.thread.join()
        return code


def run_logged(args: list, log: pathlib.Path) -> dict:
    started = time.monotonic()
    with log.open("x", encoding="utf-8") as out:
        watched = Watched(args, stdout=out, stderr=subprocess.STDOUT)
        try:
            code = watched.wait(CASE_LIMIT_S)
        except subprocess.TimeoutExpired:
            watched.proc.kill()
            watched.wait(30)
            raise
    if watched.over_limit:
        raise RuntimeError(f"{args[0]} {args[1]} went over {MEMORY_LIMIT_BYTES} bytes: see {log}")
    if code:
        raise RuntimeError(f"{args[0]} {args[1]} exited {code}: see {log}")
    return {"elapsed_s": time.monotonic() - started, "peak_memory_bytes": watched.peak}


def recover(driver: pathlib.Path, wal: pathlib.Path, out: pathlib.Path) -> dict:
    before = sha256(wal)
    run_logged([driver, "recover", wal, out / "recovery.jsonl"], out / "recovery.log")
    row = json.loads((out / "recovery.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    if sha256(wal) != before:
        raise RuntimeError(f"opening {wal} changed it")
    return row


def journal_point(driver: pathlib.Path, out: pathlib.Path, records: int) -> dict:
    point = out / f"point_{records:05}"
    point.mkdir()
    with HostLoad() as load:
        run = run_logged([driver, "populate", point, records], point / "populate.log")
        row = json.loads((point / "storage.jsonl").read_text(encoding="utf-8").splitlines()[-1])
        replay = recover(driver, point / f"base_{records}.wal", point)
    if replay["records"] != records or replay["roots"] != row["roots"]:
        raise RuntimeError(f"the replay of {records} records differs: {replay}")
    us = row["single_quote_commit"]
    print(f"  {records:>6} records: commit p50 {us['p50_us'] / 1000:.1f} ms, p95 {us['p95_us'] / 1000:.1f} ms; replay {replay['open_us'] / 1e6:.2f} s; "
          f"peak memory {(run['peak_memory_bytes'] or 0) / 2 ** 20:.1f} MiB", flush=True)
    return {"records": records, "commit_p50_ms": us["p50_us"] / 1000, "commit_p95_ms": us["p95_us"] / 1000, "replay_s": replay["open_us"] / 1e6,
            "peak_memory_bytes": run["peak_memory_bytes"], "journal_bytes": row["journal_bytes"], "roots": row["roots"], "host_cpu_percent": load.percent}


class Client:
    """One authenticated connection to audit-serve (newline-delimited JSON-RPC over TCP)."""

    def __init__(self, port: int, token: str):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=CASE_LIMIT_S)
        self.reader = self.sock.makefile("rb")
        self.n = 0
        reply = self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "auth_token": token})
        if "error" in reply:
            raise RuntimeError(f"the server refused the subject: {reply['error']}")

    def rpc(self, method: str, params: dict) -> dict:
        self.n += 1
        self.sock.sendall((json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}) + "\n").encode())
        return json.loads(self.reader.readline())

    def call(self, tool: str, **arguments) -> dict:
        reply = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        return reply["error"] if "error" in reply else reply["result"]["structuredContent"]

    def close(self) -> None:
        self.reader.close()
        self.sock.close()


def lines_for(task: dict) -> list[dict]:
    """A quarter of the sections hold nothing to record; the summary cites every quote it is shown."""
    prefix = task["local_id_prefix"]
    if task["kind"] == "SUMMARIZE":
        quotes = re.findall(r"^\s*(@[0-9a-f]{16})\s+observe\b", task["prompt"], re.M)
        return [{"kind": "claim", "local_id": prefix + "c", "subject": "status", "text": "The cited component status is reported ready.", "stance": "reported", "based_on": quotes},
                {"kind": "done", "local_id": prefix + "d", "rq_id": "RQ1", "directive_id": task["task_id"], "outcome": "answered", "answer_ids": [prefix + "c"],
                 "text": "Only the supplied synthetic records were checked."}]
    doc = task["key"][4:].rsplit("#", 1)[0]
    if doc == "seed" or int(doc[1:]) % 4 == 0:
        return []
    quote = f"The status of component {int(doc[1:]):03} is reported ready."
    return [{"kind": "observe", "local_id": prefix + "o", "doc_id": doc, "exact_quote": quote, "terms": ["status"]},
            {"kind": "claim", "local_id": prefix + "c", "subject": "status", "text": quote, "stance": "reported", "based_on": [prefix + "o"]}]


def clients_case(binary: pathlib.Path, driver: pathlib.Path, base_wal: pathlib.Path, out: pathlib.Path, k: int) -> dict:
    cell = out / f"agents_{k:02}"
    cell.mkdir()
    with base_wal.open("rb") as f:
        (cell / "run.wal").write_bytes(f.readline())  # the genesis alone: the server binds its own policy at head zero
    tokens = {f"w{i}": f"local_limits_token_{k:02}_{i:02}" for i in range(1, k + 1)} | {"owner": f"local_limits_owner_{k:02}"}
    write(cell / "subjects.json", {"subjects": [{"id": who, "token": token, "role": "owner" if who == "owner" else "swarm"} for who, token in tokens.items()]})
    write(cell / "questions.json", [{"id": "RQ1", "text": "What status is reported for the components?", "about": ["status"]}])
    args = [binary, "audit-serve", "--listen", "127.0.0.1:0", "--wal", cell / "run.wal", "--subjects", cell / "subjects.json", "--questions", cell / "questions.json",
            "--agent-timeout-ms", 300000, "--answer-timeout-ms", 900000, "--auto-rereads", 0]

    def start() -> tuple[Watched, dict]:
        server = Watched(args, stdout=subprocess.PIPE, stderr=(cell / "server.err").open("a", encoding="utf-8"), text=True, encoding="utf-8")
        first = server.proc.stdout.readline()
        if not first:
            server.proc.wait()
            raise RuntimeError(f"audit-serve did not start: {(cell / 'server.err').read_text(encoding='utf-8')[:400]}")
        return server, json.loads(first)

    def stop(server: Watched) -> None:
        if server.proc.poll() is None:
            server.proc.terminate()
        server.wait(30)
        server.proc.stdout.close()

    boot, hello = start()
    stop(boot)
    if hello["audit"]["records"] != 0:
        raise RuntimeError(f"not a new run: {hello}")
    run_logged([driver, "seed", cell / "run.wal", START_RECORDS], cell / "seed.log")
    seeded = json.loads((cell / "seed.log").read_text(encoding="utf-8").splitlines()[-1])
    server, hello = start()
    clients: list[Client] = []
    try:
        if hello["audit"]["records"] != START_RECORDS:
            raise RuntimeError(f"the server did not resume the seeded journal: {hello}")
        owner = Client(hello["port"], tokens["owner"])
        clients = [Client(hello["port"], tokens[f"w{i}"]) for i in range(1, k + 1)]
        barrier = threading.Barrier(k + 1)
        deadline = time.monotonic() + CASE_LIMIT_S
        lock = threading.Lock()
        halt = threading.Event()
        times = {"acquire": [], "submit": [], "empty": []}
        raw: list[dict] = []

        def timed(client: Client, tool: str, **arguments) -> tuple[dict, float]:
            t = time.perf_counter_ns()
            reply = client.call(tool, **arguments)
            ms = (time.perf_counter_ns() - t) / 1e6
            with lock:
                raw.append({"tool": tool, "arguments": arguments, "reply": reply, "rtt_ms": ms})
            return reply, ms

        def work(client: Client) -> int:
            done = 0
            barrier.wait()
            try:
                while not halt.is_set():
                    if time.monotonic() > deadline:
                        raise TimeoutError("the case ran out of its time")
                    task, ms = timed(client, "audit_acquire", max_wait_ms=10000)
                    if task["status"] in ("COMPLETE", "DONE"):
                        return done
                    if task["status"] == "WAIT":
                        continue
                    if task["status"] != "DIRECTIVE":
                        raise RuntimeError(f"unexpected reply: {task}")
                    lines = lines_for(task)
                    reply, sent = timed(client, "audit_submit", task_id=task["task_id"], lines=lines)
                    if reply["status"] != "COMMITTED":
                        raise RuntimeError(f"a line of the campaign was refused: {reply}")
                    with lock:
                        times["acquire"].append(ms)
                        times["submit" if lines else "empty"].append(sent)
                    done += 1
            except BaseException:
                halt.set()  # the other clients leave at their next call, not at the end of the case's time
                raise
            return done

        with HostLoad() as load, ThreadPoolExecutor(max_workers=k) as pool:
            running = [pool.submit(work, c) for c in clients]
            started = time.monotonic()
            barrier.wait()
            tasks = sum(f.result() for f in running)
            elapsed = time.monotonic() - started
        with (cell / "rpc.jsonl").open("x", encoding="utf-8") as f:
            for row in raw:
                f.write(json.dumps(row) + "\n")
        if tasks != TASKS_PER_RUN + 1:
            raise RuntimeError(f"{tasks} tasks closed, not {TASKS_PER_RUN} readings and the summary")
        receipt = owner.call("audit_terminal_receipt")
        if receipt["status"] != "TERMINAL" or owner.call("audit_close")["status"] != "CLOSED":
            raise RuntimeError(f"the run did not end: {receipt}")
        owner.close()
    finally:
        for c in clients:
            c.close()
        stop(server)
    replay = recover(driver, cell / "run.wal", cell)
    for name, value in replay["roots"].items():
        if receipt[name] != value:
            raise RuntimeError(f"{name} of the replay differs from the receipt")
    print(f"  {k:>2} clients: {tasks} tasks in {elapsed:.2f} s = {tasks / elapsed:.1f} tasks per second", flush=True)
    return {"clients": k, "tasks": tasks, "work_s": elapsed, "tasks_per_s": tasks / elapsed, "seeded_ids": seeded["record_ids_sha256"], "end_records": replay["records"],
            "acquire": stats(times["acquire"]), "submit_with_records": stats(times["submit"]), "empty_close": stats(times["empty"]), "peak_memory_bytes": server.peak,
            "host_cpu_percent": load.percent}


def verify_time(binary: pathlib.Path, wal: pathlib.Path) -> dict:
    started = time.monotonic()
    done = subprocess.run([str(binary), "audit-verify", "--wal", str(wal)], capture_output=True, text=True, encoding="utf-8")
    elapsed = time.monotonic() - started
    answer = json.loads(done.stdout) if done.stdout.strip() else {}
    print(f"  {wal.name}: {answer.get('status')} in {elapsed:.1f} s, {wal.stat().st_size / 2 ** 20:.1f} MiB", flush=True)
    return {"journal": wal.name, "bytes": wal.stat().st_size, "status": answer.get("status"), "exit": done.returncode, "elapsed_s": elapsed}


def refused_journals(rows: list[dict]) -> list[str]:
    return [row["journal"] for row in rows if row["exit"] != 0]


def find(given: str | None, *relative: str) -> pathlib.Path:
    if given:
        return pathlib.Path(given)
    target = pathlib.Path(os.environ.get("CARGO_TARGET_DIR") or REPO / "target")
    target = target if target.is_absolute() else REPO / target
    for rel in relative:
        if (target / rel).is_file():
            return target / rel
    sys.exit(f"not built: {relative[0]}; build it (see the usage above) or give its path")


def provenance(binary: pathlib.Path, driver: pathlib.Path) -> dict:
    def git(*args: str) -> str | None:
        done = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True, encoding="utf-8")
        return done.stdout.strip() if done.returncode == 0 else None

    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, encoding="utf-8").stdout.strip()
    return {"binary_version": version, "binary_sha256": sha256(binary), "driver_sha256": sha256(driver), "script_sha256": sha256(pathlib.Path(__file__)),
            "git_commit": git("rev-parse", "HEAD"), "git_tree": git("rev-parse", "HEAD^{tree}"), "git_tag": git("describe", "--tags", "--exact-match"),
            "crates_tree": git("rev-parse", "HEAD:crates"), "benchmarks_tree": git("rev-parse", "HEAD:benchmarks"),
            "python": platform.python_version(), "platform": platform.platform(), "logical_cpus": os.cpu_count(), "model_calls": 0}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=pathlib.Path, required=True, help="a new folder for everything the campaign writes")
    ap.add_argument("--bin", help="path to the sbgk (or yuce) binary")
    ap.add_argument("--driver", help="path to the limits example")
    ap.add_argument("--records", nargs="*", type=int, default=[1000, 5000, 10000], help="journal sizes, even numbers")
    ap.add_argument("--agents", nargs="*", type=int, default=[3, 8, 16, 32], help="clients at once, on a journal of 5,000 records")
    ap.add_argument("--journals", nargs="*", type=pathlib.Path, default=[], help="real journals for audit-verify")
    a = ap.parse_args()
    binary = find(a.bin, "release/sbgk.exe", "release/sbgk")
    driver = find(a.driver, "release/examples/limits.exe", "release/examples/limits")
    a.out.mkdir(parents=True, exist_ok=False)
    result = {"format": "yuce-limits/1", "provenance": provenance(binary, driver), "points": [], "agents": [], "journals": [], "status": "FAILED"}
    print(f"limits of {result['provenance']['binary_version']}, {result['provenance']['platform']}", flush=True)
    try:
        for records in a.records:
            result["points"].append(journal_point(driver, a.out, records))
        if a.agents:
            seed_dir = a.out / "seed_genesis"
            seed_dir.mkdir()
            run_logged([driver, "populate", seed_dir, 2], seed_dir / "populate.log")
            for k in a.agents:
                result["agents"].append(clients_case(binary, driver, seed_dir / "base_2.wal", a.out, k))
            if len({row["seeded_ids"] for row in result["agents"]}) != 1:
                raise RuntimeError("the cells did not start from the same records")
        for wal in a.journals:
            result["journals"].append(verify_time(binary, wal))
        refused = refused_journals(result["journals"])
        if refused:
            raise RuntimeError(f"journals that did not verify: {', '.join(refused)}")
        result["status"] = "COMPLETE"
    finally:
        write(a.out / "summary.json", result)
    print(f"done: {a.out / 'summary.json'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
