"""EXP-10: resident MCP server (`sbgk mcp-serve`), asynchronous lease registry with a shared-premise lock, the directive scope guard
in Rust and kernel auto-closure of ready Horn derivations (P2A) - Addendum v0.3.1.

Every series talks to a real `sbgk mcp-serve --listen 127.0.0.1:0` process over JSON-RPC 2.0 (one TCP connection per worker):

  10A     scaling on the c_long96 register of EXP-9 (96 services, 16 APIs, ~311 sentences), K in {4, 16, 32, 64, 100} workers that execute
          their frame exactly (deterministic oracle worker of EXP-9), in VIRTUAL time with a heterogeneous latency profile: even workers
          answer in 6-10 s, odd ones in 15-20 s, 15 % of calls straggle (45-60 s), 5 % of calls hang (the worker stops sending heartbeats
          and comes back with its answer after 60 s). Three schedules:
            sync       the EXP-9B round barrier: one `emit_batch` per round, the round lasts as long as its slowest seat (a hung seat is
                       given up after the TTL, its work is redone in a later round), no auto-closure
            async      TTL leases (30 s, renewed every 10 s while the worker is alive), no barrier, shared-premise lock, no auto-closure
            full       async + kernel auto-closure of P2A
          The latency of the n-th call of worker w is drawn from a seed of (case, w, n), the same in every schedule.
  10A-RT  the same register under REAL concurrency: K threads, one connection each, zero model latency (throughput and latency of the
          resident server under lock contention).
  10B     fan-in: 60 services on 6 deprecated interfaces (10 per interface), K = 60, three dispatchers: target-only sharding, shared-premise
          lock, lock + auto-closure.
  guard   deterministic probes of the Rust-side scope guard and of the stale-lease checks on a 10C case.
  10C     live models (Codex gpt-5.6-sol, DeepSeek-chat, Claude Sonnet 5.5) on 6 cases of 20 services with shared APIs, contradictions
          and an erratum published while the team works: the EXP-9B synchronous directive rounds (EXP-9 harness, unchanged) against the
          asynchronous MCP swarm with auto-closure and the erratum published through `sbgk_post_erratum`.

Every judgement about the graph is read back from the kernel (`sbgk_swarm_status`, snapshots, `sbgk cone --full-out`).
"""

from __future__ import annotations

import concurrent.futures as cf
import dataclasses
import hashlib
import heapq
import itertools
import json
import os
import pathlib
import platform
import random
import shutil
import socket
import statistics
import subprocess
import threading
import time
from collections import Counter, defaultdict, deque

from . import common as C
from . import exp8_env as E
from . import exp8_run as R8
from . import exp9_directive_emitter as X
from .exp7_multiagent import parse_turn

OUT = C.RESULTS / "exp10"
RUNS = OUT / "runs"
CALLS9 = X.OUT / "calls"
R8.CALLS = OUT / "calls"  # new model calls of EXP-10 go here; EXP-9's cache is read first (SharedCache), never written
VERSION = "exp10-1"

K_LIST = (4, 16, 32, 64, 100)
TTL_MS = 30_000
RENEW_S = 10.0


# ------------------------------------------------------------------ MCP client

class Lat:
    """Latencies of MCP tool calls: client round trip and the server's own time (both in microseconds)."""

    def __init__(self):
        self.d: dict[str, list[tuple[float, float]]] = defaultdict(list)
        self.lock = threading.Lock()

    def add(self, tool: str, rtt: float, srv: float) -> None:
        with self.lock:
            self.d[tool].append((rtt, srv))

    def merge(self, other: "Lat") -> None:
        for k, v in other.d.items():
            self.d[k].extend(v)

    def summary(self) -> dict:
        out = {}
        for k, v in sorted(self.d.items()):
            rtt = [x[0] for x in v]
            srv = [x[1] for x in v]
            out[k] = {"n": len(v), "rtt_p50": C.pct(rtt, 0.5), "rtt_p95": C.pct(rtt, 0.95), "srv_p50": C.pct(srv, 0.5), "srv_p95": C.pct(srv, 0.95),
                      "srv_mean": statistics.fmean(srv), "srv_max": max(srv)}
        return out


class McpClient:
    def __init__(self, port: int, lat: Lat | None = None):
        self.s = socket.create_connection(("127.0.0.1", port))
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.f = self.s.makefile("rb")
        self.id = 0
        self.lat = lat
        r = self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "exp10", "version": VERSION}})
        if r.get("result", {}).get("serverInfo", {}).get("name") != "sbgk-mcp":
            raise RuntimeError(f"unexpected initialize answer: {str(r)[:300]}")
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, obj: dict) -> None:
        self.s.sendall((json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8"))

    def rpc(self, method: str, params: dict) -> dict:
        self.id += 1
        self._send({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params})
        line = self.f.readline()
        if not line:
            raise RuntimeError("the MCP server closed the connection")
        return json.loads(line)

    def tool(self, name: str, **args) -> dict:
        t = time.perf_counter()
        v = self.rpc("tools/call", {"name": name, "arguments": args})
        rtt = (time.perf_counter() - t) * 1e6
        if "error" in v:
            raise RuntimeError(f"{name}: {v['error']}")
        out = v["result"]["structuredContent"]
        if self.lat is not None:
            self.lat.add(name, rtt, float(out.get("server_us", 0.0)))
        return out

    def close(self) -> None:
        try:
            self.s.close()
        except OSError:
            pass


class McpServer:
    def __init__(self):
        self.p = subprocess.Popen([str(C.BIN), "mcp-serve", "--listen", "127.0.0.1:0"], stdout=subprocess.PIPE, text=True, encoding="utf-8")
        first = json.loads(self.p.stdout.readline())
        self.port = int(first["port"])
        self.clients: list[McpClient] = []

    def client(self, lat: Lat | None = None) -> McpClient:
        c = McpClient(self.port, lat)
        self.clients.append(c)
        return c

    def close(self) -> None:
        try:
            McpClient(self.port).rpc("shutdown", {})
        except Exception:  # noqa: BLE001 - the process ends while answering
            pass
        for c in self.clients:
            c.close()
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def init_session(c: McpClient, case, docs: dict[str, bytes], targets: dict, auto: bool, lock: str, pack: bool = False) -> dict:
    r = c.tool("sbgk_init_session", ontology=case.onto, docs={k: v.decode("utf-8") for k, v in docs.items()}, targets=targets,
               auto_close_p2a=auto, lock_mode=lock, default_ttl_ms=TTL_MS, default_k=4, pack_multi_target=pack)
    if r.get("status") != "SESSION_READY":
        raise RuntimeError(f"init_session refused: {r}")
    return r


def lease_resources(frame: dict) -> tuple[set, set]:
    return set(frame.get("targets") or []), {c["segment_id"] for c in frame.get("chunk_slice", []) if not c.get("amendment")}


def snapshot_full(c: McpClient, scratch: pathlib.Path) -> tuple[dict, dict]:
    """Snapshot the live session into a container and read the whole compiled graph back from its bytes (as EXP-8/9 do)."""
    scratch.mkdir(parents=True, exist_ok=True)
    cont = scratch / "state.sbgk"
    snap = c.tool("sbgk_snapshot", out=str(cont))
    out = scratch / "full.json"
    C.cli("cone", cont, "--entity", "svc_000", "--reps", 1, "--full-out", out)
    return json.loads(out.read_text(encoding="utf-8")), snap


# ------------------------------------------------------------------ cases

def case96(idx: int) -> E.Case8:
    return E.Case8(X.SPECS9["c_long96"], idx, seed=X.SEEDS9["c_long96"] + idx)


class FanInCase:
    """60 services on 6 deprecated interfaces, exactly 10 services per interface; every usage window overlaps the deprecation window,
    so every service needs review. Duck-typed for the EXP-9 oracle worker (quote, api_of, use_t, dep_t)."""

    def __init__(self, idx: int, services: int = 60, apis: int = 6):
        self.idx = idx
        self.seed = 10_500 + idx
        rng = random.Random(self.seed)
        self.api_of = [i % apis for i in range(services)]
        rng.shuffle(self.api_of)
        self.use_t = [(rng.choice([100, 110, 120]), rng.choice([200, 210, 220])) for _ in range(services)]
        self.dep_t = {a: (150, 300) for a in range(apis)}
        self.sys_of: list[int] = []
        self.onto = C.ontology_review(services, apis)
        clauses = [(f"U.{i}", E._use_text(0, f"U.{i}", i, self.api_of[i], *self.use_t[i])) for i in range(services)]
        clauses += [(f"D.{a}", E._dep_text(0, f"D.{a}", a, 150, 300)) for a in range(apis)]
        self.quote = dict(clauses)
        self.dep_quotes = {t for lab, t in clauses if lab.startswith("D.")}
        sents = [s for _, s in clauses]
        rng.shuffle(sents)
        paras = [" ".join([C.filler_sentence(rng)] + sents[k:k + 2] + [C.filler_sentence(rng)]) for k in range(0, len(sents), 2)]
        self.doc = C.join_doc(paras)
        self.targets = services
        self.erratum = None


SPEC_C = E.Spec("c_swarm", services=20, apis=8, active=4, systems=0, team=("codex", "deepseek", "sonnet", "codex"), k=4, cap=12,
                parallel=True, retract=True, gold=(8, 11))
SEED_C = 10_200


def case_c(idx: int, literal_enum: bool = False) -> E.Case8:
    """`literal_enum` (new experiments only) restricts the literal objects to `true`; the default keeps the recorded EXP-10C/11A inputs."""
    case = E.Case8(SPEC_C, idx, seed=SEED_C + idx)
    if literal_enum:
        case.onto = C.with_literal_enum(case.onto)
    return case


def targets_of(case, docs=("policy",)) -> dict:
    return X.targets_for(case, list(docs))


# ------------------------------------------------------------------ latency profile (virtual time)

@dataclasses.dataclass(frozen=True)
class Profile:
    fast: tuple = (6.0, 10.0)
    medium: tuple = (15.0, 20.0)
    straggler: tuple = (45.0, 60.0)
    p_straggler: float = 0.15
    p_hang: float = 0.05
    hang_s: float = 60.0

    def draw(self, seed: int, w: int, n: int) -> tuple[float, bool]:
        """Seconds of the n-th call of worker w, and whether the worker hangs on it."""
        rng = random.Random(f"{seed}|{w}|{n}")
        u = rng.random()
        if u < self.p_hang:
            return self.hang_s, True
        if u < self.p_hang + self.p_straggler:
            return rng.uniform(*self.straggler), False
        lo, hi = self.fast if w % 2 == 0 else self.medium
        return rng.uniform(lo, hi), False

    def to_json(self) -> dict:
        return dataclasses.asdict(self)


PROFILE_A = Profile()
PROFILE_B = Profile(p_hang=0.0)


def utilization(calls: list[tuple[float, float, bool]], K: int, T: float) -> tuple[float, float]:
    """(busy share, useful share) of K workers over [0, T]; calls are (start s, duration s, useful)."""
    if T <= 0:
        return 0.0, 0.0
    busy = sum(max(0.0, min(d, T - s)) for s, d, _ in calls if s < T)
    useful = sum(max(0.0, min(d, T - s)) for s, d, u in calls if s < T and u)
    return busy / (K * T), useful / (K * T)


def count_results(events: list[dict], res: dict, dep_quotes: set | None, st: Counter) -> None:
    for ev, r in zip(events, res.get("results") or []):
        if r.get("existed"):
            st["repeats"] += 1
        if dep_quotes is not None and ev.get("op") == "bind_evidence" and ev.get("exact_quote") in dep_quotes:
            st["dep_binds"] += 1
            st["dep_binds_repeat"] += 1 if r.get("existed") else 0


# ------------------------------------------------------------------ sync round barrier (EXP-9B schedule)

def run_sync(case, K: int, prof: Profile, seed: int, k: int = 4, lat: Lat | None = None, dep_quotes: set | None = None,
             unique_prefix: bool = False) -> dict:
    """EXP-9B round barrier. Up to 1.0.0 a round's frame prefixed local ids with one of 8 seat tags (`SEAT_TAGS[seat % 8]` + round),
    so with more than 8 seats two seats of a round shared a prefix and the kernel refused the second one's ids (DUPLICATE_LOCAL_ID).
    With `unique_prefix` the worker uses `s{seat}r{round}_` instead (the barrier alone, without that defect). Since 1.1.0 the
    kernel's own prefixes are collision-free for any number of seats (`seat_prefix`), so `sync` and `sync_u` coincide."""
    lat = lat or Lat()
    orc = X.Oracle(case)
    st: Counter = Counter()
    kinds: Counter = Counter()
    calls: list[tuple[float, float, bool]] = []
    n_call = [0] * K
    t = 0.0
    rounds = 0
    with McpServer() as srv:
        c = srv.client(lat)
        init_session(c, case, {"policy": case.doc}, targets_of(case), auto=False, lock="shared_premise")
        while True:
            rounds += 1
            if rounds > 600:
                raise RuntimeError("sync run did not converge")
            b = c.tool("sbgk_emit_batch", seats=K, k=k, round=rounds)
            work = [(s, f) for s, f in enumerate(b["frames"]) if not f["noop"]]
            if not work:
                if not b["complete"]:
                    raise RuntimeError("sync: no work but the compiler is not complete")
                break
            seen_t, seen_s = set(), set()
            plan = []
            for s, f in work:
                tg, sg = lease_resources(f)
                if tg & seen_t or sg & seen_s:
                    st["collisions"] += 1
                seen_t |= tg
                seen_s |= sg
                kinds[f["kind"]] += 1
                dur, hang = prof.draw(seed, s, n_call[s])
                n_call[s] += 1
                st["calls"] += 1
                eff = TTL_MS / 1000 if hang else dur  # the barrier gives a hung seat up after the TTL
                st["hung_calls"] += hang
                calls.append((t, eff, not hang))
                plan.append((s, f, hang))
            for s, f, hang in plan:
                if hang:
                    continue
                ev = orc.events(dict(f, local_id_prefix=f"s{s}r{rounds}_") if unique_prefix else f)
                r = c.tool("sbgk_apply_events", events=ev)
                st["events_accepted"] += r["accepted"]
                if r.get("error"):
                    st["rejected"] += 1
                    st["reject_" + r["error"]["code"]] += 1
                count_results(ev, r, dep_quotes, st)
            t += max(eff for (_, eff, _) in calls[-len(plan):])
        fin = c.tool("sbgk_swarm_status", now_ms=int(t * 1000))
    busy, useful = utilization(calls, K, t)
    return {"schedule": "sync_u" if unique_prefix else "sync", "K": K, "reject_codes": {k[7:]: v for k, v in st.items() if k.startswith("reject_")}, "makespan_s": t, "rounds": rounds - 1, "calls": st["calls"], "llm_calls_p2a": kinds.get("EMIT_DERIVE_ONLY", 0),
            "kinds": dict(kinds), "util": busy, "util_useful": useful, "auto_closed": 0, "takeovers": 0, "stale": 0,
            "collisions": st["collisions"], "leases": st["calls"], "repeats": st["repeats"], "rejected": st["rejected"], "hung_calls": st["hung_calls"],
            "dep_binds": st["dep_binds"], "dep_binds_repeat": st["dep_binds_repeat"], "extract_max_per_clause": None,
            "state_root": fin["state_root"], "goal_states": fin.get("goal_states"), "complete": fin.get("complete")}


# ------------------------------------------------------------------ async swarm in virtual time

class AsyncSim:
    """Discrete-event simulation of K workers on one live `sbgk mcp-serve`; the kernel decides everything (now_ms = virtual clock)."""

    def __init__(self, case, K: int, auto: bool, lock: str, prof: Profile, seed: int, k: int = 4, lat: Lat | None = None, dep_quotes: set | None = None):
        self.case, self.K, self.auto, self.lock, self.prof, self.seed, self.k = case, K, auto, lock, prof, seed, k
        self.lat = lat or Lat()
        self.dep_quotes = dep_quotes
        self.orc = X.Oracle(case)
        self.heap: list = []
        self.ctr = itertools.count()
        self.waiting: deque = deque()
        self.live: dict[str, dict] = {}
        self.n_call = [0] * K
        self.calls: list[tuple[float, float, bool]] = []
        self.st: Counter = Counter()
        self.kinds: Counter = Counter()
        self.ext_by_seg: Counter = Counter()
        self.complete_t: float | None = None
        self.wake_at: float | None = None

    def push(self, t: float, kind: str, w: int, payload=None) -> None:
        heapq.heappush(self.heap, (t, next(self.ctr), kind, w, payload))

    def acquire(self, t: float, w: int) -> str:
        r = self.cl[w].tool("sbgk_acquire_directive", agent_id=f"w{w}", ttl_ms=TTL_MS, k=self.k, now_ms=int(t))
        for lid in r.get("expired") or []:
            self.live.pop(lid, None)
        self.st["auto_closed"] += len(r.get("auto_closed") or [])
        s = r["status"]
        if s == "DIRECTIVE":
            fr = r["frame"]
            tg, sg = lease_resources(fr)
            if any((tg & x["targets"]) or (sg & x["segs"]) for x in self.live.values() if x["exp"] > t):
                self.st["collisions"] += 1
            self.st["takeovers"] += bool(r.get("takeover"))
            self.st["leases"] += 1
            self.kinds[fr["kind"]] += 1
            if fr["kind"] == "EXTRACT_PARTNER":
                for x in sg:
                    self.ext_by_seg[x] += 1
            dur, hang = self.prof.draw(self.seed, w, self.n_call[w])
            self.n_call[w] += 1
            self.st["calls"] += 1
            self.st["hung_calls"] += hang
            self.live[r["lease_id"]] = {"exp": r["expires_at_ms"], "targets": tg, "segs": sg}
            end = t + dur * 1000
            self.push(end, "submit", w, (r, dur, t))
            if not hang:  # a live worker sends heartbeats; a hung one does not
                tr = t + RENEW_S * 1000
                while tr < end:
                    self.push(tr, "renew", w, r["lease_id"])
                    tr += RENEW_S * 1000
        elif s == "WAIT_IN_FLIGHT":
            self.st["waits"] += 1
            self.waiting.append(w)
            self.schedule_wake(t)
        elif s == "COMPLETE":
            if self.complete_t is None:
                self.complete_t = t
        else:
            raise RuntimeError(f"acquire: {r}")
        return s

    def schedule_wake(self, t: float) -> None:
        """Parked workers are woken by every commit and at the next lease expiry (a hung worker's work comes back at its TTL)."""
        exps = [x["exp"] for x in self.live.values() if x["exp"] > t]
        if not exps:
            return
        nxt = min(exps)
        if self.wake_at is None or nxt < self.wake_at or self.wake_at <= t:
            self.wake_at = nxt
            self.push(nxt, "wake", -1)

    def wake_waiting(self, t: float) -> None:
        # once one parked worker gets WAIT_IN_FLIGHT, every other one would get it too (same state, same time): stop there
        n = len(self.waiting)
        for _ in range(n):
            if not self.waiting or self.complete_t is not None:
                return
            w = self.waiting.popleft()
            if self.acquire(t, w) != "DIRECTIVE":
                return

    def submit(self, t: float, w: int, payload) -> None:
        r, dur, t0 = payload
        ev = self.orc.events(r["frame"])
        res = self.cl[w].tool("sbgk_submit_directive", lease_id=r["lease_id"], agent_id=f"w{w}", events=ev, now_ms=int(t))
        self.live.pop(r["lease_id"], None)
        s = res["status"]
        if s == "COMMITTED":
            self.st["committed"] += 1
            self.st["auto_closed"] += len(res.get("auto_closed_derivations") or [])
            count_results(ev, res, self.dep_quotes, self.st)
            self.calls.append((t0 / 1000, dur, True))
        elif s == "STALE_LEASE":
            self.st["stale"] += 1
            self.st["stale_" + res["code"]] += 1
            self.calls.append((t0 / 1000, dur, False))
        else:
            raise RuntimeError(f"submit: {res}")
        self.wake_waiting(t)
        self.push(t, "acquire", w)

    def run(self) -> dict:
        with McpServer() as srv:
            self.cl = [srv.client(self.lat) for _ in range(self.K)]
            init_session(self.cl[0], self.case, {"policy": self.case.doc}, targets_of(self.case), auto=self.auto, lock=self.lock)
            for w in range(self.K):
                self.push(0.0, "acquire", w)
            guard = 0
            while self.heap:
                guard += 1
                if guard > 2_000_000:
                    raise RuntimeError("async run did not converge")
                t, _, kind, w, p = heapq.heappop(self.heap)
                if kind == "acquire":
                    if self.complete_t is None:
                        self.acquire(t, w)
                elif kind == "submit":
                    self.submit(t, w, p)
                elif kind == "renew":
                    if p in self.live:
                        r = self.cl[w].tool("sbgk_renew_lease", lease_id=p, agent_id=f"w{w}", ttl_ms=TTL_MS, now_ms=int(t))
                        if r["status"] == "RENEWED":
                            self.live[p]["exp"] = r["expires_at_ms"]
                            self.st["renewals"] += 1
                elif kind == "wake":
                    if self.wake_at == t:
                        self.wake_at = None
                    self.wake_waiting(t)
            if self.complete_t is None:
                raise RuntimeError(f"async run ended without COMPLETE ({self.st})")
            fin = self.cl[0].tool("sbgk_swarm_status", now_ms=int(self.complete_t) + 1)
        T = self.complete_t / 1000
        busy, useful = utilization(self.calls, self.K, T)
        st = self.st
        return {"schedule": "full" if self.auto else ("async" if self.lock == "shared_premise" else "async_target_only"), "lock": self.lock, "auto": self.auto,
                "K": self.K, "makespan_s": T, "calls": st["calls"], "llm_calls_p2a": self.kinds.get("EMIT_DERIVE_ONLY", 0), "kinds": dict(self.kinds),
                "util": busy, "util_useful": useful, "auto_closed": st["auto_closed"], "takeovers": st["takeovers"], "stale": st["stale"],
                "stale_codes": {k[6:]: v for k, v in st.items() if k.startswith("stale_")}, "collisions": st["collisions"], "leases": st["leases"],
                "repeats": st["repeats"], "rejected": 0, "hung_calls": st["hung_calls"], "waits": st["waits"], "renewals": st["renewals"],
                "dep_binds": st["dep_binds"], "dep_binds_repeat": st["dep_binds_repeat"],
                "extract_max_per_clause": max(self.ext_by_seg.values()) if self.ext_by_seg else 0, "extract_leases": sum(self.ext_by_seg.values()),
                "extract_clauses": len(self.ext_by_seg), "server": fin["stats"], "state_root": fin["state_root"], "goal_states": fin.get("goal_states"),
                "complete": fin.get("complete")}


def run_async(case, K, auto, lock, prof, seed, lat=None, dep_quotes=None) -> dict:
    return AsyncSim(case, K, auto, lock, prof, seed, lat=lat, dep_quotes=dep_quotes).run()


# ------------------------------------------------------------------ 10A

SCHEDULES_A = (("sync", None, None), ("sync_u", None, None), ("async", False, "shared_premise"), ("full", True, "shared_premise"))


def exp10a(cases: list[int], ks=K_LIST, log=print) -> dict:
    rows, lat_by_k = [], {}
    for idx in cases:
        case = case96(idx)
        seed = 10_000 + idx
        ref = None
        for K in ks:
            lat = Lat()
            for name, auto, lock in SCHEDULES_A:
                t0 = time.perf_counter()
                if name.startswith("sync"):
                    r = run_sync(case, K, PROFILE_A, seed, lat=lat, unique_prefix=name == "sync_u")
                else:
                    r = run_async(case, K, auto, lock, PROFILE_A, seed, lat=lat)
                r.update({"case": idx, "schedule": name, "harness_s": time.perf_counter() - t0})
                if ref is None:
                    ref = r["state_root"]  # reference: the first sync run of the case (K = 4)
                r["root_ok"] = r["state_root"] == ref
                rows.append(r)
                log(f"  10A case {idx} K={K:<3} {name:<6}: {r['makespan_s']:7.0f} s  calls {r['calls']:4}  P2A calls {r['llm_calls_p2a']:3}  "
                    f"auto {r['auto_closed']:3}  takeovers {r['takeovers']:2}  util {100 * r['util']:5.1f}%  collisions {r['collisions']}  root_ok {r['root_ok']}  "
                    f"({r['harness_s']:.1f} s)")
            lat_by_k[K] = lat_by_k.get(K, Lat())
            lat_by_k[K].merge(lat)
    return {"rows": rows, "latency_by_k": {str(K): v.summary() for K, v in lat_by_k.items()}, "profile": PROFILE_A.to_json(), "ttl_ms": TTL_MS,
            "renew_s": RENEW_S, "register": {"services": 96, "apis": 16}, "cases": cases}


# ------------------------------------------------------------------ 10A-RT: real concurrency

def run_realtime(case, K: int, auto: bool = True, lock: str = "shared_premise") -> dict:
    lat = Lat()
    with McpServer() as srv:
        cl = [srv.client(lat) for _ in range(K)]
        init_session(cl[0], case, {"policy": case.doc}, targets_of(case), auto=auto, lock=lock)
        cond = threading.Condition()
        live: dict[str, tuple[set, set]] = {}
        st: Counter = Counter()
        state = {"version": 0, "done": False}

        def worker(w: int) -> None:
            orc = X.Oracle(case)
            while True:
                r = cl[w].tool("sbgk_acquire_directive", agent_id=f"w{w}", ttl_ms=TTL_MS, k=4)
                s = r["status"]
                if s == "DIRECTIVE":
                    tg, sg = lease_resources(r["frame"])
                    with cond:
                        if any((tg & a) or (sg & b) for a, b in live.values()):
                            st["collisions"] += 1
                        live[r["lease_id"]] = (tg, sg)
                        st["leases"] += 1
                    ev = orc.events(r["frame"])
                    with cond:  # released before the submit is sent: the server still holds the lease until it has processed it
                        live.pop(r["lease_id"], None)
                    res = cl[w].tool("sbgk_submit_directive", lease_id=r["lease_id"], agent_id=f"w{w}", events=ev)
                    with cond:
                        st[res["status"]] += 1
                        state["version"] += 1
                        cond.notify_all()
                elif s == "WAIT_IN_FLIGHT":
                    with cond:
                        v = state["version"]
                        cond.wait_for(lambda: state["version"] != v or state["done"], timeout=0.05)
                        if state["done"]:
                            return
                elif s == "COMPLETE":
                    with cond:
                        state["done"] = True
                        cond.notify_all()
                    return
                else:
                    raise RuntimeError(f"realtime acquire: {r}")

        t0 = time.perf_counter()
        with cf.ThreadPoolExecutor(max_workers=K) as ex:
            list(ex.map(worker, range(K)))
        wall = time.perf_counter() - t0
        fin = cl[0].tool("sbgk_swarm_status")
    return {"K": K, "wall_s": wall, "leases": st["leases"], "committed": st["COMMITTED"], "collisions": st["collisions"],
            "leases_per_s": st["leases"] / wall if wall else 0.0, "state_root": fin["state_root"], "server": fin["stats"], "latency": lat.summary()}


def exp10a_rt(idx: int = 0, ks=(16, 64, 100), ref_root: str | None = None, log=print) -> dict:
    case = case96(idx)
    rows = []
    for K in ks:
        r = run_realtime(case, K)
        r["root_ok"] = ref_root is None or r["state_root"] == ref_root
        rows.append(r)
        acq = r["latency"].get("sbgk_acquire_directive", {})
        log(f"  10A-RT K={K:<3}: {r['wall_s']:.2f} s wall, {r['leases']} leases ({r['leases_per_s']:.0f}/s), collisions {r['collisions']}, "
            f"acquire rtt p50/p95 {acq.get('rtt_p50', 0):.0f}/{acq.get('rtt_p95', 0):.0f} us, root_ok {r['root_ok']}")
    return {"case": idx, "rows": rows}


# ------------------------------------------------------------------ 10B

DISPATCHERS_B = (("target_only", False, "target_only"), ("premise_lock", False, "shared_premise"), ("full", True, "shared_premise"))


def exp10b(cases: list[int], K: int = 60, log=print) -> dict:
    rows = []
    lat = Lat()
    for idx in cases:
        case = FanInCase(idx)
        seed = 10_600 + idx
        ref = run_sync(case, 4, PROFILE_B, seed, dep_quotes=case.dep_quotes)["state_root"]
        for name, auto, lock in DISPATCHERS_B:
            t0 = time.perf_counter()
            r = run_async(case, K, auto, lock, PROFILE_B, seed, lat=lat, dep_quotes=case.dep_quotes)
            r.update({"case": idx, "dispatcher": name, "root_ok": r["state_root"] == ref, "harness_s": time.perf_counter() - t0,
                      "dep_clauses": len(case.dep_quotes), "services": case.targets})
            r["dep_dup_share"] = (r["dep_binds"] - len(case.dep_quotes)) / r["dep_binds"] if r["dep_binds"] else 0.0
            rows.append(r)
            log(f"  10B case {idx} {name:<12}: EXTRACT leases {r['extract_leases']:3} (max/clause {r['extract_max_per_clause']:2})  D-binds {r['dep_binds']:3} "
                f"(dup {100 * r['dep_dup_share']:4.1f}%)  calls {r['calls']:3}  P2A calls {r['llm_calls_p2a']:3}  auto {r['auto_closed']:3}  "
                f"{r['makespan_s']:5.0f} s  collisions {r['collisions']}  root_ok {r['root_ok']}")
    return {"rows": rows, "K": K, "latency": lat.summary(), "profile": PROFILE_B.to_json()}


# ------------------------------------------------------------------ guard probes (deterministic)

def guard_probes(idx: int = 0, log=print) -> dict:
    """Scope guard and stale-lease checks on a 10C case, driven by the oracle worker; afterwards the swarm is played to the end."""
    case = case_c(idx)
    orc = X.Oracle(case)
    p_api = case.p_api
    p_svcs = {f"svc_{i:03d}" for i in case.p_services}
    w_svc = f"svc_{case.role['w']:03d}"
    probes = []
    now = itertools.count(1000, 10)

    def probe(name, expect, got, detail=""):
        probes.append({"probe": name, "expected": expect, "got": got, "ok": got == expect, "detail": detail})
        log(f"  guard {name:<34} expected {str(expect):<30} got {got}")

    with McpServer() as srv:
        c = srv.client()
        init_session(c, case, {"policy": case.doc}, targets_of(case), auto=True, lock="shared_premise")
        acq = lambda agent, ttl=TTL_MS: c.tool("sbgk_acquire_directive", agent_id=agent, ttl_ms=ttl, k=4, now_ms=next(now))  # noqa: E731
        sub = lambda r, ev: c.tool("sbgk_submit_directive", lease_id=r["lease_id"], agent_id=r["agent_id"], events=ev, now_ms=next(now))  # noqa: E731
        # 1. a quote from outside the frame's slice
        l1 = acq("probe")
        other = next(t for t in case.quote.values() if t not in {x["text"] for x in l1["frame"]["chunk_slice"]})
        r = sub(l1, [{"op": "bind_evidence", "local_id": "x_e1", "doc_id": "policy", "exact_quote": other}])
        probe("foreign quote", "DIRECTIVE_VIOLATION", r.get("error", {}).get("code"), r["status"])
        ok = sub(l1, orc.events(l1["frame"]))
        bound = next((x["node"] for x in ok.get("results", []) if x.get("op") == "bind_evidence"), None)
        # 2. a revocation the directive does not list (the evidence exists: it was bound just now)
        l2 = acq("probe")
        r = sub(l2, [{"op": "revoke_evidence", "target_evidence": f"@{bound}"}])
        probe("unlisted revoke_evidence", "DIRECTIVE_VIOLATION", r.get("error", {}).get("code"), r["status"])
        sub(l2, orc.events(l2["frame"]))
        # 3. a hung worker: TTL expiry, takeover, refused late answer
        z = acq("hung", ttl=1)
        tk = acq("other")
        r = sub(z, orc.events(z["frame"]))
        probe("late answer of an expired lease", "LEASE_EXPIRED_OR_UNKNOWN", r.get("code"), f"takeover={tk.get('takeover')}")
        sub(tk, orc.events(tk["frame"]))
        # drive until we hold (P) a FORMALIZE of a p-service built on the D.p fact and (W) a FORMALIZE of the withdrawn U.w clause
        held_p = held_w = None
        for _ in range(400):
            if held_p and held_w:
                break
            r = acq("drv")
            if r["status"] != "DIRECTIVE":
                break
            fr = r["frame"]
            if held_p is None and fr["kind"] == "FORMALIZE" and set(fr["targets"]) & p_svcs and r["contract"]["required_premises"]:
                held_p = r
                continue
            if held_w is None and fr["kind"] == "FORMALIZE" and w_svc in fr["targets"]:
                held_w = r
                continue
            sub(r, orc.events(fr))
        if held_p is None or held_w is None:
            raise RuntimeError("guard: could not set up the stale-lease probes")
        # was the withdrawn clause D.p itself bound (read from the kernel), or only its restatement R.p, which the erratum keeps?
        before, _ = snapshot_full(c, OUT / "work_guard")
        trigger_bound = any(e["quote"] == case.trigger_quote for e in before["evidence"])
        c.tool("sbgk_post_erratum", doc_id="erratum", erratum_text=case.erratum.decode("utf-8"), now_ms=next(now))
        # P0 first: revoke the withdrawn evidence (only the revocations of each P0 lease; the resupport is left open for now)
        for _ in range(20):
            r = acq("drv")
            if r["status"] != "DIRECTIVE" or r["frame"]["priority"] != "P0_ResolvePolarConflict":
                if r["status"] == "DIRECTIVE":
                    c.tool("sbgk_release_lease", lease_id=r["lease_id"], agent_id="drv", now_ms=next(now))
                break
            sub(r, [e for e in orc.events(r["frame"]) if e["op"] == "revoke_evidence"])
        r = sub(held_p, orc.events(held_p["frame"]))
        # if the premise was extracted from the restatement R.p, the erratum leaves it SUPPORTED and the lease is rightly accepted
        probe("premise revoked by the erratum", "STALE_LEASE_PREMISE_REVOKED" if trigger_bound else "COMMITTED", r.get("code") or r.get("status"),
              f"api_{p_api:03d}, premise from {'D' if trigger_bound else 'R (restatement, kept by the erratum)'}.{p_api}")
        r = sub(held_w, orc.events(held_w["frame"]))
        probe("clause withdrawn by the erratum", "STALE_LEASE_SEGMENT_WITHDRAWN", r.get("code"), w_svc)
        # the swarm still converges to the right answer
        for _ in range(400):
            r = acq("drv")
            if r["status"] != "DIRECTIVE":
                break
            sub(r, orc.events(r["frame"]))
        full, _ = snapshot_full(c, OUT / "work_guard")
        ev = case.evaluate(full)
        stats = c.tool("sbgk_swarm_status", now_ms=next(now))["stats"]
    shutil.rmtree(OUT / "work_guard", ignore_errors=True)
    probe("goal after the probes", True, ev["goal"], f"done {ev['done']}/{case.targets}, false {ev['false']}")
    return {"case": idx, "probes": probes, "all_ok": all(p["ok"] for p in probes), "stats": stats, "final": ev}


# ------------------------------------------------------------------ 10C: live models

REPLAY_LATENCY = True  # 10C: answers taken from the call cache are delayed by the recorded model latency (runs resumed after a quota stop)


class SharedCache:
    """A cached EXP-8/9 backend whose lookups also see EXP-9's call cache (same key: backend + model + prompt); new calls go to EXP-10's."""

    def __init__(self, be):
        self.be = be
        self.name, self.label = be.name, be.label
        self.version = getattr(be, "version", "")
        self.exact_tokens = be.exact_tokens

    def call(self, prompt: str, tag: str = "") -> dict:
        f = CALLS9 / f"{self.be._key(prompt)}.json"
        r = None
        if f.exists():
            try:
                r = json.loads(f.read_text(encoding="utf-8"))
                r["from_cache"] = True
                r["from_exp9_cache"] = True
            except ValueError:
                r = None
        if r is None:
            r = self.be.call(prompt, tag)
        if REPLAY_LATENCY and r.get("from_cache"):
            # a cached answer arrives after the model's recorded latency, so the schedule and the run's wall time stay those of a live run
            time.sleep(float(r.get("seconds") or 0.0))
        return r


def make_backends(team) -> dict:
    return {b: SharedCache(R8.make_backend(b)) for b in sorted(set(team))}


ERRATUM_AFTER = 12  # commits after which the erratum is published once the trigger clause is bound ...
ERRATUM_LATEST = 20  # ... or at the latest (or when the compiler reports COMPLETE earlier)
LEASE_CAP = 60


PACK_LIVE = True  # 10C: a lease is topped up with further whole free targets while its event budget lasts (as a round's seat is)


def run_async_live(case, backends: dict, overhead: dict, wd: pathlib.Path, ttl_ms: int = 900_000, k: int = 4) -> dict:
    spec = case.spec
    team = spec.team
    labels = E.seat_labels(team)
    K = len(team)
    lat = Lat()
    recs: list[dict] = []
    st: Counter = Counter()
    cond = threading.Condition()
    state = {"version": 0, "commits": 0, "posted": False, "posted_at": None, "trigger": False, "done": False, "error": None, "stop": None}
    live: dict[str, tuple[set, set]] = {}
    t_start = time.time()
    srv = McpServer()
    try:
        cl = [srv.client(lat) for _ in range(K)]
        ctl = srv.client(lat)
        init_session(ctl, case, {"policy": case.doc}, targets_of(case), auto=True, lock="shared_premise", pack=PACK_LIVE)

        def post_erratum() -> None:  # under cond
            if state["posted"]:
                return
            r = ctl.tool("sbgk_post_erratum", doc_id="erratum", erratum_text=case.erratum.decode("utf-8"))
            state.update(posted=True, posted_at=state["commits"], erratum_put=r)
            state["version"] += 1
            cond.notify_all()

        def worker(w: int) -> None:
            be, label = backends[team[w]], labels[w]
            n = 0
            while True:
                with cond:
                    if state["done"]:
                        return
                    posted_before = state["posted"]
                r = cl[w].tool("sbgk_acquire_directive", agent_id=label, ttl_ms=ttl_ms, k=k)
                s = r["status"]
                if s == "COMPLETE":
                    with cond:
                        # only a COMPLETE asked for after the erratum was published ends the run (an older one did not see it)
                        if posted_before:
                            state["done"] = True
                            cond.notify_all()
                            return
                        post_erratum()
                    continue
                if s == "WAIT_IN_FLIGHT":
                    with cond:
                        v = state["version"]
                        cond.wait_for(lambda: state["version"] != v or state["done"], timeout=5)
                    continue
                if s != "DIRECTIVE":
                    raise RuntimeError(f"acquire: {str(r)[:300]}")
                fr = r["frame"]
                tg, sg = lease_resources(fr)
                with cond:
                    overlap = [lid for lid, (a, b) in live.items() if (tg & a) or (sg & b)]
                    live[r["lease_id"]] = (tg, sg)
                    st["leases"] += 1
                    over_cap = st["leases"] > LEASE_CAP
                if overlap:  # a worker drops its lease from `live` only after the submit answer: ask the server whether it is still open
                    open_ids = {x.get("lease_id") for x in cl[w].tool("sbgk_swarm_status").get("leases") or []}
                    with cond:
                        st["collisions_client_view"] = st.get("collisions_client_view", 0) + 1
                        if open_ids & set(overlap):
                            st["collisions"] += 1
                if over_cap:
                    cl[w].tool("sbgk_release_lease", lease_id=r["lease_id"], agent_id=label)
                    with cond:
                        state["stop"] = "cap"
                        state["done"] = True
                        cond.notify_all()
                    return
                n += 1
                tag = f"{spec.name}-c{case.idx}-swarm-{r['lease_id']}-{label}"
                rec = {"lease_id": r["lease_id"], "agent": label, "backend": team[w], "kind": fr["kind"], "priority": fr["priority"], "target": fr["target"],
                       "prompt_chars": fr["prompt_chars"], "in_tokens": 0, "in_net": 0, "out_tokens": 0, "cost_usd": 0.0, "seconds": 0.0, "from_cache": False,
                       "accepted": 0, "rejected": 0, "repeats": 0, "reject_codes": [], "repair_call": False, "repair_ok": None, "status": None,
                       "auto_closed": 0, "t_issue": time.time() - t_start}

                def call(prompt: str, suffix: str = "") -> dict:
                    try:
                        out = be.call(prompt, tag + suffix)
                    except Exception as e:  # noqa: BLE001 - the run is aborted and redone from the call cache
                        cl[w].tool("sbgk_release_lease", lease_id=r["lease_id"], agent_id=label)
                        raise RuntimeError(f"model call failed ({tag}{suffix}): {str(e)[:300]}") from e
                    rec["in_tokens"] += out["in_tokens"]
                    rec["in_net"] += max(0, out["in_tokens"] - overhead.get(team[w], 0))
                    rec["out_tokens"] += out["out_tokens"]
                    rec["cost_usd"] += out.get("cost_usd") or 0.0
                    rec["seconds"] += out.get("seconds", 0.0)
                    rec["from_cache"] = rec["from_cache"] or bool(out.get("from_cache"))
                    return out

                out = call(fr["prompt"])
                events, _ = parse_turn(out["text"], False)
                res = cl[w].tool("sbgk_submit_directive", lease_id=r["lease_id"], agent_id=label, events=events)
                outcomes = [(events, res)]
                if res["status"] == "REPAIR_REQUIRED":
                    rec["repair_call"] = True
                    prompt2 = fr["prompt"] + X.REPAIR_NOTE.format(prev=out["text"].strip()[:2500], n=res["failed_index"] + 1,
                                                                  err=json.dumps(res["error"], ensure_ascii=False)[:600])
                    out2 = call(prompt2, "-repair")
                    events2, _ = parse_turn(out2["text"], False)
                    res2 = cl[w].tool("sbgk_submit_directive", lease_id=r["lease_id"], agent_id=label, events=events2)
                    rec["repair_ok"] = res2["status"] == "COMMITTED"
                    outcomes.append((events2, res2))
                trig = False
                for evs, rs in outcomes:
                    rec["accepted"] += len(rs.get("results") or [])
                    for e, x in zip(evs, rs.get("results") or []):
                        rec["repeats"] += 1 if x.get("existed") and fr["kind"] not in ("RESUPPORT_FROM_RESTATEMENT", "REPAIR_UNSUPPORTED") else 0
                        if e.get("op") == "bind_evidence" and e.get("exact_quote") == case.trigger_quote:
                            trig = True
                    if rs.get("error"):
                        rec["rejected"] += 1
                        rec["reject_codes"].append(rs["error"].get("code"))
                    if rs.get("code"):
                        rec["reject_codes"].append(rs["code"])
                    rec["auto_closed"] += len(rs.get("auto_closed_derivations") or [])
                final = outcomes[-1][1]
                rec["status"] = final["status"]
                rec["t_done"] = time.time() - t_start
                with cond:
                    live.pop(r["lease_id"], None)
                    recs.append(rec)
                    if final["status"] in ("COMMITTED", "LEASE_CLOSED"):
                        state["commits"] += 1
                    state["trigger"] = state["trigger"] or trig
                    if not state["posted"] and ((state["commits"] >= ERRATUM_AFTER and state["trigger"]) or state["commits"] >= ERRATUM_LATEST):
                        post_erratum()
                    state["version"] += 1
                    cond.notify_all()

        with cf.ThreadPoolExecutor(max_workers=K) as ex:
            futs = [ex.submit(worker, w) for w in range(K)]
            for f in futs:
                try:
                    f.result()
                except Exception as e:  # noqa: BLE001
                    with cond:
                        state["error"] = state["error"] or str(e)[:400]
                        state["done"] = True
                        cond.notify_all()
        if state["error"]:
            raise RuntimeError(state["error"])
        full, snap = snapshot_full(ctl, wd / f"c{case.idx}_swarm")
        fin = ctl.tool("sbgk_swarm_status")
    finally:
        srv.close()
        shutil.rmtree(wd / f"c{case.idx}_swarm", ignore_errors=True)
    ev = case.evaluate(full)
    sm = lambda key: sum(x[key] or 0 for x in recs)  # noqa: E731
    stats = fin["stats"]
    return {
        "scenario": spec.name, "case": case.idx, "mode": "swarm", "version": VERSION, "completed": bool(ev["goal"] and state["posted"]),
        "stop_reason": state["stop"] or "complete", "targets": case.targets, "targets_done": ev["done"], "false_final": ev["false"],
        "stale_final": ev["stale"], "under_conflict_final": ev["under_conflict"], "withdrawn_active_final": ev["withdrawn_active"],
        "conflicting_final": ev["conflicting"], "wrong_facts": ev["wrong_facts"], "x_ok": ev["x_ok"], "p_ok": ev["p_ok"],
        "calls": len(recs) + sum(1 for x in recs if x["repair_call"]), "leases": len(recs), "repair_calls": sum(1 for x in recs if x["repair_call"]),
        "repair_ok": sum(1 for x in recs if x["repair_ok"]), "accepted": sm("accepted"), "rejected": sm("rejected"), "repeats": sm("repeats"),
        "reject_codes": dict(Counter(c for x in recs for c in x["reject_codes"])), "in_tokens": sm("in_tokens"), "in_net": sm("in_net"),
        "out_tokens": sm("out_tokens"), "cost_usd": sm("cost_usd"), "seconds": sm("seconds"), "from_cache": sum(1 for x in recs if x["from_cache"]),
        "wall_s": time.time() - t_start, "collisions": st["collisions"], "collisions_client_view": st.get("collisions_client_view", 0), "kinds": dict(Counter(x["kind"] for x in recs)),
        "llm_calls_p2a": sum(1 for x in recs if x["kind"] == "EMIT_DERIVE_ONLY"), "auto_closed": stats["auto_closed_total"],
        "directive_violations": stats["directive_violations"], "stale_leases": stats["stale_premise"] + stats["stale_segment"] + stats["stale_unknown"],
        "erratum_after_commits": state["posted_at"], "server": stats, "latency": lat.summary(), "state_root": fin["state_root"],
        "goal_states": fin.get("goal_states"), "recs": recs,
    }


def run_sync_live(case, backends: dict, overhead: dict, wd: pathlib.Path) -> dict:
    """The EXP-9B baseline: synchronous directive rounds through the EXP-9 harness (resident `serve`, unchanged)."""
    res = X.run_directive(case, backends, overhead, wd, first=case.idx % len(case.spec.team), oracle=False)
    res["mode"] = "sync"
    res["llm_calls_p2a"] = sum(1 for s in res["step_log"] for x in s["recs"] if x["kind"] == "EMIT_DERIVE_ONLY")
    res["critical_path_s"] = sum(max((x["seconds"] for x in s["recs"]), default=0.0) for s in res["step_log"])
    res["repeats"] = (res.get("repeat_partner") or 0) + (res.get("repeat_self") or 0)
    res["collisions"] = res.get("repeat_unavoidable") or 0  # in-round repeats between seats (emit_batch shards targets and sentences)
    return res


def exp10c(n_cases: int, workers: int = 2, fresh: bool = False, oracle_check: bool = True, log=print) -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    RUNS.mkdir(parents=True, exist_ok=True)
    global REPLAY_LATENCY
    backends = make_backends(SPEC_C.team)
    replay, REPLAY_LATENCY = REPLAY_LATENCY, False  # the overhead probes are not part of any schedule
    try:
        overhead = R8.calibrate(backends)
    finally:
        REPLAY_LATENCY = replay
    wd = OUT / "work_c"
    cases = [case_c(i) for i in range(n_cases)]
    jobs = [(c, m) for c in cases for m in ("sync", "swarm")]

    def job(j):
        c, m = j
        f = RUNS / f"c_swarm_c{c.idx}_{m}.json"
        if f.exists() and not fresh:
            res = json.loads(f.read_text(encoding="utf-8"))
            if not res.get("error"):
                return res
        t0 = time.time()
        try:
            res = run_sync_live(c, backends, overhead, wd) if m == "sync" else run_async_live(c, backends, overhead, wd)
        except Exception as e:  # noqa: BLE001 - reported; redone later from the call cache
            res = {"scenario": SPEC_C.name, "case": c.idx, "mode": m, "error": str(e)[:400], "completed": False}
        res["wall_s"] = res.get("wall_s", time.time() - t0)
        if not res.get("error"):
            f.write_text(json.dumps(res, ensure_ascii=False), encoding="utf-8")
        log(f"  10C case {c.idx} {m:<5}: completed={res.get('completed')} done={res.get('targets_done')}/{c.targets} calls={res.get('calls')} "
            f"P2A calls={res.get('llm_calls_p2a')} auto={res.get('auto_closed', 0)} in={res.get('in_tokens')} out={res.get('out_tokens')} "
            f"${res.get('cost_usd', 0) or 0:.2f} wall {res.get('wall_s', 0):.0f}s {('ERROR ' + res['error']) if res.get('error') else ''}")
        return res

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(job, jobs))
    shutil.rmtree(wd, ignore_errors=True)
    out = {"spec": {k: (list(v) if isinstance(v, tuple) else v) for k, v in SPEC_C.__dict__.items()}, "seed_base": SEED_C,
           "backends": {b: {"label": be.label, "version": be.version, "tokens_estimated": not be.exact_tokens} for b, be in backends.items()},
           "overhead_in_tokens": overhead, "results": results, "erratum_rule": {"after_commits_if_trigger_bound": ERRATUM_AFTER, "latest": ERRATUM_LATEST},
           "case_info": [{"idx": c.idx, "targets": c.targets, "seed": c.seed, "doc_bytes": len(c.doc)} for c in cases]}
    if oracle_check:
        out["oracle_swarm"] = [oracle_live_check(c) for c in cases]
    return out


def oracle_live_check(case) -> dict:
    """The 10C swarm loop with the oracle worker instead of models (no calls): the harness, the erratum rule and the kernel converge."""
    frames: dict[str, dict] = {}
    orc = X.Oracle(case)

    class OracleBackend:
        exact_tokens = True

        def __init__(self, name: str):
            self.name, self.label, self.version = name, "oracle", ""

        def call(self, prompt: str, tag: str = "") -> dict:
            fr = frames.get(prompt)
            text = "\n".join(json.dumps(e, separators=(",", ":")) for e in orc.events(fr)) if fr else ""
            return {"text": text or "\n", "in_tokens": len(prompt) // 4, "out_tokens": len(text) // 4, "cost_usd": 0.0, "seconds": 0.0}

    orig = McpClient.tool

    def tool(self, name, **args):  # remember every frame by its prompt, so the oracle can answer the prompt
        out = orig(self, name, **args)
        if name == "sbgk_acquire_directive" and out.get("status") == "DIRECTIVE":
            frames[out["frame"]["prompt"]] = out["frame"]
        return out

    McpClient.tool = tool
    try:
        r = run_async_live(case, {b: OracleBackend(b) for b in set(case.spec.team)}, {}, OUT / "work_c_oracle")
    finally:
        McpClient.tool = orig
    return {"case": case.idx, "completed": r["completed"], "targets_done": r["targets_done"], "false_final": r["false_final"],
            "withdrawn_active_final": r["withdrawn_active_final"], "leases": r["leases"], "auto_closed": r["auto_closed"], "collisions": r["collisions"],
            "collisions_client_view": r["collisions_client_view"], "llm_calls_p2a": r["llm_calls_p2a"], "erratum_after_commits": r["erratum_after_commits"]}


# ------------------------------------------------------------------ machine info

def machine() -> dict:
    from . import exp9_speed
    return {"cpu": exp9_speed.cpu_name(), "python": platform.python_version(), "binary_sha256": hashlib.sha256(C.BIN.read_bytes()).hexdigest()[:16],
            "created": time.strftime("%Y-%m-%d %H:%M:%S")}
