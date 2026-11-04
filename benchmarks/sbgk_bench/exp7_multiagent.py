"""EXP-7: a multi-agent environment where agents exchange reasoning through the compiler.

Several heterogeneous agents (Codex gpt-5.6-sol, DeepSeek via OpenClaw, Claude Opus 5.5) work on ONE shared task.
Nobody is assigned a share of the work; every turn an agent emits at most K atomic events (strict JSON). The events go
into one shared kernel session (the "compiler"), which validates and canonicalises them. The only thing that differs
between the arms is what an agent can SEE of the team's work at the start of its turn:

  iso    nothing about the others                                      -> baseline for inherent redundancy
  prose  partner messages in natural language                          -> ordinary multi-agent chat
  raw    the partner's raw event log (JSONL as emitted, with verdicts) -> structured but uncompiled
  graph  the compiled graph read back from the kernel's byte container -> the proposed mechanism
In every arm an agent also sees its OWN earlier events with the kernel's verdicts (an agent remembers what it did).

The kernel measures repetition deterministically: an accepted event that names a node (evidence or claim) that already
exists is a repeated step, whatever the surface form (aliases, local names, argument order). Who created the node first is
tracked, so repetition of a partner's step can be told from repetition of one's own step, in both directions.
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import random
import re
import shutil
import subprocess
import time
import pathlib
from collections import defaultdict

from . import agents as AG
from . import common as C

OUT = C.RESULTS / "exp7"
MODES = ["iso", "prose", "raw", "graph"]
TEAMS = [("codex", "deepseek"), ("codex", "opus"), ("deepseek", "opus"), ("codex", "deepseek", "opus")]
SEAT_TAGS = ["a", "b", "c"]
K_EVENTS = 5
MAX_TURNS = 12


# ------------------------------------------------------------------ case generator

class Case:
    """Twelve services, seven APIs; some APIs are deprecated in a window that overlaps usage (gold), one only later (trap)."""

    def __init__(self, idx: int, seed: int):
        rng = random.Random(seed)
        self.idx = idx
        S, A = 12, 7
        for _ in range(200):
            order = list(range(A))
            rng.shuffle(order)
            active, trap = set(order[:3]), order[3]
            api_of = [rng.randrange(A) for _ in range(S)]
            gold = [i for i in range(S) if api_of[i] in active]
            if 5 <= len(gold) <= 7 and trap in api_of and all(a in api_of for a in active):
                break
        self.S, self.A = S, A
        self.api_of, self.active, self.trap = api_of, active, trap
        self.use_t = [(rng.choice([100, 110, 120]), rng.choice([200, 210, 220])) for _ in range(S)]
        self.dep_t = {a: ((150, 300) if a in active else (300, 400)) for a in list(active) + [trap]}
        self.onto = C.ontology_review(S, A)
        fact_sents = []
        self.use_sent, self.dep_sent = {}, {}
        for i in range(S):
            lo, hi = self.use_t[i]
            s = f"Clause U.{i}: service svc_{i:03d} shall call interface api_{api_of[i]:03d} in production from t={lo} until t={hi}."
            self.use_sent[i] = s
            fact_sents.append(s)
        for a, (lo, hi) in sorted(self.dep_t.items()):
            s = f"Clause D.{a}: interface api_{a:03d} is deprecated in production from t={lo} until t={hi}."
            self.dep_sent[a] = s
            fact_sents.append(s)
        rng.shuffle(fact_sents)
        paras = []
        for k in range(0, len(fact_sents), 2):
            paras.append(" ".join([C.filler_sentence(rng)] + fact_sents[k:k + 2] + [C.filler_sentence(rng)]))
        self.doc = C.join_doc(paras)
        # gold
        self.gold_services = gold
        self.gold_targets = {f"svc_{i:03d}": C.intersect(self.use_t[i], self.dep_t[api_of[i]]) for i in gold}
        self.gold_facts = {(f"svc_{i:03d}", "uses_api", f"api_{api_of[i]:03d}", self.use_t[i]) for i in range(S)}
        self.gold_facts |= {(f"api_{a:03d}", "api_deprecated", "true", t) for a, t in self.dep_t.items()}

    def task_text(self) -> str:
        return ("Find every service that NEEDS REVIEW. A service needs review when the API it calls is deprecated during a time window that "
                "overlaps the service's own usage window (rule R_depr_review@1 combines uses_api and api_deprecated). Establish the supporting "
                "facts, each backed by a quoted clause, and derive needs_review for every such service. The team is finished when every service "
                "that needs review has its needs_review conclusion in the kernel. For services whose API is not deprecated in an overlapping "
                "window, derive nothing. The document may state clauses in any order.")


# ------------------------------------------------------------------ kernel session

class Kernel:
    def __init__(self, onto: pathlib.Path, docdir: pathlib.Path):
        self.p = subprocess.Popen([str(C.BIN), "serve", "--ontology", str(onto), "--docs", str(docdir), "--ack", "full"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1)
        self.next_seq = 1

    def _rt(self, obj: dict) -> dict:
        self.p.stdin.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def send(self, ev: dict) -> dict:
        body = {k: v for k, v in ev.items() if k != "seq"}
        resp = self._rt({"seq": self.next_seq, **body})
        if resp.get("status") == "ok":
            self.next_seq += 1
        return resp

    def snapshot(self, path) -> dict:
        return self._rt({"op": "snapshot", "out": str(path)})

    def close(self):
        try:
            self.p.stdin.close()
        finally:
            self.p.wait(timeout=10)


# ------------------------------------------------------------------ views (what an agent can see)

def render_graph(container) -> str:
    out = subprocess.run([str(C.BIN), "view", str(container)], capture_output=True, text=True, encoding="utf-8")
    g = json.loads(out.stdout)
    ev = {e["id"]: e for e in g["evidence"]}
    steps_of = defaultdict(list)
    asserted_ev = set()
    for s in g["steps"]:
        steps_of[s["claim"]].append(s)
        if s["kind"] == "assertion":
            asserted_ev.add(s["evidence"])
    lines = ["EVIDENCE already bound (quotes from the document):"]
    for e in sorted(g["evidence"], key=lambda x: x["quote"]):
        mark = "" if e["id"] in asserted_ev else "   [bound but no fact asserted from it yet]"
        lines.append(f'  @{e["id"]}  "{e["quote"]}"{mark}')
    if not g["evidence"]:
        lines.append("  (none)")
    lines.append("FACTS AND CONCLUSIONS established (canonical, duplicates merged):")
    claims = sorted(g["claims"], key=lambda c: (c["p"], c["s"], c["o"]))
    for c in claims:
        why = []
        for s in steps_of[c["id"]]:
            if s["kind"] == "assertion":
                why.append(f'evidence @{s["evidence"]}')
            else:
                why.append(f'{s["rule"]}(' + ", ".join("@" + p for p in s["premises"]) + ")")
        lines.append(f'  @{c["id"]}  {c["p"]}({c["s"]}, {c["o"]}) t=[{c["t"][0]},{c["t"][1]}) {c["st"]}  <- ' + " | ".join(why))
    if not claims:
        lines.append("  (none)")
    return "\n".join(lines)


def fmt_verdict(item: dict) -> str:
    r = item["resp"]
    if item.get("unsent"):
        return "NOT SENT (an earlier event this turn was rejected)"
    if r.get("status") == "ok":
        return "ok" + (" (already existed - repeated step)" if r.get("existed") else "")
    e = {k: r.get(k) for k in ("code", "field", "message", "expected_by_kernel", "obligation") if r.get(k) not in (None, "")}
    return "REJECTED " + json.dumps(e, ensure_ascii=False)


def event_line(ev) -> str:
    return json.dumps(ev, separators=(",", ":"), ensure_ascii=False) if isinstance(ev, dict) else str(ev)


def own_history(items: list[dict], limit: int | None = None) -> str:
    if not items:
        return "  (nothing yet)"
    note = ""
    if limit and len(items) > limit:
        note = f"  ({len(items) - limit} older events omitted; they were accepted unless marked otherwise)\n"
        items = items[-limit:]
    return note + "\n".join(f"  [turn {it['turn']}] {event_line(it['ev'])}   -> {fmt_verdict(it)}" for it in items)


# ------------------------------------------------------------------ prompts

BRIEF = """You are agent "{tag}" in a team of {n} AI agents working on ONE shared task. Nobody has been assigned a share of the work.
You never talk to your partners directly. The team's work lives in a deterministic kernel (a "compiler"): you write atomic events as strict
JSON, the kernel validates them (it checks every quote against the document bytes, resolves entity names, computes derived values) and stores them.
Your turn ends after your events; then a partner takes a turn, and so on until the task is complete.

TEAM OBJECTIVE: finish in as few turns as possible. Do NOT redo a step that is already established or that a partner has already done - spend
your turn on steps nobody has done yet. Because turns are limited, repeating work only slows the whole team down.

TASK: {task}

ONTOLOGY (JSON): {onto}

DOCUMENT "policy":
<<<
{doc}>>>

EVENT FORMAT - one strict JSON object per line, WITHOUT "seq" (the kernel numbers events). Context is always "prod", polarity "POS":
{{"op":"bind_evidence","local_id":"{tag}_e1","doc_id":"policy","exact_quote":"<byte-exact text copied from the document; one whole clause sentence is ideal>"}}
{{"op":"assert_fact","local_id":"{tag}_f1","s":"svc_003","p":"uses_api","o":"api_002","polarity":"POS","ctx":"prod","t":[100,200],"evidence":["{tag}_e1"]}}
{{"op":"assert_fact","local_id":"{tag}_f2","s":"api_002","p":"api_deprecated","o":"true","polarity":"POS","ctx":"prod","t":[150,300],"evidence":["{tag}_e2"]}}
{{"op":"derive","local_id":"{tag}_r1","rule":"R_depr_review@1","premises":["{tag}_f1","{tag}_f2"]}}
(derive: the kernel computes the conclusion and its interval itself, so "claim" is optional.)
References ("evidence" and "premises" entries) are: a local_id you created yourself - always prefix the local_ids you create with "{tag}_" -{refs_extra}

RULES OF YOUR TURN: at most {k} events. The kernel processes them in order and STOPS at the first rejected event; the rest are discarded.
Output only the events, one JSON object per line, no code fences, no commentary.{message_rule}
"""

MESSAGE_RULE = ('\nAfter the events add ONE final line starting with "MESSAGE:" (at most 60 words) telling your partners what you established '
                '(mention the local_ids you created) and what remains to be done.')


def refs_extra(mode: str) -> str:
    return {
        "iso": " you cannot reference anything created by others.",
        "prose": " or an id a partner told you about in a message (their local_ids are valid in this shared kernel).",
        "raw": " or a local_id from the partner's event log (their local_ids are valid in this shared kernel).",
        "graph": ' or an "@id" taken from the shared graph below (it can name evidence, facts and conclusions created by anyone).',
    }[mode]


def build_prompt(case: Case, mode: str, seat: int, n: int, own: list[dict], team_log: list[dict], messages: list[dict], graph_text: str | None,
                 last_rejected: list[dict], trim: bool = False) -> str:
    out = _build_prompt(case, mode, seat, n, own, team_log, messages, graph_text, last_rejected, 30 if trim else None)
    if not trim and len(out) > 24000:
        return build_prompt(case, mode, seat, n, own, team_log, messages, graph_text, last_rejected, trim=True)
    return out


def _build_prompt(case, mode, seat, n, own, team_log, messages, graph_text, last_rejected, limit):
    tag = SEAT_TAGS[seat]
    onto = json.dumps({"entities": [e["id"] + (" (alias: " + e["aliases"][0] + ")" if e.get("aliases") else "") for e in case.onto["entities"]],
                       "predicates": case.onto["predicates"], "rules": case.onto["rules"]}, separators=(",", ":"))
    s = BRIEF.format(tag=tag, n=n, task=case.task_text(), onto=onto, doc=case.doc.decode("utf-8"), k=K_EVENTS,
                     refs_extra=refs_extra(mode), message_rule=MESSAGE_RULE if mode == "prose" else "")
    if mode == "iso":
        s += "\nWhat you can see: only your own earlier events. Other agents work on the same task in parallel, but you cannot see their work.\n"
        s += "YOUR EARLIER EVENTS:\n" + own_history(own, limit) + "\n"
    elif mode == "prose":
        s += "\nWhat you can see: your own earlier events and the natural-language messages of your partners.\n"
        s += "YOUR EARLIER EVENTS:\n" + own_history(own, limit) + "\n"
        s += "MESSAGES FROM YOUR PARTNERS:\n" + ("\n".join(f"  [turn {m['turn']}, agent {SEAT_TAGS[m['seat']]}] {m['text']}" for m in messages) or "  (none yet)") + "\n"
    elif mode == "raw":
        s += "\nWhat you can see: your own earlier events and your partners' raw event log (their JSONL as emitted, with the kernel's verdict).\n"
        s += "YOUR EARLIER EVENTS:\n" + own_history(own, limit) + "\n"
        theirs = [it for it in team_log if it["seat"] != seat]
        if limit and len(theirs) > limit:
            theirs = theirs[-limit:]
        s += "PARTNERS' EVENT LOG:\n" + ("\n".join(f"  [turn {it['turn']}, agent {SEAT_TAGS[it['seat']]}] {event_line(it['ev'])}   -> {fmt_verdict(it)}" for it in theirs) or "  (nothing yet)") + "\n"
    else:
        s += "\nWhat you can see: your own earlier events, and the shared graph the kernel compiled from ALL accepted events of ALL agents (yours and your partners'), read back from its byte container.\n"
        s += "YOUR EARLIER EVENTS:\n" + own_history(own, limit) + "\n"
        s += "SHARED GRAPH:\n" + (graph_text or "  (empty)") + "\n"
    s += f"\nIt is your turn (turn {len(set(it['turn'] for it in team_log)) + 1}). Output your events now.\n"
    return s


# ------------------------------------------------------------------ parsing

def strip_fences(text: str) -> str:
    return re.sub(r"^```[a-zA-Z]*\s*$", "", text.strip(), flags=re.M)


def parse_turn(text: str, prose: bool):
    message = None
    body = strip_fences(text)
    if prose:
        m = re.search(r"^\s*MESSAGE:\s*(.*)\Z", body, flags=re.S | re.M | re.I)
        if m:
            message = " ".join(m.group(1).split())[:600]
            body = body[:m.start()]
    events = []
    for ln in body.splitlines():
        ln = ln.strip().rstrip(",")
        if not ln.startswith("{"):
            continue
        try:
            events.append(json.loads(ln))
        except Exception:
            events.append({"__bad_json__": ln})
    return events, message


# ------------------------------------------------------------------ one team run

def run_team(case: Case, mode: str, team: tuple[str, ...], backends: dict[str, AG.Backend], overhead: dict[str, int], wd: pathlib.Path,
             first: int = 0) -> dict:
    n = len(team)
    seats = [team[(i + first) % n] for i in range(n)]  # seat order = speaking order
    rdir = wd / f"case{case.idx}_{mode}"
    rdir.mkdir(parents=True, exist_ok=True)
    C.write_docs(rdir / "docs", {"policy": case.doc})
    onto = rdir / "ontology.json"
    onto.write_text(json.dumps(case.onto), encoding="utf-8")
    kernel = Kernel(onto, rdir / "docs")
    container = rdir / "state.sbgk"
    own: list[list[dict]] = [[] for _ in range(n)]
    team_log: list[dict] = []
    messages: list[dict] = []
    created_by: dict[str, int] = {}
    last_rejected: list[list[dict]] = [[] for _ in range(n)]
    turns = []
    goal_turn = None
    graph_text = None
    try:
        for t in range(1, MAX_TURNS + 1):
            seat = (t - 1) % n
            be = backends[seats[seat]]
            prompt = build_prompt(case, mode, seat, n, own[seat], team_log, messages, graph_text, last_rejected[seat])
            r = be.call(prompt, f"case{case.idx}-{mode}-t{t}")
            events, message = parse_turn(r["text"], mode == "prose")
            over = max(0, len(events) - K_EVENTS)
            events = events[:K_EVENTS]
            items, stopped = [], False
            rec = {"turn": t, "seat": seat, "backend": seats[seat], "emitted": len(events) + over, "over_budget": over, "accepted": 0, "new": 0,
                   "repeat_partner": 0, "repeat_self": 0, "rejected": 0, "unsent": 0, "reject_codes": []}
            for ev in events:
                if stopped:
                    items.append({"turn": t, "seat": seat, "ev": ev, "resp": {"status": "unsent"}, "unsent": True})
                    rec["unsent"] += 1
                    continue
                if not isinstance(ev, dict) or "__bad_json__" in ev:
                    resp = {"status": "error", "code": "BAD_JSON", "message": "the line is not valid JSON"}
                else:
                    resp = kernel.send(ev)
                it = {"turn": t, "seat": seat, "ev": ev, "resp": resp}
                items.append(it)
                if resp.get("status") == "ok":
                    rec["accepted"] += 1
                    node = resp.get("node")
                    if resp.get("existed"):
                        if node in created_by and created_by[node] != seat:
                            rec["repeat_partner"] += 1
                            it["repeat_of"] = created_by[node]
                        else:
                            rec["repeat_self"] += 1
                    elif node is not None and resp.get("op") != "revoke_evidence":
                        created_by.setdefault(node, seat)
                        rec["new"] += 1
                    else:
                        rec["new"] += 1
                else:
                    rec["rejected"] += 1
                    rec["reject_codes"].append(resp.get("code"))
                    stopped = True
            own[seat].extend(items)
            team_log.extend(items)
            last_rejected[seat] = [it for it in items if it["resp"].get("status") != "ok"]
            if message:
                messages.append({"turn": t, "seat": seat, "text": message})
            in_net = max(0, r["in_tokens"] - overhead.get(seats[seat], 0))
            rec.update({"in_tokens": r["in_tokens"], "in_net": in_net, "out_tokens": r["out_tokens"], "cost_usd": r.get("cost_usd"),
                        "seconds": r["seconds"], "tokens_estimated": r["tokens_estimated"], "tool_items": r.get("tool_items", 0),
                        "from_cache": bool(r.get("from_cache")), "message": message})
            snap = kernel.snapshot(container)
            claims = C.cli("dump-claims", container)
            sup = {(c["s"], c["p"]): tuple(c["t"]) for c in claims if c["status"] == "SUPPORTED"}
            done = sum(1 for svc, t_gold in case.gold_targets.items() if sup.get((svc, "needs_review")) == t_gold)
            rec["targets_done"] = done
            rec["nodes"] = snap["nodes"]
            turns.append(rec)
            if mode == "graph":
                graph_text = render_graph(container)
            if done == len(case.gold_targets):
                goal_turn = t
                break
        # final accuracy
        claims = C.cli("dump-claims", container)
        sup = [c for c in claims if c["status"] == "SUPPORTED"]
        wrong_facts = [c for c in sup if c["p"] in ("uses_api", "api_deprecated")
                       and (c["s"], c["p"], c["o"], tuple(c["t"])) not in case.gold_facts]
        false_flags = [c for c in sup if c["p"] == "needs_review" and c["s"] not in case.gold_targets]
        pair_matrix = defaultdict(int)
        for it in team_log:
            if it.get("repeat_of") is not None:
                pair_matrix[f"{seats[it['seat']]}->{seats[it['repeat_of']]}"] += 1
    finally:
        kernel.close()
        shutil.rmtree(rdir, ignore_errors=True)

    acc = sum(x["accepted"] for x in turns)
    rep_p = sum(x["repeat_partner"] for x in turns)
    rep_s = sum(x["repeat_self"] for x in turns)
    return {
        "case": case.idx, "mode": mode, "team": seats, "turns_run": len(turns), "goal_turn": goal_turn, "completed": goal_turn is not None,
        "targets": len(case.gold_targets), "targets_done": turns[-1]["targets_done"] if turns else 0,
        "events_accepted": acc, "events_new": sum(x["new"] for x in turns), "repeat_partner": rep_p, "repeat_self": rep_s,
        "rejected": sum(x["rejected"] for x in turns), "unsent": sum(x["unsent"] for x in turns), "over_budget": sum(x["over_budget"] for x in turns),
        "empty_turns": sum(1 for x in turns if x["accepted"] == 0), "wasted_turns": sum(1 for x in turns if x["new"] == 0),
        "wrong_facts": len(wrong_facts), "false_flags": len(false_flags),
        "repeat_matrix": dict(pair_matrix),
        "in_tokens": sum(x["in_tokens"] for x in turns), "in_net": sum(x["in_net"] for x in turns), "out_tokens": sum(x["out_tokens"] for x in turns),
        "cost_usd": sum(x["cost_usd"] or 0 for x in turns), "seconds": sum(x["seconds"] for x in turns),
        "tool_items": sum(x["tool_items"] for x in turns), "from_cache": sum(x["from_cache"] for x in turns),
        "turn_log": turns,
    }


# ------------------------------------------------------------------ driver

def run(n_cases: int = 8, modes: tuple[str, ...] = tuple(MODES), workers: int = 6, fresh: bool = False, max_turns: int | None = None) -> dict:
    global MAX_TURNS
    if max_turns:
        MAX_TURNS = max_turns
    if fresh and OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True, exist_ok=True)
    needed = sorted({b for p in TEAMS[:max(1, min(len(TEAMS), n_cases))] for b in p})
    backends = {b: AG.make(b) for b in needed}
    overhead = {}
    for name, be in backends.items():
        r = be.call('Reply with exactly one line of JSON: {"ok":1}. Do not use tools.', f"overhead-{name}")
        overhead[name] = r["in_tokens"]
    cases = [Case(i, seed=7000 + i) for i in range(n_cases)]
    wd = OUT / "work"
    jobs = []
    for c in cases:
        team = TEAMS[c.idx % len(TEAMS)]
        first = (c.idx // len(TEAMS)) % len(team)
        for m in modes:
            jobs.append((c, m, team, first))

    def job(j):
        c, m, team, first = j
        t0 = time.time()
        try:
            res = run_team(c, m, team, backends, overhead, wd, first)
        except Exception as e:  # noqa: BLE001 - a failed run is data, not a crash
            res = {"case": c.idx, "mode": m, "team": list(team), "error": str(e)[:400], "completed": False, "turns_run": 0}
        res["wall_s"] = time.time() - t0
        print(f"  case {c.idx} {m:<5} {'+'.join(res.get('team', team))}: completed={res.get('completed')} turns={res.get('turns_run')} "
              f"accepted={res.get('events_accepted')} repeat_partner={res.get('repeat_partner')} repeat_self={res.get('repeat_self')} "
              f"{('ERROR ' + res['error']) if res.get('error') else ''}", flush=True)
        return res

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(job, jobs))
    data = {
        "backends": {n: {"label": b.label, "version": getattr(b, "version", ""), "tokens_estimated": not b.exact_tokens} for n, b in backends.items()},
        "overhead_in_tokens": overhead, "cases": n_cases, "modes": list(modes), "k_events": K_EVENTS, "max_turns": MAX_TURNS,
        "case_info": [{"idx": c.idx, "gold_services": len(c.gold_targets), "doc_bytes": len(c.doc), "team": TEAMS[c.idx % len(TEAMS)]} for c in cases],
        "results": results,
    }
    shutil.rmtree(wd, ignore_errors=True)
    (OUT / "exp7.json").write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    return data
