"""EXP-8 environment: three stress scenarios on top of the EXP-7 kernel session.

EXP-7 showed that ANY visibility of the partners' work removes most repeated steps, but that the compiled graph was not better than
prose or a raw event log on short histories (<= 12 turns, <= 60 events, 2-3 agents). EXP-8 builds the situations where unstructured
exchange should break down, one scenario per cause (so effects are attributable):

  retract   an erratum withdraws, mid-task, a use clause (w), a deprecation clause that several conclusions rest on (p, restated in another
            clause so the fact can be re-supported and the conclusions come back without being re-derived) and one side of a contradiction
            (x); a second contradiction (y) is never resolved. Contradictions are POS/NEG facts with overlapping time.
  scale     26 services, 7 systems, a two-level derivation chain, 5 agents, 4 events per turn, up to 24 turns; clauses are written in
            three different surface forms (ids, aliases, other word order), so raw logs get long and noisy.
  parallel  4 agents act in the SAME round on the SAME snapshot; the kernel merges the round afterwards.

Visibility modes (what an agent sees of the team's work; its own earlier events with kernel verdicts are always visible):
  iso        nothing about the others
  prose      a <= 60-word natural-language message per partner turn
  raw        the partners' raw event log (JSONL as emitted, with the kernel's verdict at that time)
  graph      the compiled graph read back from the kernel's byte container (current statuses, retractions, conflicts)
  graphopen  the graph PLUS a list of open obligations (supported base facts not yet used by any derivation) - extra intelligence
             computed from the compiled graph; it is not part of the compiler's byte format

Everything an agent receives is built here; everything the kernel decides is read back from the kernel, never judged by the harness.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import random
import subprocess
from collections import defaultdict

from . import common as C
from .exp7_multiagent import event_line

OUT = C.RESULTS / "exp8"
MODES = ["iso", "prose", "raw", "graph", "graphopen"]
SEAT_TAGS = ["a", "b", "c", "d", "e"]
PROMPT_BUDGET = 27500  # characters of the Windows command line (OpenClaw takes the prompt as an argument; 28.7k tested OK)
BASE_PREDS = ("uses_api", "api_deprecated", "part_of")
CONCLUSIONS = ("needs_review", "sys_flagged")


# ------------------------------------------------------------------ scenario parameters

@dataclasses.dataclass(frozen=True)
class Spec:
    name: str
    services: int
    apis: int
    active: int
    systems: int
    team: tuple
    k: int
    cap: int
    parallel: bool
    retract: bool = False
    decoys: int = 0
    noisy: bool = False
    unique_windows: bool = False
    gold: tuple = (5, 7)
    private_notice: bool = False  # the erratum reaches ONE agent only; the others learn of it through their channel

    @property
    def unit(self) -> str:
        return "round" if self.parallel else "turn"


SPECS = {
    "retract": Spec("retract", services=16, apis=6, active=3, systems=0, team=("codex", "deepseek", "sonnet"), k=5, cap=14,
                    parallel=False, retract=True, gold=(8, 9)),
    "retractp": Spec("retractp", services=16, apis=6, active=3, systems=0, team=("codex", "deepseek", "sonnet"), k=5, cap=14,
                     parallel=False, retract=True, gold=(8, 9), private_notice=True),
    "scale": Spec("scale", services=26, apis=9, active=4, systems=7, team=("codex", "deepseek", "sonnet", "codex", "deepseek"), k=4, cap=30,
                  parallel=False, decoys=2, noisy=True, unique_windows=True, gold=(9, 11)),
    "parallel": Spec("parallel", services=20, apis=8, active=4, systems=0, team=("codex", "deepseek", "sonnet", "codex"), k=4, cap=8,
                     parallel=True, gold=(9, 11)),
}


SEED_BASE = {"retract": 8000, "retractp": 8000, "scale": 8100, "parallel": 8200}


def seat_labels(team: tuple) -> list[str]:
    """Stable label of every team position: 'codex', 'deepseek', 'opus', 'codex2', 'deepseek2'."""
    seen: dict[str, int] = defaultdict(int)
    out = []
    for b in team:
        seen[b] += 1
        out.append(b if seen[b] == 1 else f"{b}{seen[b]}")
    return out


# ------------------------------------------------------------------ case generator

def _svc(i): return f"svc_{i:03d}"
def _api(a): return f"api_{a:03d}"
def _sys(j): return f"sys_{j:02d}"


def _use_text(style: int, label: str, i: int, a: int, lo: int, hi: int) -> str:
    if style == 1:
        return f"Clause {label}: from t={lo} until t={hi}, interface {_api(a)} is called in production by service {_svc(i)}."
    if style == 2:
        return f"Clause {label}: service {i} shall call interface {a} in production from t={lo} until t={hi}."
    return f"Clause {label}: service {_svc(i)} shall call interface {_api(a)} in production from t={lo} until t={hi}."


def _dep_text(style: int, label: str, a: int, lo: int, hi: int) -> str:
    if style == 1:
        return f"Clause {label}: from t={lo} until t={hi}, production use of interface {_api(a)} is deprecated."
    if style == 2:
        return f"Clause {label}: interface {a} is deprecated in production from t={lo} until t={hi}."
    return f"Clause {label}: interface {_api(a)} is deprecated in production from t={lo} until t={hi}."


def _part_text(style: int, label: str, i: int, j: int) -> str:
    if style == 1:
        return f"Clause {label}: system {_sys(j)} includes service {_svc(i)} in production from t=0 until t=1000."
    if style == 2:
        return f"Clause {label}: service {i} is part of system {j} in production from t=0 until t=1000."
    return f"Clause {label}: service {_svc(i)} is part of system {_sys(j)} in production from t=0 until t=1000."


class Case8:
    def __init__(self, spec: Spec, idx: int, seed: int | None = None):
        self.spec, self.idx = spec, idx
        # fixed seed bases (independent of the order of SPECS); the private-notice variant replays the very same cases as "retract"
        self.seed = seed if seed is not None else SEED_BASE[spec.name] + idx
        rng = random.Random(self.seed)
        S, A = spec.services, spec.apis
        for _ in range(5000):
            order = list(range(A))
            rng.shuffle(order)
            active, trap = set(order[:spec.active]), order[spec.active]
            api_of = [rng.randrange(A) for _ in range(S)]
            gold_api = [i for i in range(S) if api_of[i] in active]
            if spec.gold[0] <= len(gold_api) - spec.decoys <= spec.gold[1] and trap in api_of and all(a in api_of for a in active):
                break
        else:  # pragma: no cover - generator constants are chosen so that this does not happen
            raise RuntimeError("case generator failed")
        self.api_of, self.active, self.trap = api_of, active, trap
        # usage windows
        if spec.unique_windows:
            his = list(range(S))
            rng.shuffle(his)
            self.use_t = [(100 + 2 * rng.randrange(11), 200 + 2 * his[i]) for i in range(S)]
        else:
            self.use_t = [(rng.choice([100, 110, 120]), rng.choice([200, 210, 220])) for _ in range(S)]
        self.decoy = set(rng.sample(gold_api, spec.decoys)) if spec.decoys else set()
        for i in self.decoy:  # active API, but the usage window ends before the deprecation starts: nothing to derive
            self.use_t[i] = (100 + 2 * rng.randrange(6), 130 + 2 * rng.randrange(10))
        self.dep_t = {a: ((150, 300) if a in active else (300, 400)) for a in list(active) + [trap]}
        self.true_gold = [i for i in gold_api if i not in self.decoy]
        self.sys_of = [rng.randrange(spec.systems) for _ in range(S)] if spec.systems else []
        # roles of the retraction scenario
        self.role: dict[str, int] = {}
        self.p_api: int | None = None
        self.p_services: list[int] = []
        if spec.retract:
            for _ in range(500):
                w, x, y = rng.sample(self.true_gold, 3)
                cand = sorted(a for a in active if all(api_of[i] != a for i in (w, x, y))
                              and sum(1 for i in self.true_gold if api_of[i] == a) >= 2)
                if cand:
                    break
            else:  # pragma: no cover
                raise RuntimeError("retraction roles failed")
            self.role = {"w": w, "x": x, "y": y}
            self.p_api = rng.choice(cand)
            self.p_services = [i for i in self.true_gold if api_of[i] == self.p_api]
        self.onto = C.ontology_review(S, A, spec.systems)
        # ---- clauses
        style = (lambda: rng.randrange(3)) if spec.noisy else (lambda: 0)
        self.clauses: list[tuple[str, str]] = []  # (label, sentence)
        self.allowed: set[tuple] = set()  # every (s,p,o,pol,t) the document actually states
        for i in range(S):
            lo, hi = self.use_t[i]
            self.clauses.append((f"U.{i}", _use_text(style(), f"U.{i}", i, api_of[i], lo, hi)))
            self.allowed.add((_svc(i), "uses_api", _api(api_of[i]), "POS", (lo, hi)))
        for a, (lo, hi) in sorted(self.dep_t.items()):
            self.clauses.append((f"D.{a}", _dep_text(style(), f"D.{a}", a, lo, hi)))
            self.allowed.add((_api(a), "api_deprecated", "true", "POS", (lo, hi)))
        if spec.systems:
            for i in range(S):
                self.clauses.append((f"P.{i}", _part_text(style(), f"P.{i}", i, self.sys_of[i])))
                self.allowed.add((_svc(i), "part_of", _sys(self.sys_of[i]), "POS", (0, 1000)))
        self.erratum: bytes | None = None
        self.erratum_text = ""
        self.withdrawn: dict[str, str] = {}  # label -> sentence
        if spec.retract:
            r, pa = self.role, self.p_api
            dlo, dhi = self.dep_t[pa]
            self.clauses.append((f"R.{pa}", f"Clause R.{pa}: from t={dlo} until t={dhi}, production use of interface {_api(pa)} is deprecated "
                                            f"(this restates clause D.{pa})."))
            for k in ("x", "y"):
                i = r[k]
                lo, hi = self.use_t[i]
                nlo, nhi = lo + 20, hi + 10
                self.clauses.append((f"N.{i}", f"Clause N.{i}: service {_svc(i)} does not call interface {_api(api_of[i])} "
                                               f"in production from t={nlo} until t={nhi}."))
                self.allowed.add((_svc(i), "uses_api", _api(api_of[i]), "NEG", (nlo, nhi)))
            text = dict(self.clauses)
            for lab in (f"U.{r['w']}", f"D.{pa}", f"N.{r['x']}"):
                self.withdrawn[lab] = text[lab]
            self.erratum_text = (f"Erratum E.1: clause U.{r['w']} is withdrawn. "
                                 f"Erratum E.2: clause D.{pa} is withdrawn; the same statement stands in clause R.{pa}. "
                                 f"Erratum E.3: clause N.{r['x']} was recorded in error and is withdrawn. "
                                 f"A withdrawn clause must no longer support anything.")
            self.erratum = (self.erratum_text + "\n").encode("utf-8")
            self.trigger_quote = text[f"D.{pa}"]
        self.quote = dict(self.clauses)
        # ---- document
        sents = [s for _, s in self.clauses]
        rng.shuffle(sents)
        per, fill = (3, 1) if spec.noisy else (2, 2)
        paras = []
        for k in range(0, len(sents), per):
            paras.append(" ".join([C.filler_sentence(rng) for _ in range(fill)] + sents[k:k + per] + [C.filler_sentence(rng) for _ in range(fill - 1 if spec.noisy else fill)]))
        self.doc = C.join_doc(paras)
        # ---- gold
        excluded = {self.role["w"], self.role["y"]} if spec.retract else set()
        self.gold_services = [i for i in self.true_gold if i not in excluded]
        self.gold_nr = {(_svc(i), C.intersect(self.use_t[i], self.dep_t[api_of[i]])) for i in self.gold_services}
        self.gold_sys = {(_sys(self.sys_of[i]), C.intersect(self.use_t[i], self.dep_t[api_of[i]])) for i in self.gold_services} if spec.systems else set()
        self.forbidden = {_svc(i) for i in excluded}  # w (withdrawn) and y (unresolved contradiction): no needs_review may stand
        self.targets = len(self.gold_nr) + len(self.gold_sys)
        # services whose conclusion may legitimately disappear and come back (x: conflict; p: shared premise withdrawn and re-supported)
        self.special = ({_svc(self.role["x"])} | {_svc(i) for i in self.p_services}) if spec.retract else set()

    @property
    def min_events(self) -> int:
        """Events an ideal team would need (no repeats, no rejections): bind + assert per fact, one derive per conclusion."""
        gold = self.gold_services
        n = 3 * len(gold) + 2 * len({self.api_of[i] for i in gold})
        if self.spec.systems:
            n += 3 * len(gold)
        if self.spec.retract:
            n += 2 + 2 + 2 + 2 + 2 + 3  # N.x, U.y + N.y, U.w + its derive, R.p premise restatement, three revokes (rough lower bound of the extras)
        return n

    # ---------------------------------------------------------------- text
    def task_text(self) -> str:
        base = ("Find every service that NEEDS REVIEW. A service needs review when the API it calls is deprecated during a time window that "
                "overlaps the service's own usage window (rule R_depr_review@1 combines uses_api and api_deprecated). Establish the supporting "
                "facts, each backed by a quoted clause, and derive needs_review for every such service. For services whose API is not deprecated "
                "in an overlapping window, derive nothing. The document may state clauses in any order. ")
        if self.spec.systems:
            base += ("Then flag every SYSTEM that contains a service which needs review: rule R_sys_flag@1 combines part_of(service, system) and "
                     "needs_review(service) into sys_flagged(system, true) for the intersection of their time windows. "
                     "The team is finished when every needs_review conclusion and every sys_flagged conclusion exists in the kernel.")
            return base
        if self.spec.retract:
            return (base + "The document may also contradict itself and the register can be corrected while you work.\n"
                    "RETRACTION AND CONFLICT RULES (part of the task):\n"
                    + ("- A NOTICE (erratum) may appear below in the course of the work. It is binding for everyone, but it is DELIVERED TO ONE OF YOU ONLY (the agent whose "
                       "turn comes next); your partners do not receive it and can only learn of it through whatever your channel shows them. If a notice reaches you, you are "
                       "responsible for the team not relying on the withdrawn clauses: remove those already in the kernel, and mark a withdrawn clause that nobody has bound yet "
                       "as withdrawn for everyone by binding its quote and revoking it (the kernel then refuses any later binding of that clause). "
                       if self.spec.private_notice else
                       "- A NOTICE (erratum) may appear below in the course of the work; it is binding for everyone. ")
                    + "A clause that a notice withdraws must no longer "
                    "support anything: remove it from the kernel with {\"op\":\"revoke_evidence\",\"target_evidence\":\"<reference of the evidence bound to that clause>\"}. "
                    "The kernel then automatically removes every fact and conclusion that rested ONLY on that clause; a fact that is also supported by another "
                    "clause stays. If you do not hold a reference to the evidence, bind the same quote again (binding an already bound quote returns the same evidence).\n"
                    "- If two clauses of the document contradict each other (one says a service calls an interface, the other says it does not, for overlapping time), "
                    "record BOTH as facts (polarity POS and NEG). The kernel then marks both CONFLICTING_SOURCES and refuses to derive from them. "
                    "Do not derive a conclusion from a fact that is CONFLICTING_SOURCES; a conflict ends only when a notice withdraws one of the two clauses.\n"
                    "The team is finished when the kernel holds exactly the right conclusions: every service that needs review (taking all notices and unresolved "
                    "contradictions into account) has its needs_review conclusion, no other service has one, and every withdrawn clause has been removed from the kernel.")
        return (base + "The team is finished when every service that needs review has its needs_review conclusion in the kernel.")

    def onto_text(self) -> str:
        return json.dumps({"entities": [e["id"] + (" (alias: " + e["aliases"][0] + ")" if e.get("aliases") else "") for e in self.onto["entities"]],
                           "predicates": self.onto["predicates"], "rules": self.onto["rules"]}, separators=(",", ":"))

    def notice_text(self, step: int) -> str:
        who = "delivered to you only; your partners do not see it" if self.spec.private_notice else "binding for everyone"
        return (f'NOTICE (published after {self.spec.unit} {step}; {who}) - the register issued a new document "erratum":\n'
                f"<<<\n{self.erratum_text}\n>>>\n")

    def body_preds(self) -> set[str]:
        return {a["p"] for r in self.onto["rules"] for a in r["body"]}

    # ---------------------------------------------------------------- judging (reads kernel output only)
    def evaluate(self, full: dict) -> dict:
        claims = full["claims"]
        sup = [c for c in claims if c["st"] == "SUPPORTED" and c["pol"] == "POS"]
        got_nr = {(c["s"], tuple(c["t"])) for c in sup if c["p"] == "needs_review"}
        got_sys = {(c["s"], tuple(c["t"])) for c in sup if c["p"] == "sys_flagged"}
        done = len(got_nr & self.gold_nr) + len(got_sys & self.gold_sys)
        false = [c for c in sup if (c["p"] == "needs_review" and (c["s"], tuple(c["t"])) not in self.gold_nr)
                 or (c["p"] == "sys_flagged" and (c["s"], tuple(c["t"])) not in self.gold_sys)]
        wrong_facts = [c for c in claims if c["p"] in BASE_PREDS and (c["s"], c["p"], c["o"], c["pol"], tuple(c["t"])) not in self.allowed]
        wd_active = sum(1 for e in full["evidence"] if e["quote"] in self.withdrawn.values() and e["st"] == "ACTIVE")
        stale = [c for c in false if c["p"] == "needs_review" and c["s"] == _svc(self.role["w"])] if self.spec.retract else []
        under_conflict = [c for c in false if c["p"] == "needs_review" and c["s"] == _svc(self.role["y"])] if self.spec.retract else []
        goal = done == self.targets and (not self.spec.retract or (not false and wd_active == 0))
        return {
            "done": done, "goal": goal, "false": len(false), "false_keys": [(c["p"], c["s"]) for c in false],
            "stale": len(stale), "under_conflict": len(under_conflict), "wrong_facts": len(wrong_facts), "withdrawn_active": wd_active,
            "conflicting": sum(1 for c in claims if c["st"] == "CONFLICTING_SOURCES"),
            "unsupported": sum(1 for c in claims if c["st"] == "UNSUPPORTED"),
            "x_ok": (_svc(self.role["x"]), tuple(C.intersect(self.use_t[self.role["x"]], self.dep_t[self.api_of[self.role["x"]]]))) in got_nr if self.spec.retract else None,
            "p_ok": all((_svc(i), tuple(C.intersect(self.use_t[i], self.dep_t[self.api_of[i]]))) in got_nr for i in self.p_services) if self.spec.retract else None,
        }


# ------------------------------------------------------------------ views of the compiled graph

def kernel_full(kernel, container: pathlib.Path, scratch: pathlib.Path) -> tuple[dict, dict]:
    """Snapshot the kernel into its byte container and read the whole compiled graph (all statuses) back from those bytes."""
    snap = kernel.snapshot(container)
    out = scratch / "full.json"
    C.cli("cone", container, "--entity", "svc_000", "--reps", 1, "--full-out", out)
    return json.loads(out.read_text(encoding="utf-8")), snap


def status_map(full: dict) -> dict[str, str]:
    m = {c["id"]: c["st"] for c in full["claims"]}
    m.update({e["id"]: e["st"] for e in full["evidence"]})
    return m


_PRED_RANK = {"api_deprecated": 0, "uses_api": 1, "part_of": 2, "needs_review": 3, "sys_flagged": 4}


def render_graph8(full: dict, compact: bool = False) -> str:
    ev = {e["id"]: e for e in full["evidence"]}
    steps_of = defaultdict(list)
    asserted_ev = set()
    for s in full["steps"]:
        steps_of[s["claim"]].append(s)
        if s["kind"] == "assertion" and s.get("active"):
            asserted_ev.add(s["evidence"])
    lines = ["EVIDENCE bound so far (quotes from the document; status in brackets):"]
    for e in sorted(full["evidence"], key=lambda x: x["quote"]):
        label = e["quote"].split(":")[0]
        text = label if compact else f'"{e["quote"]}"'
        mark = ""
        if e["st"] == "REVOKED":
            mark = "   [WITHDRAWN - no longer supports anything]"
        elif e["id"] not in asserted_ev:
            mark = "   [bound, but no fact asserted from it yet]"
        lines.append(f'  @{e["id"]} [{e["st"]}] {text}{mark}')
    if not full["evidence"]:
        lines.append("  (none)")
    lines.append("FACTS AND CONCLUSIONS (canonical; duplicates and aliases already merged; current status):")
    claims = sorted(full["claims"], key=lambda c: (_PRED_RANK.get(c["p"], 9), c["s"], c["o"], c["t"], c["pol"]))
    for c in claims:
        why = []
        for s in steps_of[c["id"]]:
            if s["kind"] == "assertion":
                tag = f'evidence @{s["evidence"]}' + (" [WITHDRAWN]" if ev.get(s["evidence"], {}).get("st") == "REVOKED" else "")
            else:
                tag = f'{s["rule"]}(' + ", ".join("@" + p for p in s["premises"]) + ")" + ("" if s.get("active") else " [premise lost]")
            why.append(tag)
        st = {"UNSUPPORTED": "UNSUPPORTED (lost its support - does not count)", "CONFLICTING_SOURCES": "CONFLICTING_SOURCES (contradicted - blocked)"}.get(c["st"], c["st"])
        pol = " [NEG]" if c["pol"] == "NEG" else ""
        lines.append(f'  @{c["id"]}  {c["p"]}({c["s"]}, {c["o"]}){pol} t=[{c["t"][0]},{c["t"][1]}) {st}  <- ' + " | ".join(why))
    if not claims:
        lines.append("  (none)")
    return "\n".join(lines)


def open_obligations(full: dict, body_preds: set[str]) -> list[dict]:
    used = set()
    for s in full["steps"]:
        if s["kind"] == "derivation" and s.get("active"):
            used.update(s["premises"])
    out = [c for c in full["claims"] if c["st"] == "SUPPORTED" and c["pol"] == "POS" and c["p"] in body_preds and c["id"] not in used]
    return sorted(out, key=lambda c: (_PRED_RANK.get(c["p"], 9), c["s"], c["o"]))


def render_open(full: dict, body_preds: set[str]) -> str:
    items = open_obligations(full, body_preds)
    lines = ["OPEN OBLIGATIONS (EXTRA INTELLIGENCE computed from the compiled graph, not part of the graph itself): SUPPORTED facts that no derivation has "
             "used yet. A fact may legitimately stay open forever if no matching partner fact with an overlapping time window exists."]
    for c in items:
        lines.append(f'  @{c["id"]}  {c["p"]}({c["s"]}, {c["o"]}) t=[{c["t"][0]},{c["t"][1]})')
    if not items:
        lines.append("  (none)")
    return "\n".join(lines)


# ------------------------------------------------------------------ verdicts and histories

def fmt_verdict(it: dict) -> str:
    r = it["resp"]
    if it.get("unsent"):
        return "NOT SENT (an earlier event this turn was rejected)"
    if r.get("status") == "ok":
        s = "ok"
        if it.get("cls") == "repeat":
            s += " (already existed - repeated step)"
        elif it.get("cls") == "repair":
            s += " (existed, but had lost its support - re-supported now)"
        cs = r.get("claim_status")
        if cs and cs != "SUPPORTED":
            s += f" [claim is now {cs}]"
        if r.get("op") == "revoke_evidence" and r.get("dred"):
            s += f' [evidence withdrawn; the cascade removed {r["dred"].get("net_removed", 0)} claim(s) that had no other support]'
        return s
    e = {k: r.get(k) for k in ("code", "field", "message", "expected_by_kernel", "obligation") if r.get(k) not in (None, "")}
    return "REJECTED " + json.dumps(e, ensure_ascii=False)


def _line(it: dict, who: bool, unit: str) -> str:
    head = f"[{unit} {it['step']}" + (f", agent {SEAT_TAGS[it['seat']]}" if who else "") + "]"
    return f"  {head} {event_line(it['ev'])}   -> {fmt_verdict(it)}"


def own_history(items: list[dict], unit: str, keep: int | None) -> tuple[str, int]:
    if not items:
        return "  (nothing yet)", 0
    note, hidden = "", 0
    if keep is not None and len(items) > keep:
        hidden = len(items) - keep
        note = f"  ({hidden} older events omitted for space; they were accepted unless marked otherwise)\n"
        items = items[-keep:]
    return note + "\n".join(_line(it, False, unit) for it in items), hidden


# ------------------------------------------------------------------ prompt

BRIEF = """You are agent "@TAG@" (seat @SEAT@ of @N@) in a team of @N@ AI agents working on ONE shared task. Nobody has been assigned a share of the work.
You never talk to your partners directly. The team's work lives in a deterministic kernel (a "compiler"): you write atomic events as strict
JSON, the kernel validates them (it checks every quote against the document bytes, resolves entity names and aliases, computes derived values) and stores them.
@FLOW@

TEAM OBJECTIVE: finish in as few @UNIT@s as possible. Do NOT redo a step that is already established or that a partner has already done - spend
your @UNIT@ on steps nobody has done yet. Because @UNIT@s are limited, repeating work only slows the whole team down.

TASK: @TASK@

ONTOLOGY (JSON): @ONTO@

DOCUMENT "policy":
<<<
@DOC@>>>

EVENT FORMAT - one strict JSON object per line, WITHOUT "seq" (the kernel numbers events). Context is always "prod".
{"op":"bind_evidence","local_id":"@TAG@@STEP@_e1","doc_id":"policy","exact_quote":"<byte-exact text copied from the document; one whole clause sentence is ideal>"}
{"op":"assert_fact","local_id":"@TAG@@STEP@_f1","s":"svc_003","p":"uses_api","o":"api_002","polarity":"POS","ctx":"prod","t":[100,200],"evidence":["@TAG@@STEP@_e1"]}
{"op":"assert_fact","local_id":"@TAG@@STEP@_f2","s":"api_002","p":"api_deprecated","o":"true","polarity":"POS","ctx":"prod","t":[150,300],"evidence":["@TAG@@STEP@_e2"]}
{"op":"derive","local_id":"@TAG@@STEP@_r1","rule":"R_depr_review@1","premises":["@TAG@@STEP@_f1","@TAG@@STEP@_f2"]}
@EXTRA_EXAMPLES@(derive: the kernel computes the conclusion and its interval itself, so "claim" is optional. Entities may be written as canonical ids or as the listed aliases.)
LOCAL IDS: start every local_id you create in this @UNIT@ with "@TAG@@STEP@_" (for example "@TAG@@STEP@_e1"); that keeps them unique across @UNIT@s.
References ("evidence" and "premises" entries) are: a local_id you created yourself@REFS@

RULES OF YOUR @UNIT_UP@: at most @K@ events. The kernel processes them in order and STOPS at the first rejected event; the rest are discarded.
Output only the events, one JSON object per line, no code fences, no commentary.@MSG@
"""

EXTRA_RETRACT = """{"op":"assert_fact","local_id":"@TAG@@STEP@_f3","s":"svc_005","p":"uses_api","o":"api_001","polarity":"NEG","ctx":"prod","t":[120,180],"evidence":["@TAG@@STEP@_e3"]}
{"op":"revoke_evidence","target_evidence":"<reference of the evidence to withdraw>"}
"""
EXTRA_SCALE = """{"op":"assert_fact","local_id":"@TAG@@STEP@_f3","s":"svc_003","p":"part_of","o":"sys_01","polarity":"POS","ctx":"prod","t":[0,1000],"evidence":["@TAG@@STEP@_e3"]}
{"op":"derive","local_id":"@TAG@@STEP@_r2","rule":"R_sys_flag@1","premises":["@TAG@@STEP@_f3","<reference of the needs_review conclusion of that service>"]}
"""

MESSAGE_RULE = ('\nAfter the events add ONE final line starting with "MESSAGE:" (at most 60 words) telling your partners what you established '
                '(mention the local_ids you created) and what remains to be done.')

COMMON_REFS = ". Binding a quote that is already bound is allowed (it returns the same evidence) but it counts as a repeated step"


def refs_extra(mode: str) -> str:
    return {
        "iso": " - you cannot reference anything created by others" + COMMON_REFS + ".",
        "prose": " - or an id a partner told you about in a message (their local_ids are valid in this shared kernel)" + COMMON_REFS + ".",
        "raw": " - or a local_id from the partners' event log (their local_ids are valid in this shared kernel)" + COMMON_REFS + ".",
        "graph": ' - or an "@id" taken from the shared graph below (it can name evidence, facts and conclusions created by anyone)' + COMMON_REFS + ".",
        "graphopen": ' - or an "@id" taken from the shared graph below (it can name evidence, facts and conclusions created by anyone)' + COMMON_REFS + ".",
    }[mode]


def fill(template: str, **kw) -> str:
    for k, v in kw.items():
        template = template.replace(f"@{k}@", str(v))
    return template


def cmdlen(s: str) -> int:
    return len(subprocess.list2cmdline([s]))


def build_prompt(case: Case8, mode: str, seat: int, step: int, own: list[dict], team_log: list[dict], messages: list[dict],
                 full: dict | None, notice: str | None) -> tuple[str, dict]:
    """Return (prompt, meta). When the prompt would exceed PROMPT_BUDGET the least compact view is shrunk first:
    the graph drops quote text, the raw log / messages / own history keep only their most recent items."""
    spec = case.spec
    n, unit = len(spec.team), spec.unit
    meta = {"compact": False, "raw_hidden": 0, "raw_total": 0, "msg_hidden": 0, "own_hidden": 0}
    theirs = [it for it in team_log if it["seat"] != seat]
    meta["raw_total"] = len(theirs)

    def assemble(raw_keep, msg_keep, own_keep, compact) -> str:
        flow = ("In every round ALL agents act at the same moment on the same state: each of you writes events without seeing what the others write in this "
                "round; afterwards the kernel merges the events of the whole round (in a rotating order). The next round starts from the merged state. "
                "If two agents take the same step in the same round, one of them has wasted its effort."
                if spec.parallel else
                "Your turn ends after your events; then a partner takes a turn, and so on until the task is complete.")
        extra = EXTRA_RETRACT if spec.retract else (EXTRA_SCALE if spec.systems else "")
        # big blocks first (they may contain the small tokens), small tokens last
        s = fill(BRIEF, FLOW=flow, TASK=case.task_text(), ONTO=case.onto_text(), DOC=case.doc.decode("utf-8"), EXTRA_EXAMPLES=extra,
                 REFS=refs_extra(mode), MSG=MESSAGE_RULE if mode == "prose" else "",
                 TAG=SEAT_TAGS[seat], SEAT=seat + 1, N=n, UNIT_UP=unit.upper(), UNIT=unit, STEP=step, K=spec.k)
        oh, meta["own_hidden"] = own_history(own, unit, own_keep)
        later = " (as merged at the end of the previous round)" if spec.parallel else ""
        if mode == "iso":
            s += ("\nWhat you can see: your own earlier events (you work alone).\n" if n == 1 else
                  "\nWhat you can see: only your own earlier events. Other agents work on the same task at the same time, but you cannot see their work.\n")
            s += "YOUR EARLIER EVENTS:\n" + oh + "\n"
        elif mode == "prose":
            s += "\nWhat you can see: your own earlier events and the natural-language messages of your partners.\n"
            s += "YOUR EARLIER EVENTS:\n" + oh + "\n"
            ms = messages
            if msg_keep is not None and len(ms) > msg_keep:
                meta["msg_hidden"] = len(ms) - msg_keep
                ms = ms[-msg_keep:]
            s += "MESSAGES FROM YOUR PARTNERS:\n" + ("\n".join(f"  [{unit} {m['step']}, agent {SEAT_TAGS[m['seat']]}] {m['text']}" for m in ms) or "  (none yet)") + "\n"
        elif mode == "raw":
            s += "\nWhat you can see: your own earlier events and your partners' raw event log (their JSONL as emitted, with the kernel's verdict at the time).\n"
            s += "YOUR EARLIER EVENTS:\n" + oh + "\n"
            th = theirs
            if raw_keep is not None and len(th) > raw_keep:
                meta["raw_hidden"] = len(th) - raw_keep
                th = th[-raw_keep:]
            note = f"  ({meta['raw_hidden']} older partner events omitted for space)\n" if meta["raw_hidden"] else ""
            s += "PARTNERS' EVENT LOG:\n" + note + ("\n".join(_line(it, True, unit) for it in th) or "  (nothing yet)") + "\n"
        else:
            s += (f"\nWhat you can see: your own earlier events, and the shared graph the kernel compiled from ALL accepted events of ALL agents (yours and "
                  f"your partners'), read back from its byte container{later}. A fact or conclusion appears once however many agents asserted it. "
                  "SUPPORTED = holds now; CONFLICTING_SOURCES = a POS and a NEG fact overlap, nothing may be derived from them; UNSUPPORTED = lost all its "
                  "support (for example its evidence was withdrawn), it no longer counts.\n")
            s += "YOUR EARLIER EVENTS:\n" + oh + "\n"
            s += "SHARED GRAPH:\n" + (render_graph8(full, compact) if full else "  (empty)") + "\n"
            if mode == "graphopen":
                s += (render_open(full, case.body_preds()) if full else "OPEN OBLIGATIONS: (none)") + "\n"
        if notice:
            s += "\n" + notice
        s += f"\nIt is your {unit} ({unit} {step}). Output your events now.\n"
        return s

    raw_keep = msg_keep = own_keep = None
    compact = False
    txt = assemble(raw_keep, msg_keep, own_keep, compact)
    guard = 0
    while cmdlen(txt) > PROMPT_BUDGET and guard < 60:
        guard += 1
        if mode in ("graph", "graphopen") and not compact:
            compact = True
        elif mode == "raw" and len(theirs) > 4 and (raw_keep is None or raw_keep > 4):
            raw_keep = max(4, int((raw_keep if raw_keep is not None else len(theirs)) * 0.8))
        elif mode == "prose" and len(messages) > 3 and (msg_keep is None or msg_keep > 3):
            msg_keep = max(3, int((msg_keep if msg_keep is not None else len(messages)) * 0.8))
        elif len(own) > 4 and (own_keep is None or own_keep > 4):
            own_keep = max(4, int((own_keep if own_keep is not None else len(own)) * 0.8))
        else:
            break
        txt = assemble(raw_keep, msg_keep, own_keep, compact)
    meta["compact"] = compact
    meta["cmdlen"] = cmdlen(txt)
    meta["chars"] = len(txt)
    return txt, meta
