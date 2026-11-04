"""Step 0 (c) of the consilium plan, offline and model-free: trace a hand-made reference inventory through archived pilot runs.

The reference (JSON, kept outside the repository with the analysis notes) lists items of the source reports by byte-exact
quotes: research-question items (RQ1 superseded/stale/qualified, RQ2 open/limitation/future), cross-report pairs (X) and
negative controls (NEG). First every quote is checked against the run's own frozen inputs (found once, ambiguous, missing).
Then, for each item and run, the loss stages:
  extracted  a stored observe overlaps one of the item's quotes
  claimed    a stored claim rests on such an observe (directly or through one claim)
  stance     such a claim carries the stance its research question asks for (RQ1 superseded/qualified, RQ2 open)
  answered   such a claim is in that question's answer of phase 1
For a pair, both ends are traced to `claimed`, then:
  linked     a link has the reference's exact relation and direction (an unspecified expectation never passes)
  accepted   that exact link is accepted
Reading and summary origin/phase are separate. Overlapping bytes are a structural proxy, not a semantic judgment.
Usage:
  python benchmarks/analysis_step0_reference_trace.py <reference.json> <run dir> [<run dir> ...] > trace.json"""
from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter

from analysis_step0_evolution_links import proposals, report_names
from analysis_step0_summary_audit import load

STANCES = {"RQ1": {"superseded", "qualified"}, "RQ1A": {"superseded", "qualified"}, "RQ1B": {"qualified"},
           "RQ2": {"open"}, "NEG": {"superseded", "qualified"}, "EXCLUDED": set()}
READING = {"EXTEND", "REQUEST", "INVESTIGATE"}


def reference_v1(reference: dict) -> dict:
    """Apply the owner's explicit denominator amendments without rewriting the historical draft file."""
    import copy
    out = copy.deepcopy(reference)
    out["amendment"] = "C17-M1: owner-approved RQ1A/RQ1B, output origin separated, exact pair contracts"
    for item in out["items"]:
        ident = item["id"]
        if item["rq"] == "RQ1":
            item["rq"] = "RQ1B" if ident in {"F-7", "F-8", "L-5", "L-6"} else "EXCLUDED" if ident == "E-2" else "RQ1A"
        if ident == "L-4":
            item["confidence"] = "firm"
        if ident in {"X3", "X4", "X5"}:
            item["matrix_bucket"] = "candidate_thematic_evolution_unlinked"
        if "ends" in item and item.get("class") == "same_as":
            item.setdefault("expected_relation", "same_as")
            item.setdefault("expected_direction", "either")
    return out


def exact_pair(item: dict, link: dict, a: set, b: set) -> bool:
    rel = item.get("expected_relation")
    direction = item.get("expected_direction")
    if not rel or not direction or item.get("matrix_bucket") == "candidate_thematic_evolution_unlinked":
        return False
    if link.get("rel") != rel:
        return False
    forward = link["from"] in a and link["to"] in b
    reverse = link["from"] in b and link["to"] in a
    return forward if direction == "0_to_1" else reverse if direction == "1_to_0" else (forward or reverse) if direction == "either" else False
MIN_OVERLAP = 16


def occurrences(raw: bytes, quote: str) -> list[tuple[int, int]]:
    q, out, i = quote.encode("utf-8"), [], raw.find(quote.encode("utf-8"))
    while i >= 0:
        out.append((i, i + len(q)))
        i = raw.find(q, i + 1)
    return out


def overlaps(a: list, b: list, need: int) -> bool:
    return any(min(x1, y1) - max(x0, y0) >= need for x0, x1 in a for y0, y1 in b)


class Run:
    def __init__(self, run: pathlib.Path, reference: dict):
        self.path = run
        inputs = run / "inputs"
        snapshot = json.loads((inputs / "snapshot.json").read_text(encoding="utf-8"))
        self.raw = {}
        for key, part in reference["reports"].items():
            paths = [p for p in snapshot["reports"] if part in p]
            if len(paths) != 1:
                raise ValueError(f"report {key} ({part}) matches {len(paths)} inputs of {run.name}")
            self.raw[key] = (inputs / "repo" / paths[0]).read_bytes()
        stem_to_key = {pathlib.Path(p).stem: k for k, part in reference["reports"].items() for p in snapshot["reports"] if part in p}
        doc_key = {d: stem_to_key.get(stem) for d, stem in report_names(run).items()}
        self.records, self.links = load(run)
        _, self.texts = proposals(run)
        contexts = [json.loads(ln) for ln in (run / "contexts.jsonl").read_text(encoding="utf-8").splitlines()]
        tasks = {c["task_id"]: (c.get("kind"), c.get("phase")) for c in contexts if c.get("task_id")}
        self.origin = {rid: tasks.get(r.get("directive"), (None, None)) for rid, r in self.records.items()}
        self.phase = 1
        # every stored observe: its report key and byte spans in that report
        self.observes = {}
        for rid, r in self.records.items():
            t = self.texts.get(rid, {})
            key = doc_key.get(r.get("doc"))
            if t.get("kind") == "observe" and key and t.get("text"):
                self.observes[rid] = (key, occurrences(self.raw[key], t["text"]))
        self.claims = {rid: r for rid, r in self.records.items() if self.texts.get(rid, {}).get("kind") == "claim"}
        summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
        outcomes = ((((summary.get("arm_c") or {}).get("phase1") or {}).get("receipt") or {}).get("outcomes") or {})
        self.answers = {rq: {a.lstrip("@")[:16] for a in o.get("answer_ids") or []} for rq, o in outcomes.items()}

    def spans(self, key: str, quotes: list) -> list:
        return [s for q in quotes for s in occurrences(self.raw[key], q)]

    def end(self, key: str, quotes: list, kinds: set | None = None) -> tuple[set, set]:
        """Observes overlapping the quotes and claims resting on them (directly or through one claim)."""
        target = self.spans(key, quotes)
        obs = {rid for rid, (k, sp) in self.observes.items() if k == key and self.origin.get(rid, (None, None))[1] == self.phase
               and (kinds == {"SUMMARIZE"} or self.origin.get(rid, (None, None))[0] in READING)
               and overlaps(sp, target, MIN_OVERLAP)}
        kinds = READING if kinds is None else kinds
        permitted = lambda rid: self.origin.get(rid, (None, None))[0] in kinds and self.origin.get(rid, (None, None))[1] == self.phase
        # Summary claims may cite reading quotes; the stage is determined by the claim's own origin, never its basis alone.
        direct = {rid for rid, c in self.claims.items() if permitted(rid) and obs & set(c["based"])}
        return obs, direct | {rid for rid, c in self.claims.items() if permitted(rid) and direct & set(c["based"])}

    def trace(self, item: dict) -> dict:
        if "ends" in item:
            ends = [self.end(e["report"], e["quotes"]) for e in item["ends"]]
            a, b = ends[0][1], ends[1][1]
            joining = [l for l in self.links.values() if (l["from"] in a and l["to"] in b) or (l["from"] in b and l["to"] in a)]
            exact = [l for l in joining if exact_pair(item, l, a, b)]
            return {"extracted": all(o for o, _ in ends), "claimed": bool(a and b), "linked": bool(exact),
                    "accepted": any(l["status"] == "accepted" for l in exact), "linked_any_diagnostic": bool(joining),
                    "expected_relation": item.get("expected_relation"), "expected_direction": item.get("expected_direction"),
                    "links": sorted({f"{l['rel']}/{l['status']}" for l in joining})}
        obs, claims = self.end(item["report"], item["quotes"])
        rq = "RQ1" if item["rq"] in {"NEG", "RQ1", "RQ1A", "RQ1B", "EXCLUDED"} else item["rq"]
        fitting = {c for c in claims if self.texts[c].get("stance") in STANCES[item["rq"]]}
        _, summary_claims = self.end(item["report"], item["quotes"], {"SUMMARIZE"})
        return {"extracted": bool(obs), "claimed": bool(claims), "stance": bool(fitting),
                "answered": bool(summary_claims & self.answers.get(rq, set())),
                "reading_claim_ids": sorted(claims), "summary_claim_ids": sorted(summary_claims), "phase": self.phase,
                "stances": dict(Counter(self.texts[c].get("stance") for c in claims))}


def verify(run: Run, reference: dict) -> list:
    bad = []
    for item in reference["items"]:
        for key, quotes in ([(e["report"], e["quotes"]) for e in item["ends"]] if "ends" in item else [(item["report"], item["quotes"])]):
            for q in quotes:
                n = len(occurrences(run.raw[key], q))
                if n != 1:
                    bad.append({"item": item["id"], "report": key, "quote": q, "found": n})
    return bad


STAGES = ("extracted", "claimed", "stance", "answered", "linked", "accepted")


def main(reference_path: str, runs: list[str]) -> list:
    reference = reference_v1(json.loads(pathlib.Path(reference_path).read_text(encoding="utf-8")))
    out = []
    for path in runs:
        run = Run(pathlib.Path(path), reference)
        items = {i["id"]: run.trace(i) for i in reference["items"]}
        stages = {}
        for i in reference["items"]:
            group = f"{i['rq']}/{i.get('confidence', '')}"
            row = stages.setdefault(group, Counter())
            row["items"] += 1
            for s in STAGES:
                row[s] += bool(items[i["id"]].get(s))
        out.append({"run": run.path.name, "quotes_not_unique": verify(run, reference),
                    "stages": {g: dict(c) for g, c in sorted(stages.items())}, "items": items, "phase": run.phase, "link_status_view": "final_WAL_not_phase_snapshot", "caveat": "byte overlap and origin trace; not semantic recall or a blind reference"})
    return out


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1], sys.argv[2:]), ensure_ascii=False, indent=1))
