"""Shared helpers: CLI wrapper, deterministic text generation, ontologies, JSONL builders."""

from __future__ import annotations

import hashlib
import json
import math
import os
import pathlib
import random
import statistics
import subprocess
from typing import Any, Iterable

ROOT = pathlib.Path(__file__).resolve().parents[2]
TARGET_DIR = pathlib.Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target")
if not TARGET_DIR.is_absolute():
    TARGET_DIR = ROOT / TARGET_DIR
# SBGK_BIN overrides the binary (e.g. a build in another target directory)
BIN = (
    pathlib.Path(os.environ["SBGK_BIN"]).resolve()
    if os.environ.get("SBGK_BIN")
    else TARGET_DIR / "release" / ("sbgk.exe" if os.name == "nt" else "sbgk")
)
RESULTS = ROOT / "results"
WORK = RESULTS / "work"

BYTES_PER_TOKEN = 4  # transparent heuristic; only ratios between arms are interpreted

# Report language. "en": the report modules in this package write the reports tracked in git (`SBGK_EXPERIMENT_REPORT*.md`).
# "ru": the local, untracked modules `<name>_ru.py` write `*_RU.md` reports (and `summary_RU.json` where a report writes a summary).
REPORT_LANG = "en"


def report_module(name: str):
    """The report module `sbgk_bench.<name>` (or its local `<name>_ru` variant when REPORT_LANG == "ru")."""
    import importlib
    return importlib.import_module(f"sbgk_bench.{name}_ru" if REPORT_LANG == "ru" else f"sbgk_bench.{name}")


def report_name(stem: str, suffix: str = ".md") -> str:
    """`stem.md` for English, `stem_RU.md` for Russian (e.g. stem = "SBGK_EXPERIMENT_REPORT_DIRECTIVE")."""
    return f"{stem}{'_RU' if REPORT_LANG == 'ru' else ''}{suffix}"


def summary_name() -> str:
    return "summary_RU.json" if REPORT_LANG == "ru" else "summary.json"


def build_release() -> None:
    subprocess.run(["cargo", "build", "--release", "--quiet"], cwd=ROOT, check=True)


def workdir(name: str) -> pathlib.Path:
    p = WORK / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def cli(*args: Any, stdin: str | None = None) -> dict | list:
    """Run `sbgk` and parse its single JSON output document."""
    cmd = [str(BIN)] + [str(a) for a in args]
    r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, encoding="utf-8", cwd=ROOT)
    if r.returncode != 0:
        raise RuntimeError(f"sbgk {' '.join(map(str, args[:3]))}... failed: {r.stderr.strip()[:500]}")
    return json.loads(r.stdout)


def tokens(nbytes: int) -> int:
    return math.ceil(nbytes / BYTES_PER_TOKEN)


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    v = sorted(values)
    return v[round((len(v) - 1) * p)]


def summarize(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "p05": pct(values, 0.05),
        "p95": pct(values, 0.95),
        "min": min(values),
        "max": max(values),
    }


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ------------------------------------------------------------------ JSONL building

def L_bind(local: str, doc: str, quote: str) -> dict:
    return {"op": "bind_evidence", "local_id": local, "doc_id": doc, "exact_quote": quote}


def L_assert(local: str, s: str, p: str, o: str, t: tuple[int, int], evidence: list[str],
             pol: str = "POS", ctx: str = "prod") -> dict:
    return {"op": "assert_fact", "local_id": local, "s": s, "p": p, "o": o, "polarity": pol,
            "ctx": ctx, "t": list(t), "evidence": evidence}


def L_derive(local: str, rule: str, premises: list[str], claim: dict | None = None) -> dict:
    d = {"op": "derive", "local_id": local, "rule": rule, "premises": premises}
    if claim is not None:
        d["claim"] = claim
    return d


def claim_of(s: str, p: str, o: str, t: tuple[int, int], pol: str = "POS", ctx: str = "prod") -> dict:
    return {"s": s, "p": p, "o": o, "polarity": pol, "ctx": ctx, "t": list(t)}


def L_revoke(target: str) -> dict:
    return {"op": "revoke_evidence", "target_evidence": target}


def numbered(ops: Iterable[dict]) -> list[dict]:
    out = []
    for i, o in enumerate(ops, 1):
        d = {"seq": i}
        d.update(o)
        out.append(d)
    return out


def jsonl(ops: Iterable[dict]) -> list[str]:
    return [json.dumps(o, ensure_ascii=False, separators=(",", ":")) for o in ops]


def write_lines(path: pathlib.Path, lines: list[str]) -> int:
    data = "\n".join(lines) + "\n"
    path.write_text(data, encoding="utf-8", newline="\n")
    return len(data.encode("utf-8"))


def intersect(*ts: tuple[int, int]) -> tuple[int, int]:
    return (max(t[0] for t in ts), min(t[1] for t in ts))


# ------------------------------------------------------------------ ontologies

def ontology_review(n_services: int, n_apis: int, n_systems: int = 0) -> dict:
    """Services / APIs / (optional) systems with the two review rules."""
    ents = [{"id": f"svc_{i:03d}", "type": "Service", "aliases": [f"service {i}"]} for i in range(n_services)]
    ents += [{"id": f"api_{i:03d}", "type": "Api", "aliases": [f"interface {i}"]} for i in range(n_apis)]
    ents += [{"id": f"sys_{i:02d}", "type": "System", "aliases": [f"system {i}"]} for i in range(n_systems)]
    preds = [
        {"id": "uses_api", "subject": "Service", "object": "Api"},
        {"id": "api_deprecated", "subject": "Api", "object": "@literal"},
        {"id": "needs_review", "subject": "Service", "object": "@literal"},
    ]
    rules = [{
        "id": "R_depr_review@1", "mode": "AND",
        "body": [{"p": "uses_api"}, {"p": "api_deprecated"}],
        "join": [["0.o", "1.s"]],
        "head": {"s": "0.s", "p": "needs_review", "o": {"const": "true"}},
    }]
    if n_systems:
        preds += [
            {"id": "part_of", "subject": "Service", "object": "System"},
            {"id": "sys_flagged", "subject": "System", "object": "@literal"},
        ]
        rules.append({
            "id": "R_sys_flag@1", "mode": "AND",
            "body": [{"p": "part_of"}, {"p": "needs_review"}],
            "join": [["0.s", "1.s"]],
            "head": {"s": "0.o", "p": "sys_flagged", "o": {"const": "true"}},
        })
    return {"entities": ents, "predicates": preds, "rules": rules}


LITERAL_ENUM = {"api_deprecated": ["true"], "needs_review": ["true"], "sys_flagged": ["true"]}


def with_literal_enum(onto: dict) -> dict:
    """A copy of a review ontology whose literal objects only admit `true` (kernel `allowed_values`). Opt-in for new experiments
    only: the field changes the ontology hash and so every genesis and state root, and the recorded EXP-1..11A runs use none."""
    out = json.loads(json.dumps(onto))
    for p in out["predicates"]:
        if p["id"] in LITERAL_ENUM and p["object"] == "@literal":
            p["allowed_values"] = LITERAL_ENUM[p["id"]]
    return out


def ontology_graph(nodes: list[str]) -> dict:
    """Directed-graph reachability: edge facts + seed/step rules (diamonds, cycles, DAGs)."""
    return {
        "entities": [{"id": n, "type": "Node"} for n in nodes],
        "predicates": [
            {"id": "edge", "subject": "Node", "object": "Node"},
            {"id": "reach", "subject": "Node", "object": "Node"},
        ],
        "rules": [
            {"id": "R_seed@1", "mode": "AND", "body": [{"p": "edge"}],
             "head": {"s": "0.s", "p": "reach", "o": "0.o"}},
            {"id": "R_step@1", "mode": "AND", "body": [{"p": "reach"}, {"p": "edge"}],
             "join": [["0.o", "1.s"]], "head": {"s": "0.s", "p": "reach", "o": "1.o"}},
        ],
    }


# ------------------------------------------------------------------ text generation

_SUBJ = ["the operator", "the custodian", "the regional office", "the audit committee", "the platform owner",
         "the release manager", "the compliance officer", "the data steward", "the incident commander"]
_VERB = ["shall archive", "must review", "is required to publish", "will escalate", "shall notify",
         "must reconcile", "is expected to validate", "shall document", "must retain"]
_OBJ = ["the access logs", "all change requests", "the quarterly summary", "the vendor attestations",
        "the retention schedule", "any exception records", "the capacity forecast", "the recovery drill results",
        "the configuration baseline", "customer-facing notices"]
_TAIL = ["within {n} business days", "before the next audit window", "unless an exemption is granted",
         "in accordance with section {n}", "and report any deviation upward", "using the approved template",
         "during the first week of each quarter", "subject to written approval"]


def filler_sentence(rng: random.Random) -> str:
    s = f"{rng.choice(_SUBJ)} {rng.choice(_VERB)} {rng.choice(_OBJ)} {rng.choice(_TAIL)}"
    s = s.replace("{n}", str(rng.randint(2, 45)))
    return s[0].upper() + s[1:] + "."


def filler_paragraph(rng: random.Random, lo: int = 3, hi: int = 6) -> str:
    return " ".join(filler_sentence(rng) for _ in range(rng.randint(lo, hi)))


def make_doc(rng: random.Random, target_bytes: int, fact_sentences: list[str], reserve_front: int = 3,
             reserve_back: int = 2) -> list[str]:
    """Paragraph list of roughly `target_bytes` with the fact sentences spread over the body.
    The first `reserve_front` and last `reserve_back` paragraphs are always pure filler."""
    paras: list[str] = []
    size = 0
    while size < target_bytes:
        p = filler_paragraph(rng)
        paras.append(p)
        size += len(p) + 2
    body = list(range(reserve_front, len(paras) - reserve_back))
    slots = sorted(rng.sample(body, len(fact_sentences)))
    for slot, fact in zip(slots, fact_sentences):
        paras[slot] = fact
    return paras


def join_doc(paras: list[str]) -> bytes:
    return ("\n\n".join(paras) + "\n").encode("utf-8")


def write_docs(dirpath: pathlib.Path, docs: dict[str, bytes]) -> None:
    dirpath.mkdir(parents=True, exist_ok=True)
    for f in dirpath.glob("*.txt"):
        f.unlink()
    for name, data in docs.items():
        (dirpath / f"{name}.txt").write_bytes(data)
