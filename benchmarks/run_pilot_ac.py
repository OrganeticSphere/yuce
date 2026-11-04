"""Comparative pilot A vs C on a corpus of dated reports (see `sbgk_bench/pilot_ac.py`).

  python benchmarks/run_pilot_ac.py --selftest          # a synthetic corpus, the stub model, both arms and phases; asserts ($0)
  python benchmarks/run_pilot_ac.py --manifest <corpus>/manifest.json --repo <corpus> --reports <corpus>/reports.txt
      --checklist <checklist.md> --withdrawal-plan <plan.json> --model stub
                                                        # a corpus (benchmarks/corpora/...) with the stub model: the mechanics ($0)

A corpus is given by --reports with its own --checklist and --withdrawal-plan. The options and models of the closed layer
(pilot_ac.CLOSED_OPTIONS, pilot_ac.CLOSED_MODELS) need the package benchmarks/sbgk_bench/closed.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from sbgk_bench import common as C  # noqa: E402
from sbgk_bench import pilot_ac as P  # noqa: E402


def save_json(path: pathlib.Path, value: dict) -> None:
    """Replace only an artifact in this newly reserved run, with a flushed complete JSON value."""
    from sbgk_bench.atomic_output import write_text
    write_text(path,json.dumps(value,indent=1,ensure_ascii=False))



class Evidence:
    """Append completed calls immediately, including when a later arm fails."""

    FILES = {"call": "calls.jsonl", "event": "events.jsonl", "context": "contexts.jsonl", "call_started": "call_starts.jsonl",
             "reply": "replies.jsonl"}

    def __init__(self, out: pathlib.Path):
        self.out, self.lock = out, threading.Lock()
        self.seen = {kind: Counter() for kind in self.FILES}
        self.sequence = 0
        self.progress = None
        for filename in (*self.FILES.values(), "journal.jsonl"):
            (out / filename).touch(exist_ok=False)

    @staticmethod
    def key(value: dict) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)

    def __call__(self, kind: str, value: dict) -> None:
        encoded = self.key(value)
        with self.lock:
            self.sequence += 1
            for filename, line in ((self.FILES[kind], encoded), ("journal.jsonl", self.key(
                    {"sequence": self.sequence, "kind": kind, "record": value}))):
                with (self.out / filename).open("a", encoding="utf-8", newline="\n") as f:
                    f.write(line + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            self.seen[kind][encoded] += 1
        if kind == "event" and value.get("status_sample") and self.progress is not None:
            self.progress()

    def mark(self) -> dict:
        with self.lock:
            return {kind: counts.copy() for kind, counts in self.seen.items()}

    def reconcile(self, arm: dict, before: dict | None = None) -> None:
        # Preserve returned records from adapters without a sink; retain repeated equal events.
        for kind, field in (("call", "calls"), ("event", "events")):
            remaining = self.seen[kind] - ((before or {}).get(kind) or Counter())
            for value in arm.get(field, []):
                key = self.key(value)
                if remaining[key]:
                    remaining[key] -= 1
                else:
                    self(kind, value)


def freeze_inputs(manifest: pathlib.Path, repo: pathlib.Path, reports: list[str], out: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, dict, dict]:
    """Both arms consume these exact captured bytes, even if the original checkout changes later."""
    if not reports or len(set(reports)) != len(reports):
        raise ValueError("reports must be nonempty and unique")
    raw_manifest = manifest.read_bytes()
    inputs = out / "inputs"
    staged_repo = inputs / "repo"
    staged_repo.mkdir(parents=True)
    pinned_manifest = inputs / "manifest.json"
    pinned_manifest.write_bytes(raw_manifest)
    docs, hashes = {}, {}
    for name in reports:
        relative = pathlib.PurePosixPath(name)
        if (relative.is_absolute() or "\\" in name or ":" in name or
                any(part in ("", ".", "..") for part in name.split("/"))):
            raise ValueError(f"unsafe report path: {name}")
        source = (repo / name).resolve()
        if not source.is_relative_to(repo.resolve()):
            raise ValueError(f"report resolves outside the source repository: {name}")
        raw = source.read_bytes()
        docs[name] = raw.decode("utf-8")
        dest = staged_repo / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        hashes[name] = {"size_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest()}
    corpus = {"manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(), "reports": reports,
              "source_bytes": hashes, "section_bytes": P.SECTION_BYTES, "questions": P.QUESTIONS}
    save_json(inputs / "snapshot.json", corpus)
    return pinned_manifest, staged_repo, docs, corpus


def provenance() -> dict:
    """What ran, fixed at the start of a run (Codex on 10A-6: the export did not name the revision or the binary): the commit and
    tree, the tracked files changed against them, and the SHA-256 of the kernel binary and of the runner's sources."""
    root = pathlib.Path(__file__).resolve().parents[1]

    def git(*args: str) -> str | None:
        try:
            cp = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=30)
            return cp.stdout.strip() if cp.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            return None

    def digest(path: pathlib.Path) -> str | None:
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return None

    dirty = git("status", "--porcelain", "--untracked-files=no")
    here = pathlib.Path(__file__).resolve().parent
    # the closed layer's sources too, when it is installed: a run may use them
    closed = sorted(p.relative_to(here).as_posix() for p in (here / "sbgk_bench" / "closed").glob("*.py") if not p.name.startswith("test_"))
    return {"git_head": git("rev-parse", "HEAD"), "git_tree": git("rev-parse", "HEAD^{tree}"),
            "changed_tracked_files": dirty.splitlines() if dirty else [], "sbgk_bin": str(C.BIN), "sbgk_sha256": digest(pathlib.Path(C.BIN)),
            "runner_sha256": {name: digest(here / name) for name in ("run_pilot_ac.py", "sbgk_bench/pilot_ac.py", *closed)}}


def corpus_choice(reports: pathlib.Path | None, plan: pathlib.Path | None, checklist: pathlib.Path | None,
                  withdraw: dict | None) -> tuple[list[str], dict, str]:
    """The reports, the withdrawal plan and the blind checklist of a run. A corpus given by a file brings both, so a checklist
    never grades a corpus it was not written for (registry R18). Without --reports the run is the first pilot's six private
    reports with their fixed plan and checklist, which only the closed layer holds."""
    if plan is not None and withdraw is not None:
        raise ValueError("give --withdraw or --withdrawal-plan, not both")
    if reports is None:
        if plan is not None or checklist is not None:
            raise ValueError("--withdrawal-plan and --checklist go with --reports")
        try:
            closed = P.closed_layer("a run without --reports (the first pilot's private six reports)")
        except P.ClosedLayerMissing as e:
            raise ValueError(f"{e}: give the corpus by --reports with its --checklist and --withdrawal-plan") from None
        return closed.REPORTS, withdraw or closed.TOBI_WITHDRAWAL, closed.CHECKLIST
    chosen = [ln.strip() for ln in reports.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not chosen or len(set(chosen)) != len(chosen):
        raise ValueError("--reports needs distinct report paths, one per line")
    if checklist is None or (plan is None and withdraw is None):
        raise ValueError("a corpus given by --reports needs its own --checklist and --withdrawal-plan (or --withdraw)")
    return chosen, withdraw or json.loads(plan.read_text(encoding="utf-8")), checklist.read_text(encoding="utf-8")



def write_circle_artifacts(out: pathlib.Path, models: dict[str, str], *, stage: str, error: str | None = None, telemetry: dict | None = None) -> dict:
    """Publish a durable prefix during C, before A, and on handled interrupts."""
    from sbgk_bench.circle_metrics import circle_metrics, acceptance_svg, matrix_markdown, jsonl_prefix
    warnings = []
    events = list(jsonl_prefix(out / "events.jsonl", warnings))
    metrics = circle_metrics(out / "arm_c" / "run.wal", events, models, frames=telemetry["frames"] if telemetry is not None else None)
    metrics["input_source"]={"kind":"authenticated_committed_checkpoints","through_sequence":telemetry.get("through_sequence"),"wal_head":telemetry.get("wal_head")} if telemetry is not None else {"kind":"closed_wal"}
    metrics["source_warnings"].extend(warnings)
    metrics["export"] = {"stage": stage, "interrupted": error is not None, "error": error, "generated_unix_ms": round(time.time()*1000),
                         "source": "durable C WAL and event journal; open circles stay open"}
    from sbgk_bench.atomic_output import write_text
    errors=[]
    for name,render in (("circle_acceptance.svg",lambda:acceptance_svg(metrics)),
                        ("circle_model_matrix.md",lambda:matrix_markdown(metrics))):
        try:
            write_text(out/name,render())
        except Exception as exc:
            errors.append({"artifact":name,"error":f"{type(exc).__name__}: {exc}"})
    metrics["export"]["artifact_errors"] = errors
    try:
        save_json(out / "circles.json",metrics)
    except OSError as exc:
        errors.append({"artifact":"circles.json","error":f"{type(exc).__name__}: {exc}"})
    if errors:
        try:
            save_json(out/"circle_artifacts_error.json",{"stage":stage,"errors":errors})
        except OSError:
            pass  # the primary summary still receives the errors; failed complete payloads remain in their tmp files
    return metrics


def safe_circle_artifacts(out, models, *, stage, error=None, telemetry=None):
    try:
        return write_circle_artifacts(out,models,stage=stage,error=error,telemetry=telemetry)
    except Exception as exc:
        failed={"stage":stage,"error":f"{type(exc).__name__}: {exc}"}
        try:
            save_json(out/"circle_artifacts_error.json",failed)
        except OSError:
            pass
        return {"rows":[],"boundaries":[],"definition":"Snapshot unavailable; primary arm results are preserved",
                "export":dict(failed,interrupted=error is not None,artifact_errors=[failed])}

def safe_graph_shape(path):
    try:
        return P.graph_shape(path)
    except Exception as exc:
        return {"status":"UNAVAILABLE","error":f"{type(exc).__name__}: {exc}"}

def reuse_arm_c(src: pathlib.Path, out: pathlib.Path, corpus: dict, withdraw: dict) -> tuple[dict, dict]:
    """Arm C of an earlier finished run on the same inputs, taken as it ended (the owner, 2026-10-29: arm C of MCPpair2_r1 finished
    every phase, and arm A lost its withdrawals to a runner defect: run only arm A again). The earlier run's corpus, questions and
    withdrawal plan must be this run's; its arm C result, WAL and circle files are copied, and where they came from is recorded."""
    status = json.loads((src / "status.json").read_text(encoding="utf-8"))
    if status.get("status") != "FINISHED":
        raise ValueError(f"{src}: arm C is taken only from a finished run")
    old = status.get("corpus") or {}
    for field in ("manifest_sha256", "reports", "source_bytes", "section_bytes", "questions"):
        if old.get(field) != corpus.get(field):
            raise ValueError(f"{src}: arm C ran on other inputs ({field})")
    if json.loads((src / "withdrawal.json").read_text(encoding="utf-8")) != json.loads(json.dumps(withdraw)):
        raise ValueError(f"{src}: arm C ran another withdrawal plan")
    c = json.loads((src / "arm_c.json").read_text(encoding="utf-8"))
    if c.get("stopped"):
        raise ValueError(f"{src}: arm C stopped ({c['stopped']}); only a finished arm C is taken")
    # the graph's measure reads the current concept associations from the ontology snapshot beside arm C, when there is one: it
    # goes with arm C, and a snapshot arm C declared must be there (Codex review of 4abec7e, REUSE-01)
    snapshot = src / "ontology_evolution.json"
    if (c.get("ontology_evolution") or {}).get("status") == "EXPORTED" and not snapshot.is_file():
        raise ValueError(f"{src}: arm C exported its ontology snapshot, and ontology_evolution.json is missing")
    shutil.copytree(src / "arm_c", out / "arm_c")
    shutil.copy2(src / "arm_c.json", out / "arm_c.json")
    for name in ("circles.json", "circle_acceptance.svg", "circle_model_matrix.md", "ontology_evolution.json"):
        if (src / name).exists():
            shutil.copy2(src / name, out / name)
    if P.graph_shape(out / "arm_c" / "run.wal") != P.graph_shape(src / "arm_c" / "run.wal"):
        raise ValueError(f"{src}: the graph's measure of the copied arm C differs from the source's")
    summary = json.loads((src / "summary.json").read_text(encoding="utf-8"))
    reused = {"from": str(src), "provenance": json.loads((src / "provenance.json").read_text(encoding="utf-8")),
              "arm_c_sha256": hashlib.sha256((src / "arm_c.json").read_bytes()).hexdigest(),
              "ontology_evolution_sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest() if snapshot.is_file() else None,
              "spend_c": ((summary.get("spend") or {}).get("budget") or {}).get("C"), "circles": (summary.get("measures") or {}).get("circles")}
    save_json(out / "arm_c_reused.json", {k: v for k, v in reused.items() if k != "circles"})
    return c, reused


def run(manifest: pathlib.Path, repo: pathlib.Path, reports: list[str], out: pathlib.Path, model: P.Model, workers: int, withdraw: dict | None,
        budget_usd: float | None = None, builder: P.Model | None = None, phase_timeout_s: float = 1800, builder_card: dict | None = None,
        jev: P.Model | None = None, checklist: str | None = None, team: list[P.Model] | None = None, max_calls: int = P.MAX_CALLS) -> dict:
    builder = builder or model
    if type(max_calls) is not int or max_calls < 1:
        raise ValueError("max_calls must be a positive integer")
    if P.CIRCLES and not P.DYNAMIC_ROLES:
        raise ValueError("circles require dynamic roles")
    if P.DYNAMIC_ROLES and (team is None or len(team) < 3):
        raise ValueError("dynamic roles need at least three readers")
    if (P.ARM_A_MODE == "team") != bool(team):
        raise ValueError("a team goes with arm A as the same team without the kernel (ARM_A_MODE team), and only with it")
    if team:
        workers = len(team)
    if type(workers) is not int or workers < 1:
        raise ValueError("workers must be a positive integer")
    # a phase deadline is a finite positive number of seconds: inf or NaN would switch the deadline off (Codex review d7d9a49, D10)
    if not (isinstance(phase_timeout_s, (int, float)) and math.isfinite(phase_timeout_s) and phase_timeout_s > 0):
        raise ValueError("phase_timeout_s must be a finite positive number of seconds")
    out.mkdir(parents=True, exist_ok=False)
    ran = provenance()
    save_json(out / "provenance.json", ran)
    evidence = Evidence(out)
    stage = "inputs"
    circle_models = {f"w{i}":m.name for i,m in enumerate(team or [],start=1)}
    circle_models[P.LINK_CHECKER_ID] = getattr(P.CHECKER_MODEL or model,"name","unknown")
    try:
        pinned_manifest, staged_repo, docs, corpus = freeze_inputs(manifest, repo, reports, out)
        if checklist is not None:  # the blind checklist written for this corpus (corpus_choice); a synthetic run may have none
            (out / "checklist.md").write_text(checklist, encoding="utf-8", newline="\n")
        withdraw = withdraw or P.default_withdrawal(docs)
        for step in P.withdrawal_steps(withdraw):
            for cand in step["candidates"]:
                if step.get("report") not in docs or not cand.get("quote") or cand["quote"] not in docs[step["report"]] or cand["anchor"] not in cand["quote"]:
                    raise ValueError("withdrawal must name a selected report and an exact quote in it (with its anchor)")
        save_json(out / "withdrawal.json", withdraw)
        # one brake per arm (S1: the kernel's arm spent the shared brake and arm A stopped before its last withdrawal step)
        budgets = {arm: P.Budget(budget_usd) if budget_usd is not None else None for arm in ("C", "A")}
        balance_before = model.balance() if hasattr(model, "balance") else None
        save_json(out / "status.json", {"status": "RUNNING", "stage": "arm_c", "corpus": corpus})
        stage = "arm_c"
        reused = None
        if P.REUSE_ARM_C is not None:
            c, reused = reuse_arm_c(P.REUSE_ARM_C, out, corpus, withdraw)
            circle_data = reused["circles"]
        elif P.CIRCLES:
            safe_circle_artifacts(out, circle_models, stage="arm_c_starting")
            last_progress = -math.inf
            def progress():
                nonlocal last_progress
                now = time.monotonic()
                if now-last_progress < 30:
                    return
                last_progress = now
                try:
                    provider=getattr(evidence,"circle_telemetry",None)
                    if provider is None: return
                    snapshot=provider()
                    if snapshot.get("format")!="r2r-circle-telemetry/1" or snapshot.get("complete") is not True: raise ValueError("kernel circle telemetry unavailable/incomplete")
                    safe_circle_artifacts(out, circle_models, stage="arm_c_progress",telemetry=snapshot)
                except Exception as artifact_error:
                    save_json(out / "circle_artifacts_error.json", {"stage":"arm_c_progress","error":f"{type(artifact_error).__name__}: {artifact_error}"})
            evidence.progress = progress
        if reused is None:
            before = evidence.mark()
            c = P.run_arm_c(model, builder, out / "arm_c", pinned_manifest, staged_repo, reports, docs, withdraw,
                            workers=workers, timeout_s=phase_timeout_s, evidence=evidence, budget=budgets["C"], builder_card=builder_card, jev=jev,
                            team=team, max_calls=max_calls)
            evidence.progress = None
            evidence.reconcile(c, before)
            save_json(out / "arm_c.json", c)
            if P.CIRCLES:
                circle_data = safe_circle_artifacts(out, circle_models, stage="arm_c_returned")
        stage = "arm_a"
        save_json(out / "status.json", {"status": "RUNNING", "stage": stage, "corpus": corpus})
        before = evidence.mark()
        if P.ARM_A_FROZEN:
            a = P.frozen_arm_a()
        elif P.ARM_A_MODE == "whole":
            a = P.run_arm_whole(model, docs, withdraw, c.get("whole") or {}, timeout_s=phase_timeout_s, evidence=evidence, budget=budgets["A"],
                                chosen=c.get("withdrawals"), max_calls=max_calls)
        elif P.ARM_A_MODE == "team":
            a = P.run_arm_team(team, docs, withdraw, timeout_s=phase_timeout_s, evidence=evidence, budget=budgets["A"], chosen=c.get("withdrawals"), max_calls=max_calls)
        elif P.ARM_A_MODE == "single":
            a = P.run_arm_single(model, docs, withdraw, timeout_s=phase_timeout_s, evidence=evidence, budget=budgets["A"],
                                 chosen=c.get("withdrawals"), max_calls=max_calls)
        else:
            a = P.run_arm_a(model, docs, withdraw, workers=workers, timeout_s=phase_timeout_s, evidence=evidence, budget=budgets["A"],
                            chosen=c.get("withdrawals"), max_calls=max_calls)
        evidence.reconcile(a, before)
        save_json(out / "arm_a.json", a)
        stage = "artifacts"
        artifact_errors=[]
        def artifact_step(name,fn,default):
            try: return fn()
            except Exception as exc:
                failure={"step":name,"error":f"{type(exc).__name__}: {exc}"};artifact_errors.append(failure)
                return dict(default,artifact_error=failure) if isinstance(default,dict) else default
        balance_after = artifact_step("balance_after",model.balance,None) if hasattr(model,"balance") else None
        spend = {"budget": {arm: b.state() for arm, b in budgets.items()} if budget_usd is not None else None, "budget_per_arm": True,
                 "balance_before_usd": balance_before, "balance_after_usd": balance_after,
                 "balance_spent_usd": round(balance_before - balance_after, 4) if balance_before is not None and balance_after is not None else None,
                 # the provider's invoice for this run: filled in from its usage export, never from the estimate (Codex's review of
                 # f23c349: one calibration does not make the formula a billing fact for every later run)
                 "billed_usd": None, "billed_source": None,
                 # DeepSeek settles the balance minutes after the calls: read at the end of a run it showed 0.36 for 10A-14, whose
                 # hourly usage export billed 0.472065, the brake's sum; the rest left the balance before the next run
                 "spend_note": "budget.spent_usd_estimate is usage x configured rates (an unknown cost keeps its reservation); it matched "
                               "DeepSeek's hourly usage export for 10A-11..10A-14 (the owner's export of 2026-10-23), a calibration, not "
                               "this run's invoice. balance_spent_usd is read at the end of the run and lags the provider's settlement"}
        if reused is not None and spend.get("budget"):
            spend["budget"]["C"] = reused["spend_c"]  # the earlier run's brake of arm C
        measures=artifact_step("measures",lambda:P.measures(a,c,docs),{"status":"UNAVAILABLE"})
        graph=artifact_step("graph_shape",lambda:P.graph_shape(out/"arm_c"/"run.wal"),{"status":"UNAVAILABLE"})
        measures["graph_shape"]=graph
        phases = ("phase1", "phase2", "phase3", "phase4")
        summary = {"provenance": ran, "arm_c_reused": None if reused is None else {k: v for k, v in reused.items() if k != "circles"},
                   "executor": P.executors.describe(), "corpus": corpus, "model": model.name, "model_config": getattr(model, "config", None), "builder_model": "per-card" if P.DYNAMIC_ROLES else builder.name,
                   "builder_model_config": None if P.DYNAMIC_ROLES else getattr(builder, "config", None), "builder_card": builder_card or "kernel defaults",
                   "jev_config": getattr(jev, "config", None),
                   "phase_timeout_s": phase_timeout_s, "workers": len(team) if team else workers, "builder_requests": P.BUILDER_REQUESTS,
                   "dynamic_roles": {"enabled": P.DYNAMIC_ROLES, "build_backlog": P.BUILD_BACKLOG,
                                     "checker": getattr(P.CHECKER_MODEL, "name", None), "max_calls_per_arm": max_calls,
                                     "circles": P.CIRCLES, "wave_sections": P.WAVE_SECTIONS,
                                     **({"circles_refiner":{"model":P.CIRCLES_REFINER.name,"refine_budget_s":P.REFINE_BUDGET_S,"timeout_s":getattr(P.CIRCLES_REFINER,"timeout_s",None)}} if P.CIRCLES_REFINER is not None else {}), "agy_timeout_s": P.AGY_TIMEOUT_S, "agent_timeout_s": P.AGENT_TIMEOUT_S,
                                     **({"graph_quality":P.GRAPH_QUALITY} if P.GRAPH_QUALITY else {}),"ontology_revisions":P.ONTOLOGY_REVISIONS,"ontology_review":P.ONTOLOGY_REVIEW,**({"unattested_at_end":True} if P.UNATTESTED_AT_END else {}),"anomaly_effort":P.ANOMALY_EFFORT,"ontology_thresholds":P.ONTOLOGY_THRESHOLDS, "phase_effort": P.PHASE_EFFORT, "answer_timeout_s": P.ANSWER_TIMEOUT_S,**({"agent_attempts":P.AGENT_ATTEMPTS} if P.AGENT_ATTEMPTS is not None else {}),**({"arm_a_answer":P.ARM_A_ANSWER} if P.ARM_A_ANSWER!="direct" else {}),**({"arm_a_reduce":P.ARM_A_REDUCE} if P.ARM_A_REDUCE!="single" else {}),**({"arm_a_orchestration":P.ARM_A_ORCHESTRATION} if P.ARM_A_ORCHESTRATION!="runner" else {}),**({"build_scope":P.BUILD_SCOPE} if P.BUILD_SCOPE!="full" else {})},
                   "strong_reader": {"arm_a": P.ARM_A_MODE, "max_lines": P.MAX_LINES, "pairs_only": P.PAIRS_ONLY, "link_checker": P.LINK_CHECKER,
                                     "whole_reader": P.WHOLE_READER, "whole_steps": P.WHOLE_STEPS, "whole_links": P.WHOLE_LINKS},
                   "team": [{"agent": f"w{i}", "model": m.name, "config": getattr(m, "config", None)} for i, m in enumerate(team, start=1)] if team else None,
                   "backpressure": {"records": P.BACKPRESSURE_RECORDS, "per_task": P.BACKPRESSURE_PER_TASK} if P.BACKPRESSURE_RECORDS else None,
                   "withdrawn": c.get("withdrawn"), "spend": spend,
                   "measures": measures, "artifact_errors":artifact_errors,
                   "arm_c": {k: c.get(k) for k in ("server", *phases, "revoke", "stopped")},
                   "arm_a": {k: a.get(k) for k in (*phases, "stopped")}}
        if P.CIRCLES:
            summary["measures"]["circles"] = circle_data
        save_json(out / "summary.json", summary)
        def blind_step():
            blind,key=P.answers_md(a,c)
            from sbgk_bench.atomic_output import write_text
            write_text(out/"answers_blind.md",blind);save_json(out/"answers_key.json",key)
        artifact_step("blind_answers",blind_step,None)
        save_json(out/"summary.json",summary)
        save_json(out / "status.json", {"status": "FINISHED", "stage": "artifacts", "corpus": corpus})
        return summary
    except BaseException as e:
        evidence.progress = None
        if P.CIRCLES:
            try:
                safe_circle_artifacts(out, circle_models, stage=stage, error=f"{type(e).__name__}: {e}")
            except Exception as artifact_error:
                save_json(out / "circle_artifacts_error.json", {"stage": stage, "error": f"{type(artifact_error).__name__}: {artifact_error}"})
        save_json(out / "status.json", {"status": "FAILED", "stage": stage, "error": f"{type(e).__name__}: {e}"})
        raise


# Front matter as the first pilot's reports have it: the later report names the earlier one, so the kernel finds the pair (A4)
# and the selftest takes a pair card to its end.
SYNTH = {
    "reports/early.md": "+++\nreport_id = \"early\"\ndate = \"2026-01-01\"\n+++\n"
                        "# Gate decision\nThe compatibility gate treats a version mismatch as a warning only.\n\n# Limits\n"
                        "Version negotiation is future work for a later stage.\n",
    "reports/later.md": "+++\nreport_id = \"later\"\ndate = \"2026-02-01\"\npredecessor_reports = [\"early\"]\n+++\n"
                        "# Freeze\nThe earlier warning rule is superseded: a version mismatch is now blocking.\n\n# Open\n"
                        "A known limitation remains: no release of the negotiation code.\n",
}


def selftest(workers: int) -> None:
    """Both arms on the synthetic corpus with the stub model, then the strong-reader comparison: one reader and a link checker in
    the kernel's arm, the builder on the kernel's pairs only, one agent without the kernel; then the team comparison: two readers and
    the link checker with the kernel against the same two sharing notes; then run S1.2: one agent's whole reading through the
    kernel's zone against the same answer without it, then run S1.3's steps: atomic records, the answers in their own call, a
    refusal asked about, a withdrawal restated on the remaining quotes."""
    selftest_run(workers)
    saved = (P.ARM_A_MODE, P.PAIRS_ONLY, P.LINK_CHECKER, P.MAX_LINES, P.WHOLE_READER, P.WHOLE_STEPS, P.WHOLE_LINKS, P.DYNAMIC_ROLES, P.BUILD_BACKLOG, P.CHECKER_MODEL, P.CIRCLES, P.WAVE_SECTIONS)
    try:
        P.ARM_A_MODE, P.PAIRS_ONLY, P.LINK_CHECKER, P.MAX_LINES = "single", True, True, 96
        selftest_run(1)
        P.ARM_A_MODE = "team"
        selftest_run(2, [P.StubModel(), P.StubModel()])
        P.ARM_A_MODE, P.WHOLE_READER, P.MAX_LINES = "whole", True, P.WHOLE_LINES
        selftest_run(1)
        P.WHOLE_STEPS = True
        selftest_run(1)
        P.LINK_CHECKER, P.WHOLE_LINKS = False, False
        selftest_run(1)
        P.ARM_A_MODE, P.PAIRS_ONLY, P.LINK_CHECKER = "team", False, True
        P.WHOLE_READER, P.WHOLE_STEPS, P.WHOLE_LINKS = False, False, True
        P.DYNAMIC_ROLES, P.BUILD_BACKLOG, P.CHECKER_MODEL = True, 1, P.StubModel()
        selftest_run(3, [P.StubModel(), P.StubModel(), P.StubModel()])
        P.CIRCLES, P.WAVE_SECTIONS = True, 3
        selftest_circles()
        selftest_circles_refiner()
    finally:
        P.ARM_A_MODE, P.PAIRS_ONLY, P.LINK_CHECKER, P.MAX_LINES, P.WHOLE_READER, P.WHOLE_STEPS, P.WHOLE_LINKS, P.DYNAMIC_ROLES, P.BUILD_BACKLOG, P.CHECKER_MODEL, P.CIRCLES, P.WAVE_SECTIONS = saved



def selftest_circles() -> None:
    """Three real kernel waves; a three-party model barrier proves concurrent BUILD without providers."""
    from sbgk_bench.circle_metrics import circle_metrics, acceptance_svg
    barrier = threading.Barrier(3)
    class CircleStub(P.StubModel):
        def __init__(self, name):
            self.name = name
        def complete(self, prompt):
            if "\nCARD:\n" in prompt:
                card = json.loads(prompt.split("\nCARD:\n", 1)[1].split("\nALREADY MAPPED", 1)[0])
                if card["records"]:
                    barrier.wait(timeout=15)
            return super().complete(prompt)
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        docs = {f"reports/circle_{i}.md": f"# Rule {i}\nA known limitation remains for version rule {i}.\n" for i in range(9)}
        entries = []
        for path, text in docs.items():
            dest = root / "repo" / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            raw = text.encode("utf-8")
            dest.write_bytes(raw)
            entries.append({"path": path, "extension": ".md", "corpus_role": "markdown_document_candidate",
                            "size_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(),
                            "references": {"commit_candidates": [], "pull_request_candidates": []}})
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({"format": "r2r.tobi_corpus_metadata_manifest.v1", "entries": entries,
                                        "source": {"origin_recorded": "https://example.invalid/circles.git", "commit": "1" * 40,
                                                   "repository": "local"}}), encoding="utf-8")
        readers = [CircleStub(f"stub-circle-{i}") for i in range(3)]
        result = P.run_arm_c(readers[0], readers[0], root / "work", manifest, root / "repo", list(docs), docs,
                             {"steps": []}, workers=3, timeout_s=120, max_calls=100, team=readers,
                             builder_card={"max_records": 16})
        assert result["phase1"]["receipt"]["status"] == "TERMINAL", result
        metrics = circle_metrics(root / "work" / "run.wal", result["events"],{f"w{i}":m.name for i,m in enumerate(readers,start=1)})
        rows = metrics["rows"]
        if os.environ.get("SBGK_CIRCLES_SELFTEST_OUT"):
            out = pathlib.Path(os.environ["SBGK_CIRCLES_SELFTEST_OUT"])
            out.mkdir(parents=True, exist_ok=False)
            save_json(out / "result.json", result)
            save_json(out / "circles.json", metrics)
            (out / "run.wal").write_bytes((root / "work" / "run.wal").read_bytes())
            (out / "circle_acceptance.svg").write_text(acceptance_svg(metrics), encoding="utf-8", newline="\n")
        assert len(rows) >= 3 and all(r["closed"] for r in rows), rows
        for row in rows:
            reads = [c for c in result["calls"] if c.get("circle") == row["circle"] and c["role"] == "EXTEND"]
            builds = [c for c in result["calls"] if c.get("circle") == row["circle"] and c["role"] == "BUILD" and c.get("circle_phase") == "BUILD"]
            assert len(reads) == 3 and len(builds) == 3, (row, reads, builds)
            assert max(c["finished_at"] for c in reads) <= min(c["started_at"] for c in builds), row
            later = [c for c in result["calls"] if c.get("circle") == row["circle"] + 1 and c["role"] == "EXTEND"]
            assert not later or max(c["finished_at"] for c in builds) <= min(c["started_at"] for c in later), row
        active, peak = set(), 0
        for e in result["events"]:
            if e.get("kind") == "BUILD" and e.get("outcome") == "CARD_ASSIGNED":
                active.add(e["card"])
                peak = max(peak, len(active))
            elif e.get("kind") == "BUILD" and e.get("outcome") == "CARD_DONE":
                active.discard(e["card"])
        assert peak >= 3, peak
        st = result["phase1"]["status"]
        assert st["builder_cursor"] == st["records"] and st["open_builder_cards"] == 0, st
        evidence = {"selftest": "circles-ok", "circles": len(rows), "peak_concurrent_cards": peak,
                    "receipt": result["phase1"]["receipt"]["status"], "metrics": metrics}
        print(json.dumps(evidence))

def selftest_circles_refiner() -> None:
    """Circles +1 on three real kernel waves: the swarm's BUILD, then the independent refiner, then the next reading."""
    from sbgk_bench.circle_metrics import circle_metrics
    saved = (P.CIRCLES_REFINER, P.REFINE_BUDGET_S)
    P.CIRCLES_REFINER, P.REFINE_BUDGET_S = P.StubModel(), 60.0
    P.CIRCLES_REFINER.name = "stub-refiner"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            docs = {f"reports/circle_{i}.md": f"# Rule {i}\nA known limitation remains for version rule {i}.\n" for i in range(9)}
            entries = []
            for path, text in docs.items():
                dest = root / "repo" / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                raw = text.encode("utf-8")
                dest.write_bytes(raw)
                entries.append({"path": path, "extension": ".md", "corpus_role": "markdown_document_candidate",
                                "size_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(),
                                "references": {"commit_candidates": [], "pull_request_candidates": []}})
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"format": "r2r.tobi_corpus_metadata_manifest.v1", "entries": entries,
                                            "source": {"origin_recorded": "https://example.invalid/circles.git", "commit": "1" * 40,
                                                       "repository": "local"}}), encoding="utf-8")
            readers = [P.StubModel() for _ in range(3)]
            result = P.run_arm_c(readers[0], readers[0], root / "work", manifest, root / "repo", list(docs), docs,
                                 {"steps": []}, workers=3, timeout_s=120, max_calls=200, team=readers, builder_card={"max_records": 16})
            assert result["phase1"]["receipt"]["status"] == "TERMINAL", result
            refines = [c for c in result["calls"] if c["role"] == "REFINER"]
            assert refines and all(c.get("circle_phase") == "REFINE" for c in refines), refines
            for n in sorted({c["circle"] for c in refines}):
                builds = [c for c in result["calls"] if c.get("circle") == n and c["role"] == "BUILD"]
                mine = [c for c in refines if c["circle"] == n]
                later = [c for c in result["calls"] if c.get("circle") == n + 1 and c["role"] == "EXTEND"]
                assert not builds or max(c["finished_at"] for c in builds) <= min(c["started_at"] for c in mine), n
                assert not later or max(c["finished_at"] for c in mine) <= min(c["started_at"] for c in later), n
            metrics = circle_metrics(root / "work" / "run.wal", result["events"], {f"w{i}": m.name for i, m in enumerate(readers, start=1)})
            print(json.dumps({"selftest": "circles-refiner-ok", "refiner_calls": len(refines),
                              "circles_refined": sorted({c["circle"] for c in refines}), "circles": len(metrics["rows"])}))
    finally:
        P.CIRCLES_REFINER, P.REFINE_BUDGET_S = saved


def selftest_run(workers: int, team: list[P.Model] | None = None) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        entries = []
        for path, text in SYNTH.items():
            (root / "repo" / path).parent.mkdir(parents=True, exist_ok=True)
            (root / "repo" / path).write_text(text, encoding="utf-8", newline="\n")
            raw = text.encode("utf-8")
            entries.append({"path": path, "extension": ".md", "corpus_role": "markdown_document_candidate", "size_bytes": len(raw),
                            "raw_sha256": hashlib.sha256(raw).hexdigest(), "references": {"commit_candidates": [], "pull_request_candidates": []}})
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({"format": "r2r.tobi_corpus_metadata_manifest.v1", "entries": entries,
                                        "source": {"origin_recorded": "https://example.invalid/r.git", "commit": "1" * 40, "repository": "local"}}),
                            encoding="utf-8")
        gone = "The earlier warning rule is superseded: a version mismatch is now blocking."
        s = run(manifest, root / "repo", list(SYNTH), root / "out", P.StubModel(), workers, {"quote": gone, "report": "reports/later.md"},
                team=team)
        c, a, m = s["arm_c"], s["arm_a"], s["measures"]
        events = json.loads((root / "out" / "arm_c.json").read_text(encoding="utf-8"))["events"]
        assert c["phase1"]["receipt"]["status"] == "TERMINAL", c["phase1"]["receipt"]
        assert s["withdrawn"][0]["observes"] and all(r["status"] == "REVOKED" for r in c["revoke"]), (s["withdrawn"], c.get("revoke"))
        assert c["phase2"]["receipt"]["status"] == "TERMINAL", c["phase2"]["receipt"]
        for ans in c["phase2"]["answers"].values():
            assert all(q["quote"] != gone for cl in ans["claims"] for q in cl["quotes"]), ans
        if P.ARM_A_MODE == "whole":
            arm_c = json.loads((root / "out" / "arm_c.json").read_text(encoding="utf-8"))
            assert arm_c["whole"]["answers"] and arm_c["whole"]["locals"], arm_c["whole"]
            assert [x for x in arm_c["calls"] if x["phase"] == 1 and x["role"] == "ZONE"] and not any(x["role"] == "BUILDER" for x in arm_c["calls"]), \
                "one zone call, no builder model"
            assert all(c["phase1"]["answers"][q["id"]]["claims"] for q in P.QUESTIONS), c["phase1"]["answers"]
            assert a["phase1"]["status"] == "COMPLETE", a["phase1"]
            assert all(q["quote"] != gone for ans in a["phase2"]["answers"].values() for cl in ans["claims"] for q in cl["quotes"]), a["phase2"]
            if not P.WHOLE_LINKS:
                assert not any(x["role"] == "VERIFY_LINK" for x in arm_c["calls"]), "no link is checked"
            if P.WHOLE_STEPS:
                roles = {x["role"] for x in arm_c["calls"]}
                later = [x["role"] for x in arm_c["calls"] if x["phase"] >= 2]
                assert "ANSWER" in roles and set(later) <= {"RESTATE"} and len(later) <= 2 * len(P.QUESTIONS), (roles, later)
                assert later and all(s["asked"] == ["restate"] for s in arm_c["whole"]["summaries"] if s["phase"] >= 2), arm_c["whole"]["summaries"]
            else:
                assert m["phase2"]["C"]["calls"] == 0, ("the kernel withdraws without a model call", m["phase2"])
        elif P.ARM_A_MODE in ("single", "team"):
            assert a["phase1"]["status"] == "COMPLETE" and set(a["phase1"]["answers"]) == {q["id"] for q in P.QUESTIONS}, a["phase1"]
            assert all(q["quote"] != gone for ans in a["phase2"]["answers"].values() for cl in ans["claims"] for q in cl["quotes"]), a["phase2"]
            if not P.DYNAMIC_ROLES:
                assert any(e.get("pairs_only") for e in events), "record cards are closed without a model"
            checks = [e for e in events if e.get("kind") in ("VERIFY_LINK", "RESOLVE_CONFLICT") and e.get("outcome")]
            checkers = {P.LINK_CHECKER_ID} | ({f"w{i}" for i in range(1, len(team) + 1)} if team else set())
            assert checks and {e["agent"] for e in checks} <= checkers, ("the link checker checks the pair's link", checks)
            assert team or {e["agent"] for e in checks} == {P.LINK_CHECKER_ID}, ("the single reader checks no link", checks)
            if team:
                arm_a = json.loads((root / "out" / "arm_a.json").read_text(encoding="utf-8"))
                assert arm_a["team"] == [m.name for m in team] and arm_a["phase1"]["notes_lines"] > 0, arm_a["phase1"]
                summaries = [e for e in events if e.get("kind") == "SUMMARIZE" and e.get("outcome")]
                assert summaries and {e["agent"] for e in summaries} == {"w1"}, ("the lead alone summarizes", summaries)
        else:
            assert all(gone not in t for t in a["phase2"]["answers"].values()), a["phase2"]
        if P.DYNAMIC_ROLES:
            built = [e for e in events if e.get("kind") == "BUILD" and e.get("outcome") == "CARD_DONE"]
            assert built and all(e["agent"] not in e["card_authors"] for e in built), built
            assert all(e.get("agent") != "gb" for e in events), "no dedicated builder"
        pair_cards = [e for e in events if str(e.get("card", "")).startswith("P0-0-") and e.get("outcome") == "CARD_DONE"]
        if P.ARM_A_MODE != "whole":  # run S1.2 runs no builder model
            assert pair_cards, "a pair card of the kernel reaches CARD_DONE"
            assert m["builder"]["cards"] >= 1 and m["builder"]["abandoned"] == 0, m["builder"]
            assert m["phase2"]["C"]["calls"] >= 1, m["phase2"]
        assert m["total"]["C"]["cost_unknown_calls"] == 0 and m["total"]["A"]["failed_calls"] == 0, m["total"]
        assert m["phase2"]["A"]["calls"] == len(P.QUESTIONS), m["phase2"]
        print(json.dumps({"selftest": "ok", "arm_a": P.ARM_A_MODE, "pair_cards": len(pair_cards), "withdrawn": gone, "calls": {k: v["calls"] for k, v in m["total"].items()},
                          "phase2_calls": {k: v["calls"] for k, v in m["phase2"].items()}, "builder": m["builder"]["cards"]}))


class ClosedOption(argparse.Action):
    """An option of the closed layer when the package is absent: one message instead of argparse's unrecognized argument."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs="?", default=None, help=argparse.SUPPRESS)

    def __call__(self, parser, namespace, values, option_string=None):
        parser.exit(2, f"{parser.prog}: {P.closed_missing(option_string)}\n")


def main() -> None:
    closed = P.closed_layer()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--selftest-c0-failover",action="store_true",help="offline real-store timeout/stream-failure imitation; no provider calls")
    ap.add_argument("--agent-attempts",type=int,help="opt-in 1..1000 failed agent attempts per work key before durable unresolved")
    ap.add_argument("--arm-a-answer",choices=("direct","map-reduce"),default="direct",help="per-report A answers followed by reduction; team/single only")
    ap.add_argument("--arm-a-reduce",choices=("single","tree"),default="single",help="map-reduce reduction: one call, or pairwise merges in report order")
    # the owner, 2026-10-30: a run of arm A with LangGraph's own checkpoints and native means, for a real comparison with LangGraph
    ap.add_argument("--arm-a-orchestration",choices=("runner","langgraph-native","temporal-native"),default="runner",
                    help="arm A's team: the runner's threads; one LangGraph graph with its checkpointer, Send fan-out, interrupt/resume and "
                         "RetryPolicy; or one Temporal workflow with activities, RetryPolicy, updates and a durable history")
    ap.add_argument("--lg-checkpointer",choices=("memory","sqlite"),default="memory",
                    help="langgraph-native: InMemorySaver, or SqliteSaver in the run's out directory (needs langgraph-checkpoint-sqlite)")
    ap.add_argument("--freeze-arm-a",action="store_true",help="run the kernel's arm only; arm A (no kernel) is recorded as frozen")
    ap.add_argument("--reuse-arm-c", type=pathlib.Path,
                    help="take arm C of this earlier finished run on the same inputs as it ended, and run only arm A")
    ap.add_argument("--model", default="stub",
                    help="stub (deterministic, free); deepseek: the DeepSeek API (key from DEEPSEEK_API_KEY); sonnet / haiku / opus: "
                         "Claude Sonnet 5.5 / Haiku 5.5 / Opus 5.5 through Claude Code on the owner's Max plan (the brake counts its "
                         "API-equivalent cost); codex:<id> or gpt-<...>: a Codex model; agy:<id>: the Antigravity CLI (AGY_BIN or agy on "
                         "PATH); the closed layer adds its own models")
    ap.add_argument("--effort", default="medium", help="the effort of a sonnet model (low, medium, high, xhigh, max)")
    ap.add_argument("--budget-usd", type=float, default=None,
                    help="the money brake of each arm (default: 2.0 for deepseek, 15.0 API-equivalent for sonnet)")
    ap.add_argument("--deepseek-max-tokens", type=int, default=P.DEEPSEEK_MAX_TOKENS,
                    help=f"the output budget of one DeepSeek call (default {P.DEEPSEEK_MAX_TOKENS}; the Claude models run with 32000)")
    ap.add_argument("--builder-model", default="same", help="the graph builder of arm C: same (as --model), sonnet (Claude Sonnet 5.5 on the Max plan, outside "
                         "the money brake of a paid swarm) or a Codex model such as gpt-5.6-sol")
    ap.add_argument("--builder-effort", default="medium", help="reasoning effort of a Codex builder model")
    ap.add_argument("--builder-max-records", type=int, help="records per builder card (kernel default 8)")
    ap.add_argument("--builder-max-neighbors", type=int, help="optional neighbours per builder card (kernel default 8)")
    ap.add_argument("--builder-max-ops", type=int, help="operations per builder card (kernel default 64)")
    ap.add_argument("--builder-max-links", type=int, help="links per builder card, each one a verification task (kernel default 8)")
    ap.add_argument("--phase-timeout-s", type=float, default=1800.0, help="the deadline of each phase of each arm")
    ap.add_argument("--control", action="store_true",
                    help="one cheap call of --model (DeepSeek also reads the balance): checks the adapter, then exits")
    ap.add_argument("--manifest", type=pathlib.Path, help="the corpus manifest (its raw bytes are hashed)")
    ap.add_argument("--repo", type=pathlib.Path, help="the checkout the manifest's report paths are read from")
    ap.add_argument("--workers", type=int, default=P.WORKERS)
    ap.add_argument("--withdraw", help="the exact quote phase 2 withdraws, fixed before the run (default: the first unique keyword line of the first report)")
    ap.add_argument("--withdraw-report", help="the report path of --withdraw")
    ap.add_argument("--reports", type=pathlib.Path, help="a file of the corpus' report paths, one per line; needs its own --checklist "
                         "and --withdrawal-plan (or --withdraw). Without it the run is the first pilot's private set (the closed layer)")
    ap.add_argument("--withdrawal-plan", type=pathlib.Path,
                    help='a JSON withdrawal plan fixed before the run: {"steps": [{"name": "2A", "report": <path>, "candidates": '
                         '[{"anchor": <text>, "quote": <exact line holding it>}]}, ...]}')
    ap.add_argument("--checklist", type=pathlib.Path, help="the blind checklist written for the corpus of --reports")
    ap.add_argument("--out", type=pathlib.Path, default=C.WORK / "pilot_ac" / time.strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--builder-requests", type=int, default=0,
                    help="the graph builder's typed requests per run (U1: reread_gap, check_coverage, find_link_basis; 0: off)")
    ap.add_argument("--backpressure-records", type=int, default=0,
                    help="backpressure: first readings wait while the builder's backlog and readings in flight would exceed this (0: off)")
    ap.add_argument("--backpressure-per-task", type=int, default=P.BACKPRESSURE_PER_TASK, help="records counted per first reading in flight")
    ap.add_argument("--strong-reader", action="store_true",
                    help="the comparison of one strong model with the kernel against it without (the owner, 2026-10-25): one reader and "
                         "a link checker, the builder on the kernel's pairs only, arm A one agent without the kernel")
    ap.add_argument("--team", metavar="PARTNER",
                    help="the team comparison (the owner, 2026-10-25): the --model agent leads and PARTNER reads and checks beside it, "
                         "with the kernel against the same two without it (shared notes, the lead answers); PARTNER is a Codex model such "
                         "as gpt-6.1-sol, or opus, sonnet, haiku or stub; the strong-reader settings otherwise, --workers is not used")
    ap.add_argument("--team-effort", default="medium", help="reasoning effort of a Codex partner")
    ap.add_argument("--team-models", help="comma-separated reader models: aliases, agy:<id>, codex:<id>")
    ap.add_argument("--checker-model", help="the separate link checker (default: the lead model)")
    ap.add_argument("--dynamic-roles", action="store_true", help="swarm agents lease sequential builder cards")
    ap.add_argument("--circles", action="store_true", help="alternate durable reading waves and concurrent BUILD")
    ap.add_argument("--wave-sections", type=int, help="reading sections per circle (default: number of readers)")
    ap.add_argument("--circles-refiner", help="circles +1: the model of the swarm's independent graph builder that refines every circle "
                    "after the swarm's BUILD (sonnet, haiku, opus or agy:<id>)")
    ap.add_argument("--refine-budget-s", type=float, default=300.0, help="the longest REFINE of a circle; past it the swarm goes on")
    ap.add_argument("--refiner-timeout-s", type=float, default=240.0, help="the bound of one refiner call")
    ap.add_argument("--term-hygiene",action="store_true")
    ap.add_argument("--term-max-words",type=int,default=None)
    ap.add_argument("--candidate-match",choices=["legacy","strict"])
    ap.add_argument("--known-concepts",choices=["off","circles","all"])
    ap.add_argument("--ring-rotate",action="store_true")
    ap.add_argument("--link-both-sides",action="store_true")
    ap.add_argument("--stale-suspect",action="store_true")
    ap.add_argument("--evolution-cards",action="store_true")
    ap.add_argument("--version-lineage", type=pathlib.Path, help="explicit ordered snapshot doc_id/SHA256 map; requires --build-scope versions")
    ap.add_argument("--build-scope",choices=("full","concepts","none","hints","versions"),default="full",
                    help="arm C's graph builder (the owner's control runs, 2026-10-30): full; concepts (names concepts and maps terms, links "
                         "off: no link, duplicate, conflict or pair card); none (no builder: no concepts, no term mapping, no links); hints (as none, and each reading task gets one more turn with the claims of other report dates that share its claims' words); versions (no graph builder, explicit version-map CHANGE reading tasks and independently verified links)")
    ap.add_argument("--temporal-summary",action="store_true",help="R30 step 2: summaries show report dates, keep supersedes/contradicts pairs whole, warn on superseded claims")
    ap.add_argument("--summary-companions",action="store_true",help="with --temporal-summary: a summary claim brings the claim of a later report it is most like by words (31.10: later states read but cut from the window)")
    ap.add_argument("--evolution-document-order",type=str,help="JSON file of chronological document ids for undated reports")
    ap.add_argument("--concept-functions",action="store_true",help="the address layer (owner and Gemini, 2026-11-01): a new concept may name the broad function of the system it belongs to; with --evolution-pairing lexical, pairs also join a claim with the records of change of its function")
    ap.add_argument("--change-summary-documents",type=str,help="with --concept-functions and --evolution-pairing lexical: JSON file of the document ids or labels that are change summaries; their claims count as records of change besides the claims that state one")
    ap.add_argument("--evolution-pairs-per-function",type=int,default=None,help="with --concept-functions: earlier records of change per claim and function (kernel default 3)")
    ap.add_argument("--evolution-pairs-per-concept",type=int,default=None)
    ap.add_argument("--evolution-pairs-per-card",type=int,default=None)
    ap.add_argument("--evolution-pairing",choices=("concepts","lexical"),default=None,
                    help="how evolution cards find their pairs: concepts (pairs of claims sharing a stored concept, the default) or lexical (step 3a of 31.10: by the claims' own words, the best earlier claim of the same page and of the whole corpus)")
    ap.add_argument("--unattested-at-end",action="store_true",help="kernel marks zero-mapping seed concepts unattested after complete reading/building")
    ap.add_argument("--ontology-review",action="store_true",help="one mandatory anomaly review per concept/circle; keep or grounded revision")
    ap.add_argument("--anomaly-effort",choices=("medium","high"),help="initial effort for ontology anomaly cards")
    ap.add_argument("--ontology-revisions", action="store_true", help="grounded revisions confirmed by the next nonproposer in a circle")
    ap.add_argument("--ontology-unmapped-circles",type=int,default=3)
    ap.add_argument("--ontology-catchall-mappings",type=int,default=8)
    ap.add_argument("--ontology-catchall-reports",type=int,default=2)
    ap.add_argument("--base-ontology", help="a seed ontology file (r2r-audit-ontology/1 with concepts) for arm C's kernel")
    ap.add_argument("--phase-effort", help="READ=medium,BUILD=low,VERIFY=medium,ANSWER=medium; opt-in same-family ladder")
    ap.add_argument("--answer-timeout-s", type=float, default=900.0, help="Antigravity transport deadline of A and C answer calls")
    ap.add_argument("--agent-timeout-s", type=float, default=300.0, help="circle response/readiness deadline; timeout permits failover")
    ap.add_argument("--agy-timeout-s", type=float, default=240.0, help="timeout of each Antigravity CLI call")
    ap.add_argument("--build-backlog", type=int, default=16, help="material records before BUILD precedes reading")
    ap.add_argument("--max-calls", type=int, default=P.MAX_CALLS, help="maximum physical model calls per arm (agy has no hidden retries)")
    ap.add_argument("--phase2-max-calls", default=str(P.PHASE2_MAX_CALLS),
                    help="maximum model calls of each withdrawal phase, per arm: a number (arm A's map-reduce needs reports x questions + "
                         "questions), or auto: arm A's answer calls of a phase, each with all its --summary-repairs rounds and "
                         "their timeout retries")
    ap.add_argument("--executor", choices=P.executors.EXECUTORS, default="threads",
                    help="who drives each agent's loop: the runner's threads, LangGraph or Temporal (the orchestration baselines)")
    ap.add_argument("--temporal-address", help="with --executor temporal: a running server (host:port); default: a local dev server for the run")
    ap.add_argument("--acquire-wait-ms", type=int, default=P.ACQUIRE_WAIT_MS,
                    help="how long an agent's audit_acquire waits inside the kernel for work (0..30000 ms); the kernel answers at once on new work")
    ap.add_argument("--repairs", type=int, default=P.REPAIRS, help="repair rounds of a refused reader submission, both arms (0..20)")
    ap.add_argument("--summary-repairs", type=int, default=P.SUMMARY_REPAIRS,
                    help="repair rounds of a refused answer, both arms: a summary of arm C, an answer call of arm A (0..20)")
    ap.add_argument("--no-link-check", action="store_true",
                    help="with --whole-reader: no link checker; the agent's relation lines are kept aside, not handed in (step 2 of "
                         "2026-10-25: the full cost of the arms without link checks)")
    ap.add_argument("--whole-steps", action="store_true",
                    help="run S1.3 with --whole-reader: atomic records, the answers in a call of their own, a refused answer line asked "
                         "about once, a withdrawal restated on the remaining quotes")
    ap.add_argument("--whole-reader", action="store_true",
                    help="run S1.2 (the owner, 2026-10-25): one strong agent reads every report in one zone task of the kernel and hands in "
                         "its records, relations and answers in one answer; arm A takes the same answer without the kernel")
    ap.add_argument("--max-lines", type=int, help="the lines one answer of the kernel may hold (default: the kernel's)")
    ap.add_argument("--section-bytes", type=int, default=P.SECTION_BYTES,
                    help="upper bound of a report section, the same for both arms and the kernel (registry R1a'': 3000 tested against 6000)")
    if closed is not None:
        closed.add_arguments(ap)
    else:
        for option in P.CLOSED_OPTIONS:
            ap.add_argument(option, action=ClosedOption)
    a = ap.parse_args()
    if closed is None:
        # a model of the closed layer stops before any work, with the same one message
        for name in (a.model, a.builder_model, a.checker_model, a.circles_refiner, a.team, *(a.team_models or "").split(",")):
            if name and name.strip() in P.CLOSED_MODELS:
                sys.exit(P.closed_missing(f"the model {name.strip()}"))
    if not 1 <= a.deepseek_max_tokens <= 393216:
        sys.exit("--deepseek-max-tokens must be 1..393216")
    P.DEEPSEEK_MAX_TOKENS = a.deepseek_max_tokens
    if a.agent_attempts is not None and not 1<=a.agent_attempts<=1000:sys.exit("--agent-attempts must be 1..1000")
    P.AGENT_ATTEMPTS=a.agent_attempts
    if a.freeze_arm_a and (a.arm_a_answer!="direct" or a.arm_a_reduce!="single"):sys.exit("--freeze-arm-a runs no arm A answer")
    P.ARM_A_ANSWER=a.arm_a_answer
    if a.arm_a_reduce!="single" and a.arm_a_answer!="map-reduce":sys.exit("--arm-a-reduce tree needs --arm-a-answer map-reduce")
    P.ARM_A_REDUCE=a.arm_a_reduce
    P.ARM_A_FROZEN=a.freeze_arm_a
    if a.reuse_arm_c is not None and (a.freeze_arm_a or not (a.reuse_arm_c / "arm_c.json").is_file()):
        sys.exit("--reuse-arm-c names a finished run with an arm_c.json, and does not go with --freeze-arm-a")
    P.REUSE_ARM_C = a.reuse_arm_c
    # both arms and the kernel's --section-bytes read this at run time; corpus.section_bytes records it
    P.SECTION_BYTES = a.section_bytes
    if a.builder_requests < 0:
        sys.exit("--builder-requests must be 0 (off) or positive")
    P.BUILDER_REQUESTS = a.builder_requests
    if a.backpressure_records < 0 or a.backpressure_per_task <= 0:
        sys.exit("--backpressure-records must be 0 (off) or positive, --backpressure-per-task positive")
    P.BACKPRESSURE_RECORDS, P.BACKPRESSURE_PER_TASK = a.backpressure_records, a.backpressure_per_task
    if a.max_lines is not None and a.max_lines <= 0:
        sys.exit("--max-lines must be positive")
    P.MAX_LINES = a.max_lines
    if a.strong_reader:
        if a.workers != 1:
            sys.exit("--strong-reader reads with one agent: give --workers 1")
        P.ARM_A_MODE, P.PAIRS_ONLY, P.LINK_CHECKER = "single", True, True
    if a.whole_reader:
        if a.team or a.strong_reader or a.workers != 1:
            sys.exit("--whole-reader reads with one agent: give --workers 1, without --team or --strong-reader")
        P.ARM_A_MODE, P.PAIRS_ONLY, P.LINK_CHECKER, P.WHOLE_READER = "whole", True, True, True
        P.MAX_LINES = P.MAX_LINES or P.WHOLE_LINES
        P.WHOLE_STEPS = a.whole_steps
        if a.no_link_check:
            P.LINK_CHECKER, P.WHOLE_LINKS = False, False
    elif a.whole_steps or a.no_link_check:
        sys.exit("--whole-steps and --no-link-check go with --whole-reader")
    if a.team_models:
        if a.team or a.strong_reader or a.whole_reader:
            sys.exit("--team-models is separate from --team, --strong-reader and --whole-reader")
        P.ARM_A_MODE, P.PAIRS_ONLY, P.LINK_CHECKER = "team", False, True
    if a.dynamic_roles and (not a.team_models or len(a.team_models.split(",")) < 3):
        sys.exit("--dynamic-roles needs --team-models with at least three readers")
    try:
        phase2_cap = None if a.phase2_max_calls == "auto" else int(a.phase2_max_calls)  # auto is set once the corpus is known
    except ValueError:
        sys.exit("--phase2-max-calls must be a positive number or auto")
    if a.max_calls < 1 or a.build_backlog < 1 or (phase2_cap is not None and phase2_cap < 1):
        sys.exit("--max-calls, --phase2-max-calls and --build-backlog must be positive")
    if phase2_cap is None and (a.freeze_arm_a or a.whole_reader):
        sys.exit("--phase2-max-calls auto is taken from arm A's answer calls: give a number with --freeze-arm-a or --whole-reader")
    if phase2_cap is not None:
        P.PHASE2_MAX_CALLS = phase2_cap
    if not (0 <= a.repairs <= 20 and 0 <= a.summary_repairs <= 20):
        sys.exit("--repairs and --summary-repairs must be 0..20")
    P.REPAIRS, P.SUMMARY_REPAIRS = a.repairs, a.summary_repairs
    if not 0 <= a.acquire_wait_ms <= 30000:
        sys.exit("--acquire-wait-ms must be 0..30000 (the kernel's cap)")
    P.ACQUIRE_WAIT_MS = a.acquire_wait_ms
    if a.temporal_address and a.executor != "temporal":
        sys.exit("--temporal-address goes with --executor temporal")
    P.executors.EXECUTOR, P.executors.TEMPORAL_ADDRESS = a.executor, a.temporal_address
    P.DYNAMIC_ROLES, P.BUILD_BACKLOG = a.dynamic_roles, a.build_backlog
    if a.circles and not a.dynamic_roles:
        sys.exit("--circles requires --dynamic-roles")
    if a.wave_sections is not None and (not a.circles or a.wave_sections < 1):
        sys.exit("--wave-sections requires --circles and a positive number")
    if not math.isfinite(a.agy_timeout_s) or a.agy_timeout_s <= 0:
        sys.exit("--agy-timeout-s must be finite and positive")
    if not math.isfinite(a.agent_timeout_s) or a.agent_timeout_s < 0.001:
        sys.exit("--agent-timeout-s must be finite and at least 0.001")
    from sbgk_bench.phase_effort import parse_phase_effort
    try:
        P.PHASE_EFFORT = parse_phase_effort(a.phase_effort)
    except ValueError as exc:
        sys.exit(str(exc))
    if not math.isfinite(a.answer_timeout_s) or a.answer_timeout_s <= 0:
        sys.exit("--answer-timeout-s must be finite and positive")
    P.ANSWER_TIMEOUT_S = a.answer_timeout_s
    P.AGENT_TIMEOUT_S = a.agent_timeout_s
    P.CIRCLES, P.WAVE_SECTIONS, P.AGY_TIMEOUT_S = a.circles, a.wave_sections, a.agy_timeout_s
    if a.circles_refiner:
        if not a.circles:sys.exit("--circles-refiner requires --circles")
        if not (math.isfinite(a.refine_budget_s) and a.refine_budget_s > 0 and math.isfinite(a.refiner_timeout_s) and a.refiner_timeout_s > 0):
            sys.exit("--refine-budget-s and --refiner-timeout-s must be finite and positive")
        claude = {"sonnet": P.CLAUDE_MODEL, "haiku": P.CLAUDE_HAIKU, "opus": P.CLAUDE_OPUS}.get(a.circles_refiner)
        P.CIRCLES_REFINER = (P.ClaudeCliModel(model=claude, timeout_s=a.refiner_timeout_s) if claude
                             else P.make_model(a.circles_refiner, timeout_s=a.refiner_timeout_s))
        P.REFINE_BUDGET_S = a.refine_budget_s
    if a.base_ontology and not pathlib.Path(a.base_ontology).is_file():
        sys.exit(f"--base-ontology {a.base_ontology} is not a file")
    P.BASE_ONTOLOGY = a.base_ontology
    if a.ontology_revisions and not a.circles: sys.exit("--ontology-revisions requires --circles")
    P.ONTOLOGY_REVISIONS=a.ontology_revisions
    P.ONTOLOGY_REVIEW=a.ontology_review
    if a.summary_companions and not a.temporal_summary: sys.exit("--summary-companions requires --temporal-summary")
    if a.change_summary_documents and not (a.concept_functions and a.evolution_pairing=="lexical"):
        sys.exit("--change-summary-documents requires --concept-functions and --evolution-pairing lexical")
    if a.evolution_pairs_per_function is not None and not a.concept_functions:
        sys.exit("--evolution-pairs-per-function requires --concept-functions")
    P.GRAPH_QUALITY={k:getattr(a,k) for k in ("term_hygiene","term_max_words","candidate_match","jev_mode","known_concepts","ring_rotate","link_both_sides","stale_suspect","temporal_summary","summary_companions","evolution_cards","evolution_pairs_per_concept","evolution_pairs_per_card","evolution_pairing","evolution_document_order","concept_functions","change_summary_documents","evolution_pairs_per_function") if getattr(a,k,None) is not None and getattr(a,k) is not False}
    if a.build_scope!="full":
        clash=[f for f,v in (("--evolution-cards",a.evolution_cards),("--evolution-document-order",a.evolution_document_order),
                             ("--evolution-pairs-per-concept",a.evolution_pairs_per_concept),("--evolution-pairs-per-card",a.evolution_pairs_per_card),("--evolution-pairing",a.evolution_pairing),("--change-summary-documents",a.change_summary_documents),
                             ("--link-both-sides",a.link_both_sides),("--circles-refiner",a.circles_refiner),("--ontology-review",a.ontology_review),
                             ("--builder-max-links",a.builder_max_links)) if v]
        if clash:sys.exit(f"--build-scope {a.build_scope} makes no links: drop {', '.join(clash)}")
    if a.build_scope in ("none","hints","versions"):
        clash=[f for f,v in (("--builder-max-records",a.builder_max_records),("--builder-max-neighbors",a.builder_max_neighbors),
                             ("--builder-max-ops",a.builder_max_ops),("--builder-requests",a.builder_requests),("--jev",getattr(a,"jev",None))) if v]
        if clash:sys.exit(f"--build-scope {a.build_scope} has no graph builder: drop {', '.join(clash)}")
    P.BUILD_SCOPE=a.build_scope
    if a.build_scope=="versions" and a.whole_reader:
        sys.exit("--whole-reader is not supported with --build-scope versions: its cached summaries do not read the version-map context; use the ordinary readers")
    if a.version_lineage is not None and a.build_scope != "versions":
        sys.exit("--version-lineage requires --build-scope versions")
    P.VERSION_LINEAGE=a.version_lineage
    for k in ("term_max_words","evolution_pairs_per_concept","evolution_pairs_per_card"):
        if k in P.GRAPH_QUALITY and not 1<=P.GRAPH_QUALITY[k]<=64:sys.exit("--"+k.replace("_","-")+" must be 1..64")
    P.UNATTESTED_AT_END=a.unattested_at_end
    P.ANOMALY_EFFORT=a.anomaly_effort
    if a.ontology_review and not (a.circles and a.ontology_revisions):sys.exit("--ontology-review requires --circles --ontology-revisions")
    P.ONTOLOGY_THRESHOLDS={"unmapped_circles":a.ontology_unmapped_circles,"catchall_mappings":a.ontology_catchall_mappings,"catchall_reports":a.ontology_catchall_reports}
    if any(not 1<=v<=100000 for v in P.ONTOLOGY_THRESHOLDS.values()): sys.exit("ontology thresholds must be in 1..100000")
    if a.team:
        if a.strong_reader:
            sys.exit("give --team or --strong-reader, not both")
        P.ARM_A_MODE, P.PAIRS_ONLY, P.LINK_CHECKER = "team", True, True
    if a.arm_a_answer=="map-reduce" and P.ARM_A_MODE not in ("team","single"):
        sys.exit("--arm-a-answer map-reduce requires --team, --team-models or --strong-reader")
    if a.arm_a_orchestration!="runner" and (P.ARM_A_MODE!="team" or a.arm_a_answer!="map-reduce" or a.arm_a_reduce!="single" or a.freeze_arm_a):
        sys.exit(f"--arm-a-orchestration {a.arm_a_orchestration} is the team's map-reduce answer: give --team-models, --arm-a-answer "
                 "map-reduce and --arm-a-reduce single")
    if a.arm_a_orchestration=="temporal-native":
        try:
            import temporalio  # noqa: F401
        except ImportError:
            sys.exit("--arm-a-orchestration temporal-native needs temporalio: run in the baselines venv")
        from sbgk_bench import arm_a_temporal
        # the team's workflow history in a SQLite file of the run (durable execution)
        arm_a_temporal.TEMPORAL_DB=str(a.out / "arm_a_temporal.db") if a.out is not None else None
    if a.arm_a_orchestration=="langgraph-native":
        try:
            import langgraph  # noqa: F401
        except ImportError:
            sys.exit("--arm-a-orchestration langgraph-native needs langgraph: run in the baselines venv")
        if a.lg_checkpointer=="sqlite":
            try:
                import langgraph.checkpoint.sqlite  # noqa: F401
            except ImportError:
                sys.exit("--lg-checkpointer sqlite needs langgraph-checkpoint-sqlite")
        from sbgk_bench import arm_a_langgraph
        arm_a_langgraph.CHECKPOINTER=a.lg_checkpointer
        arm_a_langgraph.CHECKPOINT_DB=str(a.out / "arm_a_langgraph.sqlite") if a.lg_checkpointer=="sqlite" else None
    elif a.lg_checkpointer!="memory":
        sys.exit("--lg-checkpointer goes with --arm-a-orchestration langgraph-native")
    P.ARM_A_ORCHESTRATION=a.arm_a_orchestration
    if not C.BIN.exists():
        sys.exit(f"build the kernel first: {C.BIN} is missing")
    if a.selftest_c0_failover:
        from sbgk_bench.failover_selftest import run as failover_selftest
        return failover_selftest()
    if a.selftest:
        if a.build_scope == "versions":
            from sbgk_bench.versions_selftest import run as versions_selftest
            return versions_selftest(a.out, whole=P.WHOLE_READER)
        return selftest(a.workers)
    if a.control:
        if a.model in ("sonnet", "haiku", "opus"):
            claude = P.ClaudeCliModel(model={"haiku": P.CLAUDE_HAIKU, "opus": P.CLAUDE_OPUS}.get(a.model, P.CLAUDE_MODEL), effort=a.effort)
            call = P.call_model(claude, "This is a configuration check. Reply with the single word OK.",
                                call_id="control", arm="-", role="CONTROL", phase=0)
            print(json.dumps({"ok": call.ok, "error": call.error, "text": call.text, "usage": call.usage, "cost_usd": call.cost_usd,
                              "latency_s": round(call.latency_s, 3)}, ensure_ascii=False))
            return None
        if a.model in P.CLOSED_MODELS:
            check = "This is a configuration check. Reply with the single word OK."
            with closed.model_session(a.model):
                call = P.call_model(P.make_model(a.model), check, call_id="control", arm="-", role="CONTROL", phase=0)
            print(json.dumps({"ok": call.ok, "error": call.error, "text": call.text, "usage": call.usage, "cost_usd": call.cost_usd,
                              "latency_s": round(call.latency_s, 3)}, ensure_ascii=False))
            return None
        m = P.DeepSeekModel(max_tokens=16)
        before = m.balance()
        call = P.call_model(m, "This is a configuration check. Reply with the single word OK.", call_id="control", arm="-", role="CONTROL", phase=0)
        print(json.dumps({"ok": call.ok, "error": call.error, "text": call.text, "usage": call.usage, "cost_usd": call.cost_usd,
                          "latency_s": round(call.latency_s, 3), "balance_before_usd": before, "balance_after_usd": m.balance()}, ensure_ascii=False))
        return None
    if not (a.manifest and a.repo):
        sys.exit("--manifest and --repo are required for a corpus run")
    w = {"quote": a.withdraw, "report": a.withdraw_report, "chosen": "before the run (given on the command line)"} if a.withdraw else None
    try:
        reports, w, checklist = corpus_choice(a.reports, a.withdrawal_plan, a.checklist, w)
    except (OSError, ValueError) as e:
        sys.exit(str(e))
    # arm A's answer calls of a withdrawal phase, per question: one direct answer; for map-reduce a call per report and the
    # reduction, and with the tree reduction a merge per report beyond the last two. A cap below that is refused before any model
    # call (run MCPpair_r1: 22 reports, cap 30, arm A stopped in 2A and skipped 2B); auto gives each call all its repair rounds and
    # each round its timeout retries (invoke_answer; Codex review of 729eda8, BATCH-01).
    per_question = 1 if a.arm_a_answer != "map-reduce" else len(reports) + 1 + (max(len(reports) - 2, 0) if a.arm_a_reduce == "tree" else 0)
    need = per_question * len(P.QUESTIONS)
    if phase2_cap is None:
        tries = (P.SUMMARY_REPAIRS + 1) * (P.ANSWER_TIMEOUT_RETRIES + 1)
        P.PHASE2_MAX_CALLS = need * tries
        P.PHASE2_CAP_RULE = (f"auto: {need} answer calls of arm A ({len(reports)} reports, {len(P.QUESTIONS)} questions, {a.arm_a_answer}"
                             f"{'/' + a.arm_a_reduce if a.arm_a_answer == 'map-reduce' else ''}) x {P.SUMMARY_REPAIRS + 1} attempts"
                             f" x {P.ANSWER_TIMEOUT_RETRIES + 1} tries each (a timeout retry)")
    elif w and P.withdrawal_steps(w) and not a.freeze_arm_a and P.PHASE2_MAX_CALLS < need:
        sys.exit(f"--phase2-max-calls {P.PHASE2_MAX_CALLS} is below the {need} calls arm A's {a.arm_a_answer} answer makes in a withdrawal "
                 f"phase before any repair ({len(reports)} reports, {len(P.QUESTIONS)} questions); give a larger number or auto")
    model = P.make_model(a.model, a.effort, timeout_s=1800.0 if a.whole_reader else None)
    budget = a.budget_usd if a.budget_usd is not None else {"deepseek": 2.0, "sonnet": 15.0, "haiku": 2.0, "opus": 20.0}.get(a.model)
    team = None
    if a.team_models:
        team = [P.make_model(name.strip(), a.team_effort) for name in a.team_models.split(",")]
        model = team[0]
    elif a.team:
        team = [model, P.make_model(a.team, a.team_effort)]
    builder = model if a.builder_model == "same" else P.make_model(a.builder_model, a.builder_effort)
    P.CHECKER_MODEL = P.make_model(a.checker_model, a.effort) if a.checker_model else None
    card = {k: v for k, v in (("max_records", a.builder_max_records), ("max_neighbors", a.builder_max_neighbors), ("max_ops", a.builder_max_ops),
                                         ("max_links", a.builder_max_links))
            if v is not None}
    if any(v <= 0 for v in card.values()) or not (math.isfinite(a.phase_timeout_s) and a.phase_timeout_s > 0):
        sys.exit("--builder-max-* and --phase-timeout-s must be positive")
    jev = closed.term_selector(a) if closed is not None else None
    priced = [model, builder] + (team or []) + ([P.CHECKER_MODEL] if P.CHECKER_MODEL else [])
    if any(isinstance(m, P.AgyModel) for m in priced + ([P.CIRCLES_REFINER] if P.CIRCLES_REFINER else [])):
        try:
            P.agy_exe()
        except RuntimeError as e:
            sys.exit(str(e))
    # a Temporal step may last what the whole run may: in each phase new work starts before the phase's deadline, and a step begun
    # then may outlive it by step_overrun_s (executors.STEP_TIMEOUT_S; Codex reviews of 0dc2164, 628adb3 and d80910c, EXEC-02 and
    # ACQUIRE-01: neither the drain budget nor a call's life alone bounds it, an acquire may wait its whole wait)
    if a.executor == "temporal":
        phases = 1 + (len(P.withdrawal_steps(w)) if w else 0)
        try:
            P.executors.STEP_TIMEOUT_S = phases * (a.phase_timeout_s + P.step_overrun_s(priced, a.answer_timeout_s, a.agy_timeout_s))
        except ValueError as e:
            sys.exit(f"--executor temporal bounds each step by the longest life of a call: {e}")
    if any(isinstance(m, P.AgyModel) for m in priced) and budget is not None:
        sys.exit("agy has no monetary price: omit --budget-usd and use --max-calls")
    try:
        with closed.model_session(a.model) if closed is not None else contextlib.nullcontext():
            s = run(a.manifest, a.repo, reports, a.out, model, a.workers, w, budget, builder, a.phase_timeout_s, card or None, jev, checklist,
                    team=team, max_calls=a.max_calls)
    finally:
        P.executors.close()
    print(json.dumps({"out": str(a.out), "measures": s["measures"]}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
