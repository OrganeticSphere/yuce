"""EXP-9 compiler speed: the resident `directives` op of `sbgk serve` against `sbgk emit-batch-directives` on identical states.

Every register is played with the deterministic oracle worker (no model calls) through ONE resident kernel. At the start of
every round the same state is measured three ways:

  serve      `{"op":"directives",...}` on the live session: no container is built, reopened or verified; the first call of a
             round sees the events of the previous round (incremental cache update), the repeats see an unchanged state
  cli        `sbgk emit-batch-directives` on a snapshot of that state: process start + read + verify + analysis + frames
  baseline   the same CLI call with an older `sbgk` binary (optional, `--baseline-bin`): the compiler before this change

Frames (and every non-timing field of the batch) must be identical across the three; the run fails otherwise.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import platform
import shutil
import statistics
import subprocess
import time

from . import common as C
from . import exp9_directive_emitter as X

# (block, case, services): the 16/20/48/96-service registers of EXP-9
REGISTERS = (("c_retract", 0, 16), ("b_parallel", 0, 20), ("c_long", 0, 48), ("c_long96", 0, 96))
ERRATUM_STEP = 4  # retraction register: the erratum becomes visible to the compiler from this round on (deterministic)
TIMING_KEYS = {"open_us", "analysis_us", "analysis_warm_us", "pack_us", "total_us", "resident", "status", "cache"}
VERSION = "exp9-speed-1"


def canon(batch: dict) -> str:
    return json.dumps({k: v for k, v in batch.items() if k not in TIMING_KEYS}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def resident_emit(kernel: X.ResidentKernel, targets: dict, seats: int, k: int, rnd: int) -> tuple[dict, float]:
    t = time.perf_counter()
    r = kernel.directives(targets, seats, k, rnd)
    return r, (time.perf_counter() - t) * 1e6


def cli_emit(binary: pathlib.Path, container: pathlib.Path, tfile: pathlib.Path, seats: int, k: int, rnd: int) -> tuple[dict, float]:
    cmd = [str(binary), "emit-batch-directives", "--state", str(container), "--targets", str(tfile), "--seats", str(seats), "--k", str(k), "--round", str(rnd)]
    t = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    wall = (time.perf_counter() - t) * 1e6
    if r.returncode != 0:
        raise RuntimeError(f"{binary.name} emit-batch-directives failed: {r.stderr.strip()[:400]}")
    return json.loads(r.stdout), wall


def cpu_name() -> str:
    try:
        import winreg  # Windows: the brand string (platform.processor() only gives the family / model numbers)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
            return str(winreg.QueryValueEx(k, "ProcessorNameString")[0]).strip()
    except (ImportError, OSError):
        return platform.processor()


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stats(v: list[float]) -> dict:
    if not v:
        return {"n": 0}
    s = sorted(v)
    return {"n": len(s), "median": statistics.median(s), "p95": s[int(0.95 * (len(s) - 1))], "mean": statistics.fmean(s), "max": s[-1]}


def replay(block: str, idx: int, baseline: pathlib.Path | None, reps_cli: int = 3, reps_serve: int = 5, keep: pathlib.Path | None = None) -> dict:
    case = X.make_case(block, idx)
    spec = case.spec
    seats = len(spec.team) if spec.parallel else 1
    k = spec.k
    wd = X.OUT / f"work_speed_{block}_{idx}"
    shutil.rmtree(wd, ignore_errors=True)
    wd.mkdir(parents=True, exist_ok=True)
    docs = {"policy": case.doc}
    if case.erratum:
        docs["erratum"] = case.erratum
    C.write_docs(wd / "docs", docs)
    (wd / "o.json").write_text(json.dumps(case.onto), encoding="utf-8")
    kernel = X.ResidentKernel(wd / "o.json", wd / "docs")
    orc = X.Oracle(case)
    tfile, cont = wd / "t.json", wd / "state.sbgk"
    visible = ["policy"]
    rows: list[dict] = []
    mismatches: list[dict] = []
    try:
        for step in range(1, 300):
            if case.erratum and step == ERRATUM_STEP:
                visible = ["erratum", "policy"]
            targets = X.targets_for(case, visible)
            tfile.write_text(json.dumps(targets), encoding="utf-8")
            srv, rt = resident_emit(kernel, targets, seats, k, step)
            rep = [resident_emit(kernel, targets, seats, k, step) for _ in range(reps_serve)]
            snap = kernel.snapshot(cont)
            if keep is not None:
                keep.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(cont, keep / f"{block}_c{idx}_s{step:03d}.sbgk")
                shutil.copyfile(tfile, keep / f"{block}_c{idx}_s{step:03d}.targets.json")
            cli = [cli_emit(C.BIN, cont, tfile, seats, k, step) for _ in range(reps_cli)]
            old = [cli_emit(baseline, cont, tfile, seats, k, step) for _ in range(reps_cli)] if baseline else []
            ref = canon(srv)
            same_cli = all(canon(b) == ref for b, _ in cli) and all(canon(b) == ref for b, _ in rep)
            same_old = all(canon(b) == ref for b, _ in old) if old else None
            if not same_cli or same_old is False:
                mismatches.append({"step": step, "cli_vs_serve": same_cli, "cli_vs_baseline": same_old})
            rows.append({
                "step": step, "nodes": snap.get("nodes", 0), "segments": srv["segments"], "gaps": srv["gaps_total"], "busy_seats": sum(1 for f in srv["frames"] if not f["noop"]),
                "serve": {"analysis_us": srv["analysis_us"], "pack_us": srv["pack_us"], "total_us": srv["total_us"], "roundtrip_us": rt},
                "serve_repeat": {"analysis_us": [b["analysis_us"] for b, _ in rep], "total_us": [b["total_us"] for b, _ in rep], "roundtrip_us": [t for _, t in rep]},
                "cli": {key: [b[key] for b, _ in cli] for key in ("open_us", "analysis_us", "analysis_warm_us", "pack_us", "total_us")} | {"wall_us": [t for _, t in cli]},
                "baseline": ({key: [b[key] for b, _ in old] for key in ("open_us", "analysis_us", "analysis_warm_us", "pack_us", "total_us")} | {"wall_us": [t for _, t in old]}) if old else None,
                "identical": {"cli_vs_serve": same_cli, "cli_vs_baseline": same_old},
            })
            if srv["complete"] or all(f["noop"] for f in srv["frames"]):
                break
            for fr in srv["frames"]:
                if not fr["noop"]:
                    for ev in orc.events(fr):
                        kernel.send(ev)
    finally:
        kernel.close()
        shutil.rmtree(wd, ignore_errors=True)
    return {"block": block, "case": idx, "services": spec.services, "seats": seats, "k": k, "rows": rows, "mismatches": mismatches}


def summarize(r: dict) -> dict:
    R = r["rows"]
    # every CLI call is a fresh process, so every one of its first analyses is cold; `analysis_warm_us` is the second analysis in it
    allv = lambda a, b: [v for x in R if x.get(a) for v in x[a][b]]  # noqa: E731
    out = {
        "services": r["services"], "seats": r["seats"], "k": r["k"], "rounds": len(R),
        "segments_mean": round(statistics.fmean(x["segments"] for x in R)) if R else 0, "nodes_final": R[-1]["nodes"] if R else 0,
        "identical_rounds": sum(1 for x in R if x["identical"]["cli_vs_serve"] and x["identical"]["cli_vs_baseline"] is not False),
        "serve_round_analysis_us": stats([x["serve"]["analysis_us"] for x in R]),
        "serve_round_total_us": stats([x["serve"]["total_us"] for x in R]),
        "serve_round_roundtrip_us": stats([x["serve"]["roundtrip_us"] for x in R]),
        "serve_repeat_analysis_us": stats(allv("serve_repeat", "analysis_us")),
        "serve_repeat_total_us": stats(allv("serve_repeat", "total_us")),
        "cli_cold_analysis_us": stats(allv("cli", "analysis_us")),
        "cli_warm_analysis_us": stats(allv("cli", "analysis_warm_us")),
        "cli_open_us": stats(allv("cli", "open_us")),
        "cli_total_us": stats(allv("cli", "total_us")),
        "cli_wall_us": stats(allv("cli", "wall_us")),
    }
    if any(x.get("baseline") for x in R):
        out |= {
            "baseline_cold_analysis_us": stats(allv("baseline", "analysis_us")),
            "baseline_warm_analysis_us": stats(allv("baseline", "analysis_warm_us")),
            "baseline_open_us": stats(allv("baseline", "open_us")),
            "baseline_total_us": stats(allv("baseline", "total_us")),
            "baseline_wall_us": stats(allv("baseline", "wall_us")),
        }
    return out


def fmt(s: dict, key: str = "median") -> str:
    return "—" if not s or not s.get("n") else f"{s[key]:,.0f}".replace(",", " ")


def print_table(summary: dict) -> None:
    cols = [("serve, round", "serve_round_analysis_us"), ("serve, repeat", "serve_repeat_analysis_us"), ("serve total", "serve_round_total_us"),
            ("cli cold", "cli_cold_analysis_us"), ("cli warm", "cli_warm_analysis_us"), ("cli wall", "cli_wall_us"),
            ("old cold", "baseline_cold_analysis_us"), ("old warm", "baseline_warm_analysis_us"), ("old wall", "baseline_wall_us")]
    head = f"{'register':<14}{'svc':>4}{'rounds':>7}{'segs':>6} | " + " | ".join(f"{c:>16}" for c, _ in cols)
    print("analysis / total time, microseconds: median / p95")
    print(head)
    print("-" * len(head))
    for key, s in summary.items():
        cells = [f"{fmt(s.get(m)):>7} /{fmt(s.get(m), 'p95'):>7}" for _, m in cols]
        print(f"{key:<14}{s['services']:>4}{s['rounds']:>7}{s['segments_mean']:>6} | " + " | ".join(f"{c:>16}" for c in cells))


def run(baseline: pathlib.Path | None = None, reps_cli: int = 3, reps_serve: int = 5, keep: pathlib.Path | None = None,
        registers=REGISTERS) -> dict:
    results, summary = {}, {}
    for block, idx, _ in registers:
        key = f"{block}_c{idx}"
        t0 = time.time()
        r = replay(block, idx, baseline, reps_cli, reps_serve, keep)
        results[key] = r
        summary[key] = summarize(r)
        s = summary[key]
        print(f"  {key}: {s['rounds']} rounds, identical {s['identical_rounds']}/{s['rounds']}, serve {fmt(s['serve_round_analysis_us'])} us, "
              f"cli cold {fmt(s['cli_cold_analysis_us'])} us ({time.time() - t0:.0f}s)", flush=True)
    print_table(summary)
    bad = {k: r["mismatches"] for k, r in results.items() if r["mismatches"]}
    try:
        binary = str(C.BIN.relative_to(C.ROOT))
    except ValueError:
        binary = str(C.BIN)
    return {
        "version": VERSION, "created": time.strftime("%Y-%m-%d %H:%M:%S"), "machine": {"platform": platform.platform(), "processor": cpu_name(),
        "python": platform.python_version()}, "binary": binary, "binary_sha256": sha(C.BIN),
        "baseline_binary": baseline.name if baseline else None, "baseline_sha256": sha(baseline) if baseline else None,
        "reps": {"cli": reps_cli, "serve": reps_serve}, "erratum_step": ERRATUM_STEP,
        "identical_all": not bad, "mismatches": bad, "summary": summary,
        "rows": {k: r["rows"] for k, r in results.items()},
    }
