#!/usr/bin/env python3
"""EXP-8: stress test of compiled shared state (retraction + conflict, scale, parallel rounds) -> results/exp8/ and the report.

Separate run: it does not touch results/summary.json, results/exp3_llm, results/exp7 or the earlier reports.

    python benchmarks/run_exp8_stress.py --selftest                       # offline, scripted agent, no model calls
    python benchmarks/run_exp8_stress.py --smoke                          # 2 cases x every scenario x 5 modes (real models)
    python benchmarks/run_exp8_stress.py --scenario retract --cases 7     # one scenario
    python benchmarks/run_exp8_stress.py                                  # full run (all scenarios, default case counts)
    python benchmarks/run_exp8_stress.py --report-only
    python benchmarks/run_exp8_stress.py --report-only --data opus_pilot   # the frozen EXP-8 report (Opus pilot, clean cases only)

Needs: Codex CLI >= 0.163 (logged in), OpenClaw with deepseek/deepseek-chat, Claude Code >= 2.1.280 (Opus 5.5), built `sbgk`.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from sbgk_bench import common as C  # noqa: E402
from sbgk_bench import exp8_env as E  # noqa: E402

DEFAULT_CASES = {"retract": 6, "retractp": 6, "scale": 6, "parallel": 6}


def load_all(subdir: str | None = None) -> dict:
    """Scenario results. With subdir (e.g. "opus_pilot") the archived pilot is read and, so that every paired comparison uses the same
    cases, each scenario keeps only the cases that have a run without any failed call in EVERY mode."""
    from sbgk_bench import exp8_stats as S
    base = E.OUT / subdir if subdir else E.OUT
    data = {}
    for name in E.SPECS:
        f = base / f"{name}.json"
        if not f.exists():
            continue
        d = json.loads(f.read_text(encoding="utf-8"))
        if subdir:
            modes = d["modes"]
            ok = S.usable(d["results"])
            full = sorted(c for c in {r["case"] for r in ok} if all(any(r["case"] == c and r["mode"] == m for r in ok) for m in modes))
            d["all_cases"] = len(d["case_info"])
            d["results"] = [r for r in d["results"] if r["case"] in full]
            d["case_info"] = [c for c in d["case_info"] if c["idx"] in full]
            if not full:
                continue
        data[name] = d
    return data


def write_report(name: str | None = None, subdir: str | None = None) -> None:
    report_stress = C.report_module("report_stress")
    data = load_all(subdir)
    if not data:
        print("no results yet")
        return
    out = C.ROOT / (name or C.report_name("SBGK_EXPERIMENT_REPORT_STRESS"))
    out.write_text(report_stress.render(data, frozen=bool(subdir)), encoding="utf-8")
    print(f"wrote {out}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default=",".join(E.SPECS))
    ap.add_argument("--cases", type=int, default=None, help="cases per scenario (default 6 per scenario)")
    ap.add_argument("--modes", default=",".join(E.MODES))
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--smoke", action="store_true", help="2 cases per scenario")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--fresh", action="store_true", help="ignore stored runs (the call cache is still used)")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--data", default=None, help="report from an archived subfolder of results/exp8 (e.g. opus_pilot)")
    ap.add_argument("--out", default=None, help="report file name (default SBGK_EXPERIMENT_REPORT_STRESS.md; smoke runs get .smoke.md)")
    ap.add_argument("--lang", choices=["en", "ru"], default="en", help="report language: en (tracked report) or ru (local *_RU.md from the untracked *_ru.py modules)")
    args = ap.parse_args()
    C.REPORT_LANG = args.lang

    if args.selftest:
        from sbgk_bench import exp8_selftest
        return 1 if exp8_selftest.selftest() else 0
    if args.report_only:
        write_report(args.out, args.data)
        return 0
    from sbgk_bench import exp8_run
    if not args.skip_build:
        C.build_release()
    for name in args.scenario.split(","):
        n = 2 if args.smoke else (args.cases or DEFAULT_CASES[name])
        print(f"== {name}: {n} cases x {args.modes}", flush=True)
        data = exp8_run.run_scenario(name, n, args.modes.split(","), workers=args.workers, fresh=args.fresh)
        old = E.OUT / f"{name}.json"
        # keep the largest result set already on disk (a smoke run must not overwrite a full run)
        if old.exists():
            prev = json.loads(old.read_text(encoding="utf-8"))
            if len(prev.get("case_info", [])) > len(data["case_info"]):
                print(f"  (kept the existing {old.name}: it has more cases)")
                continue
        old.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    try:
        write_report(args.out or (C.report_name("SBGK_EXPERIMENT_REPORT_STRESS", ".smoke.md") if args.smoke else None))
    except (ImportError, AttributeError) as e:
        print(f"report not written: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
