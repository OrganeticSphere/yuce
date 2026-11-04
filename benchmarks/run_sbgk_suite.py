#!/usr/bin/env python3
"""Run the six SBGK-P0 falsification experiments and write results/summary.json plus the report.

    python benchmarks/run_sbgk_suite.py                # everything (a few minutes)
    python benchmarks/run_sbgk_suite.py --quick        # reduced sizes, for smoke runs
    python benchmarks/run_sbgk_suite.py --only 1,4     # selected experiments
    python benchmarks/run_sbgk_suite.py --skip-tests   # do not re-run `cargo test --release`

Requires: Rust toolchain (cargo) and Python 3.10+. No third-party Python packages.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from sbgk_bench import common as C  # noqa: E402
from sbgk_bench import exp1, exp2, exp3, exp4, exp5, exp6  # noqa: E402

EXPERIMENTS = {1: exp1, 2: exp2, 3: exp3, 4: exp4, 5: exp5, 6: exp6}


def sh(cmd: list[str], cwd=C.ROOT) -> tuple[int, str]:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8")
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def cargo_tests() -> dict:
    """Force a rebuild of the workspace crates so that compiler warnings are really counted."""
    sh(["cargo", "clean", "--release", "-p", "sbgk-core", "-p", "sbgk-cli"])
    code, out = sh(["cargo", "test", "--release", "--workspace"])
    passed = sum(int(m) for m in re.findall(r"test result: \w+\. (\d+) passed", out))
    failed = sum(int(m) for m in re.findall(r"; (\d+) failed", out))
    warnings = len(re.findall(r"^warning(\[|:)", out, flags=re.M))
    return {"exit_code": code, "passed": passed, "failed": failed, "compiler_warnings": warnings}


def environment() -> dict:
    _, rustc = sh(["rustc", "--version"])
    _, cargo = sh(["cargo", "--version"])
    return {
        "date_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
        "rustc": rustc.strip(),
        "cargo": cargo.strip(),
        "bytes_per_token_heuristic": C.BYTES_PER_TOKEN,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--only", default="1,2,3,4,5,6")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--no-report", action="store_true")
    ap.add_argument("--report-only", action="store_true", help="re-render the report from results/summary.json")
    ap.add_argument("--keep-work", action="store_true", help="keep results/work (containers, streams, corpora)")
    ap.add_argument("--lang", choices=["en", "ru"], default="en", help="report language: en (tracked report) or ru (local *_RU.md from the untracked *_ru.py modules)")
    args = ap.parse_args()
    wanted = [int(x) for x in args.only.split(",") if x]
    C.REPORT_LANG = args.lang
    report = C.report_module("report")

    if args.report_only:
        summary = json.loads((C.RESULTS / "summary.json").read_text(encoding="utf-8"))
        target = C.ROOT / C.report_name("SBGK_EXPERIMENT_REPORT")
        target.write_text(report.render(summary), encoding="utf-8")
        print(f"wrote {target}")
        return 0

    C.RESULTS.mkdir(exist_ok=True)
    if not args.skip_build:
        print("building release binaries ...", flush=True)
        C.build_release()
    tests = None
    if not args.skip_tests:
        print("cargo test --release --workspace ...", flush=True)
        tests = cargo_tests()
        print(f"  {tests}", flush=True)
        C.build_release()

    results, timings = {}, {}
    for n in wanted:
        print(f"EXP-{n} ...", flush=True)
        t0 = time.time()
        results[f"exp{n}"] = EXPERIMENTS[n].run(quick=args.quick)
        timings[f"exp{n}"] = round(time.time() - t0, 1)
        print(f"  done in {timings[f'exp{n}']} s; pass = {results[f'exp{n}']['pass']}", flush=True)

    summary = {"environment": environment(), "quick_mode": args.quick, "cargo_tests": tests,
               "wall_seconds": timings, "experiments": results}
    out = C.RESULTS / "summary.json"
    out.write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {out}")
    if not args.no_report and len(wanted) == 6:
        md = report.render(summary)
        target = C.ROOT / C.report_name("SBGK_EXPERIMENT_REPORT", ".quick.md" if args.quick else ".md")
        target.write_text(md, encoding="utf-8")
        print(f"wrote {target}")
    if not args.keep_work and C.WORK.exists():
        shutil.rmtree(C.WORK, ignore_errors=True)
    ok = all(all(r["pass"].values()) for r in results.values())
    print("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED (see summary.json)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
