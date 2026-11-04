#!/usr/bin/env python3
"""EXP-7: heterogeneous agents exchange reasoning through the SBGK compiler -> results/exp7/exp7.json and the report.

Separate run: it does not touch results/summary.json, results/exp3_llm or the two earlier reports.

    python benchmarks/run_exp7_multiagent.py --cases 1 --max-turns 6    # smoke
    python benchmarks/run_exp7_multiagent.py                            # 8 cases x 4 sharing modes
    python benchmarks/run_exp7_multiagent.py --report-only

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
from sbgk_bench import exp7_multiagent as E  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=8)
    ap.add_argument("--modes", default=",".join(E.MODES))
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--max-turns", type=int, default=None)
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--lang", choices=["en", "ru"], default="en", help="report language: en (tracked report) or ru (local *_RU.md from the untracked *_ru.py modules)")
    args = ap.parse_args()
    C.REPORT_LANG = args.lang

    f = E.OUT / "exp7.json"
    if args.report_only:
        data = json.loads(f.read_text(encoding="utf-8"))
    else:
        if not args.skip_build:
            C.build_release()
        data = E.run(n_cases=args.cases, modes=tuple(args.modes.split(",")), workers=args.workers, fresh=args.fresh, max_turns=args.max_turns)
    try:
        report_multi = C.report_module("report_multi")
        name = args.out or C.report_name("SBGK_EXPERIMENT_REPORT_MULTIAGENT", ".md" if data["cases"] >= 8 else ".smoke.md")
        (C.ROOT / name).write_text(report_multi.render(data), encoding="utf-8")
        print(f"wrote {C.ROOT / name}")
    except ImportError:
        print("report_multi not written yet")
    print(f"wrote {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
