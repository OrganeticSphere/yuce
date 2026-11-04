#!/usr/bin/env python3
"""Live-agent EXP-3 (Codex CLI) -> results/exp3_llm/exp3_llm.json and SBGK_EXPERIMENT_REPORT_LLM.md.

This is a separate run: it does not touch results/summary.json or SBGK_EXPERIMENT_REPORT.md.

    python benchmarks/run_exp3_llm.py                      # 30 tasks x 3 arms with gpt-5.6-sol
    python benchmarks/run_exp3_llm.py --limit 4            # smoke run (one task per error type)
    python benchmarks/run_exp3_llm.py --effort low         # pass model_reasoning_effort to Codex
    python benchmarks/run_exp3_llm.py --fresh              # ignore cached model replies
    python benchmarks/run_exp3_llm.py --report-only        # re-render the report from the saved JSON

Needs Codex CLI >= 0.163 logged in (ChatGPT or API key) and a built `sbgk` binary.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from sbgk_bench import common as C  # noqa: E402
from sbgk_bench import exp3_llm  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="gpt-5.6-sol")
    ap.add_argument("--effort", default=None, help="model_reasoning_effort override (default: Codex default for the model)")
    ap.add_argument("--limit", type=int, default=None, help="number of tasks (default 30)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--arms", default="A1,A2,B")
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--codex", default=None, help="path to codex executable")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--out", default=None, help="report path (default SBGK_EXPERIMENT_REPORT_LLM.md; --limit runs get a .smoke suffix)")
    ap.add_argument("--lang", choices=["en", "ru"], default="en", help="report language: en (tracked report) or ru (local *_RU.md from the untracked *_ru.py modules)")
    args = ap.parse_args()
    C.REPORT_LANG = args.lang
    report_llm = C.report_module("report_llm")

    data_file = exp3_llm.OUT / "exp3_llm.json"
    if args.report_only:
        data = json.loads(data_file.read_text(encoding="utf-8"))
    else:
        if not args.skip_build:
            C.build_release()
        data = exp3_llm.run(model=args.model, effort=args.effort, limit=args.limit, workers=args.workers,
                            arms=tuple(args.arms.split(",")), fresh=args.fresh, codex=args.codex)
    scripted = None
    sj = C.RESULTS / "summary.json"
    if sj.exists():
        scripted = json.loads(sj.read_text(encoding="utf-8"))["experiments"].get("exp3")
    name = args.out or C.report_name("SBGK_EXPERIMENT_REPORT_LLM", ".smoke.md" if (args.limit and args.limit < 30) else ".md")
    target = C.ROOT / name
    target.write_text(report_llm.render(data, scripted), encoding="utf-8")
    print(f"wrote {data_file}\nwrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
