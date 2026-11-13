"""Check the published journals of the recorded runs with the binary of this tree: each kernel journal against the receipt of every
stage it recorded, and the last one at the journal's end. A journal of 0.2 (frames of `sbgk-session-log/3`) goes on past its last
receipt, as the server seals and closes the run after the last stage: it is checked against each receipt as a prefix, and then whole.
A rule change that a published journal does not survive fails here before a release does.

usage: python scripts/verify_published_runs.py <sbgk binary> <folder of run archives>
       python scripts/verify_published_runs.py <sbgk binary> --download <folder>   (needs `gh` and GH_TOKEN or a login)
The archives are the kernel sides of the release assets: <name>-K.tar.gz, with arm_c/run.wal and summary.json. Exit 1 if any check fails.
Standard library only."""
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile

RUNS = {"v0.1.0": ["haiku-K", "deepseek1-K", "deepseek2-K"], "v0.1.6": ["makers1-K", "makers2-K"], "v0.1.7": ["control017-K"],
        "v0.2.0": ["control02-run1-K", "control02-run2-K", "first02-run1-K", "first02-run2-K"]}
ROOTS = ("audit_root", "engine_root", "session_root", "wal_head")


def download(folder: pathlib.Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for tag, names in RUNS.items():
        for name in names:
            if not (folder / f"{name}.tar.gz").exists():
                subprocess.run(["gh", "release", "download", tag, "--repo", "OrganeticSphere/yuce", "-p", f"{name}.tar.gz", "-D", str(folder)], check=True)


def sealed_and_closed(wal: pathlib.Path) -> bool:
    """Whether the journal is of 0.2 and ends with a seal and the close of its run, the frames its server writes after the last stage."""
    with wal.open("rb") as f:
        first = json.loads(f.readline())
    if (first.get("header") or {}).get("format") != "sbgk-session-log/3":
        return False
    tail = wal.read_bytes().rstrip(b"\n").rsplit(b"\n", 2)[-2:]
    kinds = [((json.loads(line).get("body") or {}).get("command") or {}).get("kind") for line in tail]
    return kinds == ["seal", "close"]


def receipts(summary: dict) -> list[tuple[str, dict]]:
    """The receipt of every stage the kernel side recorded, in stage order."""
    side = summary.get("arm_c") or {}
    out = []
    for stage in sorted(k for k in side if k.startswith("phase")):
        receipt = (side[stage] or {}).get("receipt") or {}
        if receipt.get("audit_root"):
            out.append((stage, {k: receipt[k] for k in ROOTS if receipt.get(k)}))
    return out


def main() -> int:
    binary = pathlib.Path(sys.argv[1])
    if sys.argv[2] == "--download":
        folder = pathlib.Path(sys.argv[3])
        download(folder)
    else:
        folder = pathlib.Path(sys.argv[2])
    failed = 0
    names = [n for names in RUNS.values() for n in names]
    for name in names:
        archive = folder / f"{name}.tar.gz"
        if not archive.exists():
            print(f"{name}: MISSING {archive}")
            failed += 1
            continue
        with tempfile.TemporaryDirectory(prefix="published_") as work, tarfile.open(archive) as tar:
            wanted = [m for m in tar.getmembers() if m.name.endswith(("/arm_c/run.wal", "/summary.json")) and m.name.count("/") <= 2]
            tar.extractall(work, members=wanted, filter="data")
            wal = next(pathlib.Path(work).rglob("arm_c/run.wal"))
            summary = json.loads(next(pathlib.Path(work).rglob("summary.json")).read_text(encoding="utf-8"))
            stages = receipts(summary)
            if not stages:
                print(f"{name}: NO RECEIPT in summary.json")
                failed += 1
                continue
            closed = sealed_and_closed(wal)
            for n, (stage, receipt) in enumerate(stages):
                path = pathlib.Path(work) / f"{stage}.json"
                path.write_text(json.dumps(receipt), encoding="utf-8")
                at_end = n == len(stages) - 1 and not closed
                args = [str(binary), "audit-verify", "--wal", str(wal), "--expect", str(path)] + (["--at-end"] if at_end else [])
                done = subprocess.run(args, capture_output=True, text=True)
                try:
                    status = json.loads(done.stdout).get("status")
                except ValueError:
                    status = f"no report ({done.stderr.strip()[:120]})"
                ok = done.returncode == 0 and status == "VERIFIED"
                failed += not ok
                print(f"{name} {stage}{' at end' if at_end else ''}: {status}")
            if closed:
                done = subprocess.run([str(binary), "audit-verify", "--wal", str(wal)], capture_output=True, text=True)
                try:
                    status = json.loads(done.stdout).get("status")
                except ValueError:
                    status = f"no report ({done.stderr.strip()[:120]})"
                ok = done.returncode == 0 and status == "VERIFIED"
                failed += not ok
                print(f"{name} whole journal, sealed and closed after its last stage: {status}")
    print("published journals:", "all verified" if not failed else f"{failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
